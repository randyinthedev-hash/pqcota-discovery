// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"fmt"
	"testing"

	"github.com/randyinthedev-hash/pqcota-discovery/collectors/network"
	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
)

// 앱 키 2단계: 연결마다 앱을 짚고 앱 키별로 엣지를 묶는다.

const dst = "172.20.0.2:4433"

// hello — 연결 하나의 ClientHello·ServerHello 관측 둘. 그룹은 ServerHello에만 있다.
func hello(localPort int) []network.Observation {
	c := network.ConnTuple{SrcNode: "n1", DstAddr: dst, Port: 4433, SrcInitiated: true, LocalAddr: fmt.Sprintf("172.20.0.3:%d", localPort)}
	return []network.Observation{
		{Conn: c, HS: &network.Handshake{Protocol: "TLS", Role: "client"}},
		{Conn: c, HS: &network.Handshake{Protocol: "TLS", Role: "server", NegotiatedGroup: "secp256r1", Cipher: "TLS_AES_256_GCM_SHA384"}},
	}
}

// byPort — 출발 포트로 앱을 정하는 가짜 귀속. 표에 없는 포트는 「닫힘」, ambiguous에 있으면 「주인 모호」.
func byPort(apps map[uint32]string, ambiguous ...uint32) attributeFunc {
	amb := map[uint32]bool{}
	for _, p := range ambiguous {
		amb[p] = true
	}
	return func(lip string, lport uint32, rip string, rport uint32) procs.Attribution {
		if lip != "172.20.0.3" || rip != "172.20.0.2" || rport != 4433 {
			return procs.Attribution{Reason: "wrong endpoints passed"}
		}
		if amb[lport] {
			return procs.Attribution{Reason: procs.ReasonOwnerAmbiguous}
		}
		if k, ok := apps[lport]; ok {
			return procs.Attribution{Key: k, Kind: procs.KindSystemdUserUnit}
		}
		return procs.Attribution{Reason: procs.ReasonSocketGone}
	}
}

func counts(t *testing.T, a aggregated) map[string]uint64 {
	t.Helper()
	m := map[string]uint64{}
	for _, e := range a.edges {
		if _, dup := m[e.GetAppKey()]; dup {
			t.Errorf("two edges with app key %q", e.GetAppKey())
		}
		m[e.GetAppKey()] = e.GetObservedCount()
		if e.GetNegotiatedGroup() != "secp256r1" {
			t.Errorf("edge %q lost the group: %q", e.GetAppKey(), e.GetNegotiatedGroup())
		}
	}
	return m
}

// TestServicesOnTheSameDestinationStayApart — 같은 목적지의 두 서비스는 엣지 둘이고(B3), 같은 서비스가
// 다시 붙은 연결은 한 엣지로 모여 observed_count가 연결 수다(B2). ClientHello·ServerHello는 한 연결이다.
func TestServicesOnTheSameDestinationStayApart(t *testing.T) {
	var obs []network.Observation
	apps := map[uint32]string{}
	for i := 0; i < 2; i++ {
		obs = append(obs, hello(41000+i)...)
		apps[uint32(41000+i)] = "user@1001.service/svc-a.service"
	}
	for i := 0; i < 5; i++ {
		obs = append(obs, hello(42000+i)...)
		apps[uint32(42000+i)] = "user@1001.service/svc-b.service"
	}
	a := aggregate(obs, nil, byPort(apps))
	got := counts(t, a)
	want := map[string]uint64{"user@1001.service/svc-a.service": 2, "user@1001.service/svc-b.service": 5}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("edges %v, want %v", got, want)
	}
	if a.conns != 7 || len(a.unattributed) != 0 {
		t.Errorf("conns=%d unattributed=%v", a.conns, a.unattributed)
	}
}

// TestUnattributedStaysItsOwnEdge — 닫힌 소켓(B5)과 주인을 하나로 못 정한 소켓(B6)의 연결은 앱 키를 비운
// 채 남고, 같은 목적지의 다른 서비스 엣지에 더해지지 않는다.
func TestUnattributedStaysItsOwnEdge(t *testing.T) {
	obs := append(hello(41000), hello(41001)...) // svc-a 둘
	obs = append(obs, hello(43000)...)           // 닫힘
	obs = append(obs, hello(44000)...)           // 주인 모호
	a := aggregate(obs, nil, byPort(map[uint32]string{41000: "user@1001.service/svc-a.service", 41001: "user@1001.service/svc-a.service"}, 44000))

	got := counts(t, a)
	want := map[string]uint64{"user@1001.service/svc-a.service": 2, "": 2}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("edges %v, want %v — an unattributed connection was merged into another service or dropped", got, want)
	}
	if a.unattributed[procs.ReasonSocketGone] != 1 || a.unattributed[procs.ReasonOwnerAmbiguous] != 1 {
		t.Errorf("reasons %v", a.unattributed)
	}
	if len(a.missed) != 2 {
		t.Errorf("missed %v", a.missed)
	}
	for _, e := range a.edges {
		if e.GetAppKey() == "" && e.GetAppKeyKind() != "" {
			t.Errorf("empty key with a kind %q", e.GetAppKeyKind())
		}
	}
}

// TestSourcePortIsNotInTheEdge — 출발 포트는 소켓을 찾는 데만 쓴다(B4). 엣지에는 목적지만 남는다.
func TestSourcePortIsNotInTheEdge(t *testing.T) {
	a := aggregate(append(hello(41000), hello(41001)...), nil, byPort(map[uint32]string{41000: "x.service", 41001: "x.service"}))
	if len(a.edges) != 1 {
		t.Fatalf("%d edges — reconnects from new source ports made new edges", len(a.edges))
	}
	if e := a.edges[0]; e.GetDstAddr() != dst || e.GetPort() != 4433 {
		t.Errorf("edge %s:%d", e.GetDstAddr(), e.GetPort())
	}
}

func TestSplitAddr(t *testing.T) {
	for _, c := range []struct {
		in   string
		ip   string
		port uint32
		ok   bool
	}{
		{"172.20.0.3:41000", "172.20.0.3", 41000, true},
		{"[fd00::3]:41000", "fd00::3", 41000, true},
		{"fd00::2:4433", "fd00::2", 4433, true}, // DstAddr의 IPv6 표기(괄호 없음)
		{"", "", 0, false},
		{"host:1", "", 0, false},
	} {
		ip, port, ok := splitAddr(c.in)
		if ip != c.ip || port != c.port || ok != c.ok {
			t.Errorf("%q → %q %d %v", c.in, ip, port, ok)
		}
	}
}
