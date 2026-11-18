// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"fmt"
	"testing"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/network"
	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
)

// 앱 키 2단계: 연결마다 앱을 짚고 앱 키별로 엣지를 묶는다.

const dst = "172.20.0.2:4433"

// hello — 연결 하나의 ClientHello·ServerHello 관측 둘. 그룹은 ServerHello에만 있다.
func hello(localPort int) []network.Observation {
	c := network.TupleFor("n1", discoveryv1.EdgeRole_EDGE_ROLE_CLIENT, "172.20.0.3", uint16(localPort), "172.20.0.2", 4433)
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

// serverHello — 서버 노드(로컬 serverIP:serverPort)가 본 연결 하나. 클라이언트의 ClientHello(받음)와 자기 ServerHello(보냄).
func serverHello(serverIP string, serverPort uint16, clientIP string, clientPort uint16) []network.Observation {
	c := network.TupleFor("srv", discoveryv1.EdgeRole_EDGE_ROLE_SERVER, serverIP, serverPort, clientIP, clientPort)
	return []network.Observation{
		{Conn: c, HS: &network.Handshake{Protocol: "TLS", Role: "client"}},
		{Conn: c, HS: &network.Handshake{Protocol: "TLS", Role: "server", NegotiatedGroup: "X25519MLKEM768", Cipher: "TLS_AES_256_GCM_SHA384"}},
	}
}

// byServerPort — 서버 쪽 귀속. 로컬(서버) 끝점과 원격(클라이언트) 끝점이 바르게 넘어오는지 보고, 받은 포트로 앱을 정한다.
func byServerPort(apps map[uint32]string) attributeFunc {
	return func(lip string, lport uint32, rip string, rport uint32) procs.Attribution {
		if rport < 40000 {
			return procs.Attribution{Reason: "the client's endpoint was not passed as the remote end"}
		}
		if k, ok := apps[lport]; ok {
			return procs.Attribution{Key: k, Kind: procs.KindExePath}
		}
		return procs.Attribution{Reason: procs.ReasonSocketGone}
	}
}

// 서버 기록(S1·S3·S4): 같은 클라이언트가 출발 포트만 바꿔 다시 붙으면 서버 기록은 하나이고 observed_count가 연결 수다.
// IPv4·IPv6 모두. dst_addr는 클라이언트 ip(포트·괄호 없음), port는 받은 포트, 역할은 SERVER, 앱은 연결을 받은 프로세스.
// 한 노드의 두 프로세스가 각자 다른 포트로 받으면 엣지 둘이고, 같은 클라이언트의 연결이라도 섞이지 않는다.
func TestServerRecords(t *testing.T) {
	var obs []network.Observation
	for i := 0; i < 3; i++ {
		obs = append(obs, serverHello("10.0.1.20", 443, "10.0.1.10", uint16(41000+i))...)
		obs = append(obs, serverHello("fd00::20", 443, "fd00::10", uint16(51000+i))...)
	}
	obs = append(obs, serverHello("10.0.1.20", 8443, "10.0.1.10", 42000)...)
	a := aggregate(obs, nil, byServerPort(map[uint32]string{443: "/usr/bin/openssl", 8443: "/usr/sbin/other"}))
	got := map[string]uint64{}
	for _, e := range a.edges {
		if e.GetRole() != discoveryv1.EdgeRole_EDGE_ROLE_SERVER || e.GetSrcNodeId() != "srv" || e.GetNegotiatedGroup() != "X25519MLKEM768" {
			t.Errorf("edge %v", e)
		}
		got[fmt.Sprintf("%s|%d|%s", e.GetDstAddr(), e.GetPort(), e.GetAppKey())] = e.GetObservedCount()
	}
	want := map[string]uint64{
		"10.0.1.10|443|/usr/bin/openssl": 3,
		"fd00::10|443|/usr/bin/openssl":  3,
		"10.0.1.10|8443|/usr/sbin/other": 1,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) || a.conns != 7 || len(a.unattributed) != 0 {
		t.Fatalf("edges %v (conns %d, unattributed %v), want %v", got, a.conns, a.unattributed, want)
	}
}

// 같은 연결 튜플이라도 역할이 다르면(클라이언트·서버를 한 노드가 같이 본 경우는 없지만, 키에 역할이 있어야
// 미확인 기록과 확인된 기록이 섞이지 않는다) 연결도 엣지도 따로다.
func TestRoleIsPartOfTheConnectionKey(t *testing.T) {
	ssh := &network.Handshake{Protocol: "SSH"}
	known := network.TupleFor("n", discoveryv1.EdgeRole_EDGE_ROLE_SERVER, "10.0.0.2", 22, "10.0.0.1", 50000)
	unknown := network.TupleFor("n", discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED, "10.0.0.2", 22, "10.0.0.1", 50000)
	a := aggregate([]network.Observation{{Conn: known, HS: ssh}, {Conn: unknown, HS: ssh}}, nil,
		func(string, uint32, string, uint32) procs.Attribution {
			return procs.Attribution{Key: "sshd.service", Kind: procs.KindSystemdUnit}
		})
	if a.conns != 2 || len(a.edges) != 2 {
		t.Fatalf("conns %d edges %d", a.conns, len(a.edges))
	}
}
