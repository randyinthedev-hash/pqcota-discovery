// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"errors"
	"testing"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

const (
	client = discoveryv1.EdgeRole_EDGE_ROLE_CLIENT
	server = discoveryv1.EdgeRole_EDGE_ROLE_SERVER
	unspec = discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED
)

// TLS 역할은 메시지 종류와 방향으로 정한다. 어느 메시지 하나만 봐도 정해진다: 클라이언트 노드가 ClientHello만
// 본 경우(보냄)·ServerHello만 본 경우(받음), 서버 노드가 ClientHello만 본 경우(받음)·ServerHello만 본 경우(보냄).
func TestLocalRoleTLS(t *testing.T) {
	ch := &Handshake{Protocol: "TLS", Role: "client"}
	sh := &Handshake{Protocol: "TLS", Role: "server"}
	for name, c := range map[string]struct {
		hs          *Handshake
		sentByLocal bool
		want        discoveryv1.EdgeRole
	}{
		"client node, ClientHello only (sent)":     {ch, true, client},
		"client node, ServerHello only (received)": {sh, false, client},
		"server node, ClientHello only (received)": {ch, false, server},
		"server node, ServerHello only (sent)":     {sh, true, server},
	} {
		if got := LocalRole(c.hs, c.sentByLocal, OpenerUnseen, nil); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// SSH: SYN 방향이 먼저다. SYN을 못 봤으면 LISTEN 소켓이 있을 때만 SERVER이고, 없거나 조회에 실패하면
// UNSPECIFIED다 — 조회 시점에 리스너가 없다는 것은 이미 받은 연결이 클라이언트라는 근거가 아니다. 포트 크기로
// 추정하지 않는다.
func TestLocalRoleSSH(t *testing.T) {
	kex := &Handshake{Protocol: "SSH"}
	yes := func() (bool, error) { return true, nil }
	no := func() (bool, error) { return false, nil }
	fail := func() (bool, error) { return false, errors.New("no /proc") }
	for name, c := range map[string]struct {
		opener    Opener
		listening func() (bool, error)
		want      discoveryv1.EdgeRole
	}{
		"local sent SYN":                 {OpenerLocal, nil, client},
		"remote sent SYN":                {OpenerRemote, nil, server},
		"SYN wins over a listener":       {OpenerLocal, yes, client},
		"no SYN, listening":              {OpenerUnseen, yes, server},
		"no SYN, not listening":          {OpenerUnseen, no, unspec},
		"no SYN, lookup failed":          {OpenerUnseen, fail, unspec},
		"no SYN, no lookup":              {OpenerUnseen, nil, unspec},
		"remote sent SYN, lookup failed": {OpenerRemote, fail, server},
		"local sent SYN, not listening":  {OpenerLocal, no, client},
	} {
		for _, sent := range []bool{true, false} {
			if got := LocalRole(kex, sent, c.opener, c.listening); got != c.want {
				t.Errorf("%s (sent=%v): %v, want %v", name, sent, got, c.want)
			}
		}
	}
}

// 값 규칙: 클라이언트 기록은 지금과 같고, 서버 기록은 dst_addr에 클라이언트 ip만(포트 없음, IPv6는 괄호 없음),
// port에 받은 포트. 미확인은 상대 ip와 포트 0. 끝점은 소켓 찾기용으로 따로 남는다.
func TestTupleFor(t *testing.T) {
	c := TupleFor("web-01", client, "10.0.1.10", 40000, "10.0.1.20", 8443)
	if c.DstAddr != "10.0.1.20:8443" || c.Port != 8443 || c.LocalAddr != "10.0.1.10:40000" || c.RemoteAddr != "10.0.1.20:8443" {
		t.Errorf("client: %+v", c)
	}
	s := TupleFor("web-02", server, "10.0.1.20", 8443, "10.0.1.10", 40000)
	if s.DstAddr != "10.0.1.10" || s.Port != 8443 || s.LocalAddr != "10.0.1.20:8443" || s.RemoteAddr != "10.0.1.10:40000" {
		t.Errorf("server: %+v", s)
	}
	s6 := TupleFor("web-02", server, "fd00::20", 443, "fd00::10", 51234)
	if s6.DstAddr != "fd00::10" || s6.Port != 443 || s6.RemoteAddr != "[fd00::10]:51234" || s6.LocalAddr != "[fd00::20]:443" {
		t.Errorf("server, IPv6: %+v", s6)
	}
	u := TupleFor("web-03", unspec, "10.0.1.30", 22, "10.0.1.40", 50022)
	if u.DstAddr != "10.0.1.40" || u.Port != 0 || u.Role != unspec {
		t.Errorf("unspecified: %+v", u)
	}
	if e := BuildEdge(s, &Handshake{Protocol: "TLS", Role: "client"}); e.GetRole() != server || e.GetSrcNodeId() != "web-02" {
		t.Errorf("BuildEdge took the role from the message, not the tuple: %v", e)
	}
}
