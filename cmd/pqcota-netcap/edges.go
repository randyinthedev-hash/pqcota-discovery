// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/network"
	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
)

// attributeFunc — 연결 하나(로컬·원격 끝점)의 앱을 짚는다. 실행 때는 procs.Attributor.Conn이고, 시험은
// 가짜를 넣는다.
type attributeFunc func(localIP string, localPort uint32, remoteIP string, remotePort uint32) procs.Attribution

// aggregate — 관측(핸드셰이크 메시지)을 연결로 모으고, 연결마다 앱을 짚은 뒤, 앱 키별로 엣지를 만든다.
//
//  1. **연결로 모은다.** TLS는 ClientHello와 ServerHello가 따로 관측된다. 같은 연결(출발 포트까지 같은
//     것)의 관측은 하나로 합친다. 그래서 observed_count는 **본 연결의 수**다. 협상 그룹은 ServerHello에만
//     실리므로 그룹이 있는 관측의 값을 쓴다.
//  2. **연결마다 앱을 짚는다.** 두 끝점이 맞는 소켓 하나로 짚는다([procs.Attributor.Conn]). 못 짚으면
//     앱 키를 비우고 사유를 센다. 같은 목적지의 다른 연결로 대신 짚지 않는다.
//  3. **앱 키별로 묶는다.** 묶는 키는 (출발 노드, 목적지, 포트, 프로토콜, 앱 키, 종류)다. 출발 포트는
//     넣지 않는다 — 같은 서비스가 다시 붙은 연결은 한 엣지로 모이고, 같은 목적지에 붙은 두 서비스는
//     엣지 둘이 된다. 앱 키가 빈 연결끼리는 빈 키의 엣지 하나로 모인다.
//
// aggregated — aggregate의 결과.
type aggregated struct {
	edges        []*discoveryv1.ObservedEdge // 처음 본 순서
	conns        int                         // 본 연결 수
	unattributed map[string]int              // 못 짚은 사유 → 연결 수
	missed       []string                    // 못 짚은 연결 "로컬 → 원격: 사유"(stderr용. 결과에는 싣지 않는다)
}

func aggregate(obs []network.Observation, self map[string]bool, attribute attributeFunc) aggregated {
	type conn struct {
		tuple network.ConnTuple
		edge  *discoveryv1.ObservedEdge
	}
	var conns []*conn
	byConn := map[string]*conn{}
	for _, o := range obs {
		if o.HS == nil || !network.ShouldObserve(o.Conn, self) {
			continue
		}
		e := network.BuildEdge(o.Conn, o.HS)
		k := fmt.Sprintf("%s|%s|%d|%d|%s", e.GetSrcNodeId(), e.GetDstAddr(), e.GetPort(), e.GetProtocol(), o.Conn.LocalAddr)
		if c, ok := byConn[k]; ok {
			fillGroup(c.edge, e)
			continue
		}
		c := &conn{tuple: o.Conn, edge: e}
		byConn[k] = c
		conns = append(conns, c)
	}

	out := aggregated{conns: len(conns), unattributed: map[string]int{}}
	byKey := map[string]*discoveryv1.ObservedEdge{}
	var order []string
	for _, c := range conns {
		a := attributeConn(c.tuple, attribute)
		if a.Key == "" {
			out.unattributed[a.Reason]++
			out.missed = append(out.missed, fmt.Sprintf("%s → %s: %s", c.tuple.LocalAddr, c.tuple.DstAddr, a.Reason))
		}
		e := c.edge
		e.AppKey, e.AppKeyKind = a.Key, a.Kind
		k := fmt.Sprintf("%s|%s|%d|%d|%s|%s", e.GetSrcNodeId(), e.GetDstAddr(), e.GetPort(), e.GetProtocol(), e.GetAppKey(), e.GetAppKeyKind())
		if ex, ok := byKey[k]; ok {
			ex.ObservedCount += e.GetObservedCount()
			fillGroup(ex, e)
			continue
		}
		byKey[k] = e
		order = append(order, k)
	}
	out.edges = make([]*discoveryv1.ObservedEdge, 0, len(order))
	for _, k := range order {
		out.edges = append(out.edges, byKey[k])
	}
	return out
}

// fillGroup — 그룹을 아직 모르면 다른 관측의 그룹·cipher를 쓴다(ServerHello에만 실린다).
func fillGroup(into, e *discoveryv1.ObservedEdge) {
	if into.GetNegotiatedGroup() == "" && e.GetNegotiatedGroup() != "" {
		into.NegotiatedGroup = e.GetNegotiatedGroup()
		into.Cipher = e.GetCipher()
	}
}

// reasonBadTuple — 캡처가 준 끝점을 읽지 못했다. 정상 캡처에서는 나오지 않는다.
const reasonBadTuple = "the connection's endpoints could not be read — no socket lookup was made"

// attributeConn — 연결의 두 끝점을 풀어 앱을 짚는다.
func attributeConn(t network.ConnTuple, attribute attributeFunc) procs.Attribution {
	lip, lport, ok1 := splitAddr(t.LocalAddr)
	rip, rport, ok2 := splitAddr(t.DstAddr)
	if !ok1 || !ok2 {
		return procs.Attribution{Reason: reasonBadTuple}
	}
	return attribute(lip, lport, rip, rport)
}

// splitAddr — "ip:port" 또는 "[v6]:port". DstAddr는 IPv6도 괄호 없이 "a:b::c:443"로 적히므로 마지막
// 콜론에서 자른다.
func splitAddr(s string) (string, uint32, bool) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		i := strings.LastIndex(s, ":")
		if i <= 0 {
			return "", 0, false
		}
		host, port = s[:i], s[i+1:]
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || net.ParseIP(host) == nil {
		return "", 0, false
	}
	return host, uint32(n), true
}
