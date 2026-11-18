// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"fmt"
	"net"
	"strconv"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// LocalRole — 이 연결에서 **관측 노드(로컬)의 역할**. 메시지 종류와 패킷 방향을 함께 본다.
//
//   - TLS: ClientHello의 송신자는 클라이언트, ServerHello의 송신자는 서버다. 그래서 어느 메시지 하나만 봐도
//     정해진다. 로컬이 ClientHello를 보냈거나 ServerHello를 받았으면 CLIENT, 그 반대면 SERVER.
//   - SSH: 양쪽이 KEXINIT을 보내므로 메시지로는 정할 수 없다. 로컬 포트에 LISTEN 소켓이 있으면 SERVER,
//     읽었는데 없으면 CLIENT. **읽지 못했으면 UNSPECIFIED.** 낮은 포트로 추정하지 않는다 — 클라이언트가 낮은
//     포트를 쓰거나 서버가 높은 포트를 쓰면 반대로 판정되고, 그 추정이 확인된 역할과 같은 얼굴로 남는다.
//
// v0.17.0까지는 메시지 종류만으로 정했다(ServerHello면 SERVER). 클라이언트 쪽에서 ServerHello를 먼저 보면
// 클라이언트 기록이 SERVER가 됐다.
func LocalRole(hs *Handshake, sentByLocal bool, listening func() (bool, error)) discoveryv1.EdgeRole {
	switch hs.Protocol {
	case "TLS":
		clientSent := (hs.Role == "client") == sentByLocal // 로컬이 ClientHello를 보냈거나, 로컬이 ServerHello를 받았다
		switch hs.Role {
		case "client", "server":
			if clientSent {
				return discoveryv1.EdgeRole_EDGE_ROLE_CLIENT
			}
			return discoveryv1.EdgeRole_EDGE_ROLE_SERVER
		}
	case "SSH":
		if listening == nil {
			return discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED
		}
		on, err := listening()
		switch {
		case err != nil:
			return discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED
		case on:
			return discoveryv1.EdgeRole_EDGE_ROLE_SERVER
		default:
			return discoveryv1.EdgeRole_EDGE_ROLE_CLIENT
		}
	}
	return discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED
}

// TupleFor — 로컬·원격 끝점과 로컬의 역할로 엣지의 값을 정한다(계획 2026-11-18-server-role-edges §3).
//
//	역할        dst_addr                 port
//	CLIENT      서버 ip:port             서버 포트          (v0.17.0까지와 같다)
//	SERVER      클라이언트 ip(포트 없음)  로컬(받은) 포트
//	UNSPECIFIED 상대 ip(포트 없음)        0(어느 쪽이 서비스 포트인지 모른다)
//
// 클라이언트의 출발 포트는 연결마다 바뀌므로 엣지에 싣지 않는다. 소켓을 찾는 데만 쓴다(LocalAddr·RemoteAddr).
func TupleFor(node string, role discoveryv1.EdgeRole, localIP string, localPort uint16, remoteIP string, remotePort uint16) ConnTuple {
	t := ConnTuple{
		SrcNode:    node,
		Role:       role,
		LocalAddr:  net.JoinHostPort(localIP, strconv.Itoa(int(localPort))),
		RemoteAddr: net.JoinHostPort(remoteIP, strconv.Itoa(int(remotePort))),
	}
	switch role {
	case discoveryv1.EdgeRole_EDGE_ROLE_CLIENT:
		t.DstAddr = fmt.Sprintf("%s:%d", remoteIP, remotePort)
		t.Port = uint32(remotePort)
	case discoveryv1.EdgeRole_EDGE_ROLE_SERVER:
		t.DstAddr = remoteIP
		t.Port = uint32(localPort)
	default:
		t.DstAddr = remoteIP
	}
	return t
}
