// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package network

import (
	"fmt"
	"net"
	"strconv"
	"time"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"golang.org/x/sys/unix"
)

// LiveSource — AF_PACKET 원시 소켓 캡처(디스커버리 설계 §2.3, CAP_NET_RAW 필요). 관측 구간 동안 핸드셰이크
// 프레임을 읽어 통신 엣지 관측으로 바꾼다. 조립은 순수 부분(DissectTCPPayload·ParseHandshakePayload)의 합성.
// 소켓을 못 열면(권한 등) ErrCaptureUnavailable로 감싸 반환 → 코어가 완전성 갭으로 강등(TD-NETWORK-13).
type LiveSource struct {
	Iface   string          // 캡처 인터페이스(예 "eth0"). ""=모든 인터페이스
	Node    string          // 캡처 호스트 스코프 노드 ID(앵커)
	SelfIPs map[string]bool // 자기 IP — 패킷 방향(로컬이 보냈나)·자기참조(§2.6)
	// Listening — 로컬 주소·포트를 받는 LISTEN 소켓이 있나(SSH 역할 판정, SYN을 못 봤을 때만). 없거나, nil이거나,
	// 오류면 SSH 역할은 UNSPECIFIED다.
	Listening  func(localIP string, port uint16) (bool, error)
	Window     time.Duration // 관측 구간(0이면 3초)
	MaxPackets int           // 상한(0=구간으로만 종료)

	// Truncated — 구간을 다 채우지 못하고 읽기 오류로 중단됐나. 중단을 알리지 않고 "관측 없음"으로
	// 보고하면 **결함이 갭처럼 보인다**(§2.6) — 호출자가 완전성 노트에 반영하라고 남긴다.
	Truncated bool
	TruncErr  error

	opened map[string]bool // 관측 구간에서 본 연결 여는 SYN: 「로컬|원격」 끝점 → 로컬이 보냈나
}

func htons(x uint16) uint16 { return (x << 8) | (x >> 8) }

// WindowTruncated — TruncatingSource 구현. 구간이 읽기 오류로 중단됐는지 서비스에 알린다.
func (s *LiveSource) WindowTruncated() (bool, error) { return s.Truncated, s.TruncErr }

func (s *LiveSource) Observe(_ []string, _ map[string]string) ([]Observation, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket could not be opened (%v): %w", err, ErrCaptureUnavailable)
	}
	defer unix.Close(fd)

	if s.Iface != "" {
		if ifi, e := net.InterfaceByName(s.Iface); e == nil {
			_ = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index})
		}
	}
	// 수신 타임아웃으로 관측 구간을 폴링한다(handshake-only 필터는 BPF로 확장 예정, 디스커버리 설계 §2.3).
	tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	window := s.Window
	if window <= 0 {
		window = 3 * time.Second
	}
	end := time.Now().Add(window)
	buf := make([]byte, 65536)
	var out []Observation
	pend := newSSHPending()
	s.opened = map[string]bool{}
	for time.Now().Before(end) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// ★ EINTR을 반드시 재시도한다. Go 런타임은 고루틴 선점을 위해 스레드에 SIGURG를 보내는데,
			// 그 시그널이 블로킹 syscall을 깨우면 EINTR이 돌아온다(netpoller가 감싸주지 않는 원시
			// syscall이라 자동 재시도가 없다). 이걸 치명적 오류로 보고 break 하면 **중단 사실을 알리지 않은 채
			// 관측 구간이 무작위 시점에 끝난다** — 실측: 25초 구간이 0·0·14·25초에 끝났고, 그때마다 "핸드셰이크
			// 없음"으로 보고돼 결함이 갭처럼 보였다(§2.6).
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue // 구간 내 타임아웃·시그널 인터럽트 — 계속 관측
			}
			// 그 밖의 읽기 오류로 중단되면 구간을 다 못 채운 것이다. 숨기지 않고 표시한다.
			s.Truncated, s.TruncErr = true, err
			break
		}
		seg, ok := DissectTCP(buf[:n])
		if !ok {
			continue
		}
		if seg.OpensConnection() {
			s.noteOpen(seg)
		}
		if len(seg.Payload) == 0 {
			continue
		}
		hs, ok := ParseHandshakePayload(seg.Payload)
		if !ok {
			continue
		}
		conn, emit := s.edgeFor(seg, hs)
		if !emit {
			continue // 이 노드의 연결이 아니거나 자기 자신과의 연결
		}
		// SSH는 양쪽 KEXINIT을 다 봐야 협상 결과를 알 수 있다(RFC 4253) — 연결별로 모았다가 구간이
		// 끝난 뒤 계산한다. TLS는 ServerHello에 확정 그룹이 있어 그대로 방출한다.
		if hs.Protocol == "SSH" {
			pend.add(conn, hs, s.SelfIPs[seg.SrcIP])
			continue
		}
		out = append(out, Observation{Conn: conn, HS: hs})
		if s.MaxPackets > 0 && len(out) >= s.MaxPackets {
			break
		}
	}
	return append(out, pend.resolve()...), nil
}

// sshPending — 연결별로 클라이언트·서버 KEXINIT을 모은다. 한쪽만 봤으면 협상은 미상으로 둔다.
type sshPending struct {
	order []string               // 첫 관측 순서(결정론적 출력)
	byKey map[string]*sshKexPair //
}

type sshKexPair struct {
	conn                        ConnTuple
	client, server              []string
	unknownLocal, unknownRemote []string // 역할 미확인 — 어느 쪽이 클라이언트인지 모른다
}

func newSSHPending() *sshPending { return &sshPending{byKey: map[string]*sshKexPair{}} }

func (p *sshPending) add(conn ConnTuple, hs *Handshake, fromSelf bool) {
	// 연결마다 따로 모은다(출발 포트까지). 같은 목적지의 SSH 연결이 여럿이면 KEXINIT이 섞이지 않고,
	// 연결마다 앱을 짚을 수 있다.
	key := fmt.Sprintf("%s|%s|%s", conn.SrcNode, conn.LocalAddr, conn.RemoteAddr)
	e, ok := p.byKey[key]
	if !ok {
		e = &sshKexPair{conn: conn}
		p.byKey[key] = e
		p.order = append(p.order, key)
	}
	// 로컬이 보낸 KEXINIT은 로컬 역할의 것이다. 역할을 확인하지 못했으면 어느 쪽인지 모른다 — 협상을 정하지 않는다.
	localIsClient := conn.Role == discoveryv1.EdgeRole_EDGE_ROLE_CLIENT
	switch {
	case conn.Role == discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED:
		if fromSelf {
			e.unknownLocal = hs.OfferedGroups
		} else {
			e.unknownRemote = hs.OfferedGroups
		}
	case fromSelf == localIsClient:
		e.client = hs.OfferedGroups
	default:
		e.server = hs.OfferedGroups
	}
}

func (p *sshPending) resolve() []Observation {
	out := make([]Observation, 0, len(p.order))
	for _, k := range p.order {
		e := p.byKey[k]
		offered := e.client
		if len(offered) == 0 {
			offered = e.server // 클라이언트 KEXINIT을 놓쳤으면 본 것만 제안으로 남긴다
		}
		if e.conn.Role == discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED {
			offered = e.unknownLocal
			if len(offered) == 0 {
				offered = e.unknownRemote
			}
		}
		out = append(out, Observation{Conn: e.conn, HS: &Handshake{
			Protocol:      "SSH",
			Role:          "client",
			OfferedGroups: offered,
			// 양쪽을 다 본 경우에만 채워진다 — 아니면 "" → 코어가 ⚪ 불명으로 분류(§2.5).
			NegotiatedGroup: NegotiateSSHKex(e.client, e.server),
		}})
	}
	return out
}

// edgeFor — 세그먼트를 이 노드의 연결로 본다. 로컬은 자기 IP 쪽이다. 로컬의 역할은 [LocalRole]이 메시지 종류와
// 방향으로 정하고, 값은 [TupleFor]가 정한다. 로컬이 서버여도 방출한다(v0.18.0부터). 한쪽도 로컬이 아니거나
// 양쪽 다 로컬(자기 자신과의 연결)이면 방출하지 않는다.
//
// v0.17.0까지는 낮은 포트 쪽을 서버로 보고, 로컬이 클라이언트일 때만 방출했다. 서버에서 받은 연결은 엣지가 없었다.
func (s *LiveSource) edgeFor(seg *Segment, hs *Handshake) (ConnTuple, bool) {
	srcSelf, dstSelf := s.SelfIPs[seg.SrcIP], s.SelfIPs[seg.DstIP]
	if srcSelf == dstSelf {
		return ConnTuple{}, false
	}
	localIP, localPort, remoteIP, remotePort := seg.SrcIP, seg.SrcPort, seg.DstIP, seg.DstPort
	if dstSelf {
		localIP, localPort, remoteIP, remotePort = seg.DstIP, seg.DstPort, seg.SrcIP, seg.SrcPort
	}
	var listening func() (bool, error)
	if s.Listening != nil {
		listening = func() (bool, error) { return s.Listening(localIP, localPort) }
	}
	opener := OpenerUnseen
	if byLocal, seen := s.opened[endpoints(localIP, localPort, remoteIP, remotePort)]; seen {
		opener = OpenerRemote
		if byLocal {
			opener = OpenerLocal
		}
	}
	role := LocalRole(hs, srcSelf, opener, listening)
	return TupleFor(s.Node, role, localIP, localPort, remoteIP, remotePort), true
}

// noteOpen — 연결을 여는 SYN을 적어 둔다. 한쪽만 로컬인 연결만.
func (s *LiveSource) noteOpen(seg *Segment) {
	if s.opened == nil {
		s.opened = map[string]bool{}
	}
	srcSelf, dstSelf := s.SelfIPs[seg.SrcIP], s.SelfIPs[seg.DstIP]
	switch {
	case srcSelf && !dstSelf:
		s.opened[endpoints(seg.SrcIP, seg.SrcPort, seg.DstIP, seg.DstPort)] = true
	case dstSelf && !srcSelf:
		s.opened[endpoints(seg.DstIP, seg.DstPort, seg.SrcIP, seg.SrcPort)] = false
	}
}

// endpoints — 연결의 로컬·원격 끝점 키.
func endpoints(localIP string, localPort uint16, remoteIP string, remotePort uint16) string {
	return net.JoinHostPort(localIP, strconv.Itoa(int(localPort))) + "|" + net.JoinHostPort(remoteIP, strconv.Itoa(int(remotePort)))
}
