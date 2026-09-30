//go:build linux

package network

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// LiveSource — AF_PACKET 원시 소켓 캡처(디스커버리 설계 §2.3, CAP_NET_RAW 필요). 관측 구간 동안 핸드셰이크
// 프레임을 읽어 통신 엣지 관측으로 바꾼다. 조립은 순수 부분(DissectTCPPayload·ParseHandshakePayload)의 합성.
// 소켓을 못 열면(권한 등) ErrCaptureUnavailable로 감싸 반환 → 코어가 완전성 갭으로 강등(TD-NETWORK-13).
type LiveSource struct {
	Iface      string          // 캡처 인터페이스(예 "eth0"). ""=모든 인터페이스
	Node       string          // 캡처 호스트 스코프 노드 ID(앵커)
	SelfIPs    map[string]bool // 자기 IP — 방향 판정·자기참조(§2.6)
	Window     time.Duration   // 관측 구간(0이면 3초)
	MaxPackets int             // 상한(0=구간으로만 종료)

	// Truncated — 구간을 다 채우지 못하고 읽기 오류로 중단됐나. 중단을 알리지 않고 "관측 없음"으로
	// 보고하면 **결함이 갭처럼 보인다**(§2.6) — 호출자가 완전성 노트에 반영하라고 남긴다.
	Truncated bool
	TruncErr  error
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
		seg, ok := DissectTCPPayload(buf[:n])
		if !ok {
			continue
		}
		hs, ok := ParseHandshakePayload(seg.Payload)
		if !ok {
			continue
		}
		conn, emit := s.edgeFor(seg)
		if !emit {
			continue // 서버측 관측 — 중복·방향 혼선 방지(클라이언트가 보고)
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
	conn           ConnTuple
	client, server []string
}

func newSSHPending() *sshPending { return &sshPending{byKey: map[string]*sshKexPair{}} }

func (p *sshPending) add(conn ConnTuple, hs *Handshake, fromSelf bool) {
	key := fmt.Sprintf("%s|%s|%d", conn.SrcNode, conn.DstAddr, conn.Port)
	e, ok := p.byKey[key]
	if !ok {
		e = &sshKexPair{conn: conn}
		p.byKey[key] = e
		p.order = append(p.order, key)
	}
	// edgeFor가 로컬=클라이언트인 연결만 통과시키므로, 자기 IP에서 나간 KEXINIT이 클라이언트 것이다.
	if fromSelf {
		e.client = hs.OfferedGroups
	} else {
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

// edgeFor — 세그먼트에서 client→server 방향 엣지를 만든다. 서버 = 낮은 포트 쪽.
// 로컬이 클라이언트일 때만 방출(emit=true)한다 — 양쪽에서 잡히는 중복과 방향 혼선을 없앤다.
// 서버측에서 본 핸드셰이크는 상대(클라이언트) 노드가 보고한다. IP→노드 잇기는 코어(§1.4).
func (s *LiveSource) edgeFor(seg *Segment) (ConnTuple, bool) {
	serverIP, serverPort, clientIP := seg.SrcIP, seg.SrcPort, seg.DstIP
	if seg.SrcPort > seg.DstPort { // 낮은 포트가 서버
		serverIP, serverPort, clientIP = seg.DstIP, seg.DstPort, seg.SrcIP
	}
	if !s.SelfIPs[clientIP] {
		return ConnTuple{}, false // 로컬은 서버(또는 무관) — 방출 안 함
	}
	return ConnTuple{
		SrcNode:      s.Node,
		DstAddr:      fmt.Sprintf("%s:%d", serverIP, serverPort),
		Port:         uint32(serverPort),
		SrcInitiated: true,
	}, true
}
