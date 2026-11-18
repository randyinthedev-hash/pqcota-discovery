// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package network

import (
	"errors"
	"testing"
	"time"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// TD-NETWORK-13: CAP_NET_RAW 없이 AF_PACKET 열기 → ErrCaptureUnavailable(크래시 아님).
// 권한이 있는 환경(root)에선 소켓이 열리므로 강등 경로 미검증 → 스킵.
func TestLiveSource_noCapPerm(t *testing.T) {
	ls := &LiveSource{Node: "web-01", Window: 100 * time.Millisecond}
	_, err := ls.Observe(nil, nil)
	if err == nil {
		t.Skip("CAP_NET_RAW present (socket opened) — the degraded path does not apply in this environment")
	}
	if !errors.Is(err, ErrCaptureUnavailable) {
		t.Fatalf("a permission failure must be wrapped as ErrCaptureUnavailable: %v", err)
	}
}

// edgeFor: 로컬이 클라이언트든 서버든 이 노드의 연결로 방출한다. 역할은 메시지와 방향으로 정한다.
// 같은 연결의 두 메시지(ClientHello·ServerHello)는 어느 쪽이든 같은 튜플이 된다.
func TestEdgeForBothSides(t *testing.T) {
	ch := &Handshake{Protocol: "TLS", Role: "client"}
	sh := &Handshake{Protocol: "TLS", Role: "server"}
	toServer := &Segment{SrcIP: "10.0.1.10", DstIP: "10.0.1.20", SrcPort: 40000, DstPort: 8443} // ClientHello
	toClient := &Segment{SrcIP: "10.0.1.20", DstIP: "10.0.1.10", SrcPort: 8443, DstPort: 40000} // ServerHello

	cli := &LiveSource{Node: "web-01", SelfIPs: map[string]bool{"10.0.1.10": true}}
	for name, c := range map[string]struct {
		seg *Segment
		hs  *Handshake
	}{"ClientHello": {toServer, ch}, "ServerHello": {toClient, sh}} {
		got, ok := cli.edgeFor(c.seg, c.hs)
		if !ok || got.Role != client || got.DstAddr != "10.0.1.20:8443" || got.Port != 8443 || got.RemoteAddr != "10.0.1.20:8443" {
			t.Errorf("client node, %s: ok=%v %+v", name, ok, got)
		}
	}
	srv := &LiveSource{Node: "web-02", SelfIPs: map[string]bool{"10.0.1.20": true}}
	for name, c := range map[string]struct {
		seg *Segment
		hs  *Handshake
	}{"ClientHello": {toServer, ch}, "ServerHello": {toClient, sh}} {
		got, ok := srv.edgeFor(c.seg, c.hs)
		if !ok || got.Role != server || got.DstAddr != "10.0.1.10" || got.Port != 8443 || got.RemoteAddr != "10.0.1.10:40000" || got.LocalAddr != "10.0.1.20:8443" {
			t.Errorf("server node, %s: ok=%v %+v", name, ok, got)
		}
	}
	// 이 노드와 무관한 연결, 자기 자신과의 연결은 방출하지 않는다.
	other := &LiveSource{Node: "web-03", SelfIPs: map[string]bool{"10.0.1.30": true}}
	if _, ok := other.edgeFor(toServer, ch); ok {
		t.Error("a connection between two other hosts was emitted")
	}
	both := &LiveSource{Node: "web-04", SelfIPs: map[string]bool{"10.0.1.10": true, "10.0.1.20": true}}
	if _, ok := both.edgeFor(toServer, ch); ok {
		t.Error("a connection to itself was emitted")
	}
}

// SSH: LISTEN 조회로 역할을 정한다. 클라이언트가 낮은 포트(1022), 서버가 높은 포트(2222)를 써도 반대로 판정하지
// 않는다. 조회가 실패하면 UNSPECIFIED이고, 포트 크기로 추정하지 않는다.
func TestEdgeForSSHUsesListeningNotPortSize(t *testing.T) {
	kex := &Handshake{Protocol: "SSH"}
	seg := &Segment{SrcIP: "10.0.1.10", DstIP: "10.0.1.20", SrcPort: 1022, DstPort: 2222}
	cli := &LiveSource{Node: "web-01", SelfIPs: map[string]bool{"10.0.1.10": true},
		Listening: func(p uint16) (bool, error) { return false, nil }}
	if got, _ := cli.edgeFor(seg, kex); got.Role != client || got.DstAddr != "10.0.1.20:2222" || got.Port != 2222 {
		t.Errorf("client on a low port: %+v", got)
	}
	srv := &LiveSource{Node: "web-02", SelfIPs: map[string]bool{"10.0.1.20": true},
		Listening: func(p uint16) (bool, error) { return p == 2222, nil }}
	if got, _ := srv.edgeFor(seg, kex); got.Role != server || got.DstAddr != "10.0.1.10" || got.Port != 2222 {
		t.Errorf("server on a high port: %+v", got)
	}
	unk := &LiveSource{Node: "web-02", SelfIPs: map[string]bool{"10.0.1.20": true},
		Listening: func(p uint16) (bool, error) { return false, errors.New("no /proc") }}
	if got, _ := unk.edgeFor(seg, kex); got.Role != unspec || got.DstAddr != "10.0.1.10" || got.Port != 0 {
		t.Errorf("lookup failed: %+v", got)
	}
}

// SSH 대기열: 서버 관측에서는 로컬이 보낸 KEXINIT이 서버 것이다. 역할 미확인이면 협상 그룹을 정하지 않는다.
func TestSSHPendingPicksByRole(t *testing.T) {
	// 클라이언트 선호 순서가 협상을 정하므로, 두 목록을 바꿔 쥐면 결과가 달라진다(잘못 고르면 curve25519).
	cl := []string{"mlkem768x25519-sha256", "curve25519-sha256"}
	sv := []string{"curve25519-sha256", "mlkem768x25519-sha256"}
	for name, c := range map[string]struct {
		role      discoveryv1.EdgeRole
		wantGroup string
	}{"server": {server, "mlkem768x25519-sha256"}, "client": {client, "mlkem768x25519-sha256"}, "unspecified": {unspec, ""}} {
		p := newSSHPending()
		conn := ConnTuple{SrcNode: "n", Role: c.role, LocalAddr: "10.0.0.2:22", RemoteAddr: "10.0.0.1:50000"}
		local, remote := cl, sv // 로컬이 클라이언트면 로컬 KEXINIT이 클라이언트 것
		if c.role == server {
			local, remote = sv, cl
		}
		p.add(conn, &Handshake{Protocol: "SSH", OfferedGroups: local}, true)
		p.add(conn, &Handshake{Protocol: "SSH", OfferedGroups: remote}, false)
		out := p.resolve()
		if len(out) != 1 || out[0].HS.NegotiatedGroup != c.wantGroup {
			t.Errorf("%s: %+v", name, out[0].HS)
		}
	}
}

// ★ 관측 구간은 **끝까지 채워져야 한다.** 원시 syscall은 시그널에 깨어 EINTR을 돌려주는데(Go 런타임이
// 고루틴 선점을 위해 SIGURG를 보낸다), 그걸 치명적 오류로 보고 루프를 나가면 중단 사실을 알리지 않은 채
// 구간이 무작위 시점에 끝나고 결과가 "핸드셰이크 없음"이 된다 — 결함이 갭처럼 보인다(§2.6).
// 실측으로 재현했던 증상: 25초 구간이 0·0·14·25초에 끝남.
//
// CAP_NET_RAW가 없으면 소켓 자체가 안 열려 이 경로를 못 타므로 스킵한다.
func TestObserveFillsTheWholeWindow(t *testing.T) {
	const window = 1200 * time.Millisecond
	ls := &LiveSource{Node: "web-01", Window: window}
	start := time.Now()
	if _, err := ls.Observe(nil, nil); err != nil {
		t.Skip("no CAP_NET_RAW — the capture loop did not run")
	}
	elapsed := time.Since(start)
	// 200ms 수신 타임아웃으로 폴링하므로 구간보다 한 틱 정도만 짧을 수 있다. 그보다 일찍 끝났다면
	// 루프가 오류로 빠져나온 것이다.
	if elapsed < window-300*time.Millisecond {
		t.Errorf("the window (%v) ended early at %v — treating EINTR and friends as fatal silently cuts the observation short", window, elapsed)
	}
	if ls.Truncated {
		t.Errorf("a clean finish still set Truncated: %v", ls.TruncErr)
	}
}
