// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package procs_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
)

// 앱 키 2단계: 규칙 통합(OpenSSL·엣지가 JVM과 같은 규칙)과 연결별 귀속(두 끝점이 맞는 소켓 하나).
// 재현 근거는 v0.12.0에서 같은 UID의 사용자 서비스 둘이 user@1001.service 하나로 접힌 관측이다.

const (
	cgSvcA = "0::/user.slice/user-1001.slice/user@1001.service/app.slice/svc-a.service\n"
	cgSvcB = "0::/user.slice/user-1001.slice/user@1001.service/app.slice/svc-b.service\n"
)

// 127.0.0.1:40000 → 10.0.0.5:443 (inode 5001), 127.0.0.1:40001 → 10.0.0.5:443 (inode 5002).
// 원격은 같고 출발 포트만 다르다.
const (
	lineA = "   0: 0100007F:9C40 0500000A:01BB 01 00000000:00000000 00:00000000 00000000  1001        0 5001 1 0000000000000000 20 0 0 10 0"
	lineB = "   1: 0100007F:9C41 0500000A:01BB 01 00000000:00000000 00:00000000 00000000  1001        0 5002 1 0000000000000000 20 0 0 10 0"
)

func TestServiceKey(t *testing.T) {
	for _, c := range []struct{ cgroup, key, kind string }{
		{"0::/system.slice/payment.service\n", "payment.service", procs.KindSystemdUnit},
		{cgSvcA, "user@1001.service/svc-a.service", procs.KindSystemdUserUnit},
		{cgSvcB, "user@1001.service/svc-b.service", procs.KindSystemdUserUnit},
		// cgroup v1: 여러 줄 가운데 서비스가 있는 줄
		{"12:pids:/system.slice/payment.service\n1:name=systemd:/system.slice/payment.service\n", "payment.service", procs.KindSystemdUnit},
		// 서비스가 없다 → 키 없음(호출자가 exe로 넘어간다)
		{"0::/init.scope\n", "", ""},
		{"0::/user.slice/user-1000.slice/session-3.scope\n", "", ""},
		{"0::/user.slice/user-1001.slice/user@1001.service/app.slice/app-gnome-x-3488.scope\n", "", ""},
		{"0::/user.slice/user-1001.slice/user@1001.service\n", "", ""}, // 관리자 자신은 앱이 아니다
		{"", "", ""},
	} {
		if k, kd := procs.ServiceKey(c.cgroup); k != c.key || kd != c.kind {
			t.Errorf("%q → %q %q, want %q %q", c.cgroup, k, kd, c.key, c.kind)
		}
	}
}

// TestAppKeyUserServicesStayApart — 같은 UID의 사용자 서비스 둘이 하나로 접히지 않는다(A1).
// `.scope`만 있는 프로세스는 scope 이름이 아니라 exe 경로가 키다(A4).
func TestAppKeyUserServicesStayApart(t *testing.T) {
	f := newFakeProc(t)
	f.proc(t, 162, 1, cgSvcA, "")
	f.proc(t, 170, 1, cgSvcB, "")
	f.proc(t, 1, 0, "0::/init.scope\n", "")
	if err := os.Symlink("/usr/lib/systemd/systemd", filepath.Join(f.root, "1", "exe")); err != nil {
		t.Fatal(err)
	}

	a, _ := procs.AppKey(f.root, 162)
	b, _ := procs.AppKey(f.root, 170)
	if a == b {
		t.Fatalf("both user services got %q — they were folded into one key", a)
	}
	if a != "user@1001.service/svc-a.service" || b != "user@1001.service/svc-b.service" {
		t.Errorf("keys %q, %q", a, b)
	}
	if k, kind := procs.AppKey(f.root, 1); k != "/usr/lib/systemd/systemd" || kind != procs.KindExePath {
		t.Errorf("PID 1 in init.scope → %q %q, want the exe path (a .scope is not an app key)", k, kind)
	}
}

// TestConnMatchesBothEndpoints — 원격이 같아도 출발 포트가 다른 소켓은 고르지 않는다(B1).
// Remote로는 같은 목적지의 두 서비스가 「모호함」이 되던 자리다.
func TestConnMatchesBothEndpoints(t *testing.T) {
	f := newFakeProc(t, lineA, lineB)
	f.proc(t, 162, 1, cgSvcA, "socket:[5001]")
	f.proc(t, 170, 1, cgSvcB, "socket:[5002]")
	att := procs.NewAttributor(f.root, time.Second)

	if got := att.Conn("127.0.0.1", 40000, "10.0.0.5", 443); got.Key != "user@1001.service/svc-a.service" || got.Kind != procs.KindSystemdUserUnit {
		t.Errorf("port 40000 → %+v, want svc-a", got)
	}
	if got := att.Conn("127.0.0.1", 40001, "10.0.0.5", 443); got.Key != "user@1001.service/svc-b.service" {
		t.Errorf("port 40001 → %+v, want svc-b", got)
	}
	// 같은 목적지를 원격만으로 찾으면 둘이 갈려 모호하다 — Conn이 필요한 이유.
	if got := att.Remote("10.0.0.5", 443); got.Reason != procs.ReasonAmbiguous {
		t.Errorf("Remote → %+v, want ambiguous", got)
	}
}

// TestConnClosedIsNotTakenFromAnotherConnection — 소켓이 이미 닫혔으면 앱 키를 비운다. 같은 목적지에
// 열려 있는 다른 서비스의 소켓으로 대신 짚지 않는다(B5).
func TestConnClosedIsNotTakenFromAnotherConnection(t *testing.T) {
	f := newFakeProc(t, lineA) // 40001(svc-b)의 소켓은 닫혔다. svc-a의 소켓만 같은 목적지에 열려 있다
	f.proc(t, 162, 1, cgSvcA, "socket:[5001]")
	att := procs.NewAttributor(f.root, time.Second)

	got := att.Conn("127.0.0.1", 40001, "10.0.0.5", 443)
	if got.Key != "" || got.Reason != procs.ReasonSocketGone {
		t.Fatalf("closed socket → %+v — it must stay unattributed, not borrow the open svc-a socket", got)
	}
	// TIME_WAIT는 줄이 남아도 inode가 0이다 — 닫힌 것과 같다.
	tw := "   0: 0100007F:9C41 0500000A:01BB 06 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 20 0 0 10 0"
	f2 := newFakeProc(t, tw, lineA)
	f2.proc(t, 162, 1, cgSvcA, "socket:[5001]")
	if got := procs.NewAttributor(f2.root, time.Second).Conn("127.0.0.1", 40001, "10.0.0.5", 443); got.Key != "" || got.Reason != procs.ReasonSocketGone {
		t.Errorf("TIME_WAIT → %+v", got)
	}
}

// TestConnOwnerAmbiguous — 두 끝점이 맞는 소켓이 있어도, 그것을 쥔 프로세스들이 서로 다른 서비스이고
// 부모·자식 사이가 아니면 하나로 정하지 않는다(B6).
func TestConnOwnerAmbiguous(t *testing.T) {
	f := newFakeProc(t, lineA)
	f.proc(t, 162, 1, cgSvcA, "socket:[5001]")
	f.proc(t, 170, 1, cgSvcB, "socket:[5001]") // 남남인데 같은 inode(fd를 넘겨받은 경우)
	got := procs.NewAttributor(f.root, time.Second).Conn("127.0.0.1", 40000, "10.0.0.5", 443)
	if got.Key != "" || got.Reason != procs.ReasonOwnerAmbiguous {
		t.Fatalf("→ %+v, want unattributed (owner ambiguous)", got)
	}

	// 부모가 연 연결을 자식이 물려받은 것은 모호하지 않다 — 연 쪽(부모)의 키다.
	f2 := newFakeProc(t, lineA)
	f2.proc(t, 162, 1, cgSvcA, "socket:[5001]")
	f2.proc(t, 163, 162, cgSvcB, "socket:[5001]")
	if got := procs.NewAttributor(f2.root, time.Second).Conn("127.0.0.1", 40000, "10.0.0.5", 443); got.Key != "user@1001.service/svc-a.service" {
		t.Errorf("inherited fd → %+v, want the parent's key", got)
	}
}

// TestConnV4MappedInTcp6 — 이중 스택 소켓의 IPv4 연결은 tcp6에 ::ffff:a.b.c.d로 적힌다.
func TestConnV4MappedInTcp6(t *testing.T) {
	f := newFakeProc(t)
	// ::ffff:127.0.0.1:40000 → ::ffff:10.0.0.5:443
	line := "   0: 0000000000000000FFFF00000100007F:9C40 0000000000000000FFFF00000500000A:01BB 01 00000000:00000000 00:00000000 00000000  1001        0 5001 1 0000000000000000 20 0 0 10 0"
	write(t, filepath.Join(f.root, "net/tcp6"), "  sl  local_address remote_address st\n"+line+"\n")
	f.proc(t, 162, 1, cgSvcA, "socket:[5001]")
	if got := procs.NewAttributor(f.root, time.Second).Conn("127.0.0.1", 40000, "10.0.0.5", 443); got.Key != "user@1001.service/svc-a.service" {
		t.Errorf("→ %+v, want svc-a through the tcp6 v4-mapped entry", got)
	}
}

// TestConnRescansWhenTheCacheIsOlderThanTheSocket — fd 스캔 캐시보다 늦게 열린 소켓을 「닫힘」으로 적지 않는다.
func TestConnRescansWhenTheCacheIsOlderThanTheSocket(t *testing.T) {
	f := newFakeProc(t, lineA)
	f.proc(t, 162, 1, cgSvcA, "socket:[5001]")
	att := procs.NewAttributor(f.root, time.Hour) // 캐시가 오래 간다
	if got := att.Conn("127.0.0.1", 40000, "10.0.0.5", 443); got.Key == "" {
		t.Fatalf("first lookup → %+v", got)
	}
	// 캐시를 만든 뒤 svc-b가 새 연결을 열었다.
	write(t, filepath.Join(f.root, "net/tcp"), "  sl  local_address rem_address\n"+lineA+"\n"+lineB+"\n")
	f.proc(t, 170, 1, cgSvcB, "socket:[5002]")
	if got := att.Conn("127.0.0.1", 40001, "10.0.0.5", 443); got.Key != "user@1001.service/svc-b.service" {
		t.Errorf("socket opened after the cache → %+v, want svc-b (rescan once before giving up)", got)
	}
}
