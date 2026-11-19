// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package procs_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
)

// fakeProc — /proc 흉내. 실제 장비에서 잰 모양을 그대로 옮긴다.
type fakeProc struct{ root string }

func newFakeProc(t *testing.T, tcpLines ...string) *fakeProc {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for _, l := range tcpLines {
		body += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(root, "net/tcp"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return &fakeProc{root: root}
}

// proc — PID 하나를 만든다. inode를 쥔 fd와 cgroup·PPid를 붙인다.
func (f *fakeProc) proc(t *testing.T, pid, ppid int, cgroup, socket string) {
	t.Helper()
	base := filepath.Join(f.root, itoa(pid))
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(base, "status"), "Name:\tx\nPPid:\t"+itoa(ppid)+"\n")
	write(t, filepath.Join(base, "cgroup"), cgroup)
	if socket != "" {
		// 끊어진 심링크로 둔다 — /proc의 fd가 실제로 그런 모양이다.
		if err := os.Symlink(socket, filepath.Join(base, "fd", "3")); err != nil {
			t.Fatal(err)
		}
	}
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// 10.0.0.5:443 → "0500000A:01BB" (리틀엔디언 hex). inode 26014316.
// 실제 /proc/net/tcp의 필드 배치를 그대로 따른다 — inode는 열 번째 필드다.
// sl local rem st tx:rx tr:tm retrnsmt uid timeout **inode** ref …
const lineTo10005 = "   0: 0100007F:9C40 0500000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 26014316 1 0000000000000000 20 0 0 10 0"

// TestAttributionPicksTheProcessThatOpenedTheSocket — fd 상속을 실제로 다룬다.
//
// 실제 장비에서 한 inode에 PID 셋이 걸렸다 — 연결을 연 `bash`와 그것을 물려받은 자식 둘. 먼저 찾은
// PID를 쓰면 자식을 짚게 되는데, **연결을 연 것은 부모다.**
func TestAttributionPicksTheProcessThatOpenedTheSocket(t *testing.T) {
	f := newFakeProc(t, lineTo10005)
	f.proc(t, 100, 1, "0::/system.slice/payment.service", "socket:[26014316]")   // 연 쪽
	f.proc(t, 101, 100, "0::/system.slice/helper.service", "socket:[26014316]")  // 상속한 자식
	f.proc(t, 102, 100, "0::/system.slice/helper2.service", "socket:[26014316]") // 또 하나

	got := procs.AttributeRemote(f.root, "10.0.0.5", 443)
	if got.Key != "payment.service" {
		t.Fatalf("app_key=%q kind=%q reason=%q — it picked the child that inherited the connection, not the parent that opened it",
			got.Key, got.Kind, got.Reason)
	}
	if got.Kind != "systemd-unit" {
		t.Errorf("kind=%q — derived from cgroup, so it must be systemd-unit", got.Kind)
	}
	if got.Reason != "" {
		t.Errorf("it was attributed but a reason was left behind: %q", got.Reason)
	}
}

// TestUnattributedIsNotNoApp — 못 잡은 것과 앱이 없는 것을 가른다.
//
// 이 리포가 관측 갭에 대해 지켜 온 규칙이 여기에도 그대로 적용된다. 빈 키는 "앱이 없다"가
// 아니라 "어느 앱인지 밝히지 못했다"이고, **왜 못 했는지가 남아야** 대응이 갈린다.
func TestUnattributedIsNotNoApp(t *testing.T) {
	// ① 소켓이 이미 닫혔다 — /proc/net/tcp에 그 상대가 없다.
	f := newFakeProc(t)
	got := procs.AttributeRemote(f.root, "10.0.0.5", 443)
	if got.Key != "" || got.Reason != procs.ReasonSocketGone {
		t.Errorf("closed socket: key=%q reason=%q", got.Key, got.Reason)
	}

	// ② 프로세스는 찾았는데 안정 키를 못 뽑는다(cgroup에 유닛 없음, exe 없음).
	f2 := newFakeProc(t, lineTo10005)
	f2.proc(t, 100, 1, "0::/", "socket:[26014316]")
	if got := procs.AttributeRemote(f2.root, "10.0.0.5", 443); got.Reason != procs.ReasonNoAppKey {
		t.Errorf("no key: key=%q reason=%q", got.Key, got.Reason)
	}
}

// TestAmbiguousIsNotGuessed — 같은 상대로 두 앱이 통신 중이면 기계가 고르지 않는다.
//
// 앱을 잘못 짚으면 조치 대상이 바뀐다 — 비워 두는 것보다 나쁘다. UNOBSERVED를 기계가
// 확정하지 않는 것과 같은 자리다.
func TestAmbiguousIsNotGuessed(t *testing.T) {
	f := newFakeProc(t,
		lineTo10005,
		"   1: 0100007F:9C41 0500000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 26014317 1 0000000000000000 20 0 0 10 0")
	f.proc(t, 100, 1, "0::/system.slice/payment.service", "socket:[26014316]")
	f.proc(t, 200, 1, "0::/system.slice/billing.service", "socket:[26014317]")

	got := procs.AttributeRemote(f.root, "10.0.0.5", 443)
	if got.Key != "" {
		t.Fatalf("it picked one of the two: %q", got.Key)
	}
	if got.Reason != procs.ReasonAmbiguous {
		t.Errorf("reason=%q — it must say that the answer is ambiguous", got.Reason)
	}
}

// TestSameAppOnBothSocketsIsNotAmbiguous — 소켓이 둘이어도 같은 앱이면 모호하지 않다.
func TestSameAppOnBothSocketsIsNotAmbiguous(t *testing.T) {
	f := newFakeProc(t,
		lineTo10005,
		"   1: 0100007F:9C41 0500000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 26014317 1 0000000000000000 20 0 0 10 0")
	f.proc(t, 100, 1, "0::/system.slice/payment.service", "socket:[26014316]")
	f.proc(t, 101, 1, "0::/system.slice/payment.service", "socket:[26014317]")

	if got := procs.AttributeRemote(f.root, "10.0.0.5", 443); got.Key != "payment.service" {
		t.Fatalf("one app opened two connections and it still failed to attribute: key=%q reason=%q", got.Key, got.Reason)
	}
}

// ListeningOn — 로컬 포트에 LISTEN(0A) 소켓이 있으면 true. 같은 포트의 수립된 연결(01)이나 다른 포트의 LISTEN은 아니다.
// 두 파일 다 못 읽으면 오류(역할 「확인하지 못함」으로 이어진다).
func TestListeningOn(t *testing.T) {
	ln := func(local, st string) string {
		return "   0: " + local + " 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0"
	}
	// tcp: 0.0.0.0:22 LISTEN, 10.0.0.1:2222 LISTEN(IP-A만), 10.0.0.2:22 ESTABLISHED. tcp6는 아직 없다(IPv6 스택 없음).
	f := newFakeProc(t, ln("00000000:0016", "0A"), ln("0100000A:08AE", "0A"), ln("0200000A:0016", "01"))
	check := func(name, ip string, port uint32, want bool) {
		t.Helper()
		if got, err := procs.ListeningOn(f.root, ip, port); err != nil || got != want {
			t.Errorf("%s (%s:%d): %v %v, want %v", name, ip, port, got, err, want)
		}
	}
	check("wildcard 0.0.0.0", "10.0.0.2", 22, true)
	check("same address", "10.0.0.1", 2222, true)
	// ★ 같은 포트·다른 로컬 주소: IP-A:2222의 리스너는 IP-B:2222를 출발점으로 쓴 연결을 받지 않는다.
	check("same port, other local address", "10.0.0.2", 2222, false)
	check("established is not listening", "10.0.0.2", 50000, false)
	// IPv6 로컬인데 tcp6가 없다 — 판정에 필요한 표가 없으니 오류다(「리스너 없음」이 아니다).
	if _, err := procs.ListeningOn(f.root, "fd00::2", 22); err == nil {
		t.Error("IPv6 local without net/tcp6 should be an error")
	}

	// tcp6: [fd00::1]:8443, [::]:443, [::ffff:10.0.0.2]:993, [::ffff:0.0.0.0]:995 LISTEN.
	tcp6 := filepath.Join(f.root, "net/tcp6")
	tcp6Body := "  sl  local_address remote_address st\n" +
		ln("000000FD000000000000000001000000:20FB", "0A") + "\n" +
		ln("00000000000000000000000000000000:01BB", "0A") + "\n" +
		ln("0000000000000000FFFF00000200000A:03E1", "0A") + "\n" +
		ln("0000000000000000FFFF000000000000:03E3", "0A") + "\n"
	write(t, tcp6, tcp6Body)
	check("IPv6 same address", "fd00::1", 8443, true)
	check("IPv6 same port, other local address", "fd00::2", 8443, false)
	check("IPv6 wildcard ::", "fd00::2", 443, true)
	// ★ :: 리스너만으로는 IPv4 연결을 받는다고 하지 않는다 — IPV6_V6ONLY인지 /proc에서 알 수 없다.
	check(":: alone does not confirm IPv4", "10.0.0.2", 443, false)
	check("v4-mapped listener", "10.0.0.2", 993, true)
	check("v4-mapped listener, other address", "10.0.0.1", 993, false)
	check("v4-mapped wildcard ::ffff:0.0.0.0", "10.0.0.1", 995, true)
	check("0.0.0.0 does not take IPv6", "fd00::2", 22, false)

	// ★ 해당 주소 계열의 표를 읽다 실패하면 오류다. tcp만 읽고 「리스너 없음」으로 끝내지 않는다.
	if err := os.Remove(tcp6); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tcp6, 0o755); err != nil { // 열리지만 읽으면 실패한다
		t.Fatal(err)
	}
	for _, c := range []struct {
		ip   string
		port uint32
	}{{"10.0.0.2", 2222}, {"fd00::2", 443}} {
		if got, err := procs.ListeningOn(f.root, c.ip, c.port); err == nil {
			t.Errorf("%s:%d with unreadable net/tcp6: %v, want an error", c.ip, c.port, got)
		}
	}
	// IPv6 로컬에는 tcp가 필요 없다 — tcp를 못 읽어도 tcp6로 정한다. IPv4 로컬은 오류다.
	if err := os.Remove(tcp6); err != nil {
		t.Fatal(err)
	}
	write(t, tcp6, tcp6Body)
	tcp := filepath.Join(f.root, "net/tcp")
	if err := os.Remove(tcp); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tcp, 0o755); err != nil {
		t.Fatal(err)
	}
	check("IPv6 does not need net/tcp", "fd00::2", 443, true)
	if _, err := procs.ListeningOn(f.root, "10.0.0.2", 2222); err == nil {
		t.Error("IPv4 local with unreadable net/tcp should be an error")
	}
	if _, err := procs.ListeningOn(filepath.Join(t.TempDir(), "none"), "10.0.0.2", 22); err == nil {
		t.Error("no /proc should be an error, not 'not listening'")
	}
}
