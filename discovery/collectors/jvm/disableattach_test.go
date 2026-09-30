//go:build linux

package jvm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/randyinthedev-hash/pqcota-discovery/discovery/collectors/jvm"
)

// javaBin — 샌드박스/시스템 JDK. 없으면 이 파일의 테스트는 스킵한다.
func javaBin(t *testing.T) (bin, home string) {
	t.Helper()
	home = os.Getenv("JAVA_HOME")
	if home != "" {
		if b := filepath.Join(home, "bin", "java"); fileExists(b) {
			return b, home
		}
	}
	b, err := exec.LookPath("java")
	if err != nil {
		t.Skip("no JDK — skipping the attach-blocked integration test")
	}
	// java 실행 파일에서 JAVA_HOME을 되짚는다(.../bin/java → ...).
	real, err := filepath.EvalSymlinks(b)
	if err != nil {
		real = b
	}
	return b, filepath.Dir(filepath.Dir(real))
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// TD-JVM-9 — attach가 막힌 실물 JVM(-XX:+DisableAttachMechanism). 폴백 로직만 unit으로
// 덮여 있었고, **막힌 실물에서 그 경로를 타는지**는 확인된 적이 없었다.
//
// 확인하는 것 둘: ① attach 시도가 실패하고 그 실패가 갭으로 세어진다(표시 없이 버리지
// 않는다, §2.6). ② java.security 정적 폴백이 provider를 실제로 읽어낸다 — attach가
// 막혔다고 "provider 없음"이 되면 안 된다.
func TestDisabledAttachFallsBackToJavaSecurity(t *testing.T) {
	bin, home := javaBin(t)

	src := filepath.Join(t.TempDir(), "Sleeper.java")
	if err := os.WriteFile(src, []byte(
		"public class Sleeper { public static void main(String[] a) throws Exception { Thread.sleep(60000); } }\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-XX:+DisableAttachMechanism", src)
	// 대상 JVM의 작업 디렉터리를 임시 폴더로 둔다 — HotSpot이 attach 트리거 파일
	// `.attach_pid<N>`을 **대상의 CWD**에 만들기 때문이다. 기본값이면 그게 리포 안에 떨어진다.
	cmd.Dir = t.TempDir()
	if err := cmd.Start(); err != nil {
		t.Skipf("the JVM did not start (single-file execution may be unsupported): %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	pid := cmd.Process.Pid

	// JVM이 뜰 때까지 잠깐 기다린다(attach 소켓 경로 판정을 위해).
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if fileExists(filepath.Join("/proc", itoa(pid), "maps")) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// ① attach는 실패해야 하고, 실패는 갭으로 세어져야 한다.
	target := jvm.JVMProc{PID: pid, JavaHome: home}
	results, st := jvm.AttachAll([]jvm.JVMProc{target}, func(j jvm.JVMProc) (jvm.Collected, error) {
		return jvm.NativeAttach(j.PID, "/nonexistent-agent.jar", filepath.Join(t.TempDir(), "out"))
	})
	if st.Discovered != 1 {
		t.Fatalf("found %d, want 1", st.Discovered)
	}
	if st.Failed != 1 || st.Attached != 0 {
		t.Fatalf("attach was blocked but it was counted as a success: %+v", st)
	}
	if results[0].Err == nil {
		t.Error("the failure was not recorded as an error — dropping it silently makes that JVM look clean")
	}

	// ② 정적 폴백은 java.security에서 provider를 읽어야 한다.
	col, err := jvm.StaticFallbackGo(pid, home)
	if err != nil {
		t.Fatalf("the static fallback failed (JAVA_HOME=%s): %v", home, err)
	}
	if len(col.Providers) == 0 {
		t.Fatal("a blocked attach must not turn into zero providers — that mixes up not-observed and not-there")
	}
	if !col.Degraded {
		t.Error("a static fallback result must be marked degraded (it is not runtime introspection)")
	}
	if col.Raw == "" || !strings.Contains(col.Raw, "security.provider") {
		t.Errorf("the raw capture (java.security) was not preserved: %q", firstLine(col.Raw))
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

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
