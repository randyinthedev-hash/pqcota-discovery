package jvm

import (
	"strings"
	"testing"
)

// 순수 파싱만 검증한다(/proc I/O는 linux 파일). 이 부분이 정찰의 핵심 판단 로직이다.

func TestDeriveJavaHome(t *testing.T) {
	cases := []struct{ exe, libjvm, want string }{
		{"/opt/java/openjdk/bin/java", "", "/opt/java/openjdk"},
		{"/usr/lib/jvm/temurin-17/bin/java", "", "/usr/lib/jvm/temurin-17"},
		// exe로 못 짚으면 libjvm 경로에서
		{"", "/opt/jdk/lib/server/libjvm.so", "/opt/jdk"},
		{"", "/opt/jdk/jre/lib/amd64/server/libjvm.so", "/opt/jdk/jre"},
		// 래퍼 바이너리(exe가 java 아님) + libjvm
		{"/app/myserver", "/opt/jdk17/lib/server/libjvm.so", "/opt/jdk17"},
		// 아무것도 못 짚으면 "" — 추측 금지
		{"/weird/thing", "", ""},
	}
	for _, c := range cases {
		if got := deriveJavaHome(c.exe, c.libjvm); got != c.want {
			t.Errorf("deriveJavaHome(%q,%q) = %q, want %q", c.exe, c.libjvm, got, c.want)
		}
	}
}

func TestParseReleaseVersion(t *testing.T) {
	release := `IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.9"
JAVA_VERSION_DATE="2023-10-17"
OS_ARCH="x86_64"`
	if got := parseReleaseVersion(release); got != "17.0.9" {
		t.Errorf("version = %q, want 17.0.9", got)
	}
	if got := parseReleaseVersion("OS_ARCH=\"x86_64\"\n"); got != "" {
		t.Errorf("without JAVA_VERSION it must be empty (no guessing), got %q", got)
	}
}

func TestJavaBinFor(t *testing.T) {
	if got := javaBinFor("/opt/jdk", "/opt/jdk/bin/java"); got != "/opt/jdk/bin/java" {
		t.Errorf("with a home it must be <home>/bin/java: %q", got)
	}
	// home 못 짚으면 exe로 폴백(그래도 attach 시도는 가능)
	if got := javaBinFor("", "/app/embedded-java"); got != "/app/embedded-java" {
		t.Errorf("without a home it must fall back to exe: %q", got)
	}
}

func TestIsJavaExe(t *testing.T) {
	if !isJavaExe("/opt/jdk/bin/java") {
		t.Error("a java launcher must be recognised")
	}
	if isJavaExe("/app/myserver") {
		t.Error("something that is not java must not be taken for java")
	}
}

// cmdline에서 앱(main·jar)을 뽑는다 — 한 JDK에 앱이 여럿이어도 구별하는 안정 키. NUL 구분.
func TestParseMainId(t *testing.T) {
	nul := func(a ...string) string { return strings.Join(a, "\x00") }
	cases := []struct{ cmd, want string }{
		{nul("java", "-cp", ".:bcprov.jar", "ProviderApp"), "ProviderApp"},
		{nul("java", "-jar", "/opt/apps/payment.jar"), "payment.jar"},
		{nul("java", "-Xmx1g", "-Dk=v", "com.acme.Main"), "com.acme.Main"},
		{nul("java", "-m", "mymod/com.acme.Main"), "mymod/com.acme.Main"},
		{nul("java", "--class-path", "/x", "App"), "App"},
		{nul("java"), ""},             // 인자 없음
		{nul("java", "-version"), ""}, // 플래그만
	}
	for _, c := range cases {
		if got := parseMainId(c.cmd); got != c.want {
			t.Errorf("parseMainId(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

// Ident — 앱>JAVA_HOME>Exe 우선순위. 한 JDK의 두 앱이 구별되는지가 핵심.
func TestIdent(t *testing.T) {
	if got := (JVMProc{App: "payment.jar", JavaHome: "/opt/jdk"}).Ident(); got != "payment.jar" {
		t.Errorf("with an app it must be the app: %q", got)
	}
	if got := (JVMProc{JavaHome: "/opt/jdk", Exe: "/opt/jdk/bin/java"}).Ident(); got != "/opt/jdk" {
		t.Errorf("without an app it must be JAVA_HOME: %q", got)
	}
	if got := (JVMProc{Exe: "/x/java"}).Ident(); got != "/x/java" {
		t.Errorf("without either it must be Exe: %q", got)
	}
	// ★ 한 JDK, 두 앱 → 구별되어야 한다(dedup으로 하나 사라지면 정직성 위반).
	a := JVMProc{App: "payment.jar", JavaHome: "/opt/jdk"}
	b := JVMProc{App: "api.jar", JavaHome: "/opt/jdk"}
	if a.Ident() == b.Ident() {
		t.Error("two apps on the same JDK share one identifier — findings get merged")
	}
}

// JDK vs 순수 JRE 판별 — ② JDK 클라이언트 폴백의 후보 선택·실패 사유 설명에 쓰인다.
// (1순위 Go 네이티브는 이 값과 무관하게 JDK 없이 붙는다.)
// 파일 존재 검사를 주입해 실물 JDK 없이 검증한다(collector-deployment.md §2의 전제).
func TestAttachCapable(t *testing.T) {
	jdk := map[string]bool{"/opt/jdk21/" + AttachLibRel: true} // JDK엔 있고
	has := func(p string) bool { return jdk[p] }

	if !attachCapable("/opt/jdk21", has) {
		t.Error("with the jdk.attach native library present, attach must be possible")
	}
	if attachCapable("/opt/jre21", has) { // 순수 JRE엔 없다
		t.Error("a plain JRE must not be a ② client candidate (no jdk.attach)")
	}
	// JAVA_HOME을 못 짚었으면 '모른다' — 가능하다고 단정하지 않는다(§2.5).
	if attachCapable("", has) {
		t.Error("with JAVA_HOME unknown, attach must not be assumed possible")
	}
}

// ── Windows 경로 판별 — 리눅스 CI에서 검증한다. 실제 장비 없이 못 잡는 자리를 여기서 못 박는다.

func TestIsJavaExeWindows(t *testing.T) {
	for _, ok := range []string{`C:\Program Files\Java\jdk-21\bin\java.exe`, `C:\jdk\bin\JAVAW.EXE`, "C:/jdk/bin/java.exe"} {
		if !isJavaExeWindows(ok) {
			t.Errorf("a java launcher must be recognised: %q", ok)
		}
	}
	for _, no := range []string{`C:\Windows\System32\svchost.exe`, `C:\jdk\bin\javac.exe`, `C:\x\java`} {
		if isJavaExeWindows(no) {
			t.Errorf("something that is not a launcher was taken for one: %q", no)
		}
	}
}

func TestDeriveJavaHomeWindows(t *testing.T) {
	if got := deriveJavaHomeWindows(`C:\Program Files\Java\jdk-21\bin\java.exe`, ""); got != `C:\Program Files\Java\jdk-21` {
		t.Errorf("from the launcher: %q", got)
	}
	// 네이티브 런처가 JVM을 포함한 경우 — exe로는 못 짚고 jvm.dll 경로로 짚는다.
	if got := deriveJavaHomeWindows(`C:\app\app.exe`, `C:\jdk-21\bin\server\jvm.dll`); got != `C:\jdk-21` {
		t.Errorf("from jvm.dll: %q", got)
	}
	if got := deriveJavaHomeWindows(`C:\x\java.exe`, ""); got != "" {
		t.Errorf("without a bin directory it must not be guessed: %q", got)
	}
	if got := javaBinForWindows(`C:\jdk-21`, `C:\x\java.exe`); got != `C:\jdk-21\bin\java.exe` {
		t.Errorf("java bin: %q", got)
	}
	if got := javaBinForWindows("", `C:\x\java.exe`); got != `C:\x\java.exe` {
		t.Errorf("without a home it must fall back to exe: %q", got)
	}
}

// Windows JDK의 표식은 리눅스와 파일이 다르다 — 같은 규칙을 쓰면 순수 JRE를 JDK로 본다.
func TestAttachCapableWindows(t *testing.T) {
	// 구분자는 돌리는 OS의 filepath가 정한다 — 이 테스트가 보는 것은 **어느 파일을 찾느냐**다.
	has := func(p string) bool {
		return strings.ReplaceAll(p, `\`, "/") == "C:/jdk-21/bin/attach.dll"
	}
	if !attachCapableAt(`C:\jdk-21`, AttachLibRelWindows, has) {
		t.Error("with attach.dll present, attach must be possible")
	}
	if attachCapableAt(`C:\jre-21`, AttachLibRelWindows, has) {
		t.Error("a plain JRE must not be a ② client candidate")
	}
}
