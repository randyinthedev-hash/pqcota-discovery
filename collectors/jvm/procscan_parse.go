package jvm

import (
	"path/filepath"
	"strings"
)

// JVM 정찰 — "머신에 무엇이 실제로 도는가"를 collector가 직접 조사한다.
//
// openssl은 ScanHost가 /proc를 훑어 로드된 libssl을 스스로 찾는데, jvm은 그동안 호출자가
// PID·JDK 경로를 미리 알아 넘겨야 했다(비대칭). ScanJVMs가 그 정찰을 맡아 대칭을 맞춘다.
// 여기(파싱)는 순수 함수 — /proc I/O는 procscan.go(linux)에 분리해 테스트 가능하게 둔다.

// JVMProc — 머신에서 발견된 실행 중 JVM 하나.
type JVMProc struct {
	PID       int
	Exe       string // /proc/<pid>/exe를 따라간 결과(대개 런처 java 경로)
	App       string // cmdline에서 뽑은 실행 앱(main 클래스 또는 -jar) — 자산 식별의 안정 키
	JavaHome  string // exe/libjvm 경로에서 파생(best-effort, 못 짚으면 "")
	JavaBin   string // <JavaHome>/bin/java, 없으면 Exe
	Version   string // <JavaHome>/release의 JAVA_VERSION(best-effort, 없으면 "")
	ViaLibjvm bool   // exe 이름이 아니라 maps의 libjvm.so로 식별됨
	// AttachCapable — 이 JVM의 JAVA_HOME이 jdk.attach 있는 **JDK**인가(순수 JRE면 false).
	// ★ 이게 false여도 attach를 포기하지 않는다 — Go 네이티브 경로(①)는 JDK 없이 붙는다.
	// 이 값은 **② JDK 클라이언트 폴백의 후보 선택**(OpenJ9 등)과 실패 사유 설명에 쓰인다.
	AttachCapable bool
}

// Ident — 이 JVM을 자산으로 구별하는 안정 식별자. 앱(main·jar)이 있으면 그것 —
// 한 JDK에 앱이 여럿이어도 구별되고, 재시작해도 같다(휘발 PID와 달리). 없으면 JAVA_HOME→Exe.
func (j JVMProc) Ident() string {
	switch {
	case j.App != "":
		return j.App
	case j.JavaHome != "":
		return j.JavaHome
	default:
		return j.Exe
	}
}

// JVMScanStats — 스캔 커버리지(완전성 맵 원천, openssl ScanStats와 대칭).
type JVMScanStats struct {
	Accessible int // /proc 접근 가능 프로세스
	Denied     int // 접근 불가(타 사용자·종료) — 갭(≠부재, §2.6)
	WithJVM    int // JVM으로 식별된 프로세스

	// ProcUnavailable — 프로세스 목록 자체를 얻지 못했나(마운트 안 된 `/proc`·chroot,
	// Windows면 스냅샷 실패). 이때 "JVM 0개"는 **없다가 아니라 관측하지 못했다**이다.
	// 구별하지 않으면 결함이 갭으로 위장된다(§2.6).
	ProcUnavailable bool

	// CmdlineUnavailable — 이 플랫폼에서 프로세스 **명령줄을 읽지 않았나**.
	//
	// Windows에서 남의 프로세스 명령줄을 읽으려면 그 프로세스의 메모리(PEB)를 들여다봐야 한다.
	// 관측하자고 남의 프로세스 메모리를 읽는 선은 넘지 않는다 — 대신 [JVMProc.App]이 비고,
	// 한 JDK 위에 앱이 여럿이면 [JVMProc.Ident]가 뭉개진다. **그 사실이 값으로 남아야**
	// 완전성 노트가 "왜 앱이 안 붙었나"를 설명할 수 있다(§2.6).
	CmdlineUnavailable bool
}

func isJavaExe(exe string) bool { return filepath.Base(exe) == "java" }

// AttachLibRel — attach 능력의 표식. jdk.attach 모듈의 네이티브 라이브러리로, **JDK엔 있고 순수
// JRE엔 없다**. 프로세스를 띄우지 않고 파일 존재만으로 판별한다(정찰은 가벼워야 한다).
const AttachLibRel = "lib/libattach.so"

// attachCapable — 이 JAVA_HOME으로 attach를 걸 수 있나(= jdk.attach 있는 JDK인가).
// exists를 주입받아 실물 파일시스템 없이 테스트된다.
//
// 왜 필요한가 — ① **② JDK 클라이언트 폴백**(비-HotSpot용)의 후보를 고르는 데 쓰이고,
// ② attach 실패 사유를 겪기 전에 미리 설명해 준다(§2.6 갭 고지의 질).
// ★ false라고 attach를 포기하는 뜻은 아니다 — 1순위 Go 네이티브는 JDK 없이 붙는다.
func attachCapable(javaHome string, exists func(string) bool) bool {
	return attachCapableAt(javaHome, AttachLibRel, exists)
}

// attachCapableAt — 표식의 상대 경로가 OS마다 다르다(리눅스 lib/libattach.so, Windows bin/attach.dll).
func attachCapableAt(javaHome, rel string, exists func(string) bool) bool {
	if javaHome == "" {
		return false // JAVA_HOME을 못 짚었으면 모른다 — 가능하다고 단정하지 않는다(§2.5)
	}
	return exists(filepath.Join(javaHome, rel))
}

// ── Windows 판별기 ─────────────────────────────────────────────────────────────
//
// 태그를 달지 않는 이유: 경로 규칙은 순수 문자열 처리라 **리눅스 CI에서도 검증**돼야 한다.
// 그래서 `filepath`에 기대지 않고 구분자를 직접 다룬다(리눅스의 filepath는 `\`를 모른다).

// AttachLibRelWindows — Windows JDK의 jdk.attach 네이티브 라이브러리. 리눅스의 lib/libattach.so에 해당.
const AttachLibRelWindows = "bin/attach.dll"

// winParts — Windows 경로를 조각으로. `\`와 `/`를 섞어 써도 받는다(윈도 API가 둘 다 받는다).
func winParts(p string) []string { return strings.Split(strings.ReplaceAll(p, `\`, "/"), "/") }

// isJavaExeWindows — 런처는 둘이다: java.exe(콘솔)와 javaw.exe(콘솔 없음).
// 파일명 대소문자를 가리지 않는 것은 Windows의 규칙이다.
func isJavaExeWindows(exe string) bool {
	p := winParts(exe)
	b := strings.ToLower(p[len(p)-1])
	return b == "java.exe" || b == "javaw.exe"
}

// deriveJavaHomeWindows — 런처 exe 또는 jvm.dll 경로에서 JAVA_HOME(best-effort, 못 짚으면 "").
// 배치가 리눅스와 다르다: `<home>\bin\java.exe` · `<home>\bin\server\jvm.dll`.
func deriveJavaHomeWindows(exe, jvmDLL string) string {
	join := func(parts []string) string { return strings.Join(parts, `\`) }
	if exe != "" {
		if p := winParts(exe); len(p) >= 3 && strings.EqualFold(p[len(p)-2], "bin") {
			return join(p[:len(p)-2])
		}
	}
	if jvmDLL != "" {
		p := winParts(jvmDLL)
		for i := len(p) - 1; i > 0; i-- { // .../bin/server/jvm.dll — 가장 안쪽 bin의 부모
			if strings.EqualFold(p[i], "bin") {
				return join(p[:i])
			}
		}
	}
	return ""
}

func javaBinForWindows(home, exe string) string {
	if home != "" {
		return home + `\bin\java.exe`
	}
	return exe
}

// ───────────────────────────────────────────────────────────────────────────────

// deriveJavaHome — 런처 exe 또는 libjvm.so 경로에서 JAVA_HOME을 추정한다(best-effort).
// 못 짚으면 "" — 추측해 채우지 않는다(§2.5).
func deriveJavaHome(exe, libjvm string) string {
	if exe != "" {
		if d := filepath.Dir(exe); filepath.Base(d) == "bin" { // .../bin/java → .../
			return filepath.Dir(d)
		}
	}
	if libjvm != "" {
		if i := strings.Index(libjvm, "/lib/"); i > 0 { // .../lib[/<arch>]/server/libjvm.so
			return libjvm[:i]
		}
	}
	return ""
}

func javaBinFor(home, exe string) string {
	if home != "" {
		return filepath.Join(home, "bin", "java")
	}
	return exe
}

// parseMainId — cmdline(NUL 구분)에서 이 JVM이 도는 **앱**을 식별한다(main 클래스 또는 -jar).
// 앱은 재시작해도 같아(휘발 PID와 달리) 이력의 안정 식별자로 맞다. 못 짚으면 "".
//
// java 인자 문법을 최소 커버: -jar <x> → x 파일명, -m/--module <mod/Main> → 그대로,
// -cp/-classpath/--class-path/-p/--module-path <v> → 값 건너뜀, 그 외 -플래그(-Xmx·-Dk=v·-XX:.. 단일
// 토큰) → 건너뜀, 첫 비플래그 → main 클래스.
func parseMainId(cmdline string) string {
	args := strings.Split(strings.Trim(cmdline, "\x00"), "\x00")
	for i := 1; i < len(args); i++ { // argv[0]=java 런처 건너뜀
		a := args[i]
		switch a {
		case "-jar":
			if i+1 < len(args) {
				return filepath.Base(args[i+1])
			}
			return ""
		case "-m", "--module":
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case "-cp", "-classpath", "--class-path", "-p", "--module-path":
			i++ // 값 건너뜀
			continue
		}
		if strings.HasPrefix(a, "-") || a == "" {
			continue
		}
		return a // 첫 비플래그 = main 클래스
	}
	return ""
}

// parseReleaseVersion — JDK의 release 파일에서 JAVA_VERSION을 뽑는다. 없으면 "".
func parseReleaseVersion(release string) string {
	for _, line := range strings.Split(release, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "JAVA_VERSION="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}
