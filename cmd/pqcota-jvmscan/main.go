// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-jvmscan — 타깃(Java) 노드에서 실행. 실 JVM에 java.security 프로바이더 체인을
// 조회(Security.getProviders())해 JCA 자산을 CollectionResult JSON으로 낸다.
//
// 먼저 이 머신의 **실행 중 JVM을 정찰**한다(/proc 스캔, openssl과 대칭) — 발견된 JVM·JDK를
// stderr로 보이고, JAVA_BIN이 없으면 그 java 바이너리를 기본값으로 쓴다. 즉 호출자가 JDK
// 경로를 미리 몰라도 된다. (PQCOTA_JVM_AGENT가 있으면 발견된 JVM에 attach해 동적 addProvider까지 본다.
// 없을 때 --pid가 있으면 그 JVM의 java.security를 Go가 직접 읽고, --pid도 없으면 프로브 JVM으로
// 정적 등록 체인만 보는 경량 경로로 폴백한다, §2.2.)
//
// usage: pqcota-jvmscan [--output json|table] [--pid N] [node-id]
//
//	--output json (기본) CollectionResult JSON을 stdout에 — 중앙이 회수해 적재한다
//	        table       정규화까지 하고 사람이 읽는 표를 stdout에 — 저장하지 않는다
//	--pid N             그 PID의 JVM 하나만 관측(기본: 정찰로 찾은 전부)
//	--recon             정찰만 → 발견 JVM JSON(배포 결정용, 관측 안 함)
//
// env: JAVA_BIN(미지정 시 정찰로 발견한 java, 없으면 PATH의 java), JVMSCAN_CP(bcprov 등 classpath)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/cmd/internal/localview"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/jvm"
	"google.golang.org/protobuf/encoding/protojson"
)

// Java 11+ 단일 파일 소스 실행으로 프로바이더 체인을 "N|name|version|class"로 덤프한다
// (collectors/jvm.ParseProviders 입력 형식과 일치).
const probeSrc = `import java.security.*;
public class Probe {
  public static void main(String[] a){
    Provider[] ps = Security.getProviders();
    for (int i=0;i<ps.length;i++){
      Provider p = ps[i];
      String v;
      try { v = p.getVersionStr(); } catch (Throwable t){ v = String.valueOf(p.getVersion()); }
      System.out.println((i+1)+"|"+p.getName()+"|"+v+"|"+p.getClass().getName());
    }
  }
}
`

func main() {
	recon := flag.Bool("recon", false, "recon only → JSON of discovered JVMs (no observation)")
	pidOnly := flag.Int("pid", 0, "observe only the JVM with this PID (0 = every JVM found by recon)")
	out := flag.String("output", "json", "output format: json | table")
	flag.Parse()
	if *out != "json" && *out != "table" {
		fmt.Fprintf(os.Stderr, "unknown --output %q — use json | table\n", *out)
		os.Exit(2)
	}

	// --recon: 정찰만 하고 발견된 JVM을 JSON으로 낸다(관측 안 함). **배포 결정용** —
	// 오케스트레이터(Ansible 등)가 "이 노드에 JVM이 있나"를 보고 에이전트 JAR를 보낼지 정한다.
	// JVM이 없으면 `[]` — 없는 노드에 Java 애드온을 뿌리지 않기 위한 근거다(배포 설계 §2).
	if *recon {
		emitRecon()
		return
	}

	node := flag.Arg(0)
	if node == "" {
		node = "host://local"
	}

	// 선행 정찰 — 이 머신에 실제로 도는 JVM을 먼저 조사한다(openssl의 /proc 스캔과 대칭).
	// 호출자가 JDK 경로를 몰라도 되게, 발견된 JVM의 java 바이너리를 기본값으로 삼는다.
	jvms, st := jvm.ScanJVMs()
	for _, j := range jvms {
		via := "exe"
		if j.ViaLibjvm {
			via = "libjvm"
		}
		fmt.Fprintf(os.Stderr, "[jvmscan] found JVM pid=%d ver=%s home=%s (%s)\n",
			j.PID, nz(j.Version), nz(j.JavaHome), via)
	}
	if st.ProcUnavailable {
		// "JVM 0개"와 "관측하지 못했다"를 같은 얼굴로 내보내지 않는다(§2.6).
		fmt.Fprintln(os.Stderr, "[jvmscan] ⚠ the process list could not be read, so nothing was enumerated — no JVM was observed, which is not the same as no JVM existing")
	}
	if st.CmdlineUnavailable && len(jvms) > 0 {
		// 앱 이름이 빈 이유를 여기서 밝혀야 한다 — 안 밝히면 "이 JVM에 앱이 없다"로 읽힌다.
		fmt.Fprintln(os.Stderr, "[jvmscan] ⚠ process command lines were not read on this platform, so the app is left empty — several apps on one JDK collapse into one identifier")
	}
	fmt.Fprintf(os.Stderr, "[jvmscan] recon: reachable %d · denied %d (not observed) · JVMs %d\n", st.Accessible, st.Denied, st.WithJVM)
	deniedHint(st.Denied)

	// --pid: 그 JVM 하나만. 정찰에 없으면 알리지 않은 채 전부 훑지 않고 실패한다 — 사용자가 지목한
	// 대상을 관측하지 못한 것은 갭이지 "전부 보기"로 갈아탈 이유가 아니다(§2.5).
	if *pidOnly > 0 {
		var only []jvm.JVMProc
		for _, j := range jvms {
			if j.PID == *pidOnly {
				only = append(only, j)
			}
		}
		if len(only) == 0 {
			fmt.Fprintf(os.Stderr, "[jvmscan] pid=%d was not among the running JVMs (check permissions, or it exited)\n", *pidOnly)
			os.Exit(1)
		}
		jvms = only
	}

	// 실 attach 경로 — PQCOTA_JVM_AGENT(collector JAR)가 있으면 발견된 각 PID에 실제 attach해
	// 그 JVM의 provider 체인(동적 등록 포함)을 관측한다. 정찰→attach 대칭 완성.
	// 없으면 프로브 경로(정적 등록 체인, 데모 경량)로 폴백한다.
	if agent := os.Getenv("PQCOTA_JVM_AGENT"); agent != "" && len(jvms) > 0 {
		res, observed := attachAll(node, jvms, agent)
		// **관측한 수를 적는다.** 찾은 수를 적으면 갭이 관측으로 세어진다 — 실측에서
		// "2 JVMs observed" 아래에 행이 하나만 있었다.
		head := fmt.Sprintf("%d JVMs observed", observed)
		if gap := len(jvms) - observed; gap > 0 {
			head += fmt.Sprintf(" · %d found but not observed (gap)", gap)
		}
		emit(*out, node, res, true, head)
		return
	}

	// --pid인데 에이전트가 없으면 프로브 경로(머신 전역 정적 체인)로 새지 않는다. 그 PID의
	// java.security를 Go가 직접 읽는다 — 동적 등록은 사각이라 갭으로 고지된다.
	if *pidOnly > 0 {
		j := jvms[0]
		c, err := jvm.StaticFallbackGo(j.PID, j.JavaHome)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[jvmscan] static fallback failed for pid=%d: %v\n", j.PID, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[jvmscan] static fallback pid=%d: %d providers (dynamic registrations are a blind spot — not observed)\n",
			j.PID, len(c.Providers))
		emit(*out, node, []*discoveryv1.CollectionResult{jvm.BuildResultFor(node, c, j.Ident())}, false,
			fmt.Sprintf("1 JVM observed (pid %d, static path)", j.PID))
		return
	}

	// 프로브 경로 — JAVA_BIN 명시가 있으면 그것, 없으면 발견된 JVM의 java, 그것도 없으면 PATH의 java.
	javaBin := os.Getenv("JAVA_BIN")
	if javaBin == "" && len(jvms) > 0 {
		javaBin = jvms[0].JavaBin
	}
	if javaBin == "" {
		javaBin = "java"
	}

	dir, err := os.MkdirTemp("", "jvmscan")
	if err != nil {
		fmt.Fprintln(os.Stderr, "tmp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "Probe.java")
	if err := os.WriteFile(src, []byte(probeSrc), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write probe:", err)
		os.Exit(1)
	}

	var args []string
	if cp := os.Getenv("JVMSCAN_CP"); cp != "" {
		args = append(args, "--class-path", cp)
	}
	args = append(args, src)
	probeOut, err := exec.Command(javaBin, args...).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[jvmscan] warning while running java: %v\n%s\n", err, probeOut)
	}

	// ★ 이 경로는 **도는 JVM을 본 것이 아니다.** 위에서 java를 하나 띄워 그 JVM에게 물었다.
	// 그러니 confirmed·runtime-introspection으로 낼 수 없다 — 도구가 만든 것을 관측이라고
	// 적는 것이 된다. 값은 쓸모가 있다("이 머신의 java는 무엇으로 시작하는가")지만 **그 이름으로**
	// 적어야 한다. nodescan이 /proc에 로드된 libssl만 보는 것과 같은 규칙이다.
	c := jvm.ParseProviders(string(probeOut))
	c.Degraded = true
	// 왜 이 경로에 왔는지는 **발견한 수에 따라 다르다.** JVM을 찾고도 에이전트를 안 준 것과 하나도
	// 못 찾은 것, 프로세스 목록을 못 읽은 것을 한 문장으로 적으면 읽는 사람이 관측 범위를 잘못 안다.
	why := probeReason(len(jvms), st.ProcUnavailable)
	c.Note = why + " — the machine's java launcher was started for this probe, so this is its default provider chain, not an observation of a running app (the runtime registrations of real apps are a blind spot)"
	emit(*out, node, []*discoveryv1.CollectionResult{jvm.BuildResult(node, c)}, false,
		"0 JVMs observed — probed the machine's java launcher instead")
	fmt.Fprintf(os.Stderr, "[jvmscan] ⚠ %s. The machine's java launcher was started to probe instead — this is not an observation of a running app\n", why)
	fmt.Fprintf(os.Stderr, "[jvmscan] %s: %d providers (default chain of %s)\n", node, len(c.Providers), javaBin)
}

// emit — 수집 결과를 요청한 형식으로 낸다. jsonl=true면 한 줄에 하나(여러 JVM), 아니면
// 들여쓴 단일 객체.
func emit(mode, node string, results []*discoveryv1.CollectionResult, jsonl bool, headline string) {
	if mode == "json" {
		enc := protojson.MarshalOptions{Multiline: !jsonl, Indent: "  "}
		for _, r := range results {
			b, err := enc.Marshal(r)
			if err != nil {
				fmt.Fprintln(os.Stderr, "marshal:", err)
				continue
			}
			os.Stdout.Write(b)
			if jsonl {
				os.Stdout.Write([]byte("\n"))
			}
		}
	}
	if mode == "table" {
		w := os.Stdout
		tbl, err := localview.Render(node, results)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[jvmscan]", err)
			os.Exit(1)
		}
		fmt.Fprintf(w, "== pqcota JVM Discovery — %s (read-only; nothing is stored) ==\n", node)
		fmt.Fprintf(w, "%s\n\n", headline)
		fmt.Fprint(w, tbl)
	}
}

// emitRecon — 정찰 결과를 JSON 배열로 stdout에. 관측(attach·프로브)은 하지 않는다.
// 접근 불가 프로세스 수까지 함께 내보내 "관측하지 못한 게 있다"를 오케스트레이터도 알 수 있게 한다(§2.6).
func emitRecon() {
	jvms, st := jvm.ScanJVMs()
	type reconJVM struct {
		PID           int    `json:"pid"`
		App           string `json:"app,omitempty"`
		JavaHome      string `json:"javaHome,omitempty"`
		Version       string `json:"version,omitempty"`
		AttachCapable bool   `json:"attachCapable"`
	}
	out := make([]reconJVM, 0, len(jvms))
	for _, j := range jvms {
		out = append(out, reconJVM{PID: j.PID, App: j.App, JavaHome: j.JavaHome,
			Version: j.Version, AttachCapable: j.AttachCapable})
	}
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "recon marshal:", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
	fmt.Fprintf(os.Stderr, "[jvmscan -recon] %d JVMs · reachable %d · denied %d (not observed)\n", len(out), st.Accessible, st.Denied)
	deniedHint(st.Denied)
}

// deniedHint — 열지 못한 프로세스가 있으면 그 뜻과 넓히는 법을 함께 낸다.
//
// 숫자만 내면 "JVM 0개"로 읽힌다. **못 본 것이지 없는 것이 아니다**(§2.6). Windows에서
// 특히 크게 갈린다 — 실측(Windows 11 26200)에서 일반 사용자는 265개 중 163개를 못 열었고
// 관리자는 264개 중 3개였다. Java 서버가 Windows 서비스(SYSTEM)로 도는 배치가 흔하므로,
// 권한 없이 돌리면 **정작 봐야 할 JVM이 통째로 안 보인다**.
func deniedHint(denied int) {
	if denied == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "[jvmscan] ⚠ %d processes could not be opened, so a JVM running as another user is invisible here — that is a gap, not an absence.\n", denied)
	// 이미 권한이 있으면 남은 것은 더 올려도 안 열린다(실측: 관리자에게도 3개가 남았다).
	// 그 자리에서 "관리자로 돌리세요"는 안내가 아니라 잡음이다.
	if !privileged() {
		fmt.Fprintf(os.Stderr, "[jvmscan]   run as %s to widen the view.\n", elevateAs)
	}
}

// probeReason — 프로브 경로로 온 까닭. 프로브는 대상 JVM을 보지 않고 새로 띄운 java의 기본 체인을 읽는다.
// 까닭은 셋이고 서로 다른 이야기다: 도는 JVM을 찾았는데 에이전트(PQCOTA_JVM_AGENT)를 안 줬다 /
// 프로세스 목록을 못 읽어 있는지 없는지 모른다 / 목록을 읽었고 JVM이 하나도 없었다.
// "no JVM was running"은 마지막 경우에만 쓴다 — 아니면 관측하지 않은 것을 없다고 적게 된다.
func probeReason(found int, procUnavailable bool) string {
	switch {
	case found > 0:
		return fmt.Sprintf("%d running JVM(s) were found but neither a collector JAR (PQCOTA_JVM_AGENT) nor --pid was given, so none was observed", found)
	case procUnavailable:
		return "the process list could not be read, so it is not known whether a JVM was running"
	default:
		return "no JVM was running"
	}
}

// nativeOutPath — 에이전트가 **대상 안에서** 쓸 출력 경로. 대상의 /tmp 기준이라 PID로 갈라
// 여러 JVM이 서로 덮어쓰지 않게 한다(호스트에서 읽을 때는 /proc/<pid>/root/가 앞에 붙는다).
func nativeOutPath(pid int) string { return fmt.Sprintf("/tmp/pqcota-providers-%d.txt", pid) }

func nz(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// attachAll — 발견된 각 JVM에 attach(agent JAR)해 provider 체인을 관측하고 JVM별로 구별되는
// CollectionResult를 모아 돌려준다. attach 실패는 갭으로 센다(표시 없이 0이 되지 않게 §2.5).
func attachAll(node string, jvms []jvm.JVMProc, agent string) (res []*discoveryv1.CollectionResult, observed int) {
	// attach 경로는 3계층이다(collector 배포 설계 §2) — 앞이 막히면 뒤로, 다 막히면 정직히 갭.
	//   ① Go 네이티브: JDK 없이 HotSpot 프로토콜로 직접. JRE·jlink·최소 컨테이너까지 커버.
	//   ② JDK 클라이언트: 벤더 무관(OpenJ9 등 HotSpot 아닌 JVM). 머신에 JDK가 있어야.
	//   ③ (호출부 밖) 정적 폴백 — 동적 등록은 사각으로 남고 갭·강등으로 고지(§2.5·§2.6).
	client := jvm.AttachClient(jvms) // ②용 — 대상이 JRE여도 머신의 다른 JDK를 쓴다
	attach := func(j jvm.JVMProc) (jvm.Collected, error) {
		if c, err := jvm.NativeAttach(j.PID, agent, nativeOutPath(j.PID)); err == nil {
			return c, nil
		} else {
			fmt.Fprintf(os.Stderr, "[jvmscan] native attach failed for pid=%d: %v → retrying with the JDK client\n", j.PID, err)
		}
		bin := j.JavaBin
		if !j.AttachCapable && client != "" {
			bin = client
		}
		if bin != "" && (j.AttachCapable || client != "") {
			run := jvm.SubprocessRunner(bin, agent)
			if c, err := run(node, map[string]string{"pid": strconv.Itoa(j.PID)}); err == nil {
				return c, nil
			} else {
				fmt.Fprintf(os.Stderr, "[jvmscan] JDK client attach failed for pid=%d: %v → falling back to static\n", j.PID, err)
			}
		}
		// ③ 정적 폴백 — java.security는 텍스트 파일이라 Go가 직접 읽는다. 어떤 JVM·런타임이어도
		// 최소한 정적 등록 체인은 낸다(강등·갭 고지). 관측 실패가 표시 없는 0이 되지 않게(§2.5).
		c, err := jvm.StaticFallbackGo(j.PID, j.JavaHome)
		if err != nil {
			return jvm.Collected{}, fmt.Errorf("every attach path failed and the static fallback is unavailable: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[jvmscan] static fallback pid=%d: %d providers (dynamic registrations are a blind spot — not observed)\n",
			j.PID, len(c.Providers))
		return c, nil
	}
	results, ast := jvm.AttachAll(jvms, attach)
	out := make([]*discoveryv1.CollectionResult, 0, len(results))
	for _, r := range results {
		if r.Err != nil {
			// 결과를 안 내면 이 JVM이 있었다는 사실이 중앙에 닿지 않는다 — 갭을 실어 보낸다(§2.6).
			fmt.Fprintf(os.Stderr, "[jvmscan] attach failed pid=%d: %v (gap)\n", r.JVM.PID, r.Err)
			out = append(out, jvm.GapResult(node, r.JVM.Ident(),
				"a JVM was found but could not be observed: "+r.Err.Error()))
			continue
		}
		// 식별자는 앱(main·jar) 우선, 없으면 JAVA_HOME→exe — PID는 휘발이라 이력이 깨진다.
		out = append(out, jvm.BuildResultFor(node, r.Collected, r.JVM.Ident()))
	}
	fmt.Fprintf(os.Stderr, "[jvmscan] attach: found %d · ok %d · failed %d (gap) → emitted %d\n",
		ast.Discovered, ast.Attached, ast.Failed, len(out))
	return out, ast.Attached
}
