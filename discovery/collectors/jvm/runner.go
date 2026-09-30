package jvm

import (
	"fmt"
	"os"
	"os/exec"
)

// SubprocessRunner — 실제 attach 사이드카(순수 Java)를 서브프로세스로 실행해 provider 출력을
// 얻는다(라이선스 정리 — 프로세스 분리). jvm.Service.Runner에 주입한다.
//
//	javaBin      : attach 가능 JDK의 java(jdk.attach 필요). ★ 이 경로는 **② 폴백**이다 —
//	               1순위는 JDK 없이 붙는 Go 네이티브(NativeAttach). 여기 오는 건 네이티브가
//	               실패했을 때(비-HotSpot JVM 등)뿐이라 벤더 무관성이 존재 이유다.
//	collectorJar : 제품 jar(Agent-Class=IntrospectAgent + pqcota.jvm.Attacher 포함)
//
// 전제: 대상 JVM과 동일 UID(또는 root), attach 미차단. **불가 시 폴백하지 않고 실패로 끝낸다** —
// 정적 폴백은 대상의 JAVA_HOME을 아는 [StaticFallbackGo]가 맡는다(§2.2).
func SubprocessRunner(javaBin, collectorJar string) func(node string, opts map[string]string) (Collected, error) {
	return func(node string, opts map[string]string) (Collected, error) {
		pid := opts["pid"]
		if pid == "" {
			return Collected{}, fmt.Errorf("jvm runner: opts[\"pid\"] is required")
		}
		out, err := os.CreateTemp("", "pqcota-prov-*.txt")
		if err != nil {
			return Collected{}, err
		}
		outPath := out.Name()
		_ = out.Close()
		defer os.Remove(outPath)

		// java --add-modules jdk.attach -cp <jar> pqcota.jvm.Attacher <pid> <jar> <out>
		cmd := exec.Command(javaBin, "--add-modules", "jdk.attach", "-cp", collectorJar,
			"pqcota.jvm.Attacher", pid, collectorJar, outPath)
		if b, err := cmd.CombinedOutput(); err != nil {
			return Collected{}, fmt.Errorf("attach subprocess failed: %v: %s", err, string(b))
		}
		data, err := os.ReadFile(outPath)
		if err != nil {
			return Collected{}, err
		}
		return ParseProviders(string(data)), nil
	}
}
