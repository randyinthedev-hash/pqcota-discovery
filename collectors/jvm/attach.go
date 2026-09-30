package jvm

// 정찰(ScanJVMs) → attach 오케스트레이션. openssl의 ScanHost가 프로세스별 탐지를 모으는 것과
// 대칭 — 발견한 JVM 각각에 attach해 실체 provider 체인을 얻는다. attach는 주입한다:
// 실배포는 SubprocessRunner 어댑터, 테스트는 fake(실 JVM·agent 없이 오케스트레이션만 검증).
//
// AttachClient — 이 머신에서 attach 클라이언트로 쓸 java를 고른다(jdk.attach 있는 JDK).
//
// ★ 클라이언트는 **대상 JVM의 java일 필요가 없다.** 붙는 쪽에 jdk.attach 모듈만 있으면 되므로,
// 대상이 순수 JRE여도 같은 머신의 다른 JDK로 붙을 수 있다. 그래서 collector가 자체 런타임을
// 동봉할 이유가 없다 — **있는 걸 찾아 쓴다**(collector 배포 설계 §2).
// 하나도 없으면 "" — 그때는 attach를 포기하고 정적 폴백으로 정직히 내려간다(§2.5).
func AttachClient(jvms []JVMProc) string {
	for _, j := range jvms {
		if j.AttachCapable && j.JavaBin != "" {
			return j.JavaBin
		}
	}
	return ""
}

// AttachResult — 발견된 JVM 하나에 attach한 결과. Err!=nil이면 attach 실패(권한·차단 등).
type AttachResult struct {
	JVM       JVMProc
	Collected Collected
	Err       error
}

// AttachStats — 정찰→attach 커버리지(완전성 맵 원천).
type AttachStats struct {
	Discovered int
	Attached   int
	Failed     int // attach 실패 — 표시 없는 0이 아니라 갭(§2.6 갭≠부재)
}

// AttachAll — 발견한 JVM들에 각각 attach한다. 실패한 JVM은 버리지 않고 Err로 담아 갭으로 센다.
func AttachAll(jvms []JVMProc, attach func(JVMProc) (Collected, error)) ([]AttachResult, AttachStats) {
	st := AttachStats{Discovered: len(jvms)}
	out := make([]AttachResult, 0, len(jvms))
	for _, j := range jvms {
		c, err := attach(j)
		if err != nil {
			st.Failed++
			out = append(out, AttachResult{JVM: j, Err: err})
			continue
		}
		st.Attached++
		out = append(out, AttachResult{JVM: j, Collected: c})
	}
	return out, st
}
