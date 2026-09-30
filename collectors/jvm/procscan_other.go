//go:build !linux && !windows

package jvm

// ScanJVMs — 리눅스도 Windows도 아닌 플랫폼의 스텁. JVM attach 자체는 OS-비의존이나 프로세스 열거는 /proc에
// 의존하므로 여기선 빈 결과를 낸다(jvm 패키지의 크로스컴파일을 깨지 않기 위함).
func ScanJVMs() ([]JVMProc, JVMScanStats) {
	// 빈 결과가 아니라 **관측하지 못했다**로 표시한다 — 그러지 않으면 "JVM 없음"으로 읽힌다(§2.6).
	return nil, JVMScanStats{ProcUnavailable: true}
}
