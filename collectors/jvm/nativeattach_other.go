//go:build !linux

package jvm

import "errors"

// NativeAttach — 비-Linux 스텁. 네이티브 attach는 대상 프로세스의 파일시스템 네임스페이스
// (`/proc/<pid>/root`)와 유닉스 도메인 소켓 규약에 의존해 **리눅스에서만** 성립한다.
//
// 스텁을 두는 이유: 이 리포는 리눅스 노드를 관측하지만 **개발은 다른 OS에서도 한다.**
// 스텁이 없으면 macOS·Windows에서 `go build ./...`가 깨져 클론 직후 첫 명령부터 막힌다.
// 오류를 돌려주므로 호출부의 3계층 폴백(② JDK 클라이언트 → ③ 정적)이 그대로 이어진다 —
// 성공한 척하지 않는다(§2.5).
func NativeAttach(pid int, agentJar, outPath string) (Collected, error) {
	return Collected{}, errors.New("native attach is Linux-only (/proc and unix sockets) — not possible on this platform")
}
