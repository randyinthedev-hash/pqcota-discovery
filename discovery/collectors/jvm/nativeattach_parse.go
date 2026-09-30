package jvm

import (
	"fmt"
	"strconv"
	"strings"
)

// HotSpot attach 프로토콜의 **순수 부분** — 요청 조립·응답 파싱·NSpid 추출. 실 JVM 없이
// 단위 테스트된다(리눅스 전용 I/O는 nativeattach_linux.go).

// attachProtocolVersion — HotSpot attach 프로토콜 버전(현재 "1").
// 프로토콜 상수라 **여기**(태그 없는 파일)에 둔다 — 리눅스 전용 파일에 두면 macOS·Windows에서
// `go build ./...`가 깨진다(실제로 깨졌다).
const attachProtocolVersion = "1"

// loadAgentRequest — `load` 명령 요청 바이트.
//
// 형식: <ver>\0load\0instrument\0false\0<jar>=<agentArgs>\0
//   - 인자 슬롯은 **정확히 3개**여야 한다(모자라면 대상이 읽다 멈춰 응답이 안 온다).
//   - "instrument"는 에이전트 로딩을 담당하는 내장 에이전트, "false"는 절대경로 아님 플래그가
//     아니라 **에이전트가 이미 로드됐는지 무시하고 실행**하라는 의미의 프로토콜 상수.
//   - Java의 `loadAgent(jar, opts)`는 내부적으로 `jar=opts`로 합쳐 보낸다 — 여기서도 같게 만든다.
func loadAgentRequest(agentJar, agentArgs string) string {
	arg := agentJar
	if agentArgs != "" {
		arg = agentJar + "=" + agentArgs
	}
	return strings.Join([]string{attachProtocolVersion, "load", "instrument", "false", arg}, "\x00") + "\x00"
}

// parseAttachResponse — 응답의 첫 줄은 리턴 코드다. 0이면 성공, 아니면 뒤따르는 메시지가 사유.
// 빈 응답은 성공으로 치지 않는다 — 대상이 아무 말도 안 했으면 로드됐는지 모른다(§2.5).
func parseAttachResponse(resp string) error {
	s := strings.TrimLeft(resp, "\n")
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("no attach response — whether the agent loaded is unknown")
	}
	line, rest, _ := strings.Cut(s, "\n")
	code, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		return fmt.Errorf("could not read the return code of the attach response: %q", strings.TrimSpace(line))
	}
	if code != 0 {
		msg := strings.TrimSpace(rest)
		if msg == "" {
			msg = "(the target gave no reason)"
		}
		return fmt.Errorf("attach refused (code %d): %s", code, msg)
	}
	return nil
}

// parseNSpid — /proc/<pid>/status의 `NSpid:` 줄에서 **가장 안쪽 네임스페이스의 PID**를 뽑는다.
// 컨테이너 안 JVM은 소켓·트리거 파일 이름에 이 값을 쓰므로, 호스트 PID로 찾으면 못 만난다.
// 줄이 없으면(구 커널·같은 NS) fallback을 그대로 쓴다.
func parseNSpid(status string, fallback int) int {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "NSpid:"))
		if len(f) == 0 {
			break
		}
		if v, err := strconv.Atoi(f[len(f)-1]); err == nil { // 마지막 = 가장 안쪽 NS
			return v
		}
	}
	return fallback
}
