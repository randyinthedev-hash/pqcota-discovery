//go:build linux

package jvm

// HotSpot attach 프로토콜을 **Go로 직접** 구현한다 — JDK 없이 붙기 위해.
//
// 왜 필요한가: `jdk.attach`는 이 OS 메커니즘(트리거 파일 + SIGQUIT + 유닉스 소켓)을 감싼 편의
// API일 뿐이다. 그걸 직접 구현하면 **대상이 순수 JRE·jlink 런타임이어도**, 머신에 JDK가 하나도
// 없어도 attach할 수 있다 — collector가 자체 런타임을 동봉할 이유가 사라진다
// (collector 배포 설계 §2). openssl collector가 `ldd` 없이 /proc·ELF를 직접 파싱하는 것과 같은 결.
//
// ★ 한계(정직히): 이 프로토콜은 **HotSpot 전용**이다. OpenJ9는 공유 세마포어 기반의 다른
// 메커니즘을 쓴다. 그래서 이 경로는 **1순위일 뿐 유일하지 않다** — 실패하면 JDK 클라이언트
// (벤더 무관) → 정적 폴백으로 내려간다(§2.5).

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// NativeAttach — 대상 JVM(pid)에 에이전트 JAR를 로드시키고, 에이전트가 outPath에 쓴 결과를 읽어
// 돌려준다. Java 사이드카의 `VirtualMachine.attach(pid).loadAgent(jar, out)`과 같은 일을 한다.
func NativeAttach(pid int, agentJar, outPath string) (Collected, error) {
	nspid := namespacedPID(pid)
	sock := socketPath(pid, nspid)

	if _, err := os.Stat(sock); err != nil {
		trigger, err := createTriggerFile(pid, nspid)
		if err != nil {
			return Collected{}, err
		}
		// ★ 소켓이 열릴 때까지 트리거 파일을 **살려둔다.** JVM은 SIGQUIT을 비동기로 처리하므로
		// 보내자마자 지우면 신호 처리 시점에 파일이 없어, JVM이 이를 평범한 스레드 덤프 요청으로
		// 보고 **앱 stdout에 덤프를 쏟는다** — 관측하려다 운영 로그를 어지럽히게 된다.
		defer os.Remove(trigger)

		if err := syscall.Kill(pid, syscall.SIGQUIT); err != nil {
			return Collected{}, fmt.Errorf("sending SIGQUIT (pid=%d): %w", pid, err)
		}
		if err := waitForSocket(sock, 5*time.Second); err != nil {
			return Collected{}, fmt.Errorf("attach listener socket did not open (%s): %w", sock, err)
		}
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return Collected{}, fmt.Errorf("connecting to the attach socket (%s): %w", sock, err)
	}
	defer conn.Close()

	// 프로토콜: <ver>\0load\0instrument\0false\0<jar>=<agentArgs>\0
	// 인자 슬롯은 정확히 3개다(모자라면 대상이 응답하지 않는다).
	if _, err := conn.Write([]byte(loadAgentRequest(agentJar, outPath))); err != nil {
		return Collected{}, fmt.Errorf("sending the attach request: %w", err)
	}
	if err := readAttachResult(conn); err != nil {
		return Collected{}, err
	}

	data, err := os.ReadFile(agentOutHostPath(pid, outPath))
	if err != nil {
		return Collected{}, fmt.Errorf("reading the agent output: %w", err)
	}
	return ParseProviders(string(data)), nil
}

// createTriggerFile — `.attach_pid<nspid>`를 대상이 보는 위치에 만든다.
//
// ★ 이 파일과 SIGQUIT은 **둘 다, 이 순서로** 필요하다. 파일이 "이것은 attach 요청"이라는 표시이고,
// 없으면 JVM은 평범한 스레드 덤프 요청으로 보고 앱 stdout에 덤프를 쏟는다. 그리고 신호 처리가
// 비동기라 **소켓이 열릴 때까지 지우면 안 된다**(호출부가 defer로 지운다).
//
// HotSpot은 자신의 cwd를
// 먼저 보고 없으면 /tmp를 본다 — 같은 순서로 시도한다(호스트에서는 /proc/<pid>/{cwd,root/tmp}).
func createTriggerFile(pid, nspid int) (string, error) {
	name := fmt.Sprintf(".attach_pid%d", nspid)
	candidates := []string{
		filepath.Join("/proc", strconv.Itoa(pid), "cwd", name),
		filepath.Join("/proc", strconv.Itoa(pid), "root", "tmp", name),
	}
	var lastErr error
	for _, p := range candidates {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o660)
		if err == nil {
			_ = f.Close()
			return p, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("could not create the attach trigger file (check for the same UID and permissions): %w", lastErr)
}

// socketPath — 대상이 여는 유닉스 소켓의 **호스트에서 본** 경로. 컨테이너 대상이면 대상의 /tmp는
// /proc/<pid>/root/tmp이고 파일명엔 **네임스페이스 내부 PID**가 쓰인다.
func socketPath(pid, nspid int) string {
	return filepath.Join("/proc", strconv.Itoa(pid), "root", "tmp", fmt.Sprintf(".java_pid%d", nspid))
}

// agentOutHostPath — 에이전트가 대상 안에서 쓴 파일을 호스트에서 읽는 경로(네임스페이스 교차).
func agentOutHostPath(pid int, outPath string) string {
	host := filepath.Join("/proc", strconv.Itoa(pid), "root", outPath)
	if _, err := os.Stat(host); err == nil {
		return host
	}
	return outPath // 같은 네임스페이스면 그대로
}

// namespacedPID — /proc/<pid>/status의 NSpid 마지막 값(대상이 자기 자신을 부르는 PID).
// 컨테이너 안 JVM은 소켓·트리거 파일 이름에 이 값을 쓴다. 못 읽으면 pid 그대로(같은 NS 가정).
func namespacedPID(pid int) int {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return pid
	}
	return parseNSpid(string(b), pid)
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return os.ErrNotExist
}

// readAttachResult — 응답 첫 줄은 리턴 코드("0"이 성공), 그 뒤는 대상이 낸 메시지.
func readAttachResult(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 4096)
	var sb strings.Builder
	for {
		n, err := conn.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return parseAttachResponse(sb.String())
}
