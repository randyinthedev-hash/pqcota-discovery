// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package procs — app에 라이브 프로세스를 그때그때 이어 붙이기 (자산 모델 §1.5, ProcessMatch).
// PID는 휘발이라 저장하지 않고, 프로비저닝 직전에 /proc을 스캔해 "지금 이 앱의 프로세스"를 확정한다.
// (L3 재시작 대상 확정용 — 조회만 한다.)
package procs

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// Match — 한 프로세스(exe·cmdline·cgroup)가 ProcessMatch 규칙에 맞는지. 순수(TDD).
// 규칙이 여럿이면 AND(모두 만족). 규칙이 하나도 없으면 false(무조건 전체 매칭 방지).
func Match(exe, cmdline, cgroup string, m *discoveryv1.ProcessMatch) bool {
	if m == nil {
		return false
	}
	any := false
	if u := m.GetSystemdUnit(); u != "" {
		any = true
		if !strings.Contains(cgroup, u) { // cgroup 경로에 유닛명 포함(systemd slice)
			return false
		}
	}
	if e := m.GetExePath(); e != "" {
		any = true
		if exe != e {
			return false
		}
	}
	if rx := m.GetCmdlineRegex(); rx != "" {
		any = true
		re, err := regexp.Compile(rx)
		if err != nil || !re.MatchString(cmdline) {
			return false
		}
	}
	return any
}

// Resolve — procRoot(기본 "/proc") 스캔 → 규칙에 맞는 라이브 프로세스. 호출 시각 스냅샷(휘발).
func Resolve(procRoot string, m *discoveryv1.ProcessMatch) ([]*discoveryv1.LiveProcess, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var out []*discoveryv1.LiveProcess
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // 숫자 아닌 항목(cpuinfo 등)
		}
		base := filepath.Join(procRoot, e.Name())
		exe, _ := os.Readlink(filepath.Join(base, "exe")) // 접근 불가면 빈 값(정직)
		cmdline := readCmdline(filepath.Join(base, "cmdline"))
		cgroup := readText(filepath.Join(base, "cgroup"))
		if Match(exe, cmdline, cgroup, m) {
			out = append(out, &discoveryv1.LiveProcess{Pid: uint32(pid), Cmdline: cmdline})
		}
	}
	return out, nil
}

// 앱 키의 종류. JVM 수집기도 같은 값을 쓴다(그쪽에는 JVM에만 있는 종류가 더 있다).
const (
	KindSystemdUnit     = "systemd-unit"
	KindSystemdUserUnit = "systemd-user-unit"
	KindExePath         = "exe-path"
)

// AppKey — PID에서 안정 app_key를 파생한다(§1.5 자산이 어느 앱 것인지). systemd 서비스(cgroup,
// [ServiceKey]) 우선, 없으면 exe 경로. 반환: (app_key, kind). 둘 다 실패면 ("","").
//
// OpenSSL 수집기와 통신 엣지가 이 함수를 쓰고, JVM 수집기는 [ServiceKey]를 직접 쓴다. 규칙은 한 곳에만 있다.
func AppKey(procRoot string, pid int) (key, kind string) {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	if k, kd := ServiceKey(readText(filepath.Join(base, "cgroup"))); k != "" {
		return k, kd
	}
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil && exe != "" {
		return exe, KindExePath
	}
	return "", ""
}

// ServiceKey — cgroup 텍스트에서 systemd **서비스**를 찾는다.
//   - 경로 마디 가운데 `.service`로 끝나는 **마지막** 것을 쓴다.
//   - `user@<uid>.service`(사용자 관리자)는 후보가 아니다. 그 아래의 서비스가 실제 앱이다.
//   - `.scope`(session-N, init.scope, docker-<id>, app-…-<pid>)는 쓰지 않는다. 세션·실행마다 이름이
//     바뀌어 앱 키로 오래 가지 않는다. 없으면 호출자가 exe 경로로 넘어간다.
//   - 사용자 관리자 아래의 서비스면 키는 `user@<uid>.service/<유닛>`이다. 이름 `foo.service`는 사용자마다의
//     관리자 아래에 따로 있을 수 있어, 이름만 쓰면 한 노드에서 다시 합쳐진다.
//
// v0.12.0까지 OpenSSL·엣지는 처음 나오는 `.service`·`.scope`를 골라, 같은 UID의 사용자 서비스가
// 모두 `user@<uid>.service` 하나로 접혔다.
func ServiceKey(cgroup string) (key, kind string) {
	for _, line := range strings.Split(cgroup, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path := line
		if i := strings.LastIndex(line, ":"); i >= 0 { // "0::/a/b" · "1:name=systemd:/a/b"
			path = line[i+1:]
		}
		manager, unit := "", ""
		for _, seg := range strings.Split(path, "/") {
			switch {
			case strings.HasPrefix(seg, "user@") && strings.HasSuffix(seg, ".service"):
				manager, unit = seg, "" // 관리자 아래에서 다시 찾는다
			case strings.HasSuffix(seg, ".service"):
				unit = seg
			}
		}
		if unit == "" {
			continue
		}
		if manager != "" {
			return manager + "/" + unit, KindSystemdUserUnit
		}
		return unit, KindSystemdUnit
	}
	return "", ""
}

func readCmdline(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

func readText(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}
