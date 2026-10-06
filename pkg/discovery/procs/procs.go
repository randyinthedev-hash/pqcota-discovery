// SPDX-FileCopyrightText: 2026 randyinthedev
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

// AppKey — PID에서 안정 app_key를 파생한다(§1.5 자산이 어느 앱 것인지). systemd 유닛(cgroup) 우선, 없으면 exe 경로.
// 반환: (app_key, kind). 둘 다 실패면 ("","").
func AppKey(procRoot string, pid int) (key, kind string) {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	if u := systemdUnit(readText(filepath.Join(base, "cgroup"))); u != "" {
		return u, "systemd-unit"
	}
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil && exe != "" {
		return exe, "exe-path"
	}
	return "", ""
}

// systemdUnit — cgroup 텍스트에서 *.service/*.scope 유닛명을 뽑는다(예: /system.slice/payment.service → payment.service).
func systemdUnit(cgroup string) string {
	for _, seg := range strings.Split(strings.ReplaceAll(cgroup, "\n", "/"), "/") {
		seg = strings.TrimSpace(seg)
		if strings.HasSuffix(seg, ".service") || strings.HasSuffix(seg, ".scope") {
			return seg
		}
	}
	return ""
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
