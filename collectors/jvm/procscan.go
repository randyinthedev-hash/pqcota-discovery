// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ScanJVMs — 접근 가능한 모든 프로세스의 /proc를 스캔해 실행 중인 JVM을 열거한다(openssl
// ScanHost와 대칭). "무엇이 실제로 도는가"를 collector가 직접 정찰하므로, 호출자가 PID·JDK를
// 미리 알아 넘겨야 하던 비대칭이 사라진다. root(또는 동일 UID)면 그 사용자 프로세스를 본다.
// 못 읽은 프로세스는 Denied로 세어 완전성 갭의 원천이 된다(§2.6 갭≠부재).
func ScanJVMs() ([]JVMProc, JVMScanStats) {
	var st JVMScanStats
	entries, err := os.ReadDir("/proc")
	if err != nil {
		st.ProcUnavailable = true
		return nil, st
	}
	var out []JVMProc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			st.Denied++ // 접근 불가·종료 — 갭
			continue
		}
		st.Accessible++
		libjvm := findLibjvm(pid)
		if !isJavaExe(exe) && libjvm == "" {
			continue // JVM 아님
		}
		st.WithJVM++
		home := deriveJavaHome(exe, libjvm)
		base := filepath.Join("/proc", e.Name())
		cmdline, _ := os.ReadFile(filepath.Join(base, "cmdline"))
		cwd, _ := os.Readlink(filepath.Join(base, "cwd")) // 못 읽으면 빈 값 — 상대 -jar는 약한 키로 내려간다
		cgroup, _ := os.ReadFile(filepath.Join(base, "cgroup"))
		out = append(out, JVMProc{
			PID: pid, Exe: exe, App: parseMainId(string(cmdline)), JavaHome: home,
			Cmdline: string(cmdline), Cwd: cwd, Cgroup: string(cgroup),
			JavaBin:       javaBinFor(home, exe),
			Version:       readReleaseVersion(home),
			ViaLibjvm:     !isJavaExe(exe) && libjvm != "",
			AttachCapable: attachCapable(home, fileExists),
		})
	}
	return out, st
}

// findLibjvm — 프로세스 maps에서 libjvm.so 경로를 찾는다(없으면 ""). exe가 java가 아니어도
// (래퍼·재실행 등) libjvm 로드로 JVM을 잡아낸다.
func findLibjvm(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, "libjvm.so") {
			continue
		}
		if i := strings.IndexByte(line, '/'); i >= 0 { // maps 경로 필드는 첫 '/'부터
			return strings.TrimSpace(line[i:])
		}
	}
	return ""
}
