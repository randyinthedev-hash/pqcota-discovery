// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package procs_test

import (
	"os"
	"path/filepath"
	"testing"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
)

func TestMatch(t *testing.T) {
	exe, cmd, cg := "/opt/java/bin/java", "java -jar /opt/payment/app.jar", "0::/system.slice/payment.service"

	// systemd_unit — cgroup 포함
	if !procs.Match(exe, cmd, cg, &discoveryv1.ProcessMatch{SystemdUnit: "payment.service"}) {
		t.Error("systemd_unit did not match")
	}
	if procs.Match(exe, cmd, "0::/system.slice/other.service", &discoveryv1.ProcessMatch{SystemdUnit: "payment.service"}) {
		t.Error("a different unit matched")
	}
	// exe_path 정확
	if !procs.Match(exe, cmd, cg, &discoveryv1.ProcessMatch{ExePath: "/opt/java/bin/java"}) {
		t.Error("exe_path did not match")
	}
	// cmdline_regex
	if !procs.Match(exe, cmd, cg, &discoveryv1.ProcessMatch{CmdlineRegex: "payment/app\\.jar"}) {
		t.Error("cmdline_regex did not match")
	}
	// AND: 둘 다 만족해야
	if procs.Match(exe, cmd, cg, &discoveryv1.ProcessMatch{ExePath: "/opt/java/bin/java", SystemdUnit: "other.service"}) {
		t.Error("AND violated (matched with one condition unmet)")
	}
	// 규칙 없음 → false(전체 매칭 방지)
	if procs.Match(exe, cmd, cg, &discoveryv1.ProcessMatch{}) || procs.Match(exe, cmd, cg, nil) {
		t.Error("an empty rule matched")
	}
}

// Resolve — 가짜 /proc 트리로 exe/cmdline으로 찾아내는지 검증.
func TestResolve(t *testing.T) {
	root := t.TempDir()
	mkProc := func(pid, cmdline, target string) {
		d := filepath.Join(root, pid)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "cmdline"), []byte(cmdline), 0o644)
		os.WriteFile(filepath.Join(d, "cgroup"), []byte("0::/system.slice/x"), 0o644)
		os.Symlink(target, filepath.Join(d, "exe"))
	}
	mkProc("101", "java\x00-jar\x00/opt/app.jar", "/opt/java/bin/java")
	mkProc("202", "nginx", "/usr/sbin/nginx")
	os.WriteFile(filepath.Join(root, "cpuinfo"), []byte("x"), 0o644) // 숫자 아닌 항목

	got, err := procs.Resolve(root, &discoveryv1.ProcessMatch{ExePath: "/opt/java/bin/java"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].GetPid() != 101 {
		t.Fatalf("resolution result: %+v (want pid 101 alone)", got)
	}
	if got[0].GetCmdline() != "java -jar /opt/app.jar" {
		t.Errorf("wrong cmdline normalization: %q", got[0].GetCmdline())
	}
}
