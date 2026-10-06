// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-procs — 타깃 노드에서 실행. app 매칭 규칙으로 **지금의 라이브 프로세스**를 조회한다.
// 프로비저닝 직전 "이 앱의 재시작 대상 PID"를 확정하는 용도. PID는 휘발이라 실시간 조회(자산 §1.5).
// usage: pqcota-procs [--unit UNIT] [--exe PATH] [--cmd REGEX]   (하나 이상 지정)
package main

import (
	"flag"
	"fmt"
	"os"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
)

func main() {
	unit := flag.String("unit", "", "systemd unit name (matched via cgroup)")
	exe := flag.String("exe", "", "executable path (exact match)")
	cmd := flag.String("cmd", "", "cmdline regular expression")
	flag.Parse()

	if *unit == "" && *exe == "" && *cmd == "" {
		fmt.Fprintln(os.Stderr, "usage: pqcota-procs [--unit UNIT] [--exe PATH] [--cmd REGEX] (at least one)")
		os.Exit(2)
	}
	m := &discoveryv1.ProcessMatch{SystemdUnit: *unit, ExePath: *exe, CmdlineRegex: *cmd}

	ps, err := procs.Resolve("/proc", m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	fmt.Printf("%d live processes (rule: unit=%q exe=%q cmd=%q · snapshot at call time)\n", len(ps), *unit, *exe, *cmd)
	for _, p := range ps {
		fmt.Printf("  pid=%-7d %s\n", p.GetPid(), p.GetCmdline())
	}
}
