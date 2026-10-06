// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Command openssl-collector — PoC/CLI. 주어진 PID의 로드된 OpenSSL을 탐지·출력한다(SD-1·SD-3).
// 통합 테스트에서 실물 /proc·ELF 검증에 쓰인다.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/openssl"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: openssl-collector <pid>")
		os.Exit(2)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid pid:", err)
		os.Exit(2)
	}
	dets, err := openssl.DetectForPID(pid, registry.DefaultForkSignatures)
	if err != nil {
		fmt.Fprintln(os.Stderr, "detect error:", err)
		os.Exit(1)
	}
	if len(dets) == 0 {
		fmt.Println("no OpenSSL libraries loaded")
		return
	}
	for _, d := range dets {
		fork := d.Fork
		if fork == "" {
			fork = "unknown"
		}
		fmt.Printf("lib=%s fork=%s version=%s binding=%s method=%s path=%s\n",
			d.Lib, fork, d.Version, d.BindingMode, d.DetectionMethod, d.Path)
	}
}
