// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// 프로브 경로에 온 까닭을 사실대로 적는다. JVM을 찾고도 에이전트를 안 줬는데 「no JVM was running」이라
// 적으면 관측 범위를 잘못 알리고, 프로세스 목록을 못 읽은 것을 「JVM 없음」으로 적으면 못 본 것을 없다고 한다.
func TestProbeReasonTellsWhyTheProbeRan(t *testing.T) {
	cases := []struct {
		name        string
		found       int
		procUnavail bool
		want        []string
		notWant     []string
	}{
		{"found but no agent", 2, false, []string{"2 running JVM(s) were found", "PQCOTA_JVM_AGENT", "--pid"}, []string{"no JVM was running"}},
		{"process list unreadable", 0, true, []string{"could not be read", "not known whether"}, []string{"no JVM was running"}},
		{"none found", 0, false, []string{"no JVM was running"}, []string{"were found"}},
	}
	for _, c := range cases {
		got := probeReason(c.found, c.procUnavail)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q should contain %q", c.name, got, w)
			}
		}
		for _, n := range c.notWant {
			if strings.Contains(got, n) {
				t.Errorf("%s: %q must not contain %q", c.name, got, n)
			}
		}
	}
}
