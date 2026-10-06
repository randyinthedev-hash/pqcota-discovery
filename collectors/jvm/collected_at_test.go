// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"testing"
	"time"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// TestEveryResultCarriesCollectedAt — JVM 결과가 수집 시각을 싣는다.
//
// v0.1.0~v0.1.2에서 비어 있었고, 이 collector는 **JVM마다 결과를 하나씩** 낸다.
// 그래서 한 노드의 결과 여럿이 (collector_id, node_id, 제로 시각)으로 완전히 같아졌다 —
// 수신 측이 그 셋을 중복 키로 쓰면 JVM 여러 개가 하나로 접힌다.
func TestEveryResultCarriesCollectedAt(t *testing.T) {
	fixed := time.Date(2026, 8, 12, 3, 4, 5, 0, time.UTC)
	defer func(orig func() time.Time) { now = orig }(now)
	now = func() time.Time { return fixed }

	for name, res := range map[string]*discoveryv1.CollectionResult{
		"BuildResult":                   BuildResult("node-a", Collected{}),
		"BuildResultFor (single)":       BuildResultFor("node-a", Collected{}, ""),
		"BuildResultFor (several JVMs)": BuildResultFor("node-a", Collected{}, "app-a"),
	} {
		if at := res.GetEnvelope().GetCollectedAt().AsTime(); !at.Equal(fixed) {
			t.Errorf("%s: collected at %v — the injected clock (%v) is not used", name, at, fixed)
		}
	}
}
