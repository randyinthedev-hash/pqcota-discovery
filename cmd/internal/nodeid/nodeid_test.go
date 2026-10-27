// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package nodeid

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// 노드를 정하는 순서: 인자 → 지문의 self-id → host://local. jvmscan이 둘째 단계를 건너뛰어
// 인자 없이 돌리면 같은 머신의 OpenSSL과 JCA가 두 노드로 갈라졌다.
func TestResolveOrder(t *testing.T) {
	fp := &commonv1.MachineIdentity{MachineId: "m", SelfAssignedId: "node:abc"}
	cases := []struct {
		name string
		arg  string
		fp   *commonv1.MachineIdentity
		want string
	}{
		{"the given node-id wins over the fingerprint", "pay-app", fp, "pay-app"},
		{"omitted, the fingerprint's self-id", "", fp, "node:abc"},
		{"no self-id, host://local", "", &commonv1.MachineIdentity{MachineId: "m"}, Fallback},
		{"no fingerprint at all, host://local", "", nil, Fallback},
	}
	for _, c := range cases {
		if got := Resolve(c.arg, c.fp); got != c.want {
			t.Errorf("%s: Resolve(%q) = %q, want %q", c.name, c.arg, got, c.want)
		}
	}
}

// JVM이 여럿이면 결과도 여럿이다. 하나라도 지문이 빠지면 적재의 중복·충돌 검사가 그 결과를 건너뛴다.
func TestStampEveryResult(t *testing.T) {
	fp := &commonv1.MachineIdentity{SelfAssignedId: "node:abc"}
	rs := []*discoveryv1.CollectionResult{
		{Envelope: &commonv1.Envelope{TargetNodeId: "node:abc"}},
		{Envelope: &commonv1.Envelope{TargetNodeId: "node:abc"}},
		{}, // 봉투가 없는 결과에서 멈추지 않는다
	}
	Stamp(rs, fp)
	for i, r := range rs[:2] {
		if r.GetEnvelope().GetMachine() != fp {
			t.Errorf("result %d: machine fingerprint not attached", i)
		}
	}
}
