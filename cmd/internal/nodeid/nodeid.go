// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package nodeid — 수집 결과를 어느 노드에 귀속시킬지 정하고, 그 머신의 지문을 결과에 붙인다(§1.4).
//
// 규칙은 하나다: node-id 인자(CMDB 권위) → 지문에서 결정론적으로 파생한 self-id → host://local.
// 수집기마다 따로 적어 두었을 때 jvmscan만 지문을 건너뛰어, 인자 없이 돌리면 같은 머신의 OpenSSL은
// node:…로, JCA는 host://local로 갈라졌다. 결과에 지문이 없으면 적재 때의 node_id 중복·충돌 검사도
// 그 결과를 건너뛴다.
package nodeid

import (
	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// Fallback — 인자도 지문도 없을 때의 노드. 어느 머신인지 모른다는 표시다.
const Fallback = "host://local"

// Resolve — 귀속시킬 노드. arg가 있으면 그것, 없으면 fp의 self-id, 그것도 없으면 Fallback.
func Resolve(arg string, fp *commonv1.MachineIdentity) string {
	if arg != "" {
		return arg
	}
	if id := fp.GetSelfAssignedId(); id != "" {
		return id
	}
	return Fallback
}

// Stamp — 결과마다 머신 지문을 붙인다. 한 번에 여러 결과(JVM 여럿)를 내는 수집기도 빠짐없이 붙게 한다.
func Stamp(results []*discoveryv1.CollectionResult, fp *commonv1.MachineIdentity) {
	for _, r := range results {
		if e := r.GetEnvelope(); e != nil {
			e.Machine = fp
		}
	}
}
