// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package localview — 수집 결과를 **그 자리에서** 사람이 읽는 뷰로 렌더한다.
//
// 중앙(`pqcota-ingest`)이 하는 정규화를 인메모리로 한 번 돌리고 버린다. 저장하지 않으므로
// 히스토리·스냅샷 diff는 생기지 않는다 — 그것은 중앙에 쌓아야 나온다. 한 대를 그 자리에서
// 확인할 때만 쓰는 경로다.
//
// 스캐너(nodescan·jvmscan) 두 곳이 같은 코드를 쓰도록 여기 둔다. 엣지 바이너리가 이걸
// 링크해도 비용은 작다(실측 +106KB) — 정규화는 이미 들어 있고 뷰 렌더만 더해진다.
package localview

import (
	"fmt"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
)

// Render — 수집 결과들을 정규화해 인벤토리 뷰 문자열로 만든다.
func Render(node string, results []*discoveryv1.CollectionResult) (string, error) {
	// 조직을 대지 않는다 — 이 저장소는 화면을 그리는 동안만 살고 아무것도 남기지 않는다.
	// 격리할 것이 없다(적재 경로는 org.FromEnv를 쓴다).
	snap, err := normalize.Normalize(results, "snap-local", node, normalize.RulesetVersion, history.NewMemStore(), nil)
	if err != nil {
		return "", fmt.Errorf("normalize: %w", err)
	}
	return inventory.Render(snap), nil
}
