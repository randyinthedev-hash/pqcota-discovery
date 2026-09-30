package network

import (
	"testing"
	"time"
)

// TestEveryResultCarriesCollectedAt — 이 collector가 내는 모든 결과가 수집 시각을 싣는다.
//
// v0.1.0~v0.1.2에서 비어 있었다. 아무것도 그 값을 읽지 않아 드러나지 않았지만, Envelope의
// 선언된 목적이 provenance이고 sign.Canonical이 그 값을 서명 범위에 넣는다 — 빈 값에
// 서명하는 것은 "언제 봤는지 모른다"에 서명하는 것이다.
//
// DegradedResult도 예외가 아니다. 포집이 실패했어도 **언제 시도했는지**가 갭 기록의 근거다.
func TestEveryResultCarriesCollectedAt(t *testing.T) {
	fixed := time.Date(2026, 8, 12, 3, 4, 5, 0, time.UTC)
	defer func(orig func() time.Time) { now = orig }(now)
	now = func() time.Time { return fixed }

	for name, at := range map[string]time.Time{
		"BuildResult":    BuildResult("node-a", nil, "").GetEnvelope().GetCollectedAt().AsTime(),
		"DegradedResult": DegradedResult("node-a", "no CAP_NET_RAW").GetEnvelope().GetCollectedAt().AsTime(),
	} {
		if !at.Equal(fixed) {
			t.Errorf("%s: collected at %v — the injected clock (%v) is not used", name, at, fixed)
		}
	}
}
