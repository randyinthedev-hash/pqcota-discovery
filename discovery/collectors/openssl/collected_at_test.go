package openssl

import (
	"testing"
	"time"
)

// TestBuildResultCarriesCollectedAt — CLI 경로(pqcota-nodescan)가 쓰는 BuildResult도
// 수집 시각을 싣는다.
//
// v0.1.0~v0.1.2에서는 gRPC 서비스 경로만 이 값을 채웠다. 데모가 쓰는 CLI 경로는 비어 있었다 —
// 같은 collector인데 어느 문으로 나왔느냐에 따라 provenance가 갈렸다.
func TestBuildResultCarriesCollectedAt(t *testing.T) {
	fixed := time.Date(2026, 8, 12, 3, 4, 5, 0, time.UTC)
	defer func(orig func() time.Time) { now = orig }(now)
	now = func() time.Time { return fixed }

	if at := BuildResult("node-a", nil).GetEnvelope().GetCollectedAt().AsTime(); !at.Equal(fixed) {
		t.Errorf("collected at %v — the injected clock (%v) is not used", at, fixed)
	}
	// 서비스 경로도 같은 시계로 떨어진다(Now 미주입 시 패키지 시계로 폴백).
	if got := (&Service{}).now(); !got.Equal(fixed) {
		t.Errorf("Service.now() does not fall back to the package clock: %v", got)
	}
}
