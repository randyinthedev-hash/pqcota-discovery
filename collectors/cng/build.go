// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package cng

import (
	"encoding/json"
	"strings"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/completeness"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// now — 수집 시각의 출처. 테스트가 갈아끼울 수 있게 변수로 둔다(시그니처는 건드리지 않는다).
var now = time.Now

// CollectorID·Version — Envelope에 실리는 이름. 서명 검증이 collector_id로 키를 고르므로(§2.6)
// 한 번 정하면 함부로 바꾸지 않는다.
const (
	CollectorID = "cng-collector"
	Version     = "0.1.0"
)

// BuildResult — 관측을 정규화된 CBOM Envelope(CollectionResult)로 조립한다.
//
// obs가 비면 CNG 계층을 **커버로 세지 않는다** — provider가 없다는 뜻이 아니라 못 봤다는 뜻이고,
// 그 둘을 같은 모양으로 내보내면 인벤토리에서 "이 노드엔 CNG가 없다"로 읽힌다(§2.6).
func BuildResult(node string, obs Observation, obsErr error) *discoveryv1.CollectionResult {
	declared := []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_CNG_INTROSPECTION}

	var covered []commonv1.CollectionLayer
	var cyclone, raw []byte
	rawFormat := ""
	var note string

	switch {
	case obsErr != nil:
		// 관측을 시도했는데 못 했다. 사유를 그대로 싣는다 — 사유가 다르면 대응이 다르다.
		note = "CNG was not observed — not absent, just unobserved: " + obsErr.Error()
	case obs.Empty():
		// 봤는데 아무것도 없었다. 이것도 관측 결과이므로 계층은 커버된 것이다.
		covered = declared
		note = "CNG observed; no registered provider"
	default:
		covered = declared
		cyclone = buildCycloneDX(obs)
		raw, _ = json.Marshal(obs)
		rawFormat = CollectorID + "/native-v1"
	}

	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      CollectorID,
			CollectorVersion: Version,
			DetectionMethod:  commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			CollectedAt:      timestamppb.New(now()),
			TargetNodeId:     node,
			CollectorLicense: "Apache-2.0",
		},
		RawCapture:           raw,
		RawFormat:            rawFormat,
		CbomCyclonedx:        cyclone,
		CyclonedxSpecVersion: "1.6",
		Completeness:         completeness.BuildCompleteness(declared, covered, note),
	}
}

// buildCycloneDX — 관측을 CycloneDX 본문 + pqcota properties(§3.2)로.
//
// JCA와 같은 모양을 쓴다 — `provider_set`은 **등록 순서 CSV**다. 관측된 순서 그대로 싣고, 그 순서가
// 우선순위인지는 CNG에서 미확인이다(cbom.proto CngAxes). 알고리즘은 v0.6.0 실측 뒤에 계약에 자리가 생겨 함께 싣는다 —
// provider 이름만으로는 "이 노드가 ML-DSA를 할 수 있나"에 답할 수 없다.
func buildCycloneDX(obs Observation) []byte {
	type prop struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type comp struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Properties []prop `json:"properties,omitempty"`
	}
	type doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []comp `json:"components"`
	}
	c := comp{
		Type: "cryptographic-asset",
		Name: "cng-providers",
		Properties: []prop{
			{"pqcota:crypto_runtime", "cng"},
			{"pqcota:detection_method", "runtime-introspection"},
			{"pqcota:cng.provider_set", strings.Join(obs.Providers, ",")},
			{"pqcota:cng.algorithms", EncodeAlgorithms(obs.Algorithms)},
		},
	}
	b, _ := json.Marshal(doc{BomFormat: "CycloneDX", SpecVersion: "1.6", Components: []comp{c}})
	return b
}
