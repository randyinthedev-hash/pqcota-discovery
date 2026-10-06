// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package openssl

import (
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/completeness"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// now — 수집 시각의 출처. 테스트가 갈아끼울 수 있게 변수로 둔다(시그니처는 건드리지 않는다).
var now = time.Now

// BuildResult — 탐지 결과를 정규화된 CBOM Envelope(CollectionResult)로. 노드 단위 집계에 쓴다.
// dets가 비면 프로세스 계층 미커버(갭). CycloneDX + pqcota properties(§3.2).
func BuildResult(node string, dets []Detection) *discoveryv1.CollectionResult {
	declared := []commonv1.CollectionLayer{
		commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS,
		commonv1.CollectionLayer_COLLECTION_LAYER_ARTIFACT,
	}
	var covered []commonv1.CollectionLayer
	var cyclone []byte
	note := "OpenSSL not detected, or inaccessible"
	if len(dets) > 0 {
		covered = []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS}
		cyclone, _ = buildCycloneDX(dets)
		note = ""
	}
	// 원본이 없으면 형식 이름도 비운다(§1.2 — 재정규화할 것이 없는데 있다고 하지 않는다).
	raw := RawCapture(dets)
	rawFormat := "openssl-collector/native-v1"
	if len(raw) == 0 {
		rawFormat = ""
	}
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      "openssl-collector",
			CollectorVersion: "0.1.0",
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
