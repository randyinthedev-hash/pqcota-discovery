// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package openssl

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/completeness"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Service — openssl-collector를 intake 계약(§1.6, contracts/collector.proto)으로 낸다.
// 코어는 이 서비스 뒤가 openssl-collector인지 모른다 — 정규화된 CBOM Envelope만 받는다.
type Service struct {
	discoveryv1.UnimplementedCollectorServer
	Now func() time.Time // 주입 가능(테스트 결정론)
}

func NewService() *Service { return &Service{Now: time.Now} }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return now()
}

// Describe — 능력 신고(§1.6). 코어가 완전성 맵·계층 커버리지·라이선스 UX 판단에 사용.
func (s *Service) Describe(_ context.Context, _ *discoveryv1.DescribeRequest) (*discoveryv1.CollectorCapabilities, error) {
	return &discoveryv1.CollectorCapabilities{
		CollectorId:    "openssl-collector",
		Version:        "0.1.0",
		CryptoRuntimes: []commonv1.CryptoRuntime{commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL},
		Layers: []commonv1.CollectionLayer{
			commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS,
			commonv1.CollectionLayer_COLLECTION_LAYER_ARTIFACT,
		},
		DetectionMethods: []commonv1.DetectionMethod{
			commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			commonv1.DetectionMethod_DETECTION_METHOD_SYMBOL_ANALYSIS,
		},
		License:  "Apache-2.0",
		Invasive: false,
	}, nil
}

// Collect — 대상 노드별로 정규화된 CBOM Envelope를 스트림 반환. 데모는 options["pid"]로 프로세스 지정.
func (s *Service) Collect(req *discoveryv1.CollectRequest, stream grpc.ServerStreamingServer[discoveryv1.CollectionResult]) error {
	for _, node := range req.GetTargetNodeIds() {
		if err := stream.Send(s.collectNode(node, req.GetOptions())); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) collectNode(node string, opts map[string]string) *discoveryv1.CollectionResult {
	declared := []commonv1.CollectionLayer{
		commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS,
		commonv1.CollectionLayer_COLLECTION_LAYER_ARTIFACT,
	}
	var covered []commonv1.CollectionLayer
	var cyclone, raw []byte
	note := "no pid given — PROCESS layer not collected"

	if pidStr := opts["pid"]; pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err == nil {
			dets, err := DetectForPID(pid, registry.DefaultForkSignatures)
			switch {
			case err != nil:
				// 대상 프로세스를 **관측하지 못했다**. 컨테이너 네임스페이스가 갈렸거나 권한이 없다.
				// PROCESS를 커버로 세지 않아 갭으로 남는다 — 관측하지 못한 것은 부재가 아니다(§2.6).
				note = "target process not visible (namespace separation, permissions, …) — unobserved != absent: " + err.Error()
			case len(dets) == 0:
				// 봤는데 없었다. 이것은 관측 결과이므로 계층은 커버된 것이다.
				covered = append(covered, commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS)
				note = "process observed; no OpenSSL"
			default:
				covered = append(covered, commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS)
				cyclone, _ = buildCycloneDX(dets)
				raw = RawCapture(dets)
				note = ""
			}
		}
	}
	// 원본이 없으면 형식 이름도 달지 않는다 — 이름만 있고 내용이 없으면 "원본을 보관한다"는
	// 약속이 거짓이 된다(§1.2).
	rawFormat := "openssl-collector/native-v1"
	if len(raw) == 0 {
		rawFormat = ""
	}

	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      "openssl-collector",
			CollectorVersion: "0.1.0",
			DetectionMethod:  commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			CollectedAt:      timestamppb.New(s.now()),
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

// buildCycloneDX — 탐지 결과를 표준 CycloneDX 본문 + pqcota properties(§3.2)로.
func buildCycloneDX(dets []Detection) ([]byte, error) {
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
	comps := make([]comp, 0, len(dets))
	for _, d := range dets {
		comps = append(comps, comp{
			Type: "cryptographic-asset",
			Name: filepath.Base(d.Path), // 파일별로 구분 — 벤더링/NSS/시스템 각각(§2.3)
			Properties: []prop{
				{"pqcota:crypto_runtime", "openssl"},
				{"pqcota:detection_method", d.DetectionMethod},
				{"pqcota:openssl.lib", d.Lib},
				{"pqcota:openssl.fork", d.Fork},
				{"pqcota:openssl.version", d.Version},
				{"pqcota:openssl.binding_mode", d.BindingMode},
				{"pqcota:openssl.path", d.Path},
				{"pqcota:app_keys", strings.Join(d.AppKeys, ",")}, // 자산이 어느 앱 것인지(§1.5) — 다중 앱이면 CSV
			},
		})
	}
	return json.Marshal(doc{BomFormat: "CycloneDX", SpecVersion: "1.6", Components: comps})
}
