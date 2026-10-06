// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Package jvm — JVM collector의 Go 쪽: Java attach
// sidecar 출력을 정규화된 CBOM Envelope(CollectionResult)로 변환하고 intake 계약(§1.6)으로 노출한다.
// (attach 자체는 순수 Java 사이드카 — collectors/jvm/collector. 여기선 결과를 계약으로.)
package jvm

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// now — 수집 시각의 출처. 테스트가 갈아끼울 수 있게 변수로 둔다(시그니처는 건드리지 않는다).
var now = time.Now

// Provider — getProviders() 실체의 한 항목(등록 순서 포함, 수용 원칙 §2.2).
type Provider struct {
	Order     int
	Name      string
	Version   string
	ClassName string
}

// Collected — 사이드카 출력 파싱 결과. Degraded=true면 attach 불가로 정적 폴백(설계 §2.2, TD-JVM-4).
type Collected struct {
	Providers []Provider
	Degraded  bool
	// Raw — 파싱 전 원본 텍스트. raw_capture로 실려 재정규화의 입력이 된다(§2.4 step 1).
	Raw string

	// Note — 왜 강등인지. 비면 attach 폴백의 기본 사유를 쓴다.
	//
	// 강등에도 여러 사유가 있다. attach가 막혀 대상의 java.security를 읽은 것과, **도는 JVM이
	// 없어 도구가 java를 하나 띄워 본 것**은 읽는 사람에게 전혀 다른 이야기다. 하나로 적으면
	// 뒤엣것이 앞엣것처럼 읽힌다.
	Note string
}

// ParseProviders — Java 사이드카 출력("N|name|version|class" 또는 정적 폴백)을 파싱.
func ParseProviders(output string) Collected {
	c := Collected{Degraded: strings.Contains(output, "PQCOTA_STATIC_FALLBACK_BEGIN"), Raw: output}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PQCOTA_") ||
			strings.HasPrefix(line, "evidence_strength=") || strings.HasPrefix(line, "gap=") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		ord, _ := strconv.Atoi(parts[0])
		p := Provider{Order: ord, Name: parts[1]}
		if len(parts) >= 3 {
			p.Version = parts[2]
		}
		if len(parts) >= 4 {
			p.ClassName = parts[3]
		}
		c.Providers = append(c.Providers, p)
	}
	return c
}

// GapResult — **JVM을 찾았는데 관측하지 못했다**를 계약에 실어 보낸다(network의 DegradedResult와 같은 자리).
//
// 예전에는 attach가 다 막히면 그 JVM의 결과를 아예 내지 않았다. 그러면 실패는 stderr에만 남고
// **중앙은 그런 JVM이 있었다는 것조차 모른다** — "관측하지 못했다"가 "없다"와 같은 얼굴이 된다(§2.6).
//
// 컴포넌트를 만들지 않는 이유: provider를 하나도 못 봤는데 빈 체인을 실으면 "이 JVM엔 provider가
// 없다"로 읽힌다. 실은 것은 완전성 갭과 사유뿐이다.
func GapResult(node, ident, reason string) *discoveryv1.CollectionResult {
	if ident != "" {
		reason = ident + ": " + reason
	}
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      "jvm-collector",
			CollectorVersion: "0.1.0",
			DetectionMethod:  commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			CollectedAt:      timestamppb.New(now()),
			TargetNodeId:     node,
			CollectorLicense: "Apache-2.0",
		},
		Completeness: &commonv1.Completeness{
			LayersMissing: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_JVM_INTROSPECTION},
			Note:          reason,
		},
	}
}

// BuildResult — ident 없는 단일 JVM 편의 형태. 다중 JVM은 BuildResultFor로 구별한다.
func BuildResult(node string, c Collected) *discoveryv1.CollectionResult {
	return BuildResultFor(node, c, "")
}

// BuildResultFor — 파싱 결과를 정규화된 CBOM Envelope로. attach 성공은 runtime-introspection(confirmed 근거),
// 정적 폴백은 artifact + 완전성 갭(§2.5 갭≠부재). provider_set 순서 보존(수용 원칙 §2.2).
//
// ident: 한 노드에 JVM이 여럿일 때 이들을 **구별**하는 안정 식별자(JAVA_HOME 권장). 비면 단일.
// finding id는 (node|컴포넌트명|runtime|fork) 해시라, ident를 컴포넌트명에 실어야 서로 다른 JVM이
// 하나로 뭉개지지 않는다. **PID는 쓰지 않는다** — 매 스캔 달라져 이력이 "매번 새 자산"으로 깨진다.
func BuildResultFor(node string, c Collected, ident string) *discoveryv1.CollectionResult {
	dm := commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION
	dmStr := "runtime-introspection"
	covered := []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_JVM_INTROSPECTION}
	var missing []commonv1.CollectionLayer
	note := ""
	if c.Degraded {
		dm = commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT
		dmStr = "artifact"
		covered = nil
		missing = []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_JVM_INTROSPECTION}
		note = c.Note
		if note == "" {
			note = "attach unavailable — static java.security path (runtime-introspection gap; dynamic registrations are a blind spot)"
		}
	}

	// 노드에 JVM이 여럿이면 결과가 여럿이고, 노트는 노드 하나로 합쳐져 화면에 나온다.
	// 그때 **어느 JVM 이야기인지 적지 않으면 노드 전체가 그런 것으로 읽힌다** — 실측에서
	// attach가 성공한 행 바로 아래에 "attach unavailable"이 붙어 실제보다 나쁘게 보였다.
	if note != "" && ident != "" {
		note = ident + ": " + note
	}

	names := make([]string, 0, len(c.Providers))
	for _, p := range c.Providers {
		names = append(names, p.Name)
	}

	compName := "jca-provider-chain"
	var appKeys []string
	if ident != "" { // 다중 JVM 구별 — 컴포넌트명·앱 표시에 안정 식별자
		compName += "@" + ident
		appKeys = []string{ident}
	}

	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      "jvm-collector",
			CollectorVersion: "0.1.0",
			DetectionMethod:  dm,
			CollectedAt:      timestamppb.New(now()),
			TargetNodeId:     node,
			CollectorLicense: "Apache-2.0",
		},
		RawCapture:           []byte(c.Raw),
		RawFormat:            "jvm-collector/providers-v1",
		CbomCyclonedx:        buildJcaCycloneDX(names, dmStr, compName, appKeys),
		CyclonedxSpecVersion: "1.6",
		Completeness: &commonv1.Completeness{
			LayersCovered: covered,
			LayersMissing: missing,
			Note:          note,
		},
	}
}

// buildJcaCycloneDX — provider 체인을 CycloneDX 본문 + pqcota properties(§3.2)로.
// provider_set은 등록 순서 CSV(수용 원칙 §2.2 우선순위 협상 판정 근거). compName·appKeys로 다중 JVM 구별.
func buildJcaCycloneDX(providerNames []string, detectionMethod, compName string, appKeys []string) []byte {
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
	props := []prop{
		{"pqcota:crypto_runtime", "jca"},
		{"pqcota:detection_method", detectionMethod},
		{"pqcota:jca.provider_set", strings.Join(providerNames, ",")},
		{"pqcota:jca.registration_mode", "dynamic"},
	}
	if len(appKeys) > 0 { // JVM이 여럿일 때의 앱 표시(§1.5와 같은 결) — 어느 JDK/앱의 체인인지
		props = append(props, prop{"pqcota:app_keys", strings.Join(appKeys, ",")})
	}
	c := comp{Type: "cryptographic-asset", Name: compName, Properties: props}
	b, _ := json.Marshal(doc{BomFormat: "CycloneDX", SpecVersion: "1.6", Components: []comp{c}})
	return b
}
