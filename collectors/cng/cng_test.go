// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package cng

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
)

func init() { now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() } }

// TD-CNG-1 — 관측한 provider 순서를 그대로 싣는다.
// 관측된 순서를 그대로 보존한다(cbom.proto CngAxes). 정렬하거나 집합으로 만들면 관측 당시의
// 순서 정보를 잃는다.
func TestProviderOrderIsPreserved(t *testing.T) {
	obs := Observation{Providers: []string{"Microsoft Primitive Provider", "Vendor KSP", "Microsoft Smart Card Key Storage Provider"}}
	res := BuildResult("win-01", obs, nil)

	got := providerSetProp(t, res.GetCbomCyclonedx())
	want := "Microsoft Primitive Provider,Vendor KSP,Microsoft Smart Card Key Storage Provider"
	if got != want {
		t.Errorf("provider_set does not match the observed order:\n got %q\nwant %q", got, want)
	}
}

// TD-CNG-2 — 관측하지 못한 것과 "provider가 없다"를 같은 얼굴로 내보내지 않는다(§2.6).
func TestUnobservedIsNotAbsence(t *testing.T) {
	failed := BuildResult("win-01", Observation{}, ErrNotWindows)
	if len(failed.GetCompleteness().GetLayersCovered()) != 0 {
		t.Error("nothing was observed, yet the layer counts as covered — the inventory would read that as absence")
	}
	if !strings.Contains(failed.GetCompleteness().GetNote(), "not absent, just unobserved") {
		t.Errorf("the note does not say that nothing was seen: %q", failed.GetCompleteness().GetNote())
	}
	if len(failed.GetCbomCyclonedx()) != 0 || len(failed.GetRawCapture()) != 0 {
		t.Error("nothing was observed, yet a body was attached")
	}

	empty := BuildResult("win-01", Observation{}, nil)
	covered := empty.GetCompleteness().GetLayersCovered()
	if len(covered) != 1 || covered[0] != commonv1.CollectionLayer_COLLECTION_LAYER_CNG_INTROSPECTION {
		t.Errorf("looked and found none — that counts as covered: covered=%v", covered)
	}
}

// TD-CNG-3 — 원본이 없으면 형식 이름도 비운다(§1.2 — 재정규화할 것이 없는데 있다고 하지 않는다).
func TestRawFormatEmptyWithoutRaw(t *testing.T) {
	res := BuildResult("win-01", Observation{}, nil)
	if res.GetRawFormat() != "" {
		t.Errorf("a raw format name is set although there is no raw capture: %q", res.GetRawFormat())
	}
	full := BuildResult("win-01", Observation{Providers: []string{"P"}}, nil)
	if full.GetRawFormat() == "" || len(full.GetRawCapture()) == 0 {
		t.Error("once observed, the raw capture and its format name must both be present")
	}
}

// TD-CNG-4 — 알고리즘은 파생 뷰와 원본 **양쪽**에 남는다.
//
// v0.6.0 실측 전에는 계약에 자리가 없어 원본에만 실었다. provider 이름 9개가 전부 Microsoft라
// "이 노드가 ML-DSA를 할 수 있나"에 답하지 못한다는 것이 실측에서 드러나 계약에 더했다.
func TestAlgorithmsRideOnBothLanes(t *testing.T) {
	obs := Observation{
		Providers:  []string{"Microsoft Primitive Provider"},
		Algorithms: []Algorithm{{Name: "ML-DSA", Class: "signature"}, {Name: "SHA256", Class: "hash"}},
	}
	res := BuildResult("win-01", obs, nil)

	if got := propValue(t, res.GetCbomCyclonedx(), "pqcota:cng.algorithms"); got != "ML-DSA:signature,SHA256:hash" {
		t.Errorf("the algorithms carried on the derived lane differ: %q", got)
	}
	var back Observation
	if err := json.Unmarshal(res.GetRawCapture(), &back); err != nil {
		t.Fatalf("the raw capture cannot be read back: %v", err)
	}
	if len(back.Algorithms) != 2 {
		t.Errorf("an observed algorithm vanished from the raw capture: %+v", back.Algorithms)
	}
}

// TD-CNG-8 — 종류를 못 읽어도 알고리즘 자체는 남는다(§2.6 갭 ≠ 부재).
func TestUnknownClassKeepsTheAlgorithm(t *testing.T) {
	// 종류가 빈 값인 관측(모르는 dwClass) → 표기에서도 빈 값 → 되읽어도 이름은 그대로.
	encoded := EncodeAlgorithms([]Algorithm{{Name: "FUTURE-ALG"}, {Name: "AES", Class: "cipher"}})
	if encoded != "FUTURE-ALG:,AES:cipher" {
		t.Fatalf("the encoding differs: %q", encoded)
	}
	back := DecodeAlgorithms(encoded)
	if len(back) != 2 || back[0].Name != "FUTURE-ALG" || back[0].Class != "" {
		t.Errorf("an unknown class either dropped the algorithm or invented a class: %+v", back)
	}
	// 이름 없는 항목은 나를 것이 없다 — 빈 줄이 알고리즘 하나로 세어지면 개수가 거짓이 된다.
	if got := DecodeAlgorithms(",:cipher,AES:cipher"); len(got) != 1 || got[0].Name != "AES" {
		t.Errorf("a nameless entry was counted as an algorithm: %+v", got)
	}
}

func providerSetProp(t *testing.T, cyclone []byte) string {
	t.Helper()
	return propValue(t, cyclone, "pqcota:cng.provider_set")
}

func propValue(t *testing.T, cyclone []byte, key string) string {
	t.Helper()
	var doc struct {
		Components []struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(cyclone, &doc); err != nil {
		t.Fatalf("failed to parse the CycloneDX: %v", err)
	}
	for _, c := range doc.Components {
		for _, p := range c.Properties {
			if p.Name == key {
				return p.Value
			}
		}
	}
	t.Fatalf("property %s is missing", key)
	return ""
}

// TD-CNG-6 — dwClass 매핑을 실측에 못 박는다.
//
// 첫 실측(Windows 11 26200)에서 50개 중 18개가 빈 종류로 나오고 DH·ECDH가 `secret-agreement`가
// 아니라 `asymmetric-encryption`으로 **틀리게** 붙었다. 원인은 열거 **요청**의 연산 비트마스크와
// 반환값의 **인터페이스 상수**를 같은 어휘로 본 것이다. 값이 겹쳐 오류 없이 틀리는 자리라 못 박는다.
func TestAlgorithmClassFollowsTheInterfaceConstants(t *testing.T) {
	for _, c := range []struct {
		dwClass uint32
		want    string
		seenAs  string // 그 인터페이스로 실제 관측된 알고리즘(실측 근거)
	}{
		{1, "cipher", "AES"},
		{2, "hash", "SHA256"},
		{3, "asymmetric-encryption", "RSA"},
		{4, "secret-agreement", "ECDH_P256"},
		{5, "signature", "ML-DSA"},
		{6, "rng", "RNG"},
		{7, "key-derivation", "HKDF"},
	} {
		if got := AlgorithmClass(c.dwClass); got != c.want {
			t.Errorf("dwClass=%d(%s): got %q, want %q", c.dwClass, c.seenAs, got, c.want)
		}
	}
	// 모르는 값을 아는 것으로 적지 않는다(§2.5). 0과 미래 값 둘 다 빈 값이어야 한다.
	for _, unknown := range []uint32{0, 8, 0x10, 0x40, 99} {
		if got := AlgorithmClass(unknown); got != "" {
			t.Errorf("an unknown dwClass=%d was given a class: %q", unknown, got)
		}
	}
}

// TD-CNG-10 — provider 매핑을 나르는 자리. 등록 목록은 "머신에 무엇이 있나"만 답하므로,
// "누가 ML-DSA를 하나"는 알고리즘마다 따로 물어 나른다.
func TestAlgorithmProvidersRoundTrip(t *testing.T) {
	algs := []Algorithm{
		{Name: "ML-DSA", Class: "signature", Providers: []string{"Microsoft Primitive Provider", "Microsoft Software Key Storage Provider"}},
		{Name: "SHA256", Class: "hash"}, // 못 물은 경우 — 셋째 칸이 아예 없다
	}
	enc := EncodeAlgorithms(algs)
	const want = "ML-DSA:signature:Microsoft Primitive Provider|Microsoft Software Key Storage Provider,SHA256:hash"
	if enc != want {
		t.Fatalf("the encoding differs:\n got %q\nwant %q", enc, want)
	}
	back := DecodeAlgorithms(enc)
	if len(back) != 2 {
		t.Fatalf("read back as %d entries", len(back))
	}
	if len(back[0].Providers) != 2 || back[0].Providers[0] != "Microsoft Primitive Provider" {
		t.Errorf("providers did not read back in order: %v", back[0].Providers)
	}
	// **못 물은 것과 "없더라"를 같게 적지 않는다** — 셋째 칸이 없으면 빈 목록으로 남는다.
	if back[1].Providers != nil {
		t.Errorf("providers appeared where none were asked for: %v", back[1].Providers)
	}
}
