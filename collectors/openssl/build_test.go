package openssl_test

import (
	"encoding/json"
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/openssl"
)

func det(lib, path, fork, ver string, apps ...string) openssl.Detection {
	return openssl.Detection{
		Lib: lib, Path: path, Fork: fork, Version: ver,
		BindingMode: "dynamic", DetectionMethod: "runtime-introspection+symbol-analysis",
		AppKeys: apps,
	}
}

// TD-OPENSSL-5 — 탐지 결과를 결과물로 조립하는 자리. 여기가 비면 collector가 무엇을 봤든
// 코어에 아무것도 도달하지 않는다.
func TestBuildResult(t *testing.T) {
	res := openssl.BuildResult("cmdb://web-01", []openssl.Detection{
		det("libcrypto", "/usr/lib/libcrypto.so.3", "OpenSSL", "3.0.13", "/opt/apps/pay"),
	})
	env := res.GetEnvelope()
	if env.GetTargetNodeId() != "cmdb://web-01" || env.GetCollectorId() != "openssl-collector" {
		t.Errorf("Envelope anchor and collector id: %+v", env)
	}
	if env.GetDetectionMethod() != commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION {
		t.Errorf("detection_method = %v", env.GetDetectionMethod())
	}
	// 원본은 형식 이름만 있고 내용이 비면 "재정규화 가능"이 거짓말이 된다(§1.2).
	if res.GetRawFormat() == "" || len(res.GetRawCapture()) == 0 {
		t.Errorf("raw_format=%q raw_capture=%dB — a format with no raw capture behind it",
			res.GetRawFormat(), len(res.GetRawCapture()))
	}
	body := string(res.GetCbomCyclonedx())
	for _, want := range []string{`"bomFormat":"CycloneDX"`, "libcrypto", "pqcota:crypto_runtime", "/opt/apps/pay"} {
		if !strings.Contains(body, want) {
			t.Errorf("the CycloneDX body does not contain %q:\n%s", want, body)
		}
	}
	if got := res.GetCompleteness().GetLayersCovered(); len(got) != 1 ||
		got[0] != commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS {
		t.Errorf("with detections the PROCESS layer must be covered: %v", got)
	}
	// ARTIFACT는 선언만 하고 덮지 않았으므로 갭으로 남아야 한다 — 갭 ≠ 부재(§2.6).
	if m := res.GetCompleteness().GetLayersMissing(); len(m) != 1 ||
		m[0] != commonv1.CollectionLayer_COLLECTION_LAYER_ARTIFACT {
		t.Errorf("layers that were not covered must remain as gaps: %v", m)
	}
}

// 탐지가 하나도 없을 때가 위험하다 — "없다"로 읽히면 안 되고 "관측하지 못했다"로 남아야 한다.
func TestBuildResultNoDetection(t *testing.T) {
	res := openssl.BuildResult("cmdb://web-01", nil)
	if len(res.GetCbomCyclonedx()) != 0 || len(res.GetRawCapture()) != 0 {
		t.Error("no detections, yet body and raw capture were filled in")
	}
	c := res.GetCompleteness()
	if len(c.GetLayersCovered()) != 0 || len(c.GetLayersMissing()) != 2 || c.GetNote() == "" {
		t.Errorf("no detection must mean every layer is a gap plus a stated reason: %+v", c)
	}
}

// raw_capture는 서명이 덮는 값이라(§2.6) 같은 관측이면 같은 바이트여야 한다.
func TestRawCaptureRoundTripsAndIsStable(t *testing.T) {
	dets := []openssl.Detection{
		det("libssl", "/usr/lib/libssl.so.3", "OpenSSL", "3.0.13"),
		det("libcrypto", "/usr/lib/libcrypto.so.3", "AWS-LC", ""),
	}
	a, b := openssl.RawCapture(dets), openssl.RawCapture(dets)
	if string(a) != string(b) {
		t.Errorf("the same observation produced different bytes:\n%s\n%s", a, b)
	}
	var back []openssl.Detection
	if err := json.Unmarshal(a, &back); err != nil {
		t.Fatalf("the raw capture cannot be read back: %v", err)
	}
	if len(back) != 2 || back[1].Fork != "AWS-LC" || back[0].Path != "/usr/lib/libssl.so.3" {
		t.Errorf("the detections were not restored from the raw capture: %+v", back)
	}
	if openssl.RawCapture(nil) != nil {
		t.Error("with no detections there must be no raw capture either (no invented empty array)")
	}
}
