// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package jvm_test

import (
	"bytes"
	"strings"
	"testing"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/jvm"
	"google.golang.org/protobuf/encoding/protojson"
)

// 한 줄 모드는 결과마다 정확히 한 줄이다. v0.10.6까지는 Indent 때문에 결과마다 여러 줄이 됐다.
func TestEncodeResultsOneLinePerResult(t *testing.T) {
	results := []*discoveryv1.CollectionResult{
		jvm.BuildResultFor("pay-app", jvm.ParseProviders(attachOutput), "/opt/a/app.jar"),
		jvm.BuildResultFor("pay-app", jvm.ParseProviders(attachOutput), "/opt/b/app.jar"),
	}
	var buf bytes.Buffer
	if err := jvm.EncodeResults(&buf, results, true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("한 줄 모드의 끝에 줄바꿈이 없다: %q", out[max(0, len(out)-20):])
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(results) {
		t.Fatalf("결과 %d개가 %d줄이 됐다(한 줄에 하나여야 한다)", len(results), len(lines))
	}
	for i, l := range lines {
		r := &discoveryv1.CollectionResult{}
		if err := protojson.Unmarshal([]byte(l), r); err != nil {
			t.Errorf("%d번째 줄이 결과 하나로 읽히지 않는다: %v", i+1, err)
		}
	}
}

// 단일 모드는 사람이 읽는 들여쓴 객체 하나다. 한 줄 모드를 고치면서 바뀌지 않았다.
func TestEncodeResultsSingleIsIndented(t *testing.T) {
	res := jvm.BuildResult("pay-app", jvm.ParseProviders(attachOutput))
	var buf bytes.Buffer
	if err := jvm.EncodeResults(&buf, []*discoveryv1.CollectionResult{res}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\n  \"envelope\"") {
		t.Errorf("단일 모드가 들여쓴 객체가 아니다: %.80q", buf.String())
	}
	if err := protojson.Unmarshal(buf.Bytes(), &discoveryv1.CollectionResult{}); err != nil {
		t.Errorf("단일 모드의 출력이 객체 하나로 읽히지 않는다: %v", err)
	}
}
