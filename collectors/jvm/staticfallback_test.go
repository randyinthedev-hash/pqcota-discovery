// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package jvm_test

import (
	"testing"

	"github.com/randyinthedev-hash/pqcota-discovery/collectors/jvm"
)

// java.security 파싱 — 정적 등록 provider를 **N 순서대로**. 순서가 곧 우선순위라(수용 원칙 §2.2)
// 파일에 적힌 줄 순서가 아니라 숫자 순이 맞다.
func TestParseJavaSecurity(t *testing.T) {
	// 일부러 줄 순서를 뒤섞고, 주석·빈 줄·인자 붙은 값·무관한 키를 섞는다.
	content := `# excerpt from a standard JDK java.security
security.provider.3=SunEC
security.provider.1=SUN

security.provider.2=SunRsaSign
# the entries below carry arguments
security.provider.4=SunPKCS11 ${java.home}/conf/security/pkcs11.cfg
securerandom.source=file:/dev/random
security.provider.5=
`
	c := jvm.ParseJavaSecurity(content)
	if !c.Degraded {
		t.Error("the static path must always be degraded (dynamic registration is a blind spot)")
	}
	want := []string{"SUN", "SunRsaSign", "SunEC", "SunPKCS11"}
	if len(c.Providers) != len(want) {
		t.Fatalf("%d providers, want %d: %+v", len(c.Providers), len(want), c.Providers)
	}
	for i, w := range want {
		if c.Providers[i].Name != w {
			t.Errorf("[%d] = %q, want %q (must follow the N order)", i, c.Providers[i].Name, w)
		}
		if c.Providers[i].Order != i+1 {
			t.Errorf("[%d] Order = %d, want %d", i, c.Providers[i].Order, i+1)
		}
	}
}

// 빈 파일·provider 없음도 오류가 아니다 — 빈 목록 + 강등이 정직한 관측이다(§2.5).
func TestParseJavaSecurityEmpty(t *testing.T) {
	c := jvm.ParseJavaSecurity("# comments only\nsecurerandom.source=file:/dev/random\n")
	if len(c.Providers) != 0 {
		t.Errorf("there must be no providers: %+v", c.Providers)
	}
	if !c.Degraded {
		t.Error("even an empty result must stay marked degraded — not 'there are none' but 'this path cannot observe them'")
	}
}

// JAVA_HOME을 못 짚었으면 파일 위치를 모른다 — 지어내지 않고 오류 + 강등으로 돌려준다.
func TestStaticFallbackNoJavaHome(t *testing.T) {
	c, err := jvm.StaticFallbackGo(1, "")
	if err == nil {
		t.Error("an unknown JAVA_HOME must be an error")
	}
	if !c.Degraded {
		t.Error("even on failure the degraded mark must be there (no silent zero)")
	}
}
