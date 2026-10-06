// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package jvm_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/randyinthedev-hash/pqcota-discovery/collectors/jvm"
)

// TD-JVM-6 — 정찰→attach 오케스트레이션. 실 JVM·agent 없이 attach를 주입해 검증한다.
// 실패한 JVM은 표시 없이 버리지 않고 갭으로 세어야 한다(§2.6).
func TestAttachAll(t *testing.T) {
	jvms := []jvm.JVMProc{
		{PID: 10, JavaHome: "/opt/jdk17"},
		{PID: 20, JavaHome: "/opt/jdk8"}, // 이 JVM은 attach 실패로 만든다
		{PID: 30, JavaHome: "/opt/jdk21"},
	}
	attach := func(j jvm.JVMProc) (jvm.Collected, error) {
		if j.PID == 20 {
			return jvm.Collected{}, errors.New("attach blocked (DisableAttachMechanism)")
		}
		return jvm.Collected{Providers: []jvm.Provider{{Order: 1, Name: "SUN"}, {Order: 2, Name: "BC"}}}, nil
	}

	results, st := jvm.AttachAll(jvms, attach)
	if st.Discovered != 3 || st.Attached != 2 || st.Failed != 1 {
		t.Fatalf("stats = %+v, want discovered 3 · attached 2 · failed 1", st)
	}
	if len(results) != 3 {
		t.Fatalf("one result per JVM found (3, failures included): %d", len(results))
	}
	// 실패한 JVM도 결과에 남아야 한다(갭으로 보고할 근거) — 표시 없이 사라지면 안 됨.
	var sawFail bool
	for _, r := range results {
		if r.JVM.PID == 20 {
			sawFail = true
			if r.Err == nil {
				t.Error("a JVM that failed to attach must carry Err")
			}
		}
	}
	if !sawFail {
		t.Error("the failed JVM vanished from the results — the gap is hidden")
	}
}

func TestAttachAllEmpty(t *testing.T) {
	results, st := jvm.AttachAll(nil, func(jvm.JVMProc) (jvm.Collected, error) { return jvm.Collected{}, nil })
	if len(results) != 0 || st.Discovered != 0 {
		t.Errorf("empty input gives an empty result: %+v %+v", results, st)
	}
}

// TD-JVM-7 — 다중 JVM 구별. 서로 다른 JDK는 서로 다른 finding으로 잡혀야 한다(하나로 안 뭉개짐).
// finding id는 컴포넌트명을 포함하므로, ident(JAVA_HOME)를 컴포넌트명에 실어 구별한다.
func TestBuildResultForDistinguishesJVMs(t *testing.T) {
	c := jvm.Collected{Providers: []jvm.Provider{{Order: 1, Name: "SUN"}, {Order: 2, Name: "BC"}}}
	a := string(jvm.BuildResultFor("node-app", c, "/opt/jdk17").GetCbomCyclonedx())
	b := string(jvm.BuildResultFor("node-app", c, "/opt/jdk8").GetCbomCyclonedx())

	if a == b {
		t.Fatal("different JDKs but identical CBOMs — the findings get merged into one")
	}
	for _, want := range []string{"jca-provider-chain@/opt/jdk17", "pqcota:app_keys", "/opt/jdk17"} {
		if !strings.Contains(a, want) {
			t.Errorf("the JDK17 result does not contain %q:\n%s", want, a)
		}
	}
	// ident 없으면 기존 단일 형태 그대로(하위호환) — @·app_keys 미부착.
	single := string(jvm.BuildResult("node-app", c).GetCbomCyclonedx())
	if strings.Contains(single, "@") || strings.Contains(single, "app_keys") {
		t.Errorf("a discriminator was added to a single result with no ident:\n%s", single)
	}
}

// ident에 PID를 쓰면 이력이 매번 새 자산으로 깨진다 — JAVA_HOME(안정)을 쓰는지 회귀로 못 박는다.
// (정책: BuildResultFor 호출자는 PID가 아니라 안정 식별자를 넘겨야 한다. 여기선 계약을 문서화·고정.)
func TestBuildResultForIdentIsStable(t *testing.T) {
	c := jvm.Collected{Providers: []jvm.Provider{{Order: 1, Name: "SUN"}}}
	// 같은 JAVA_HOME이면 PID가 달라도 같은 결과여야 한다(재스캔 안정성).
	r1 := string(jvm.BuildResultFor("n", c, "/opt/jdk17").GetCbomCyclonedx())
	r2 := string(jvm.BuildResultFor("n", c, "/opt/jdk17").GetCbomCyclonedx())
	if r1 != r2 {
		t.Error("the same identifier must give a deterministic result (stable history)")
	}
}

// attach 클라이언트는 대상의 java일 필요가 없다 — 머신의 attach 가능 JDK를 재사용한다.
// (이게 성립하므로 collector가 자체 런타임을 동봉할 이유가 없다.)
func TestAttachClient(t *testing.T) {
	// 대상은 JRE(attach 불가)인데 같은 머신에 JDK가 있다 → 그 JDK를 클라이언트로.
	mixed := []jvm.JVMProc{
		{PID: 1, JavaBin: "/opt/jre/bin/java", AttachCapable: false},
		{PID: 2, JavaBin: "/opt/jdk21/bin/java", AttachCapable: true},
	}
	if got := jvm.AttachClient(mixed); got != "/opt/jdk21/bin/java" {
		t.Errorf("a JDK that can attach must be chosen: %q", got)
	}
	// 하나도 없으면 "" — 별도 런타임을 지어내지 않고 정적 폴백으로 내려간다(§2.5).
	jreOnly := []jvm.JVMProc{{PID: 1, JavaBin: "/opt/jre/bin/java", AttachCapable: false}}
	if got := jvm.AttachClient(jreOnly); got != "" {
		t.Errorf("with no attach-capable JDK it must be empty: %q", got)
	}
	if got := jvm.AttachClient(nil); got != "" {
		t.Errorf("with no JVM it must be empty: %q", got)
	}
}

// 갭 노트는 어느 JVM 이야기인지 밝혀야 한다. 노드에 JVM이 여럿이면 노트가 노드 하나로
// 합쳐져 나오는데, 그때 이름이 없으면 **노드 전체가 attach 불가로 읽힌다** — 실측에서
// attach가 성공한 행 바로 아래에 "attach unavailable"이 붙었다.
func TestDegradedNoteNamesTheJVM(t *testing.T) {
	degraded := jvm.Collected{Degraded: true}
	note := jvm.BuildResultFor("n", degraded, "/opt/jdk17").GetCompleteness().GetNote()
	if !strings.Contains(note, "/opt/jdk17") {
		t.Errorf("the note does not say which JVM it is about: %q", note)
	}
	if !strings.Contains(note, "attach unavailable") {
		t.Errorf("the reason disappeared from the note: %q", note)
	}
	// JVM이 하나뿐이면 붙일 이름이 없다 — 사유만 남는다.
	if n := jvm.BuildResultFor("n", degraded, "").GetCompleteness().GetNote(); !strings.HasPrefix(n, "attach unavailable") {
		t.Errorf("a single JVM must keep the plain note: %q", n)
	}
	// attach가 됐으면 노트가 없다 — 없는 갭을 지어내지 않는다.
	if n := jvm.BuildResultFor("n", jvm.Collected{}, "/opt/jdk17").GetCompleteness().GetNote(); n != "" {
		t.Errorf("a successful attach must leave no note: %q", n)
	}
}

// 강등 사유가 하나뿐인 것처럼 적히면 안 된다. attach가 막혀 대상의 java.security를 읽은 것과,
// 도는 JVM이 없어 도구가 java를 띄워 본 것은 읽는 사람에게 전혀 다른 이야기다.
func TestDegradedNoteCarriesItsOwnReason(t *testing.T) {
	own := jvm.Collected{Degraded: true, Note: "no JVM was running — the launcher was started for this probe"}
	n := jvm.BuildResultFor("n", own, "").GetCompleteness().GetNote()
	if n != own.Note {
		t.Errorf("the given reason was replaced: %q", n)
	}
	// 사유를 안 주면 attach 폴백의 기본 사유가 쓰인다.
	if n := jvm.BuildResultFor("n", jvm.Collected{Degraded: true}, "").GetCompleteness().GetNote(); !strings.HasPrefix(n, "attach unavailable") {
		t.Errorf("the default reason disappeared: %q", n)
	}
}

// 찾았는데 관측하지 못한 JVM은 **계약에 실려 중앙까지 가야 한다.** 결과를 안 내면 실패가
// stderr에만 남고 중앙은 그런 JVM이 있었다는 것조차 모른다 — 갭이 부재와 같은 얼굴이 된다.
func TestGapResultCarriesTheJVMToTheCentre(t *testing.T) {
	r := jvm.GapResult("node-a", "/opt/jdk21", "a JVM was found but could not be observed: jvm.dll not loaded")
	c := r.GetCompleteness()
	if len(c.GetLayersMissing()) != 1 {
		t.Fatalf("the JVM layer must be marked missing: %+v", c.GetLayersMissing())
	}
	if !strings.Contains(c.GetNote(), "/opt/jdk21") || !strings.Contains(c.GetNote(), "jvm.dll") {
		t.Errorf("the note must say which JVM and why: %q", c.GetNote())
	}
	// **컴포넌트를 만들지 않는다** — 빈 provider 체인은 "이 JVM엔 provider가 없다"로 읽힌다.
	if len(r.GetCbomCyclonedx()) > 0 {
		t.Errorf("a gap must not carry a CBOM body: %s", r.GetCbomCyclonedx())
	}
}
