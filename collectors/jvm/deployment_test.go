// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package jvm_test

import (
	"encoding/json"
	"errors"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/jvm"
)

// JCA 식별 1단계(v0.12.0): 배포본 키와 설정 변형.

func cmd(args ...string) string {
	return strings.Join(append([]string{"/opt/jdk/bin/java"}, args...), "\x00") + "\x00"
}

func TestDeploymentKeySystemdService(t *testing.T) {
	for _, c := range []struct {
		cgroup, key, kind string
	}{
		{"0::/system.slice/payment.service\n", "payment.service", jvm.KindSystemdUnit},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service\n", "user@1000.service/foo.service", jvm.KindSystemdUserUnit},
		{"0::/user.slice/user-1001.slice/user@1001.service/app.slice/foo.service\n", "user@1001.service/foo.service", jvm.KindSystemdUserUnit},
		{"0::/user.slice/user-1000.slice/user@1000.service/session.slice/dbus.service\n", "user@1000.service/dbus.service", jvm.KindSystemdUserUnit},
		// v1 계층: 여러 줄 가운데 서비스가 있는 줄
		{"12:pids:/system.slice/payment.service\n1:name=systemd:/system.slice/payment.service\n", "payment.service", jvm.KindSystemdUnit},
	} {
		key, kind := jvm.DeploymentKey(jvm.JVMProc{Cgroup: c.cgroup, Cmdline: cmd("-jar", "/opt/a/app.jar")})
		if key != c.key || kind != c.kind {
			t.Errorf("%q → %q %q, want %q %q", c.cgroup, key, kind, c.key, c.kind)
		}
	}
	// 서비스가 아닌 것은 후보가 아니다. 다음 키(-jar 절대 경로)로 내려간다.
	for _, cg := range []string{
		"0::/user.slice/user-1000.slice/session-3.scope\n",
		"0::/system.slice/docker-bdc21106e4133de4.scope\n",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-x-3488.scope\n",
		"0::/user.slice/user-1000.slice/user@1000.service\n",
		"0::/\n",
		"",
	} {
		key, kind := jvm.DeploymentKey(jvm.JVMProc{Cgroup: cg, Cmdline: cmd("-jar", "/opt/a/app.jar")})
		if kind != jvm.KindJarPath || key != "/opt/a/app.jar" {
			t.Errorf("%q → %q %q, want the -jar path", cg, key, kind)
		}
	}
}

func TestDeploymentKeyFromTheCommandLine(t *testing.T) {
	full := regexp.MustCompile(`^com\.x\.Main#[0-9a-f]{64}$`)
	for _, c := range []struct {
		name string
		j    jvm.JVMProc
		key  string
		kind string
	}{
		{"-jar 절대 경로", jvm.JVMProc{Cmdline: cmd("-Xmx1g", "-jar", "/opt/a/app.jar", "--port", "8080")}, "/opt/a/app.jar", jvm.KindJarPath},
		{"-jar 상대 경로, cwd 있음", jvm.JVMProc{Cmdline: cmd("-jar", "app.jar"), Cwd: "/srv/b"}, "/srv/b/app.jar", jvm.KindJarPath},
		{"-jar 상대 경로, cwd 없음", jvm.JVMProc{Cmdline: cmd("-jar", "lib/app.jar")}, "app.jar", jvm.KindJarName},
		{"모듈", jvm.JVMProc{Cmdline: cmd("-p", "/m", "-m", "com.x/com.x.Main")}, "com.x", jvm.KindModule},
		{"main 클래스, classpath 없음", jvm.JVMProc{Cmdline: cmd("com.x.Main")}, "com.x.Main", jvm.KindMainClass},
		{"소스 파일", jvm.JVMProc{Cmdline: cmd("--class-path", "/opt/bcprov.jar", "/opt/CryptoApp.java")}, "/opt/CryptoApp.java", jvm.KindSourceFile},
		{"명령줄 없음(Windows)", jvm.JVMProc{JavaHome: `C:\jdk21`}, `C:\jdk21`, jvm.KindJavaHome},
		{"JAVA_HOME도 없음", jvm.JVMProc{Exe: "/usr/bin/java"}, "/usr/bin/java", jvm.KindExePath},
	} {
		key, kind := jvm.DeploymentKey(c.j)
		if key != c.key || kind != c.kind {
			t.Errorf("%s: %q %q, want %q %q", c.name, key, kind, c.key, c.kind)
		}
	}
	// main 클래스 + classpath: 키에 **전체** SHA-256을 싣는다(표시용으로 줄이지 않는다). 순서가 다르면 다른 배포본이다.
	a, kind := jvm.DeploymentKey(jvm.JVMProc{Cmdline: cmd("-cp", "/l/a.jar:/l/b.jar", "com.x.Main")})
	b, _ := jvm.DeploymentKey(jvm.JVMProc{Cmdline: cmd("-cp", "/l/b.jar:/l/a.jar", "com.x.Main")})
	if kind != jvm.KindMainClass || !full.MatchString(a) || !full.MatchString(b) || a == b {
		t.Errorf("classpath keys: %q %q (%s)", a, b, kind)
	}
	// 상대 classpath는 cwd로 푼다. cwd가 다르면 다른 배포본이다.
	c1, _ := jvm.DeploymentKey(jvm.JVMProc{Cmdline: cmd("-cp", "lib/a.jar", "com.x.Main"), Cwd: "/srv/1"})
	c2, _ := jvm.DeploymentKey(jvm.JVMProc{Cmdline: cmd("-cp", "lib/a.jar", "com.x.Main"), Cwd: "/srv/2"})
	if c1 == c2 {
		t.Error("relative classpaths under different working directories got one key")
	}
}

// 같은 키 값이라도 종류가 다르면 다른 배포본이다: `-jar foo.service`(cwd 못 풂)와 systemd의 foo.service.
func TestDeploymentKindSeparatesTheSameKeyValue(t *testing.T) {
	jar := jvm.JVMProc{Cmdline: cmd("-jar", "foo.service")}
	unit := jvm.JVMProc{Cgroup: "0::/system.slice/foo.service\n", Cmdline: cmd("com.y.Main")}
	ds := jvm.GroupDeployments([]jvm.Member{{JVM: jar, Collected: &jvm.Collected{}}, {JVM: unit, Collected: &jvm.Collected{}}})
	if len(ds) != 2 || ds[0].Key != "foo.service" || ds[1].Key != "foo.service" || ds[0].Kind == ds[1].Kind {
		t.Fatalf("deployments = %+v", ds)
	}
	// cwd를 못 푼 같은 파일 이름은 한 배포본이다(jar-name의 한계). 버려지지는 않는다.
	ds = jvm.GroupDeployments([]jvm.Member{
		{JVM: jvm.JVMProc{Cmdline: cmd("-jar", "a/app.jar")}, Collected: &jvm.Collected{}},
		{JVM: jvm.JVMProc{Cmdline: cmd("-jar", "b/app.jar")}, Collected: &jvm.Collected{}},
	})
	if len(ds) != 1 || ds[0].Kind != jvm.KindJarName || len(ds[0].Members) != 2 {
		t.Fatalf("jar-name deployments = %+v", ds)
	}
}

func collected(degraded bool, names ...string) *jvm.Collected {
	c := &jvm.Collected{Degraded: degraded, Raw: "raw:" + strings.Join(names, ",")}
	for i, n := range names {
		p := jvm.Provider{Order: i + 1, Name: n}
		if !degraded {
			p.ServicesSeen = true
			if n == "BC" {
				p.PQCServices = []string{"ML-DSA-65", "ML-KEM-768", "SLH-DSA-SHA2-128S"}
			}
		}
		c.Providers = append(c.Providers, p)
	}
	return c
}

// 수집기 시험은 정규화를 부르지 않는다(collector 영역은 다른 단계 코드를 import하지 않는다, checkdeps R5).
// 정규화까지 잇는 시험은 pqcota/test/crossstage에 있다.
type propInstance struct {
	VariantKey    string   `json:"variantKey"`
	ChainObserved bool     `json:"chainObserved"`
	ProviderSet   []string `json:"providerSet"`
	ModeCounts    []struct {
		Mode  string `json:"mode"`
		Count uint32 `json:"count"`
	} `json:"modeCounts"`
	Count uint32 `json:"count"`
}

func propsOf(t *testing.T, r *discoveryv1.CollectionResult) (string, map[string]string) {
	t.Helper()
	var doc struct {
		Components []struct {
			Name       string                         `json:"name"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(r.GetCbomCyclonedx(), &doc); err != nil || len(doc.Components) != 1 {
		t.Fatalf("cbom: %v %s", err, r.GetCbomCyclonedx())
	}
	m := map[string]string{}
	for _, p := range doc.Components[0].Properties {
		m[p.Name] = p.Value
	}
	return doc.Components[0].Name, m
}

func instancesOf(t *testing.T, r *discoveryv1.CollectionResult) []propInstance {
	t.Helper()
	_, m := propsOf(t, r)
	var out []propInstance
	if err := json.Unmarshal([]byte(m["pqcota:jca.instances"]), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func instanceKeys(t *testing.T, m jvm.Member) string {
	t.Helper()
	return instancesOf(t, jvm.BuildDeploymentResult("n", jvm.Deployment{Key: "k", Kind: jvm.KindJarPath, Members: []jvm.Member{m}}))[0].VariantKey
}

// 변형 키: 세 입력을 구조로 직렬화한다. 덮어쓰기와 덧붙이기, 설정 없음과 빈 값이 모두 다르고, 구분자가 값 안에
// 있어도 경계가 옮겨지지 않는다.
func TestVariantKeyInputs(t *testing.T) {
	mk := func(home string, args ...string) jvm.Member {
		return jvm.Member{JVM: jvm.JVMProc{JavaHome: home, Cmdline: cmd(append(args, "-jar", "/opt/a/app.jar")...)}, Collected: collected(false, "SUN")}
	}
	keys := map[string]string{
		"설정 없음":  instanceKeys(t, mk("/jdk")),
		"빈 값":    instanceKeys(t, mk("/jdk", "-Djava.security.properties=")),
		"덧붙이기":   instanceKeys(t, mk("/jdk", "-Djava.security.properties=/etc/x")),
		"덮어쓰기":   instanceKeys(t, mk("/jdk", "-Djava.security.properties==/etc/x")),
		"경계 짝 1": instanceKeys(t, mk("/jdk|x", "-Djava.security.properties=y")),
		"경계 짝 2": instanceKeys(t, mk("/jdk", "-Djava.security.properties=x|y")),
	}
	seen := map[string]string{}
	for name, k := range keys {
		if other, ok := seen[k]; ok {
			t.Errorf("%s and %s got one variant key", name, other)
		}
		seen[k] = name
		if len(k) != 64 {
			t.Errorf("%s: variant key %q is not a full SHA-256", name, k)
		}
	}
}

// 수집기 → 정규화: 런타임 관측과 정적 폴백이 같은 체인을 보고하고, 같은 배포본의 다른 JVM 하나는 체인을 얻지 못했다.
//   - 관측한 둘은 한 변형으로 묶이고 두 모드의 수가 각각 남는다.
//   - 못 본 JVM은 따로 변형으로 남는다.
//   - finding의 provider_set은 비어 있다.
//
// 입력 순서를 바꿔도 결과가 바이트까지 같다.
func TestDeploymentWithStaticRuntimeAndUnobservedJVMs(t *testing.T) {
	j := jvm.JVMProc{JavaHome: "/opt/jdk", Cmdline: cmd("-jar", "/opt/pay/app.jar")}
	members := []jvm.Member{
		{JVM: j, Collected: collected(false, "SUN", "SunRsaSign", "BC")},
		{JVM: j, Collected: collected(true, "SUN", "SunRsaSign", "BC")},
		{JVM: j, Err: errors.New("attach refused")},
	}
	ds := jvm.GroupDeployments(members)
	if len(ds) != 1 {
		t.Fatalf("%d deployments, want 1", len(ds))
	}
	r := jvm.BuildDeploymentResult("pay", ds[0])
	if !strings.Contains(string(r.GetCbomCyclonedx()), `"jca-provider-chain@/opt/pay/app.jar"`) {
		t.Errorf("the component name does not carry the full key: %s", r.GetCbomCyclonedx())
	}
	_, props := propsOf(t, r)
	if _, ok := props["pqcota:jca.provider_set"]; ok {
		t.Errorf("provider_set is set although one JVM was not observed: %q", props["pqcota:jca.provider_set"])
	}
	if props["pqcota:jca.app_key_kind"] != jvm.KindJarPath {
		t.Errorf("kind = %q", props["pqcota:jca.app_key_kind"])
	}
	insts := instancesOf(t, r)
	if len(insts) != 2 {
		t.Fatalf("%d instances, want 2", len(insts))
	}
	var observed, unobserved int
	for _, in := range insts {
		modes := map[string]uint32{}
		for _, mc := range in.ModeCounts {
			modes[mc.Mode] = mc.Count
		}
		if in.ChainObserved {
			observed++
			if in.Count != 2 || modes["static"] != 1 || modes["dynamic"] != 1 || strings.Join(in.ProviderSet, ",") != "SUN,SunRsaSign,BC" {
				t.Errorf("observed variant: count %d modes %v chain %v", in.Count, modes, in.ProviderSet)
			}
		} else {
			unobserved++
			if in.Count != 1 || len(in.ProviderSet) != 0 || modes[""] != 1 {
				t.Errorf("unobserved variant: count %d chain %v modes %v", in.Count, in.ProviderSet, modes)
			}
		}
	}
	if observed != 1 || unobserved != 1 {
		t.Errorf("observed %d unobserved %d, want 1 1", observed, unobserved)
	}

	want := string(r.GetCbomCyclonedx()) + string(r.GetRawCapture()) + r.GetCompleteness().GetNote()
	rnd := rand.New(rand.NewSource(3))
	for i := 0; i < 20; i++ {
		ms := append([]jvm.Member(nil), members...)
		rnd.Shuffle(len(ms), func(a, b int) { ms[a], ms[b] = ms[b], ms[a] })
		got := jvm.BuildDeploymentResult("pay", jvm.GroupDeployments(ms)[0])
		if string(got.GetCbomCyclonedx())+string(got.GetRawCapture())+got.GetCompleteness().GetNote() != want {
			t.Fatal("the result depends on the order the JVMs were found in")
		}
	}
}

// 배포본의 JVM을 하나도 관측하지 못했으면 지금처럼 갭 결과다(finding 없음).
func TestDeploymentAllUnobservedIsAGap(t *testing.T) {
	j := jvm.JVMProc{Cmdline: cmd("-jar", "/opt/pay/app.jar")}
	r := jvm.BuildDeploymentResult("pay", jvm.GroupDeployments([]jvm.Member{{JVM: j, Err: errors.New("a")}, {JVM: j, Err: errors.New("b")}})[0])
	if len(r.GetCbomCyclonedx()) != 0 || !strings.Contains(r.GetCompleteness().GetNote(), "2 JVM(s)") {
		t.Fatalf("cbom %q note %q", r.GetCbomCyclonedx(), r.GetCompleteness().GetNote())
	}
}

// 프로브 경로는 실행 중 앱이 아니다. 배포본과 섞지 않는다.
func TestLauncherDefaultIsNotADeployment(t *testing.T) {
	r := jvm.BuildLauncherDefaultResult("n", "/opt/jdk", *collected(true, "SUN"))
	name, props := propsOf(t, r)
	if name != "jca-launcher-default@/opt/jdk" || props["pqcota:jca.app_key_kind"] != jvm.KindLauncherDefault {
		t.Errorf("probe result: %s %v", name, props)
	}
}

// --pid로 하나만 관측했으면 관측 범위를 표시하고, 같은 배포본의 다른 JVM을 체인 없는 변형으로 남긴다.
func TestSelectPIDKeepsTheOtherJVMs(t *testing.T) {
	svc := "0::/system.slice/pay.service\n"
	j1 := jvm.JVMProc{PID: 101, Cgroup: svc, Cmdline: cmd("-jar", "/opt/pay/app.jar")}
	j2 := jvm.JVMProc{PID: 102, Cgroup: svc, Cmdline: cmd("-jar", "/opt/pay/app.jar")}
	other := jvm.JVMProc{PID: 103, Cmdline: cmd("-jar", "/opt/other.jar")}
	d := jvm.SelectPID(jvm.GroupDeployments([]jvm.Member{{JVM: j1, Collected: collected(false, "SUN", "BC")}})[0], []jvm.JVMProc{j1, j2, other}, 101)
	r := jvm.BuildDeploymentResult("n", d)
	_, props := propsOf(t, r)
	if props["pqcota:jca.observation_scope"] != jvm.ScopeSelectedPID {
		t.Errorf("scope = %q", props["pqcota:jca.observation_scope"])
	}
	if _, ok := props["pqcota:jca.provider_set"]; ok {
		t.Error("provider_set is set although only the selected JVM was observed")
	}
	var total, unobserved uint32
	for _, in := range instancesOf(t, r) {
		total += in.Count
		if !in.ChainObserved {
			unobserved += in.Count
		}
	}
	if total != 2 || unobserved != 1 {
		t.Errorf("%d JVMs (%d unobserved), want 2 (1) — the other service's JVM must not be counted", total, unobserved)
	}
	if !strings.Contains(r.GetCompleteness().GetNote(), "--pid") {
		t.Errorf("note = %q", r.GetCompleteness().GetNote())
	}
}
