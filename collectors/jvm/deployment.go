// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// JCA 식별 1단계(v0.12.0). 수집기가 발견한 JVM을 **배포본**으로 묶고, 그 안의 JVM을 **설정 변형**으로 센다.
// 결과는 배포본마다 하나다. 관측하지 못한 JVM도 변형으로 남긴다(체인 없음) — 정규화에서 묶으면 attach에
// 실패한 JVM이 배포본에 들어오지 못한다(그 JVM은 finding 없이 갭으로만 나갔다).
//
// 순수 함수다. /proc 읽기는 procscan.go에 있다.

// Kind — 배포본 키를 무엇으로 골랐나(계약의 JcaAxes.app_key_kind).
const (
	KindSystemdUnit     = "systemd-unit"
	KindSystemdUserUnit = "systemd-user-unit"
	KindJarPath         = "jar-path"
	KindJarName         = "jar-name" // 약한 키: cwd를 못 풀어 파일 이름만 남았다
	KindModule          = "module"
	KindMainClass       = "main-class"
	KindSourceFile      = "source-file"
	KindJavaHome        = "java-home" // 약한 키: JDK 하나에 앱이 여럿일 수 있다
	KindExePath         = "exe-path"  // 약한 키: JAVA_HOME도 못 짚었다
	KindLauncherDefault = "launcher-default"
)

// systemdServiceKey — cgroup 텍스트에서 systemd **서비스**를 찾는다(결정 A).
//   - 경로 마디 가운데 `.service`로 끝나는 **마지막** 것을 쓴다.
//   - `user@<uid>.service`(사용자 관리자)는 후보가 아니다. 그 아래의 서비스가 실제 앱이다.
//   - `.scope`(session-N, docker-<id>, app-…-<pid>)는 쓰지 않는다.
//   - 사용자 관리자 아래의 서비스면 키는 `user@<uid>.service/<유닛>`이다. 이름 `foo.service`는 사용자마다의
//     관리자 아래에 따로 있을 수 있어, 이름만 쓰면 한 노드에서 다시 합쳐진다.
//
// procs.systemdUnit(OpenSSL·엣지)은 처음 나오는 `.service`·`.scope`를 고른다. 그쪽은 2단계에서 고친다.
func systemdServiceKey(cgroup string) (key, kind string) {
	for _, line := range strings.Split(cgroup, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path := line
		if i := strings.LastIndex(line, ":"); i >= 0 { // "0::/a/b" · "1:name=systemd:/a/b"
			path = line[i+1:]
		}
		manager, unit := "", ""
		for _, seg := range strings.Split(path, "/") {
			switch {
			case strings.HasPrefix(seg, "user@") && strings.HasSuffix(seg, ".service"):
				manager, unit = seg, "" // 관리자 아래에서 다시 찾는다
			case strings.HasSuffix(seg, ".service"):
				unit = seg
			}
		}
		if unit == "" {
			continue
		}
		if manager != "" {
			return manager + "/" + unit, KindSystemdUserUnit
		}
		return unit, KindSystemdUnit
	}
	return "", ""
}

// launch — 명령줄에서 읽은 JVM 옵션과 실행 대상. 실행 대상 뒤의 인자는 앱의 것이라 보지 않는다.
type launch struct {
	jar, module, mainClass, sourceFile string
	classpath                          []string
	secPropsSet                        bool
	secProps                           string
}

// parseLaunch — NUL로 끊긴 cmdline에서. 문법은 parseMainId와 같은 최소 범위다.
func parseLaunch(cmdline string) launch {
	var l launch
	args := strings.Split(strings.Trim(cmdline, "\x00"), "\x00")
	for i := 1; i < len(args); i++ { // argv[0]=java 런처
		a := args[i]
		switch a {
		case "-jar":
			if i+1 < len(args) {
				l.jar = args[i+1]
			}
			return l
		case "-m", "--module":
			if i+1 < len(args) {
				l.module, _, _ = strings.Cut(args[i+1], "/")
			}
			return l
		case "-cp", "-classpath", "--class-path":
			if i+1 < len(args) {
				l.classpath = strings.Split(args[i+1], ":")
				i++
			}
			continue
		case "-p", "--module-path":
			i++
			continue
		}
		// 같은 속성을 여러 번 주면 JVM은 마지막 것을 쓴다.
		if v, ok := strings.CutPrefix(a, "-Djava.security.properties"); ok {
			if v == "" || strings.HasPrefix(v, "=") {
				l.secPropsSet, l.secProps = true, strings.TrimPrefix(v, "=") // "==x"(덮어쓰기)는 "=x"로 남는다
			}
			continue
		}
		if strings.HasPrefix(a, "-") || a == "" {
			continue
		}
		if strings.HasSuffix(a, ".java") {
			l.sourceFile = a
		} else {
			l.mainClass = a
		}
		return l
	}
	return l
}

func absUnder(cwd, p string) (string, bool) {
	if filepath.IsAbs(p) {
		return filepath.Clean(p), true
	}
	if cwd == "" {
		return p, false
	}
	return filepath.Join(cwd, p), true
}

// DeploymentKey — 이 JVM이 속한 배포본의 키와 그 종류(결정 A, 계획 §3). 순서:
// systemd 서비스 → -jar 절대 경로 → 모듈 → main 클래스 + classpath → 소스 파일 → JAVA_HOME → exe.
// **키는 줄이지 않는다.** 코어가 컴포넌트 이름의 키로 finding id를 만든다(계약 README의 app_key_kind).
func DeploymentKey(j JVMProc) (key, kind string) {
	if k, kd := systemdServiceKey(j.Cgroup); k != "" {
		return k, kd
	}
	l := parseLaunch(j.Cmdline)
	switch {
	case l.jar != "":
		if p, ok := absUnder(j.Cwd, l.jar); ok {
			return p, KindJarPath
		}
		// cwd를 못 풀었다. 파일 이름만 남기고 약한 키로 알린다 — 같은 파일 이름의 JVM은 한 배포본으로 묶인다.
		return filepath.Base(l.jar), KindJarName
	case l.module != "":
		return l.module, KindModule
	case l.mainClass != "":
		if len(l.classpath) == 0 {
			return l.mainClass, KindMainClass
		}
		cp := make([]string, 0, len(l.classpath))
		for _, e := range l.classpath { // 순서를 보존한다(앞선 항목이 이긴다)
			p, _ := absUnder(j.Cwd, e)
			cp = append(cp, p)
		}
		return l.mainClass + "#" + sha256Hex(mustJSON(cp)), KindMainClass
	case l.sourceFile != "":
		p, _ := absUnder(j.Cwd, l.sourceFile)
		return p, KindSourceFile
	case j.JavaHome != "":
		return j.JavaHome, KindJavaHome
	default:
		return j.Exe, KindExePath
	}
}

// Member — 배포본 안의 JVM 하나와 그 관측 결과. Collected가 nil이면 체인을 보지 못했다(Err가 사유).
type Member struct {
	JVM       JVMProc
	Collected *Collected
	Err       error
}

// variantInput — 변형 키의 입력(결정 C). 필드 순서가 고정된 구조로 직렬화한다. 체인을 보지 못했으면 null이고,
// 빈 체인(`[]`)과 다른 바이트다.
type variantInput struct {
	JavaHome           string `json:"java_home"`
	SecurityProperties struct {
		Set   bool   `json:"set"`
		Value string `json:"value"`
	} `json:"security_properties"`
	ProviderChain *[]string `json:"provider_chain"`
}

func variantOf(m Member) (key string, in variantInput) {
	l := parseLaunch(m.JVM.Cmdline)
	in.JavaHome = m.JVM.JavaHome
	in.SecurityProperties.Set, in.SecurityProperties.Value = l.secPropsSet, l.secProps
	if m.Collected != nil {
		chain := make([]string, 0, len(m.Collected.Providers))
		for _, p := range m.Collected.Providers {
			chain = append(chain, p.Name)
		}
		in.ProviderChain = &chain
	}
	return sha256Hex(mustJSON(in)), in
}

func modeOf(m Member) string {
	switch {
	case m.Collected == nil:
		return ""
	case m.Collected.Degraded:
		return "static"
	default:
		return "dynamic"
	}
}

// Deployment — 배포본 하나와 그 JVM들.
type Deployment struct {
	Key, Kind string
	Members   []Member
	// Scope — 관측 범위(계약의 JcaAxes.observation_scope). 비면 찾은 JVM 전부, ScopeSelectedPID면 지정한 JVM만.
	Scope string
}

// ScopeSelectedPID — 수집기가 지정한 JVM만 관측했다(pqcota-jvmscan --pid).
const ScopeSelectedPID = "selected-pid"

// errNotSelected — 같은 배포본에서 찾았지만 --pid로 고르지 않아 관측하지 않은 JVM.
type errNotSelected struct{ pid int }

func (e errNotSelected) Error() string {
	return fmt.Sprintf("found in this deployment but not observed: only pid %d was selected (--pid)", e.pid)
}

// SelectPID — 지정한 PID 하나만 관측했을 때의 배포본. 정찰로 찾은 같은 배포본의 다른 JVM을 **체인 없는 변형으로**
// 남기고 관측 범위를 표시한다. 그러지 않으면 여러 JVM이 도는 서비스가 count=1로 보이고, 그 한 JVM의 체인이 배포본
// 전체의 before처럼 기록될 수 있다.
func SelectPID(d Deployment, found []JVMProc, pid int) Deployment {
	d.Scope = ScopeSelectedPID
	for _, j := range found {
		if j.PID == pid {
			continue
		}
		if k, kd := DeploymentKey(j); k == d.Key && kd == d.Kind {
			d.Members = append(d.Members, Member{JVM: j, Err: errNotSelected{pid}})
		}
	}
	return d
}

// GroupDeployments — 멤버를 (종류, 키)로 묶는다. 결과는 (종류, 키) 순이다. 입력 순서와 무관하다.
func GroupDeployments(members []Member) []Deployment {
	idx := map[[2]string]int{}
	var out []Deployment
	for _, m := range members {
		k, kd := DeploymentKey(m.JVM)
		id := [2]string{kd, k}
		i, ok := idx[id]
		if !ok {
			i = len(out)
			idx[id] = i
			out = append(out, Deployment{Key: k, Kind: kd})
		}
		out[i].Members = append(out[i].Members, m)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Kind != out[b].Kind {
			return out[a].Kind < out[b].Kind
		}
		return out[a].Key < out[b].Key
	})
	return out
}

// instanceProp — `pqcota:jca.instances`의 원소(계약 README의 속성 표와 같은 이름).
type instanceProp struct {
	VariantKey         string `json:"variantKey"`
	JavaHome           string `json:"javaHome"`
	SecurityProperties struct {
		Set   bool   `json:"set"`
		Value string `json:"value"`
	} `json:"securityProperties"`
	ChainObserved bool        `json:"chainObserved"`
	ProviderSet   []string    `json:"providerSet,omitempty"`
	PqcServices   string      `json:"pqcServices,omitempty"`
	ModeCounts    []modeCount `json:"modeCounts"`
	Count         uint32      `json:"count"`
}

type modeCount struct {
	Mode  string `json:"mode"`
	Count uint32 `json:"count"`
}

var modeOrder = map[string]int{"": 0, "static": 1, "dynamic": 2, "explicit": 3} // 계약 열거값 순

// servicesOf — 변형의 provider마다 본 PQC 서비스. 같은 변형에 정적 폴백(서비스를 못 봄)과 런타임 관측이 섞이면,
// 본 쪽의 목록을 쓴다. 여럿이 봤으면 합친다. 아무도 못 본 provider는 적지 않는다(「안 봤다」와 「없다」는 다르다).
func servicesOf(ms []Member) string {
	seen := map[string]map[string]bool{}
	var order []string
	for _, m := range ms {
		if m.Collected == nil {
			continue
		}
		for _, p := range m.Collected.Providers {
			if !p.ServicesSeen {
				continue
			}
			if seen[p.Name] == nil {
				seen[p.Name] = map[string]bool{}
				order = append(order, p.Name)
			}
			for _, a := range p.PQCServices {
				seen[p.Name][a] = true
			}
		}
	}
	sort.Strings(order)
	var parts []string
	for _, name := range order {
		var algs []string
		for a := range seen[name] {
			algs = append(algs, a)
		}
		sort.Strings(algs)
		parts = append(parts, name+"="+strings.Join(algs, "|"))
	}
	return strings.Join(parts, ",")
}

// rawMember — 원본(raw_capture)의 한 항목. PID는 넣지 않는다(재시작마다 바뀐다).
type rawMember struct {
	VariantKey string `json:"variant_key"`
	Mode       string `json:"mode"`
	Raw        string `json:"raw,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RawFormatDeployment — 배포본 결과의 raw_capture 형식. 멤버마다 사이드카 원문을 변형 키·모드와 함께 싣는다.
const RawFormatDeployment = "jvm-collector/deployment-v1"

// BuildDeploymentResult — 배포본 하나를 결과 하나로. 멤버를 모두 관측하지 못했으면 지금처럼 갭 결과다
// (finding을 만들지 않는다). 일부만 못 봤으면 finding을 내고 그 JVM을 체인 없는 변형으로 싣는다.
func BuildDeploymentResult(node string, d Deployment) *discoveryv1.CollectionResult {
	return buildDeployment(node, d, "jca-provider-chain@")
}

// BuildLauncherDefaultResult — 도는 JVM을 보지 않고 런처를 띄워 본 체인(프로브 경로). 실행 중 앱이 아니므로
// 배포본과 섞지 않는다: 이름은 `jca-launcher-default@<키>`, 종류는 launcher-default다.
func BuildLauncherDefaultResult(node, key string, c Collected) *discoveryv1.CollectionResult {
	return buildDeployment(node, Deployment{Key: key, Kind: KindLauncherDefault,
		Members: []Member{{JVM: JVMProc{JavaHome: key}, Collected: &c}}}, "jca-launcher-default@")
}

func buildDeployment(node string, d Deployment, prefix string) *discoveryv1.CollectionResult {
	type entry struct {
		key string
		in  variantInput
		m   Member
	}
	var es []entry
	attached, static, unobserved := 0, 0, 0
	var reasons, notes []string
	for _, m := range d.Members {
		k, in := variantOf(m)
		es = append(es, entry{k, in, m})
		switch modeOf(m) {
		case "":
			unobserved++
			if m.Err != nil {
				reasons = append(reasons, m.Err.Error())
			}
		case "static":
			static++
			if m.Collected.Note != "" {
				notes = append(notes, m.Collected.Note)
			}
		default:
			attached++
		}
	}
	if attached+static == 0 {
		sort.Strings(reasons)
		return GapResult(node, d.Key, fmt.Sprintf("%d JVM(s) of this deployment were found but could not be observed: %s",
			len(d.Members), strings.Join(dedup(reasons), "; ")))
	}
	sort.Slice(es, func(a, b int) bool {
		if es[a].key != es[b].key {
			return es[a].key < es[b].key
		}
		return modeOrder[modeOf(es[a].m)] < modeOrder[modeOf(es[b].m)]
	})

	// 변형마다 묶는다.
	var insts []instanceProp
	var raws []rawMember
	for i := 0; i < len(es); {
		j := i
		var group []Member
		counts := map[string]uint32{}
		for ; j < len(es) && es[j].key == es[i].key; j++ {
			group = append(group, es[j].m)
			counts[modeOf(es[j].m)]++
			rm := rawMember{VariantKey: es[j].key, Mode: modeOf(es[j].m)}
			if es[j].m.Collected != nil {
				rm.Raw = es[j].m.Collected.Raw
			} else if es[j].m.Err != nil {
				rm.Error = es[j].m.Err.Error()
			}
			raws = append(raws, rm)
		}
		in := es[i].in
		p := instanceProp{VariantKey: es[i].key, JavaHome: in.JavaHome, ChainObserved: in.ProviderChain != nil,
			PqcServices: servicesOf(group), Count: uint32(len(group))}
		p.SecurityProperties.Set, p.SecurityProperties.Value = in.SecurityProperties.Set, in.SecurityProperties.Value
		if in.ProviderChain != nil {
			p.ProviderSet = *in.ProviderChain
		}
		var modes []string
		for m := range counts {
			modes = append(modes, m)
		}
		sort.Slice(modes, func(a, b int) bool { return modeOrder[modes[a]] < modeOrder[modes[b]] })
		for _, m := range modes {
			p.ModeCounts = append(p.ModeCounts, modeCount{m, counts[m]})
		}
		insts = append(insts, p)
		i = j
	}
	sort.Slice(raws, func(a, b int) bool {
		if raws[a].VariantKey != raws[b].VariantKey {
			return raws[a].VariantKey < raws[b].VariantKey
		}
		if raws[a].Mode != raws[b].Mode {
			return modeOrder[raws[a].Mode] < modeOrder[raws[b].Mode]
		}
		return raws[a].Raw+raws[a].Error < raws[b].Raw+raws[b].Error
	})

	// finding 수준의 속성. 체인은 모든 변형을 관측했고 하나일 때만 싣는다(코어도 같은 규칙으로 정한다).
	chains := map[string]bool{}
	for _, p := range insts {
		if p.ChainObserved {
			chains[mustJSON(p.ProviderSet)] = true
		}
	}
	providerSet, services := "", ""
	if unobserved == 0 && len(chains) == 1 {
		providerSet, services = strings.Join(insts[0].ProviderSet, ","), insts[0].PqcServices
	}
	mode := ""
	switch {
	case attached > 0 && static == 0 && unobserved == 0:
		mode = "dynamic"
	case static > 0 && attached == 0 && unobserved == 0:
		mode = "static"
	}

	dm, dmStr := commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION, "runtime-introspection"
	var covered, missing []commonv1.CollectionLayer
	if attached > 0 {
		covered = []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_JVM_INTROSPECTION}
	} else {
		dm, dmStr = commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT, "artifact"
	}
	if static > 0 || unobserved > 0 {
		missing = []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_JVM_INTROSPECTION}
	}
	var note string
	if static > 0 || unobserved > 0 || len(d.Members) > 1 || d.Scope != "" {
		note = fmt.Sprintf("%s: %d JVM(s) — attached %d, static java.security path %d, not observed %d", d.Key, len(d.Members), attached, static, unobserved)
		if static > 0 {
			if ns := dedup(notes); len(ns) > 0 {
				note += " (static: " + strings.Join(ns, "; ") + ")"
			} else {
				note += " (static: attach unavailable — dynamic registrations are a blind spot)"
			}
		}
		if d.Scope == ScopeSelectedPID {
			note += " (only the JVM selected with --pid was observed)"
		}
		if unobserved > 0 && len(reasons) > 0 {
			sort.Strings(reasons)
			note += " (not observed: " + strings.Join(dedup(reasons), "; ") + ")"
		}
	}

	props := []prop{
		{"pqcota:crypto_runtime", "jca"},
		{"pqcota:detection_method", dmStr},
		{"pqcota:jca.app_key_kind", d.Kind},
		{"pqcota:jca.instances", mustJSON(insts)},
	}
	if d.Scope != "" {
		props = append(props, prop{"pqcota:jca.observation_scope", d.Scope})
	}
	if providerSet != "" {
		props = append(props, prop{"pqcota:jca.provider_set", providerSet})
	}
	if mode != "" {
		props = append(props, prop{"pqcota:jca.registration_mode", mode})
	}
	if services != "" {
		props = append(props, prop{"pqcota:jca.pqc_services", services})
	}
	props = append(props, prop{"pqcota:app_keys", d.Key})

	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      "jvm-collector",
			CollectorVersion: "0.1.0",
			DetectionMethod:  dm,
			CollectedAt:      timestamppb.New(now()),
			TargetNodeId:     node,
			CollectorLicense: "Apache-2.0",
		},
		RawCapture:           []byte(mustJSON(raws)),
		RawFormat:            RawFormatDeployment,
		CbomCyclonedx:        jcaDoc(prefix+d.Key, props),
		CyclonedxSpecVersion: "1.6",
		Completeness:         &commonv1.Completeness{LayersCovered: covered, LayersMissing: missing, Note: note},
	}
}

type prop struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func jcaDoc(name string, props []prop) []byte {
	type comp struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Properties []prop `json:"properties,omitempty"`
	}
	b, _ := json.Marshal(struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []comp `json:"components"`
	}{"CycloneDX", "1.6", []comp{{"cryptographic-asset", name, props}}})
	return b
}

func dedup(ss []string) []string {
	var out []string
	for i, s := range ss {
		if i == 0 || s != ss[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // 이 패키지가 만든 구조만 넘긴다
	}
	return string(b)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// LauncherHome — 프로브에 쓴 java의 JAVA_HOME. 못 짚으면 그 java 경로다.
func LauncherHome(javaBin string) string {
	p := javaBin
	if !filepath.IsAbs(p) { // PATH의 java
		if lp, err := exec.LookPath(p); err == nil {
			p = lp
		}
	}
	if rp, err := filepath.EvalSymlinks(p); err == nil {
		p = rp
	}
	if h := deriveJavaHome(p, ""); h != "" {
		return h
	}
	return p
}
