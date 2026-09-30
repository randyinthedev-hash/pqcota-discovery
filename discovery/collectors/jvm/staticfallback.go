package jvm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// 정적 폴백(③)의 **Go 구현** — attach가 어느 경로로도 안 될 때 최소한의 관측은 낸다.
//
// 왜 Go인가: 예전 폴백은 `StaticFallback.java`라 **그걸 돌릴 java가 있어야** 했다.
// 그런데 ②(JDK 클라이언트)는 `--add-modules jdk.attach`로 뜨므로 **순수 JRE에선 시작조차 못 하고**,
// 그러면 폴백까지 함께 못 돌아 노드가 통째로 갭이 됐다. `java.security`는 그냥 텍스트 파일이라
// Go가 직접 읽으면 그 구멍이 닫힌다 — "관측 실패가 표시 없는 0이 되지 않는다"(§2.5)를 끝까지 지킨다.
//
// ★ 여전히 **정적 등록만** 본다. 동적 `addProvider`는 이 경로의 사각지대이고, 그 사실을
// Degraded(=갭·강등)로 고지한다. 없는 걸 봤다고 하지 않는다(§2.6).

// javaSecurityRel — java.security의 JAVA_HOME 기준 상대 경로. JDK 9+는 conf/, 8 이하는 lib/.
var javaSecurityRel = []string{
	filepath.Join("conf", "security", "java.security"),
	filepath.Join("lib", "security", "java.security"),
}

// StaticFallbackGo — 대상의 java.security에서 **정적 등록 provider**를 등록 순서대로 읽는다.
// pid는 네임스페이스 교차(컨테이너 대상의 파일을 호스트에서 읽기) 용도다.
// 파일을 못 찾아도 오류가 아니라 **빈 목록 + Degraded**로 돌려준다 — 그 자체가 정직한 관측이다.
func StaticFallbackGo(pid int, javaHome string) (Collected, error) {
	if javaHome == "" {
		return Collected{Degraded: true}, fmt.Errorf("JAVA_HOME unknown — the location of java.security is not known")
	}
	for _, rel := range javaSecurityRel {
		p := hostPath(pid, filepath.Join(javaHome, rel))
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		c := ParseJavaSecurity(string(b))
		c.Degraded = true // 정적 경로 = 항상 강등(동적 등록 사각)
		return c, nil
	}
	return Collected{Degraded: true}, fmt.Errorf("java.security not found (%s)", javaHome)
}

// hostPath — 컨테이너 대상의 경로를 호스트에서 읽을 수 있게 /proc/<pid>/root를 앞에 붙인다.
// 같은 네임스페이스면 원래 경로가 그대로 열리므로 그걸 쓴다.
func hostPath(pid int, p string) string {
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return filepath.Join("/proc", strconv.Itoa(pid), "root", p)
}

// ParseJavaSecurity — `security.provider.N=<값>` 줄을 **N 순서대로** 뽑는다(순수 함수).
//
// 순서가 곧 우선순위라 정렬이 결과의 의미를 바꾼다(수용 원칙 §2.2) — 파일에 적힌 순서가 아니라
// **N 숫자 순**이 실제 등록 순서다. 값에 인자가 붙는 경우(`SunPKCS11 ${java.home}/conf/...`)는
// 첫 토큰이 provider 이름·클래스다.
func ParseJavaSecurity(content string) Collected {
	type entry struct {
		n    int
		name string
	}
	var es []entry
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(t, "security.provider.")
		if !ok {
			continue
		}
		numStr, val, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(numStr))
		if err != nil {
			continue
		}
		v := strings.TrimSpace(val)
		if v == "" {
			continue
		}
		if i := strings.IndexAny(v, " \t"); i > 0 { // "SunPKCS11 <conf>" → 첫 토큰
			v = v[:i]
		}
		es = append(es, entry{n: n, name: v})
	}
	sort.SliceStable(es, func(i, j int) bool { return es[i].n < es[j].n })

	c := Collected{Degraded: true, Raw: content}
	for i, e := range es {
		c.Providers = append(c.Providers, Provider{Order: i + 1, Name: e.name})
	}
	return c
}
