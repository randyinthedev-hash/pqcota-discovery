// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command pqcota-netcap — 타깃 노드에서 실행. 관측 구간 동안 TLS/SSH 핸드셰이크를 AF_PACKET으로
// 수동 관측해 통신 엣지를 CollectionResult JSON으로 stdout에 낸다(디스커버리 설계 §2.3).
// CAP_NET_RAW 필요. 없으면 **관측이 안 된다** — 그 사실을 stderr로 분명히 알리고, stdout으로는
// 완전성 갭(DegradedResult)을 낸다. 갭을 중앙까지 보내야 인벤토리가 "관측하지 못했다"와 "링크가 없다"를
// 구분한다(§2.6). 종료코드는 0이라 fleet 실행(Ansible)이 그 갭을 회수한다 — --strict면 1.
// usage: pqcota-netcap [--strict] <node-id> [iface] [window-seconds]
// env: NETCAP_IFACE, NETCAP_WINDOW_SEC, PQCOTA_SIGN_KEY(선택, base64 ed25519 개인키 → 결과에 서명)
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/machineid"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-discovery/cmd/internal/nodeid"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/network"
	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	strict := flag.Bool("strict", false, "on failure to observe, exit 1 instead of emitting a gap and succeeding")
	flag.Parse()

	// 노드: node-id 인자(CMDB 권위) → 지문의 self-id → host://local(§1.4, 다른 수집기와 같은 규칙).
	machine = machineid.Fingerprint()
	node := nodeid.Resolve(flag.Arg(0), machine)
	iface := envOr("NETCAP_IFACE", "eth0")
	if a := flag.Arg(1); a != "" {
		iface = a
	}
	windowSec := 8
	if v := os.Getenv("NETCAP_WINDOW_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			windowSec = n
		}
	}
	if a := flag.Arg(2); a != "" {
		if n, err := strconv.Atoi(a); err == nil {
			windowSec = n
		}
	}

	src := &network.LiveSource{
		Iface:   iface,
		Node:    node,
		SelfIPs: localIPs(),
		Window:  time.Duration(windowSec) * time.Second,
	}
	fmt.Fprintf(os.Stderr, "[netcap] %s iface=%s window=%ds — starting observation…\n", node, iface, windowSec)

	obs, err := src.Observe(nil, nil)
	if err != nil {
		if errors.Is(err, network.ErrCaptureUnavailable) {
			emit(network.DegradedResult(node, "no CAP_NET_RAW — not observed (not absent): "+err.Error()))
			// **관측은 실패했다**고 분명히 밝힌다. 이전 메시지("캡처 불가 → 완전성 갭 강등")는
			// 무엇이 없는지도 어떻게 고치는지도 알리지 않아, 손으로 돌린 사람이 성공으로 읽었다.
			exe, _ := os.Executable()
			fmt.Fprint(os.Stderr, captureUnavailableNote(exe, *strict))
			if *strict {
				os.Exit(1)
			}
			return
		}
		fmt.Fprintln(os.Stderr, "[netcap] observe:", err)
		os.Exit(1)
	}

	self := src.SelfIPs
	// 관측을 연결로 모으고, 연결마다 두 끝점이 맞는 소켓으로 앱을 짚은 뒤, 앱 키별로 엣지를 만든다
	// (aggregate). 비싼 fd 스캔만 구간 안에서 짧게 재사용한다.
	att := procs.NewAttributor("/proc", time.Second)
	agg := aggregate(obs, self, att.Conn)
	edges, conns, unattributed := agg.edges, agg.conns, agg.unattributed
	// 구간이 중간에 끊겼으면 "관측 없음"과 구별되게 노트에 남긴다 — 결함을 갭으로 위장하지 않는다.
	// 어느 앱인지 못 밝힌 엣지는 **"앱 없음"이 아니라 "어느 앱인지 밝히지 못함"이다.** 사유별로 몇 건인지
	// 완전성 노트에 남긴다 — 안 적으면 빈 app_key가 "이 통신에 앱이 없다"로 읽힌다.
	note := attributionNote(conns, unattributed)
	if src.Truncated {
		note = strings.TrimSpace(note + " " + fmt.Sprintf("observation window cut short by a read error (%v) — this result does not represent the whole window (gap != absence)", src.TruncErr))
		fmt.Fprintln(os.Stderr, "[netcap] ⚠ "+note)
	}
	emit(network.BuildResult(node, edges, note))
	fmt.Fprintf(os.Stderr, "[netcap] %d observed edges", len(edges))
	if n := total(unattributed); n > 0 {
		fmt.Fprintf(os.Stderr, "  · %d of %d connections without an app", n, conns)
	}
	fmt.Fprintln(os.Stderr)
	for reason, n := range unattributed {
		fmt.Fprintf(os.Stderr, "[netcap]   %d: %s\n", n, reason)
	}
	for _, m := range agg.missed { // 어느 연결이었는지 — 출발 포트는 여기에만 나온다(결과에는 없다)
		fmt.Fprintf(os.Stderr, "[netcap]   unattributed %s\n", m)
	}
}

// captureUnavailableNote — 캡처를 못 열었을 때 stderr로 내는 안내. 마지막 두 줄은 실제 종료 코드와
// 맞아야 한다. 예전에는 --strict로 1을 내면서도 「그래서 성공으로 끝난다, 실패시키려면 --strict」를
// 그대로 출력해, 같은 출력에 종료 코드만 다른 두 실행을 사람이 구분할 수 없었다.
func captureUnavailableNote(exe string, strict bool) string {
	head := fmt.Sprintf(`[netcap] ✗ nothing was observed — the AF_PACKET socket could not be opened (no CAP_NET_RAW).
          grant it: sudo setcap cap_net_raw+ep %s   (or run as root)
          what was emitted is not an observation but **a record that nothing was observed** — it does not mean there are no links.
`, exe)
	if strict {
		return head + `          --strict: exiting 1. The record above is still printed so it can be kept.
`
	}
	return head + `          that is why this exits successfully rather than failing: an error exit would keep this record from reaching the centre.
          use --strict to fail instead.
`
}

// attributionNote — 앱을 짚은 결과를 완전성 노트 문장으로. 전부 잡았으면 빈 문자열. 앱은 연결마다
// 짚으므로 연결 수로 센다.
func attributionNote(conns int, unattributed map[string]int) string {
	n := total(unattributed)
	if n == 0 {
		return ""
	}
	reasons := make([]string, 0, len(unattributed))
	for r, c := range unattributed {
		reasons = append(reasons, fmt.Sprintf("%s(%d)", r, c))
	}
	sort.Strings(reasons) // 순서가 흔들리면 같은 관측이 다른 스냅샷으로 보인다
	return fmt.Sprintf("%[2]d of %[1]d observed connections could not be attributed to an app — **this does not mean there is no app**. Reasons: %[3]s",
		conns, n, strings.Join(reasons, " · "))
}

func total(m map[string]int) int {
	n := 0
	for _, c := range m {
		n += c
	}
	return n
}

// machine — 이 머신의 지문. main이 한 번 채우고 emit이 결과에 붙인다.
var machine *commonv1.MachineIdentity

func emit(res *discoveryv1.CollectionResult) {
	nodeid.Stamp([]*discoveryv1.CollectionResult{res}, machine) // 적재 때 node_id 중복·충돌을 이것으로 잡는다(§1.4)
	// 서명은 지문을 붙인 뒤에 한다(서명 대상에 지문이 들어 있다). 갭만 담은 결과도 서명한다 — ID 결합 모드의
	// 적재기는 서명 없는 결과를 받지 않으므로, 서명하지 않으면 「관측하지 못했다」가 중앙에 닿지 않는다.
	if key := os.Getenv("PQCOTA_SIGN_KEY"); key != "" {
		if err := sign.SignAll(key, []*discoveryv1.CollectionResult{res}); err != nil {
			fmt.Fprintln(os.Stderr, "[netcap] PQCOTA_SIGN_KEY cannot sign:", err, "— not emitting an unsigned result")
			os.Exit(1)
		}
	}
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(res)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}

// localIPs — 자기 IP·"ip:*" 표기를 모아 자기참조 회피·방향 판정에 쓴다.
func localIPs() map[string]bool {
	self := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			self[ipn.IP.String()] = true
		}
	}
	return self
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
