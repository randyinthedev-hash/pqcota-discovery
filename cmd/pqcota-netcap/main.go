// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command pqcota-netcap — 타깃 노드에서 실행. 관측 구간 동안 TLS/SSH 핸드셰이크를 AF_PACKET으로
// 수동 관측해 통신 엣지를 CollectionResult JSON으로 stdout에 낸다(디스커버리 설계 §2.3).
// CAP_NET_RAW 필요. 없으면 **관측이 안 된다** — 그 사실을 stderr로 분명히 알리고, stdout으로는
// 완전성 갭(DegradedResult)을 낸다. 갭을 중앙까지 보내야 인벤토리가 "관측하지 못했다"와 "링크가 없다"를
// 구분한다(§2.6). 종료코드는 0이라 fleet 실행(Ansible)이 그 갭을 회수한다 — --strict면 1.
// usage: pqcota-netcap [--strict] <node-id> [iface] [window-seconds]
// env: NETCAP_IFACE, NETCAP_WINDOW_SEC
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

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/network"
	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	strict := flag.Bool("strict", false, "on failure to observe, exit 1 instead of emitting a gap and succeeding")
	flag.Parse()

	node := flag.Arg(0)
	if node == "" {
		node = "host://local"
	}
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
			fmt.Fprintf(os.Stderr, `[netcap] ✗ nothing was observed — the AF_PACKET socket could not be opened (no CAP_NET_RAW).
          grant it: sudo setcap cap_net_raw+ep %s   (or run as root)
          what was emitted is not an observation but **a record that nothing was observed** — it does not mean there are no links.
          that is why this exits successfully rather than failing: an error exit would keep this record from reaching the centre.
          use --strict to fail instead.
`, exe)
			if *strict {
				os.Exit(1)
			}
			return
		}
		fmt.Fprintln(os.Stderr, "[netcap] observe:", err)
		os.Exit(1)
	}

	// 같은 엣지의 여러 관측(ClientHello/ServerHello 등)을 키별로 병합한다.
	// TLS는 ServerHello에만 협상 그룹이 실리므로 "그룹 있는 관측"을 우선 채택한다.
	self := src.SelfIPs
	// 앱은 **엣지를 보는 그 자리에서** 짚는다. 캡처가 끝난 뒤 몰아 하면 그 사이에 닫힌 소켓을
	// 더 놓친다. 비싼 fd 스캔만 구간 안에서 짧게 재사용한다.
	att := procs.NewAttributor("/proc", time.Second)
	unattributed := map[string]int{} // 사유 → 건수
	byKey := map[string]*discoveryv1.ObservedEdge{}
	var order []string
	for _, o := range obs {
		if o.HS == nil || !network.ShouldObserve(o.Conn, self) {
			continue
		}
		e := network.BuildEdge(o.Conn, o.HS)
		k := fmt.Sprintf("%s|%s|%d|%d", e.GetSrcNodeId(), e.GetDstAddr(), e.GetPort(), e.GetProtocol())
		if ex, ok := byKey[k]; ok {
			ex.ObservedCount++
			if ex.GetNegotiatedGroup() == "" && e.GetNegotiatedGroup() != "" {
				ex.NegotiatedGroup = e.GetNegotiatedGroup()
				ex.Cipher = e.GetCipher()
			}
		} else {
			if ip, _, err := net.SplitHostPort(e.GetDstAddr()); err == nil {
				a := att.Remote(ip, e.GetPort())
				e.AppKey, e.AppKeyKind = a.Key, a.Kind
				if a.Key == "" {
					unattributed[a.Reason]++
				}
			}
			byKey[k] = e
			order = append(order, k)
		}
	}
	edges := make([]*discoveryv1.ObservedEdge, 0, len(order))
	for _, k := range order {
		edges = append(edges, byKey[k])
	}
	// 구간이 중간에 끊겼으면 "관측 없음"과 구별되게 노트에 남긴다 — 결함을 갭으로 위장하지 않는다.
	// 어느 앱인지 못 밝힌 엣지는 **"앱 없음"이 아니라 "어느 앱인지 밝히지 못함"이다.** 사유별로 몇 건인지
	// 완전성 노트에 남긴다 — 안 적으면 빈 app_key가 "이 통신에 앱이 없다"로 읽힌다.
	note := attributionNote(len(order), unattributed)
	if src.Truncated {
		note = strings.TrimSpace(note + " " + fmt.Sprintf("observation window cut short by a read error (%v) — this result does not represent the whole window (gap != absence)", src.TruncErr))
		fmt.Fprintln(os.Stderr, "[netcap] ⚠ "+note)
	}
	emit(network.BuildResult(node, edges, note))
	fmt.Fprintf(os.Stderr, "[netcap] %d observed edges", len(edges))
	if n := total(unattributed); n > 0 {
		fmt.Fprintf(os.Stderr, "  · %d without an app", n)
	}
	fmt.Fprintln(os.Stderr)
	for reason, n := range unattributed {
		fmt.Fprintf(os.Stderr, "[netcap]   %d: %s\n", n, reason)
	}
}

// attributionNote — 앱을 짚은 결과를 완전성 노트 문장으로. 전부 잡았으면 빈 문자열.
func attributionNote(edges int, unattributed map[string]int) string {
	n := total(unattributed)
	if n == 0 {
		return ""
	}
	reasons := make([]string, 0, len(unattributed))
	for r, c := range unattributed {
		reasons = append(reasons, fmt.Sprintf("%s(%d)", r, c))
	}
	sort.Strings(reasons) // 순서가 흔들리면 같은 관측이 다른 스냅샷으로 보인다
	return fmt.Sprintf("%[2]d of %[1]d edges could not be attributed to an app — **this does not mean there is no app**. Reasons: %[3]s",
		edges, n, strings.Join(reasons, " · "))
}

func total(m map[string]int) int {
	n := 0
	for _, c := range m {
		n += c
	}
	return n
}

func emit(res *discoveryv1.CollectionResult) {
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
