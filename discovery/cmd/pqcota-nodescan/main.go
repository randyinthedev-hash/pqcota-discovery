// Command pqcota-nodescan — 타깃 노드에서 실행. /proc OpenSSL 스캔 결과를 낸다.
// 데모에서 Ansible이 각 노드에서 돌려 컨트롤러로 회수한다.
//
// usage: pqcota-nodescan [--output json|table] [node-id]
//
//	json (기본) CollectionResult JSON을 stdout에 — 중앙이 회수해 적재한다
//	table       정규화까지 하고 사람이 읽는 표를 stdout에 — 저장하지 않는다
//
// env PQCOTA_SIGN_KEY: (선택) base64 ed25519 개인키 → 리포트에 서명(§2.6). 중앙이 공개키로 검증.
package main

import (
	"flag"
	"fmt"
	"os"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/machineid"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-discovery/discovery/cmd/internal/localview"
	"github.com/randyinthedev-hash/pqcota-discovery/discovery/collectors/openssl"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	out := flag.String("output", "json", "output format: json | table")
	flag.Parse()
	if *out != "json" && *out != "table" {
		fmt.Fprintf(os.Stderr, "unknown --output %q — use json | table\n", *out)
		os.Exit(2)
	}

	// 머신 지문 수집. node-id 인자(CMDB 권위)가 있으면 그것, 없으면 지문에서 결정론적 self-id(§1.4).
	fp := machineid.Fingerprint()
	node := flag.Arg(0) // CMDB 권위 override
	if node == "" {
		node = fp.GetSelfAssignedId() // 자동 self-id(중복 없는 결정론적)
	}
	if node == "" {
		node = "host://local" // 지문도 없을 때 최후 폴백
	}
	dets, st := openssl.ScanHost(registry.DefaultForkSignatures)
	res := openssl.BuildResult(node, dets)
	// `/proc`를 못 열었으면 "OpenSSL 없음"이 아니라 **관측 자체가 불가**다. 빈 결과를 그대로
	// 내보내면 부재로 읽히므로 완전성 노트에 남기고 크게 알린다(§2.6).
	if st.ProcUnavailable {
		const note = "/proc could not be opened, so nothing was observed — not absent, just unobserved (run this on Linux)"
		if c := res.GetCompleteness(); c != nil {
			c.Note = note
		}
		fmt.Fprintln(os.Stderr, "[nodescan] ⚠ "+note)
	}
	res.GetEnvelope().Machine = fp // 상관 지문 부착(§1.4 — IP·수동입력에 흔들리지 않게)

	// 리포트 서명(§2.6) — 키가 있으면. 전송 보안 없는 경로의 신뢰 앵커.
	if key := os.Getenv("PQCOTA_SIGN_KEY"); key != "" {
		if sig, err := sign.Sign(key, res); err == nil {
			res.GetEnvelope().Signature = sig
		} else {
			fmt.Fprintln(os.Stderr, "[nodescan] signing failed:", err)
		}
	}

	if *out == "json" {
		b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(res)
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal:", err)
			os.Exit(1)
		}
		os.Stdout.Write(b)
	}
	if *out == "table" {
		w := os.Stdout
		tbl, err := localview.Render(node, []*discoveryv1.CollectionResult{res})
		if err != nil {
			fmt.Fprintln(os.Stderr, "[nodescan]", err)
			os.Exit(1)
		}
		fmt.Fprintf(w, "== pqcota Discovery — %s (read-only; nothing is stored) ==\n", node)
		fmt.Fprintf(w, "scan: reachable %d · unreachable/exited %d · OpenSSL libs %d\n\n", st.Accessible, st.Denied, len(dets))
		fmt.Fprint(w, tbl)
		fmt.Fprintf(w, "\n(%d unreachable = recorded in the completeness map as \"not observed\" — without root another user's /proc is unreadable; not absence, §2.6)\n", st.Denied)
	}
	fmt.Fprintf(os.Stderr, "[nodescan] %s: reachable %d · denied %d · OpenSSL libs %d\n",
		node, st.Accessible, st.Denied, len(dets))
}
