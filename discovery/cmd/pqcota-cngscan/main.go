// Command pqcota-cngscan — 타깃(Windows) 노드에서 실행. 등록된 CNG provider를 관측해 낸다.
//
// usage: pqcota-cngscan [--output json|table] [node-id]
//
//	json (기본) CollectionResult JSON을 stdout에 — 중앙이 회수해 적재한다
//	table       사람이 읽는 표를 stdout에 — 저장하지 않는다
//
// env PQCOTA_SIGN_KEY: (선택) base64 ed25519 개인키 → 리포트에 서명(§2.6).
//
// **Windows가 아니면 빈 결과가 아니라 갭을 낸다.** 종료코드도 0이다 — 갭이 중앙까지 가야
// "CNG가 없는 노드"와 "CNG를 못 본 노드"가 구별된다(netcap의 CAP_NET_RAW 처리와 같은 규칙).
package main

import (
	"flag"
	"fmt"
	"os"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/machineid"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-discovery/discovery/cmd/internal/localview"
	"github.com/randyinthedev-hash/pqcota-discovery/discovery/collectors/cng"
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
	node := flag.Arg(0)
	if node == "" {
		node = fp.GetSelfAssignedId()
	}
	if node == "" {
		node = "host://local"
	}

	obs, err := cng.Enumerate()
	res := cng.BuildResult(node, obs, err)
	res.GetEnvelope().Machine = fp
	if err != nil {
		fmt.Fprintf(os.Stderr, "[cngscan] ⚠ %v\n", err)
	}

	if key := os.Getenv("PQCOTA_SIGN_KEY"); key != "" {
		if sig, sErr := sign.Sign(key, res); sErr == nil {
			res.GetEnvelope().Signature = sig
		} else {
			fmt.Fprintln(os.Stderr, "[cngscan] signing failed:", sErr)
		}
	}

	if *out == "table" {
		view, vErr := localview.Render(node, []*discoveryv1.CollectionResult{res})
		if vErr != nil {
			fmt.Fprintln(os.Stderr, "rendering the view failed:", vErr)
			os.Exit(1)
		}
		fmt.Print(view)
		return
	}
	b, mErr := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(res)
	if mErr != nil {
		fmt.Fprintln(os.Stderr, "serialization failed:", mErr)
		os.Exit(1)
	}
	fmt.Println(string(b))
}
