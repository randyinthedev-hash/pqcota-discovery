// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"errors"
	"fmt"
	"io"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// EncodeResults — 수집 결과를 JSON으로 w에 쓴다. oneLine이면 결과마다 한 줄(JSON Lines)이고, 아니면
// 들여쓴 객체를 낸다.
//
// ★ 한 줄 출력에는 Indent를 두지 않는다. protojson은 Indent가 비어 있지 않으면 Multiline을 켠다.
// v0.10.6까지는 두 설정을 함께 둬서 「한 줄에 하나」가 결과마다 여러 줄이 됐다. 그래서 JVM이 둘 이상인
// 노드의 파일을 적재가 줄 단위로 읽지 못했고, 적재 요청 전체가 거부됐다. 하나일 때는 파일 전체가 객체
// 하나로 읽혀 드러나지 않았다.
//
// 직렬화에 실패한 결과는 건너뛰고 나머지를 쓴다. 실패는 모아 돌려준다.
func EncodeResults(w io.Writer, results []*discoveryv1.CollectionResult, oneLine bool) error {
	enc := protojson.MarshalOptions{Multiline: true, Indent: "  "}
	if oneLine {
		enc = protojson.MarshalOptions{}
	}
	var errs []error
	for _, r := range results {
		b, err := enc.Marshal(r)
		if err != nil {
			errs = append(errs, fmt.Errorf("marshal: %w", err))
			continue
		}
		if oneLine {
			b = append(b, '\n')
		}
		if _, err := w.Write(b); err != nil {
			return errors.Join(append(errs, err)...)
		}
	}
	return errors.Join(errs...)
}
