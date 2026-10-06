// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package openssl

import (
	"os"
	"sort"
	"strconv"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
)

// sortedKeys — 집합을 결정적(정렬) 슬라이스로. 빈 집합이면 nil(속성 미emit).
func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ScanStats — 호스트 스캔 커버리지(완전성 맵 원천).
type ScanStats struct {
	Accessible int // /proc 접근 가능 프로세스
	Denied     int // 접근 불가(타 사용자)·종료 — 갭(≠부재, §2.6)
	WithSSL    int // libssl/libcrypto 로드 프로세스

	// ProcUnavailable — `/proc` 자체를 열 수 없었나(비-리눅스, 마운트 안 됨).
	// 이때 결과가 비는 것은 **"없다"가 아니라 "관측하지 못했다"**이다. 구별하지 않으면 결함이 갭으로
	// 위장된다(§2.6) — netcap이 CAP_NET_RAW 부재를 강등으로 내는 것과 같은 자리.
	ProcUnavailable bool
}

// ScanHost — 접근 가능한 모든 프로세스의 /proc를 스캔해 로드된 OpenSSL을 **경로별 유니크**로 수집한다.
// 여러 프로세스가 같은 .so를 로드하므로 경로 dedup. root(또는 CAP_SYS_PTRACE)면 전 프로세스를 본다.
// ★ 같은 .so를 서로 다른 앱이 로드하면 app_key를 **합집합**한다(§1.5 여러 앱에 걸침) — 그 .so 교체는
//
//	로더 앱 전부에 영향이므로 하나로 뭉개면 안 된다.
func ScanHost(sigs []registry.ForkSignature) ([]Detection, ScanStats) {
	var st ScanStats
	entries, err := os.ReadDir("/proc")
	if err != nil {
		st.ProcUnavailable = true
		return nil, st
	}
	var perPID [][]Detection
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dets, err := DetectForPID(pid, sigs)
		if err != nil {
			st.Denied++
			continue
		}
		st.Accessible++
		if len(dets) > 0 {
			st.WithSSL++
			perPID = append(perPID, dets)
		}
	}
	return mergeByPath(perPID), st
}

// mergeByPath — 프로세스별 탐지들을 **경로별 유니크**로 합치되, 서로 다른 앱이 같은 .so를 로드하면
// app_key를 **합집합**한다(§1.5 여러 앱에 걸침). 첫 관측 순서 보존·app_key 정렬로 결정적. 순수 함수(테스트 가능).
func mergeByPath(perPID [][]Detection) []Detection {
	byPath := map[string]Detection{}
	appsByPath := map[string]map[string]bool{}
	var order []string
	for _, dets := range perPID {
		for _, d := range dets {
			if _, seen := byPath[d.Path]; !seen {
				order = append(order, d.Path)
				appsByPath[d.Path] = map[string]bool{}
			}
			byPath[d.Path] = d // 최신 탐지 메타(fork·version 동일 .so라 무해)
			for _, ak := range d.AppKeys {
				appsByPath[d.Path][ak] = true
			}
		}
	}
	out := make([]Detection, 0, len(order))
	for _, p := range order {
		d := byPath[p]
		d.AppKeys = sortedKeys(appsByPath[p]) // 합집합·결정적 순서
		out = append(out, d)
	}
	return out
}
