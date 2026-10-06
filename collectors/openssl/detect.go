// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package openssl

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
	"github.com/randyinthedev-hash/pqcota-discovery/pkg/discovery/procs"
)

// Detection — 한 로드된 OpenSSL 라이브러리의 탐지 결과(설계 §2.1).
// json 태그는 raw_capture(§2.4 step 1)에 실리는 형식이다 — 필드 이름을 바꾸면 과거 포집을
// 재정규화할 수 없게 되므로 raw_format을 함께 올린다("openssl-collector/native-v1").
type Detection struct {
	Lib             string   `json:"lib"` // libssl | libcrypto
	Path            string   `json:"path"`
	Fork            string   `json:"fork,omitempty"` // registry.MatchFork 결과 ("" = unknown, §2.5)
	Version         string   `json:"version,omitempty"`
	BindingMode     string   `json:"bindingMode,omitempty"`     // maps에서 .so로 발견 → dynamic
	DetectionMethod string   `json:"detectionMethod,omitempty"` // runtime-introspection(maps) + symbol-analysis(fork)
	AppKeys         []string `json:"appKeys,omitempty"`         // 자산이 어느 앱 것인지(§1.5) — 이 .so를 로드한 앱(들). host-wide 스캔에서 dedup 시 합집합.
}

// RawCapture — 탐지 결과를 collector 네이티브 형식(JSON)으로. CycloneDX 변환 **전**의 원본이라
// 강화 규칙이 좋아지면 재수집 없이 여기서 다시 정규화한다(§1.2·§2.4 step 1).
// mergeByPath가 순서를 고정하므로 같은 관측이면 같은 바이트다(서명이 이 값을 덮는다, §2.6).
func RawCapture(dets []Detection) []byte {
	if len(dets) == 0 {
		return nil
	}
	b, err := json.Marshal(dets)
	if err != nil {
		return nil // 원본을 못 담아도 관측 자체는 낸다 — 없는 것을 있는 척하지 않는다
	}
	return b
}

// DetectForPID — 실행 중 프로세스의 /proc/<pid>/maps를 읽어 로드된 OpenSSL을 찾고,
// 각 라이브러리의 ELF 문자열에서 fork·version을 판별한다(SD-1 런타임 + SD-3 심볼).
func DetectForPID(pid int, sigs []registry.ForkSignature) ([]Detection, error) {
	maps, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer maps.Close()

	appKey, _ := procs.AppKey("/proc", pid) // 이 PID의 앱 키(§1.5) — cgroup systemd 유닛 or exe
	var appKeys []string
	if appKey != "" {
		appKeys = []string{appKey}
	}
	var out []Detection
	for _, lib := range ParseProcMaps(maps) {
		d := Detection{
			Lib:             lib.Lib,
			Path:            lib.Path,
			BindingMode:     bindingMode(lib.Path), // 시스템 경로 밖이면 vendored (§2.3)
			DetectionMethod: "runtime-introspection",
			AppKeys:         appKeys,
		}
		if strs, err := ExtractStrings(lib.Path, 4); err == nil {
			fm := registry.MatchFork(strs, sigs)
			d.Fork = fm.Fork
			d.Version = fm.Version
			if fm.Matched {
				d.DetectionMethod = "runtime-introspection+symbol-analysis"
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// bindingMode — 표준 시스템 라이브러리 경로면 dynamic, 그 밖(앱 번들 등)이면 vendored(수용 원칙 §2.4).
func bindingMode(path string) string {
	for _, sys := range []string{"/usr/lib/", "/lib/", "/usr/local/lib/", "/lib64/", "/usr/lib64/"} {
		if strings.HasPrefix(path, sys) {
			return "dynamic"
		}
	}
	return "vendored"
}
