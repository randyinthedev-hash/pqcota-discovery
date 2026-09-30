// Package openssl — OpenSSL 런타임 collector(디스커버리 설계 §2.1, SD-1·SD-3).
// /proc·ELF를 Go로 자체 파싱한다 — ldd/lsof/ss/readelf에 의존하지 않는다(최소 이미지 대응 · 노드에 남는 것 최소화, §2.3).
package openssl

import (
	"bufio"
	"io"
	"path/filepath"
	"strings"
)

// LoadedLib — /proc/<pid>/maps에서 발견한 로드된 OpenSSL 공유 라이브러리.
type LoadedLib struct {
	Lib  string // "libssl" | "libcrypto"
	Path string // 실제 매핑 경로 (심볼 분석 대상)
}

// ParseProcMaps — /proc/<pid>/maps 내용에서 libssl/libcrypto 로드를 추출한다(SD-1 런타임 계층).
// dlopen·벤더링된 라이브러리도 maps에 나타나므로 포착된다(§2.3). 경로 기준으로 dedup.
// 순수 함수(reader 입력) — 실물 프로세스 없이 단위 테스트 가능(설계 §2.1).
func ParseProcMaps(r io.Reader) []LoadedLib {
	seen := map[string]bool{}
	var libs []LoadedLib
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// maps 형식: "addr perms offset dev inode  pathname"
		// pathname은 6번째 필드부터(공백 포함 가능). 파일 매핑만 대상.
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := strings.Join(fields[5:], " ")
		if !strings.HasPrefix(path, "/") {
			continue // [heap], [stack], 익명 매핑 등 제외
		}
		base := filepath.Base(path)
		var lib string
		switch {
		case strings.HasPrefix(base, "libssl3"):
			continue // NSS(Mozilla) libssl3.so — OpenSSL 아님(거짓 양성 방지)
		case strings.Contains(base, "libssl"):
			lib = "libssl"
		case strings.Contains(base, "libcrypto"):
			lib = "libcrypto"
		default:
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		libs = append(libs, LoadedLib{Lib: lib, Path: path})
	}
	return libs
}
