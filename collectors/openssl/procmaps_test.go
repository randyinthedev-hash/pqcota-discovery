package openssl_test

import (
	"strings"
	"testing"

	"github.com/randyinthedev-hash/pqcota-discovery/collectors/openssl"
)

// TD-OPENSSL-1 (testcases.md §2). /proc/<pid>/maps 파싱.
func TestParseProcMaps(t *testing.T) {
	// 실제 maps 스냅샷 형태(주소·권한·오프셋·dev·inode·경로).
	const maps = `561e0a000000-561e0a021000 r--p 00000000 fd:01 100  /usr/bin/python3.11
7f2a10000000-7f2a10021000 r-xp 00000000 fd:01 200  /usr/lib/x86_64-linux-gnu/libssl.so.3
7f2a10100000-7f2a10300000 r-xp 00000000 fd:01 201  /usr/lib/x86_64-linux-gnu/libcrypto.so.3
7f2a10400000-7f2a10401000 r-xp 00000000 fd:01 201  /usr/lib/x86_64-linux-gnu/libcrypto.so.3
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0    [stack]
7f2a10500000-7f2a10521000 rw-p 00000000 00:00 0 `

	libs := openssl.ParseProcMaps(strings.NewReader(maps))
	if len(libs) != 2 {
		t.Fatalf("got %d libs, want 2 (libssl+libcrypto, deduped): %+v", len(libs), libs)
	}
	found := map[string]bool{}
	for _, l := range libs {
		found[l.Lib] = true
	}
	if !found["libssl"] || !found["libcrypto"] {
		t.Errorf("expected both libssl and libcrypto, got %+v", libs)
	}
}

func TestParseProcMaps_none(t *testing.T) {
	const maps = `561e0a000000-561e0a021000 r--p 0 fd:01 100 /usr/bin/bash
7ffd00000000-7ffd00021000 rw-p 0 00:00 0 [stack]`
	if libs := openssl.ParseProcMaps(strings.NewReader(maps)); len(libs) != 0 {
		t.Errorf("expected no OpenSSL libs, got %+v", libs)
	}
}
