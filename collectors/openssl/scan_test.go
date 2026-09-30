package openssl

import (
	"strings"
	"testing"
)

// mergeByPath — 서로 다른 앱이 같은 .so를 로드하면 app_key를 합집합(#3 host-wide 여러 앱에 걸침).
func TestMergeByPathUnionsAppKeys(t *testing.T) {
	// payment.service와 api.service가 같은 libcrypto.so.3을, batch.service는 libssl.so.3만.
	perPID := [][]Detection{
		{{Lib: "libcrypto", Path: "/usr/lib/libcrypto.so.3", AppKeys: []string{"payment.service"}}},
		{{Lib: "libcrypto", Path: "/usr/lib/libcrypto.so.3", AppKeys: []string{"api.service"}}},
		{{Lib: "libssl", Path: "/usr/lib/libssl.so.3", AppKeys: []string{"batch.service"}}},
		{{Lib: "libcrypto", Path: "/usr/lib/libcrypto.so.3", AppKeys: []string{"payment.service"}}}, // 중복 → 제거
	}
	out := mergeByPath(perPID)

	if len(out) != 2 {
		t.Fatalf("%d unique paths (want 2): %v", len(out), out)
	}
	byPath := map[string][]string{}
	for _, d := range out {
		byPath[d.Path] = d.AppKeys
	}
	crypto := byPath["/usr/lib/libcrypto.so.3"]
	if strings.Join(crypto, ",") != "api.service,payment.service" { // 합집합·정렬·중복제거
		t.Errorf("a shared .so did not span several apps: %v", crypto)
	}
	if ssl := byPath["/usr/lib/libssl.so.3"]; len(ssl) != 1 || ssl[0] != "batch.service" {
		t.Errorf("it must collapse into one app: %v", ssl)
	}
}

// 빈 app_key(비-PID 스캔·앱을 못 짚는 경우)는 nil로 — CSV 속성이 빈 문자열이어도 무해.
func TestMergeByPathNoAppKeys(t *testing.T) {
	out := mergeByPath([][]Detection{{{Path: "/usr/lib/libcrypto.so.3"}}})
	if len(out) != 1 || out[0].AppKeys != nil {
		t.Errorf("with no using app it must be nil: %v", out)
	}
}
