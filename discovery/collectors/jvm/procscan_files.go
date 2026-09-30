package jvm

import (
	"os"
	"path/filepath"
)

// 정찰이 파일시스템에서 읽는 것들 — OS를 가리지 않으므로 빌드 태그 밖에 둔다.

// readReleaseVersion — <JavaHome>/release의 JAVA_VERSION. 없으면 "" — 지어내지 않는다(§2.5).
func readReleaseVersion(home string) string {
	if home == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, "release"))
	if err != nil {
		return ""
	}
	return parseReleaseVersion(string(b))
}

// fileExists — attachCapable에 주입하는 실물 검사(순수 판별 로직과 I/O를 분리한다).
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
