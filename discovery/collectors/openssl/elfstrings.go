package openssl

import (
	"debug/elf"
	"strings"
)

// ExtractStrings — ELF 파일의 문자열 섹션에서 fork 판별용 인쇄가능 문자열을 추출한다
// (설계 §2.1 심볼 계층). debug/elf 사용 — readelf/strings 미의존.
// .rodata/.comment/.data.rel.ro의 printable ASCII 런(길이 >= minLen)을 모은다.
func ExtractStrings(path string, minLen int) ([]string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS {
			continue
		}
		if !(strings.HasPrefix(sec.Name, ".rodata") || sec.Name == ".comment" || sec.Name == ".data.rel.ro") {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		out = append(out, printableRuns(data, minLen)...)
	}
	return out, nil
}

// printableRuns — 바이트열에서 인쇄가능 ASCII(0x20~0x7e) 연속 구간을 minLen 이상만 추출.
func printableRuns(data []byte, minLen int) []string {
	var runs []string
	var b strings.Builder
	flush := func() {
		if b.Len() >= minLen {
			runs = append(runs, b.String())
		}
		b.Reset()
	}
	for _, c := range data {
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		} else {
			flush()
		}
	}
	flush()
	return runs
}
