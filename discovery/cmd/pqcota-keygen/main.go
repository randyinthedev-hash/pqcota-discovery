// Command pqcota-keygen — collector 리포트 서명용 ed25519 키쌍을 생성한다(§2.6).
// 개인키는 노드 스캐너(PQCOTA_SIGN_KEY)에, 공개키는 중앙 적재(PQCOTA_VERIFY_KEY)에 등록한다.
// usage: pqcota-keygen
package main

import (
	"fmt"
	"os"

	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
)

func main() {
	pub, priv, err := sign.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	fmt.Printf("# sign on the node scanner: export PQCOTA_SIGN_KEY=<priv>\n")
	fmt.Printf("PQCOTA_SIGN_KEY=%s\n\n", priv)
	fmt.Printf("# verify at central ingest (comma-separated for several): export PQCOTA_VERIFY_KEY=<pub>\n")
	fmt.Printf("PQCOTA_VERIFY_KEY=%s\n", pub)
}
