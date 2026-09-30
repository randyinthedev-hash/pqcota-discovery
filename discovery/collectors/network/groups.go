// Package network — network-collector(디스커버리 설계 §2.3). TLS/SSH
// 핸드셰이크를 수동 관측해 협상된 KEX 그룹과 통신 엣지를 잡는다. 복호화 없이 평문 핸드셰이크만 본다.
//
// 책임 경계(§1.6 유지): collector는 협상 그룹 "관측"까지. 등급 분류(🟢🔴⚪)는 코어 파생(§1.2, pkg/kernel/posture).
// 산출은 노드 내부 Finding이 아니라 통신 엣지(contracts ObservedEdge, 인벤토리 설계 §6 토폴로지 그래프)다.
package network

import "fmt"

// tlsGroupNames — TLS supported_groups/key_share 코드포인트 → 이름(IANA + PQC 하이브리드).
// 이름 문자열이 pkg/kernel/posture.Classify의 입력이 된다(MLKEM 포함 여부로 등급 판정).
var tlsGroupNames = map[uint16]string{
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",
	0x001d: "x25519",
	0x001e: "x448",
	0x0100: "ffdhe2048",
	0x0101: "ffdhe3072",
	// PQC 하이브리드 (IANA 등록 코드포인트)
	0x11ec: "X25519MLKEM768",
	0x11eb: "SecP256r1MLKEM768",
	0x11ed: "SecP384r1MLKEM1024",
	0x6399: "X25519Kyber768Draft00",
	0x639a: "SecP256r1Kyber768Draft00",
}

// tlsGroupName — 코드포인트를 이름으로. 미등록이면 "unknown(0xNNNN)"로 정직히 표기(임의 추정 금지).
func tlsGroupName(code uint16) string {
	if n, ok := tlsGroupNames[code]; ok {
		return n
	}
	return fmt.Sprintf("unknown(0x%04x)", code)
}

// tlsCipherNames — 관측 부가 근거용 cipher suite 이름(TLS 1.3 AEAD 중심).
var tlsCipherNames = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

func tlsCipherName(code uint16) string {
	if n, ok := tlsCipherNames[code]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", code)
}

// tlsVersionName — legacy_version/supported_versions 코드포인트.
func tlsVersionName(code uint16) string {
	switch code {
	case 0x0304:
		return "TLS1.3"
	case 0x0303:
		return "TLS1.2"
	case 0x0302:
		return "TLS1.1"
	case 0x0301:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%04x", code)
	}
}
