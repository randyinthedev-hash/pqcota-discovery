// Package cng — Windows CNG(Cryptography Next Generation) collector.
//
// **왜 별도 collector인가** — CNG는 provider(KSP/SSP) 아키텍처라 JCA와 동형이다(수용 원칙 §2.1).
// 등록된 provider 목록이 곧 능력의 경계라, JCA collector가 provider 체인을
// 보는 것과 같은 축을 본다. 다만 수집 수단은 하나도 겹치지 않는다 — `/proc`도 ELF도 attach도 아닌
// `bcrypt.dll`의 열거 API다(검토 중인 설계 §2.2).
//
// **관측까지만 한다.** evidence_strength·pqc_readiness 같은 파생은 코어가 만든다(§1.2).
package cng

import (
	"errors"
	"strings"
)

// ErrNotWindows — Windows가 아닌 곳에서 관측을 요청했다. **"CNG 없음"이 아니라 "관측 불가"다**(§2.6).
var ErrNotWindows = errors.New("CNG can only be observed on Windows — this is not an absence, it is what cannot be seen from here")

// Observation — 한 노드의 CNG 관측 결과.
//
// 순수 데이터라 Windows 없이도 만들고 검사할 수 있다 — 실물 없이 단위 테스트되게 파싱·조립을
// I/O에서 뗀 것이다.
type Observation struct {
	// Providers — 등록된 provider 이름. **순서를 보존한다**(관측된 등록 순서 그대로. 우선순위인지는 미확인, cbom.proto CngAxes).
	Providers []string `json:"providers"`
	// Algorithms — 열거된 알고리즘. v0.6.0에서 CngAxes.algorithms가 생겨 파생 뷰까지 간다.
	// 원본(raw_capture)에도 그대로 실어 보낸다 — 관측한 것을 버리지 않는다(§1.2 재계산 가능).
	Algorithms []Algorithm `json:"algorithms,omitempty"`
}

// Algorithm — CNG가 열거한 알고리즘 하나와 그 종류, 그리고 그것을 구현하는 provider들.
type Algorithm struct {
	Name  string `json:"name"`
	Class string `json:"class"` // cipher · hash · asymmetric-encryption · secret-agreement · signature · rng · key-derivation
	// Providers — 이 알고리즘을 서비스하는 provider(`BCryptEnumProviders`). 등록 목록은
	// "머신에 무엇이 있나"만 답한다 — "누가 ML-DSA를 하나"는 여기에만 있다. 못 물었으면 빈 목록.
	Providers []string `json:"providers,omitempty"`
}

// Empty — 아무것도 관측하지 못했나. 빈 관측과 "provider가 없다"는 다르다 — 부르는 쪽이 갭으로
// 적을지 판단할 수 있게 관측 자체의 공백만 답한다.
func (o Observation) Empty() bool { return len(o.Providers) == 0 && len(o.Algorithms) == 0 }

// BCRYPT_*_INTERFACE — `BCRYPT_ALGORITHM_IDENTIFIER.dwClass`가 담는 값(bcrypt.h).
//
// ★ 열거를 **요청**할 때 쓰는 연산 비트마스크(1·2·4·8·0x10…)와 **다른 어휘**다. 처음엔 같은 것으로
// 보고 비트마스크로 옮겼는데, 첫 실측에서 절반이 빈 값으로 나오고 DH·ECDH가 `secret-agreement`가
// 아니라 `asymmetric-encryption`으로 **틀리게** 붙었다. 값이 겹쳐서 오류 없이 틀리는 자리다.
const (
	ifaceCipher            = 1
	ifaceHash              = 2
	ifaceAsymmetricEncrypt = 3
	ifaceSecretAgreement   = 4
	ifaceSignature         = 5
	ifaceRNG               = 6
	ifaceKeyDerivation     = 7
)

// AlgorithmClass — dwClass를 사람이 읽는 종류로. 모르는 값은 **빈 값**으로 둔다 —
// 모르는 것을 아는 것으로 적지 않는다(§2.5 unknown은 1급).
//
// OS 호출과 떼어 둔 순수 함수라 Windows 없이 테스트된다. 앞의 결함이 이 규칙을 어긴 대가였다.
func AlgorithmClass(dwClass uint32) string {
	switch dwClass {
	case ifaceCipher:
		return "cipher"
	case ifaceHash:
		return "hash"
	case ifaceAsymmetricEncrypt:
		return "asymmetric-encryption"
	case ifaceSecretAgreement:
		return "secret-agreement"
	case ifaceSignature:
		return "signature"
	case ifaceRNG:
		return "rng"
	case ifaceKeyDerivation:
		return "key-derivation"
	default:
		return ""
	}
}

// 알고리즘 목록을 properties 한 줄로 나르는 표기. CycloneDX property는 이름·값 두 문자열뿐이라
// 목록을 실으려면 인코딩이 필요하다. `이름:종류`를 쉼표로 잇는다 — 관측된 CNG 이름에는 쉼표도
// 콜론도 없다(실측 50개 확인: `SHA3-256`·`CHACHA20_POLY1305`·`XTS-AES` 같은 모양뿐).
const (
	algorithmSep         = ","
	algorithmClassSep    = ":"
	algorithmProviderSep = "|" // provider 이름에는 `|`가 없다(실측 9개 확인)
)

// EncodeAlgorithms — 알고리즘 목록을 property 값으로. 종류를 모르면 빈 값으로 남긴다(§2.5).
//
// 모양은 `이름:종류` 또는 `이름:종류:provider|provider`다. provider를 못 물었으면 **셋째 칸을
// 아예 두지 않는다** — 빈 칸과 "물어봤는데 없더라"를 같은 모양으로 적지 않기 위해서다.
func EncodeAlgorithms(algs []Algorithm) string {
	if len(algs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(algs))
	for _, a := range algs {
		if a.Name == "" {
			continue // 이름 없는 항목은 나를 것이 없다
		}
		part := a.Name + algorithmClassSep + a.Class
		if len(a.Providers) > 0 {
			part += algorithmClassSep + strings.Join(a.Providers, algorithmProviderSep)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, algorithmSep)
}

// DecodeAlgorithms — [EncodeAlgorithms]의 역. 코어 정규화가 파생 뷰를 만들 때 쓴다.
//
// 모양이 깨진 항목은 **버리지 않고 이름만 살린다** — 종류를 못 읽은 것이 알고리즘을 못 본 것이
// 되면 안 된다(§2.6 갭 ≠ 부재).
func DecodeAlgorithms(s string) []Algorithm {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []Algorithm
	for _, part := range strings.Split(s, algorithmSep) {
		name, rest, _ := strings.Cut(part, algorithmClassSep)
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		class, provs, _ := strings.Cut(rest, algorithmClassSep)
		a := Algorithm{Name: name, Class: strings.TrimSpace(class)}
		for _, p := range strings.Split(provs, algorithmProviderSep) {
			if p = strings.TrimSpace(p); p != "" {
				a.Providers = append(a.Providers, p)
			}
		}
		out = append(out, a)
	}
	return out
}
