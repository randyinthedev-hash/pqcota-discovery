package network

import (
	"bytes"
	"errors"
	"strings"
)

const sshMsgKexInit = 20

// ParseSSHKexInit — SSH KEXINIT 패킷을 파싱해 제시된 KEX 알고리즘 목록을 뽑는다(TD-NETWORK-3).
// SSH-2.0 바이너리 패킷: packet_length(4)+padding_length(1)+payload+padding. KEXINIT은 미암호화(디스커버리 설계 §2.3).
// 버전 문자열("SSH-...\r\n")이 앞에 붙어 있으면 스킵한다.
func ParseSSHKexInit(b []byte) (*Handshake, error) {
	if bytes.HasPrefix(b, []byte("SSH-")) {
		if i := bytes.IndexByte(b, '\n'); i >= 0 && i+1 < len(b) {
			b = b[i+1:]
		}
	}
	c := &cursor{b: b}
	pktLen, ok := c.u32()
	if !ok {
		return nil, errors.New("ssh: no packet_length")
	}
	padLen, ok := c.u8()
	if !ok {
		return nil, errTruncated
	}
	msgCode, ok := c.u8()
	if !ok {
		return nil, errTruncated
	}
	if msgCode != sshMsgKexInit {
		return nil, errors.New("ssh: not a KEXINIT(20)")
	}
	if _, ok := c.take(16); !ok { // cookie
		return nil, errTruncated
	}
	// 첫 name-list = kex_algorithms.
	kexList, ok := c.sshNameList()
	if !ok {
		return nil, errTruncated
	}
	_ = pktLen
	_ = padLen

	// ★ NegotiatedGroup을 여기서 채우지 않는다. KEXINIT 하나는 **한쪽의 제안**일 뿐이고, 협상 결과는
	// 양쪽 목록의 교집합(RFC 4253 §7.1)이라 이 함수만으로는 알 수 없다. 최선호를 negotiated로 넣으면
	// 상대가 그 알고리즘을 지원하지 않는 연결까지 그걸로 협상됐다고 **거짓 보고**하게 된다(§2.1·§2.5).
	// 협상 계산은 NegotiateSSHKex가, 양쪽 KEXINIT을 모은 캡처 계층에서 한다.
	return &Handshake{Protocol: "SSH", OfferedGroups: splitNameList(kexList)}, nil
}

// NegotiateSSHKex — 실제 협상되는 KEX를 결정론적으로 계산한다(RFC 4253 §7.1):
// **클라이언트 목록에서 첫 번째로 서버 목록에도 있는 것**. 한쪽이라도 관측하지 못했으면 "" — 지어내지 않는다.
//
// 이게 없으면 "OpenSSH 9 클라이언트가 sntrup761을 제안했다"는 사실만으로 레거시 서버(8.2, PQC KEX
// 없음)와의 연결까지 🟢 PQC로 등급된다. 실제로 그 오보가 있었고 이 함수가 그 회귀를 막는다.
func NegotiateSSHKex(clientKex, serverKex []string) string {
	if len(clientKex) == 0 || len(serverKex) == 0 {
		return "" // 한쪽만 관측 — 협상 결과 미상(⚪). 제안은 OfferedGroups에 남는다.
	}
	server := make(map[string]bool, len(serverKex))
	for _, s := range serverKex {
		server[s] = true
	}
	for _, c := range clientKex { // 클라이언트 선호 순서가 결정한다
		if server[c] {
			return c
		}
	}
	return "" // 공통 알고리즘 없음 — 연결이 성립하지 않는다. 없는 협상을 지어내지 않는다.
}

// sshNameList — uint32 길이 접두 name-list의 원시 문자열을 돌려준다.
func (c *cursor) sshNameList() (string, bool) {
	n, ok := c.u32()
	if !ok {
		return "", false
	}
	data, ok := c.take(int(n))
	if !ok {
		return "", false
	}
	return string(data), true
}

func splitNameList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
