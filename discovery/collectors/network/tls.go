package network

import (
	"encoding/binary"
	"errors"
)

// ParseTLSHandshake — TLS 핸드셰이크(ClientHello/ServerHello)를 파싱해 협상 정보를 뽑는다(TD-NETWORK-1,2).
// 입력은 TLS 레코드(content_type 0x16로 시작) 또는 벌거벗은 핸드셰이크 메시지 둘 다 허용한다.
// 복호화 없음 — supported_groups/key_share/cipher/version 평문 필드만 읽는다(디스커버리 설계 §2.3).
func ParseTLSHandshake(b []byte) (*Handshake, error) {
	// TLS 레코드 헤더(22=handshake)면 5바이트 스킵.
	if len(b) >= 5 && b[0] == 0x16 {
		recLen := int(binary.BigEndian.Uint16(b[3:5]))
		body := b[5:]
		if recLen <= len(body) {
			body = body[:recLen]
		}
		b = body
	}
	c := &cursor{b: b}
	msgType, ok := c.u8()
	if !ok {
		return nil, errors.New("tls: no handshake message type")
	}
	msgLen, ok := c.u24()
	if !ok {
		return nil, errors.New("tls: no handshake length")
	}
	body, ok := c.take(int(msgLen))
	if !ok {
		body = c.rest() // 캡처 절단 허용 — 있는 만큼 파싱(관측 부분성 정직)
	}
	switch msgType {
	case 1:
		return parseClientHello(body)
	case 2:
		return parseServerHello(body)
	default:
		return nil, errors.New("tls: not a ClientHello/ServerHello")
	}
}

func parseClientHello(b []byte) (*Handshake, error) {
	hs := &Handshake{Protocol: "TLS", Role: "client"}
	c := &cursor{b: b}
	if _, ok := c.take(2); !ok { // client_version
		return nil, errTruncated
	}
	if _, ok := c.take(32); !ok { // random
		return nil, errTruncated
	}
	if !c.skipVec(1) { // session_id
		return nil, errTruncated
	}
	if !c.skipVec(2) { // cipher_suites
		return nil, errTruncated
	}
	if !c.skipVec(1) { // compression_methods
		return nil, errTruncated
	}
	parseExtensions(c, hs, false)
	return hs, nil
}

func parseServerHello(b []byte) (*Handshake, error) {
	hs := &Handshake{Protocol: "TLS", Role: "server", Version: "TLS1.2"}
	c := &cursor{b: b}
	ver, ok := c.u16() // legacy_version (실제는 supported_versions 확장에서 갱신)
	if !ok {
		return nil, errTruncated
	}
	hs.Version = tlsVersionName(ver)
	if _, ok := c.take(32); !ok { // random
		return nil, errTruncated
	}
	if !c.skipVec(1) { // session_id
		return nil, errTruncated
	}
	cs, ok := c.u16() // cipher_suite
	if !ok {
		return nil, errTruncated
	}
	hs.Cipher = tlsCipherName(cs)
	if _, ok := c.take(1); !ok { // compression_method
		return nil, errTruncated
	}
	parseExtensions(c, hs, true)
	return hs, nil
}

// parseExtensions — 확장 블록(len2 + 확장들)을 순회하며 관심 확장만 뽑는다.
// server=true면 key_share=선택 그룹(NegotiatedGroup), false면 supported_groups=후보(OfferedGroups).
func parseExtensions(c *cursor, hs *Handshake, server bool) {
	extBlock, ok := c.vec(2)
	if !ok {
		return // 확장 없음(캡처 절단 등) — 있는 것만
	}
	ec := &cursor{b: extBlock}
	for {
		etype, ok := ec.u16()
		if !ok {
			return
		}
		edata, ok := ec.vec(2)
		if !ok {
			return
		}
		switch etype {
		case 0x000a: // supported_groups
			for _, g := range readU16List(edata, 2) {
				hs.OfferedGroups = append(hs.OfferedGroups, tlsGroupName(g))
			}
		case 0x0033: // key_share
			if server {
				// ServerHello: server_share = group(2)+keylen(2)+key → 선택된 그룹.
				if len(edata) >= 2 {
					hs.NegotiatedGroup = tlsGroupName(binary.BigEndian.Uint16(edata[:2]))
				}
			} else {
				// ClientHello: client_shares = len(2) + [group(2)+keylen(2)+key]...
				kc := &cursor{b: edata}
				shares, ok := kc.vec(2)
				if ok {
					sc := &cursor{b: shares}
					for {
						g, ok := sc.u16()
						if !ok {
							break
						}
						hs.OfferedGroups = appendUnique(hs.OfferedGroups, tlsGroupName(g))
						if !sc.skipVec(2) { // key_exchange
							break
						}
					}
				}
			}
		case 0x002b: // supported_versions
			if server {
				if v, ok := (&cursor{b: edata}).u16(); ok {
					hs.Version = tlsVersionName(v)
				}
			} else if len(edata) >= 1 {
				// ClientHello: list_len(1) + versions(2). TLS1.3 있으면 채택.
				for _, v := range readU16List(edata[1:], 0) {
					if v == 0x0304 {
						hs.Version = "TLS1.3"
					}
				}
			}
		}
	}
}
