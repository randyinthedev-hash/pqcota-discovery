package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Segment — 프레임에서 뽑은 TCP 세그먼트(라이브 캡처 파이프라인의 순수 부분).
type Segment struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Payload          []byte
}

// DissectTCPPayload — Ethernet II + IPv4/IPv6 + TCP 프레임에서 TCP 세그먼트를 뽑는다.
// 핸드셰이크 프레임 처리용. 비TCP·VLAN(단일 태그만)·조각화·절단은 정직히 (nil,false)로 스킵한다.
func DissectTCPPayload(frame []byte) (*Segment, bool) {
	if len(frame) < 14 {
		return nil, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	off := 14
	if etherType == 0x8100 { // 802.1Q VLAN 태그 → 4바이트 뒤 실제 ethertype
		if len(frame) < 18 {
			return nil, false
		}
		etherType = binary.BigEndian.Uint16(frame[16:18])
		off = 18
	}

	var srcIP, dstIP string
	var tcp []byte
	switch etherType {
	case 0x0800: // IPv4
		srcIP, dstIP, tcp = ipv4TCP(frame[off:])
	case 0x86DD: // IPv6
		srcIP, dstIP, tcp = ipv6TCP(frame[off:])
	default:
		return nil, false
	}
	if tcp == nil || len(tcp) < 20 {
		return nil, false
	}

	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return nil, false
	}
	seg := &Segment{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: binary.BigEndian.Uint16(tcp[0:2]),
		DstPort: binary.BigEndian.Uint16(tcp[2:4]),
		Payload: tcp[dataOff:],
	}
	if len(seg.Payload) == 0 {
		return nil, false // SYN/ACK 등 페이로드 없는 세그먼트
	}
	return seg, true
}

// ipv4TCP — IPv4 헤더에서 (src, dst, TCP 바이트). TCP 아니면 tcp=nil.
func ipv4TCP(ip []byte) (src, dst string, tcp []byte) {
	if len(ip) < 20 {
		return "", "", nil
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl || ip[9] != 6 { // protocol=TCP
		return "", "", nil
	}
	if total := int(binary.BigEndian.Uint16(ip[2:4])); total >= ihl && total <= len(ip) {
		ip = ip[:total]
	}
	return ipv4Str(ip[12:16]), ipv4Str(ip[16:20]), ip[ihl:]
}

// ipv6TCP — IPv6 고정 헤더(40B) + 확장 헤더 스킵 후 TCP 바이트. 조각화/미지원 확장/비TCP면 tcp=nil.
func ipv6TCP(ip []byte) (src, dst string, tcp []byte) {
	if len(ip) < 40 {
		return "", "", nil
	}
	nh := ip[6] // Next Header
	src = net.IP(ip[8:24]).String()
	dst = net.IP(ip[24:40]).String()
	rest := ip[40:]
	for {
		switch nh {
		case 6: // TCP
			return src, dst, rest
		case 0, 43, 60: // Hop-by-Hop·Routing·Destination 확장(형식: [nextHdr][hdrExtLen] …, 길이=(hdrExtLen+1)*8)
			if len(rest) < 2 {
				return "", "", nil
			}
			hlen := (int(rest[1]) + 1) * 8
			if len(rest) < hlen {
				return "", "", nil
			}
			nh, rest = rest[0], rest[hlen:]
		default: // Fragment(44)·기타 → 조각화된/미지원 핸드셰이크는 정직히 스킵
			return "", "", nil
		}
	}
}

func ipv4Str(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// ParseHandshakePayload — TCP 페이로드를 프로토콜 추정해 파싱한다(TLS 레코드 / SSH 배너·KEXINIT).
// 핸드셰이크가 아니면 (nil,false). 복호화 없이 평문 핸드셰이크만 인식(디스커버리 설계 §2.3).
func ParseHandshakePayload(payload []byte) (*Handshake, bool) {
	if len(payload) == 0 {
		return nil, false
	}
	if payload[0] == 0x16 { // TLS handshake record content_type
		if hs, err := ParseTLSHandshake(payload); err == nil {
			return hs, true
		}
	}
	if bytes.HasPrefix(payload, []byte("SSH-")) || looksLikeSSHKexInit(payload) {
		if hs, err := ParseSSHKexInit(payload); err == nil {
			return hs, true
		}
	}
	return nil, false
}

// looksLikeSSHKexInit — 배너 없이 바로 온 SSH 바이너리 패킷의 첫 KEXINIT(msg=20) 휴리스틱.
func looksLikeSSHKexInit(payload []byte) bool {
	// packet_length(4) + padding_length(1) + msg_code(1). msg_code==20(KEXINIT)이면 강한 신호.
	return len(payload) >= 6 && payload[5] == sshMsgKexInit
}
