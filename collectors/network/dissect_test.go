package network_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/network"
)

// ethIPv4TCP — 페이로드를 Ethernet II + IPv4 + TCP 프레임으로 감싼다(디섹션 테스트용).
func ethIPv4TCP(srcPort, dstPort uint16, payload []byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800) // IPv4
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[9] = 6 // TCP
	copy(ip[12:16], []byte{10, 0, 1, 10})
	copy(ip[16:20], []byte{10, 0, 1, 20})
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4 // data offset = 5 words (20B)
	frame := append(append(append(eth, ip...), tcp...), payload...)
	return frame
}

// ethIPv6TCP — 페이로드를 Ethernet II + IPv6 + TCP 프레임으로 감싼다(확장 헤더 없음).
func ethIPv6TCP(srcPort, dstPort uint16, payload []byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x86DD) // IPv6
	ip := make([]byte, 40)
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(20+len(payload)))
	ip[6] = 6    // Next Header = TCP
	ip[7] = 64   // hop limit
	ip[8] = 0x20 // src fd00::1 류
	ip[23] = 0x01
	ip[24] = 0x20 // dst
	ip[39] = 0x02
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4
	return append(append(append(eth, ip...), tcp...), payload...)
}

// IPv6 프레임도 종단 디섹션 + 핸드셰이크 파싱 (IPv6 커버리지 완료).
func TestDissectAndParse_IPv6(t *testing.T) {
	seg, ok := network.DissectTCPPayload(ethIPv6TCP(40000, 8443, serverHelloX25519MLKEM()))
	if !ok {
		t.Fatal("dissecting the IPv6 TCP segment failed")
	}
	if seg.DstPort != 8443 {
		t.Errorf("wrong ports: %+v", seg)
	}
	hs, ok := network.ParseHandshakePayload(seg.Payload)
	if !ok || hs.NegotiatedGroup != "X25519MLKEM768" {
		t.Errorf("wrong IPv6 handshake parse: %+v", hs)
	}
}

// 프레임 → TCP 세그먼트 → 핸드셰이크(실 캡처 파이프라인의 순수 코어).
func TestDissectAndParse_TLS(t *testing.T) {
	frame := ethIPv4TCP(40000, 8443, serverHelloX25519MLKEM())
	seg, ok := network.DissectTCPPayload(frame)
	if !ok {
		t.Fatal("dissecting the TCP segment failed")
	}
	if seg.SrcIP != "10.0.1.10" || seg.DstIP != "10.0.1.20" || seg.DstPort != 8443 {
		t.Errorf("wrong endpoint parse: %+v", seg)
	}
	hs, ok := network.ParseHandshakePayload(seg.Payload)
	if !ok {
		t.Fatal("parsing the handshake failed")
	}
	if hs.Protocol != "TLS" || hs.NegotiatedGroup != "X25519MLKEM768" {
		t.Errorf("parse result: %+v", hs)
	}
}

func TestDissectAndParse_SSH(t *testing.T) {
	frame := ethIPv4TCP(50000, 22, sshKexInitSntrup())
	seg, ok := network.DissectTCPPayload(frame)
	if !ok {
		t.Fatal("dissection failed")
	}
	hs, ok := network.ParseHandshakePayload(seg.Payload)
	if !ok || hs.Protocol != "SSH" {
		t.Fatalf("parsing SSH failed: %+v", hs)
	}
}

func TestDissect_skipsNonTCP(t *testing.T) {
	// 페이로드 없는 세그먼트(SYN 등) → 스킵.
	if _, ok := network.DissectTCPPayload(ethIPv4TCP(1, 2, nil)); ok {
		t.Error("an empty payload must be skipped")
	}
	// 너무 짧은 프레임 → 스킵.
	if _, ok := network.DissectTCPPayload([]byte{1, 2, 3}); ok {
		t.Error("a truncated frame must be skipped")
	}
}

// 강등 경로(TD-NETWORK-13): 소스가 ErrCaptureUnavailable → Collect가 노드별 완전성 갭 결과를 스트림.
type errSource struct{ err error }

func (e errSource) Observe([]string, map[string]string) ([]network.Observation, error) {
	return nil, e.err
}

func TestCollect_degradesOnCaptureUnavailable(t *testing.T) {
	svc := network.NewService(errSource{err: fmt.Errorf("no CAP_NET_RAW: %w", network.ErrCaptureUnavailable)}, nil)
	fs := &fakeStream{}
	if err := svc.Collect(&discoveryv1.CollectRequest{TargetNodeIds: []string{"web-01"}}, fs); err != nil {
		t.Fatalf("a degraded result must not be an RPC failure: %v", err)
	}
	if len(fs.sent) != 1 {
		t.Fatalf("one result per node expected, got %d", len(fs.sent))
	}
	miss := fs.sent[0].GetCompleteness().GetLayersMissing()
	if len(miss) != 1 || miss[0] != commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK {
		t.Errorf("the gap must be at the NETWORK layer: %v", miss)
	}
	if len(fs.sent[0].GetObservedEdges()) != 0 {
		t.Error("a degraded result carries no edges (not absent, not observed)")
	}
}
