// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// now — 수집 시각의 출처. 테스트가 갈아끼울 수 있게 변수로 둔다(시그니처는 건드리지 않는다).
var now = time.Now

const (
	collectorID      = "network-collector"
	collectorVersion = "0.1.0"
	collectorLicense = "Apache-2.0"
)

// ConnTuple — 관측된 TCP 연결의 종단 정보(캡처 계층이 채운다). 등급·협상은 Handshake에.
type ConnTuple struct {
	SrcNode      string // 캡처 호스트 = 스코프 노드 ID(앵커, 알려짐)
	DstNodeID    string // 코어가 스코프 마스터로 이어 붙였으면 채워짐. 보통 "" (코어가 사후에 잇는다)
	DstAddr      string // 원시 상대 주소 "ip:port" — off-scope 판정 근거(§1.4, IC-E3)
	Port         uint32
	SrcInitiated bool // src가 TCP 연결 개시자면 src=client (역할 방향의 근거)
}

// BuildEdge — 파싱된 핸드셰이크 + 연결 튜플 → 관측 통신 엣지(ObservedEdge). TD-NETWORK-4.
// 등급은 넣지 않는다 — negotiated_group만 채우고 코어가 분류(§1.2).
func BuildEdge(conn ConnTuple, hs *Handshake) *discoveryv1.ObservedEdge {
	e := &discoveryv1.ObservedEdge{
		SrcNodeId:       conn.SrcNode,
		DstNodeId:       conn.DstNodeID,
		DstAddr:         conn.DstAddr,
		Port:            conn.Port,
		Protocol:        networkProtocol(hs.Protocol),
		Role:            edgeRole(hs, conn.SrcInitiated),
		NegotiatedGroup: hs.NegotiatedGroup,
		Cipher:          hs.Cipher,
		// 수동 관측이지만 실제 협상을 직접 봤으므로 confirmed로 파생되는 방법을 쓴다(§2.3).
		DetectionMethod: commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
		ObservedCount:   1,
	}
	return e
}

// ShouldObserve — 자기참조(자기 노드 대상/자기 트래픽) 핸드셰이크는 엣지에서 제외한다(TD-NETWORK-8, §2.6).
// selfAddrs: 캡처 호스트 자신의 주소·노드ID 집합. dst가 여기 속하면 관측 대상 아님.
func ShouldObserve(conn ConnTuple, selfAddrs map[string]bool) bool {
	if conn.DstNodeID != "" && conn.DstNodeID == conn.SrcNode {
		return false
	}
	if selfAddrs[conn.DstAddr] || selfAddrs[conn.DstNodeID] {
		return false
	}
	return true
}

// BuildResult — 관측 엣지들을 관측 레인 CollectionResult로 조립한다(TD-NETWORK-6).
// crypto_runtime은 채우지 않는다(TLS≠OpenSSL, 노드 내부 Finding 아님). NETWORK 계층만 커버.
// windowNote: 관측 구간 한계를 정직히 기록(미관측 링크 ≠ 부재, TD-NETWORK-7/§2.6).
func BuildResult(node string, edges []*discoveryv1.ObservedEdge, windowNote string) *discoveryv1.CollectionResult {
	if windowNote == "" {
		windowNote = "only handshakes that flowed during the observation window — idle, batch and DR links are unobserved (gap != absence)"
	}
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      collectorID,
			CollectorVersion: collectorVersion,
			DetectionMethod:  commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			CollectedAt:      timestamppb.New(now()),
			TargetNodeId:     node,
			CollectorLicense: collectorLicense,
		},
		// raw_format·raw_capture를 비운다 — 이 collector의 네이티브 형식은 **observed_edges 그 자체**라
		// 따로 담으면 같은 관측을 두 벌 나르게 된다. 재정규화(등급 파생)도 edges에서 다시 한다.
		Completeness: &commonv1.Completeness{
			LayersCovered: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK},
			Note:          windowNote,
		},
		ObservedEdges: edges,
	}
}

// DegradedResult — 캡처 자체가 불가할 때(예: CAP_NET_RAW 없음) 관측 대신 완전성 갭을 낸다(TD-NETWORK-13).
// NETWORK 계층을 layers_missing으로 표기 — "관측하지 못함"을 "연결 없음/부재"로 처리 금지(§2.6).
func DegradedResult(node, reason string) *discoveryv1.CollectionResult {
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			CollectorId:      collectorID,
			CollectorVersion: collectorVersion,
			DetectionMethod:  commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			CollectedAt:      timestamppb.New(now()),
			TargetNodeId:     node,
			CollectorLicense: collectorLicense,
		},
		// 포집 자체가 없었으므로 원본도 없다.
		Completeness: &commonv1.Completeness{
			LayersMissing: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK},
			Note:          reason,
		},
	}
}

func networkProtocol(p string) discoveryv1.NetworkProtocol {
	switch p {
	case "TLS":
		return discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS
	case "SSH":
		return discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_SSH
	case "QUIC":
		return discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_QUIC
	default:
		return discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_UNSPECIFIED
	}
}

// edgeRole — 역할 방향. TLS는 핸드셰이크 메시지가 확정(ClientHello/ServerHello),
// SSH 등 미상이면 TCP 개시자로 추정.
func edgeRole(hs *Handshake, srcInitiated bool) discoveryv1.EdgeRole {
	switch hs.Role {
	case "client":
		return discoveryv1.EdgeRole_EDGE_ROLE_CLIENT
	case "server":
		return discoveryv1.EdgeRole_EDGE_ROLE_SERVER
	}
	if srcInitiated {
		return discoveryv1.EdgeRole_EDGE_ROLE_CLIENT
	}
	return discoveryv1.EdgeRole_EDGE_ROLE_UNSPECIFIED
}
