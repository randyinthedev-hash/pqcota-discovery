package network

import (
	"context"
	"errors"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"google.golang.org/grpc"
)

// ErrCaptureUnavailable — 캡처 자체가 불가함(예: CAP_NET_RAW 없음). RPC 실패가 아니라
// 완전성 갭으로 강등한다(§2.6). 라이브 소스가 소켓을 못 열면 이 오류로 감싸 반환한다.
var ErrCaptureUnavailable = errors.New("network: capture unavailable (permission/interface)")

// Observation — 관측 소스가 내놓는 한 핸드셰이크(연결 튜플 + 파싱 결과).
type Observation struct {
	Conn ConnTuple
	HS   *Handshake
}

// Source — 관측 소스 추상. 라이브 pcap 캡처는 별도(cgo/libpcap) 구현, 순수 테스트는 슬라이스 소스.
// 이 경계 덕분에 서비스·엣지 로직은 libpcap 의존 없이 TDD된다.
type Source interface {
	Observe(nodes []string, opts map[string]string) ([]Observation, error)
}

// TruncatingSource — 관측 구간을 끝까지 채우지 못한 소스가 그 사실을 알리는 선택 인터페이스.
// Observe가 오류를 돌려주지 않아도(부분 관측은 성공이다) 구간이 중단됐으면 결과가 구간 전체를
// 대표하지 않는다. 중단과 무관측을 같은 얼굴로 내보내면 결함이 갭으로 위장된다(§2.6).
type TruncatingSource interface {
	// WindowTruncated — 중단됐나, 그리고 사유. 중단되지 않았으면 (false, nil).
	WindowTruncated() (bool, error)
}

// Service — network-collector를 intake 계약(§1.6)으로 노출한다. 코어는 뒤가 pcap인지 모른다.
type Service struct {
	discoveryv1.UnimplementedCollectorServer
	Source Source          // 관측 소스(주입)
	Self   map[string]bool // 자기참조 회피용 자기 주소/노드 집합(§2.6)
}

func NewService(src Source, self map[string]bool) *Service {
	return &Service{Source: src, Self: self}
}

// Describe — 능력 신고(TD-NETWORK-10). 네트워크 계층·수동 관측·비침습.
func (s *Service) Describe(_ context.Context, _ *discoveryv1.DescribeRequest) (*discoveryv1.CollectorCapabilities, error) {
	return &discoveryv1.CollectorCapabilities{
		CollectorId: collectorID,
		Version:     collectorVersion,
		// crypto_runtimes 비움 — 네트워크 엣지는 특정 런타임으로 단정하지 않는다(TLS≠OpenSSL, §2.2).
		Layers: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK},
		DetectionMethods: []commonv1.DetectionMethod{
			commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
		},
		License:  collectorLicense,
		Invasive: false, // 수동·비침습(핸드셰이크 평문만, 복호화 없음, 디스커버리 설계 §2.3)
	}, nil
}

// Collect — 대상 노드별로 관측 엣지를 관측 레인 CollectionResult로 스트림 반환.
func (s *Service) Collect(req *discoveryv1.CollectRequest, stream grpc.ServerStreamingServer[discoveryv1.CollectionResult]) error {
	obs, err := s.Source.Observe(req.GetTargetNodeIds(), req.GetOptions())
	if err != nil {
		// 캡처 불가(권한 등)는 RPC 실패가 아니라 노드별 완전성 갭으로 강등한다(TD-NETWORK-13).
		if errors.Is(err, ErrCaptureUnavailable) {
			for _, n := range req.GetTargetNodeIds() {
				if e := stream.Send(DegradedResult(n, "network capture unavailable (CAP_NET_RAW etc.) — not observed (not absent): "+err.Error())); e != nil {
					return e
				}
			}
			return nil
		}
		return err
	}
	// 노드(캡처 호스트)별로 엣지를 모은다.
	byNode := map[string][]*discoveryv1.ObservedEdge{}
	order := []string{}
	for _, o := range obs {
		if o.HS == nil || !ShouldObserve(o.Conn, s.Self) {
			continue // 자기참조·빈 관측 제외(§2.6)
		}
		n := o.Conn.SrcNode
		if _, seen := byNode[n]; !seen {
			order = append(order, n)
		}
		byNode[n] = append(byNode[n], BuildEdge(o.Conn, o.HS))
	}
	note := ""
	if ts, ok := s.Source.(TruncatingSource); ok {
		if cut, cause := ts.WindowTruncated(); cut {
			// 구간이 중단됐으면 관측 결과가 구간 전체를 대표하지 않는다 — 엣지가 없더라도
			// "핸드셰이크 없음"이 아니라 "끝까지 관측하지 못했음"이다.
			note = "the observation window was cut short — this result does not represent the whole window (unobserved != absent)"
			if cause != nil {
				note += ": " + cause.Error()
			}
		}
	}
	// 중단됐는데 엣지가 하나도 없으면 노드별 결과 자체가 안 나가 사실이 사라진다.
	if note != "" && len(order) == 0 {
		for _, n := range req.GetTargetNodeIds() {
			if err := stream.Send(BuildResult(n, nil, note)); err != nil {
				return err
			}
		}
		return nil
	}
	for _, n := range order {
		if err := stream.Send(BuildResult(n, byNode[n], note)); err != nil {
			return err
		}
	}
	return nil
}
