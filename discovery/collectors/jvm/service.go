package jvm

import (
	"context"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"google.golang.org/grpc"
)

// Service — jvm-collector를 intake 계약(§1.6)으로 낸다. openssl-collector와 대칭.
// Runner는 실제 attach 사이드카(discovery/collectors/jvm/collector)를 실행해 provider 출력을 얻는다.
// 테스트는 Runner를 주입하고, 실배포는 Java 사이드카 서브프로세스를 호출한다(라이선스 정리 — 프로세스 분리).
type Service struct {
	discoveryv1.UnimplementedCollectorServer
	Runner func(node string, opts map[string]string) (Collected, error)
}

func NewService(runner func(string, map[string]string) (Collected, error)) *Service {
	return &Service{Runner: runner}
}

func (s *Service) Describe(_ context.Context, _ *discoveryv1.DescribeRequest) (*discoveryv1.CollectorCapabilities, error) {
	return &discoveryv1.CollectorCapabilities{
		CollectorId:    "jvm-collector",
		Version:        "0.1.0",
		CryptoRuntimes: []commonv1.CryptoRuntime{commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA},
		Layers: []commonv1.CollectionLayer{
			commonv1.CollectionLayer_COLLECTION_LAYER_JVM_INTROSPECTION,
			commonv1.CollectionLayer_COLLECTION_LAYER_ARTIFACT,
		},
		DetectionMethods: []commonv1.DetectionMethod{
			commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
			commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT,
		},
		License:  "Apache-2.0",
		Invasive: false,
	}, nil
}

func (s *Service) Collect(req *discoveryv1.CollectRequest, stream grpc.ServerStreamingServer[discoveryv1.CollectionResult]) error {
	for _, node := range req.GetTargetNodeIds() {
		var c Collected
		if s.Runner != nil {
			cc, err := s.Runner(node, req.GetOptions())
			if err != nil {
				return err
			}
			c = cc
		}
		if err := stream.Send(BuildResult(node, c)); err != nil {
			return err
		}
	}
	return nil
}
