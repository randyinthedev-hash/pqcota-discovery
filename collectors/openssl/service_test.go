// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package openssl_test

import (
	"context"
	"net"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/openssl"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// intake 계약 gRPC 라운드트립 검증 — Describe + Collect (§1.6).
// 실제 프로세스 탐지는 Docker 통합에서 검증됨. 여기선 계약 배선을 검증한다.
func TestCollectorServiceContract(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	discoveryv1.RegisterCollectorServer(srv, openssl.NewService())
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cli := discoveryv1.NewCollectorClient(conn)

	// Describe
	caps, err := cli.Describe(context.Background(), &discoveryv1.DescribeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if caps.GetCollectorId() != "openssl-collector" {
		t.Errorf("collector_id = %q", caps.GetCollectorId())
	}
	if caps.GetLicense() != "Apache-2.0" {
		t.Errorf("license = %q, want Apache-2.0", caps.GetLicense())
	}
	if len(caps.GetCryptoRuntimes()) == 0 || caps.GetCryptoRuntimes()[0] != commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL {
		t.Errorf("crypto_runtimes = %v, want [OPENSSL]", caps.GetCryptoRuntimes())
	}

	// Collect (pid 미지정 → 프로세스 계층 갭)
	stream, err := cli.Collect(context.Background(), &discoveryv1.CollectRequest{TargetNodeIds: []string{"cmdb://node/1"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if res.GetEnvelope().GetTargetNodeId() != "cmdb://node/1" {
		t.Errorf("target_node_id = %q", res.GetEnvelope().GetTargetNodeId())
	}
	if res.GetEnvelope().GetCollectorLicense() != "Apache-2.0" {
		t.Errorf("collector_license = %q", res.GetEnvelope().GetCollectorLicense())
	}
	// pid 없으므로 PROCESS 계층이 갭이어야 함(§2.6 갭≠부재).
	missing := res.GetCompleteness().GetLayersMissing()
	if len(missing) == 0 {
		t.Error("expected PROCESS layer gap when no pid provided")
	}
}
