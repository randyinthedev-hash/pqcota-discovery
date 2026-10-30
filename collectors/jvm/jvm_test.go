// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package jvm_test

import (
	"context"
	"net"
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/jvm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const attachOutput = `PQCOTA_PROVIDERS_BEGIN
0|SUN|21|sun.security.provider.Sun
12|BC|1.79|org.bouncycastle.jce.provider.BouncyCastleProvider
PQCOTA_PROVIDERS_END`

const fallbackOutput = `PQCOTA_STATIC_FALLBACK_BEGIN
evidence_strength=inferred
gap=runtime-introspection
0|SUN
PQCOTA_STATIC_FALLBACK_END`

func TestParseProviders(t *testing.T) {
	c := jvm.ParseProviders(attachOutput)
	if c.Degraded {
		t.Error("attach succeeded yet Degraded=true")
	}
	if len(c.Providers) != 2 || c.Providers[1].Name != "BC" {
		t.Fatalf("providers = %+v, want [SUN BC]", c.Providers)
	}
	if d := jvm.ParseProviders(fallbackOutput); !d.Degraded {
		t.Error("a static fallback result yet Degraded=false")
	}
}

func TestBuildResult(t *testing.T) {
	res := jvm.BuildResult("cmdb://n1", jvm.ParseProviders(attachOutput))
	cbom := string(res.GetCbomCyclonedx())
	if !strings.Contains(cbom, `"pqcota:crypto_runtime"`) || !strings.Contains(cbom, "SUN,BC") {
		t.Errorf("the CycloneDX body has no jca provider_set: %s", cbom)
	}
	if len(res.GetCompleteness().GetLayersMissing()) != 0 {
		t.Error("attach succeeded yet a gap is present")
	}
	// 정적 폴백 → JVM_INTROSPECTION 갭
	deg := jvm.BuildResult("cmdb://n1", jvm.ParseProviders(fallbackOutput))
	if len(deg.GetCompleteness().GetLayersMissing()) == 0 {
		t.Error("a static fallback with no gap")
	}
}

// 에이전트·프로브의 다섯째 칸(PQC 서비스)을 `pqcota:jca.pqc_services`로 싣는다. 체인은 실측(2026-10-30,
// Temurin 21.0.13 프로브)에서 앞 다섯을 줄였다 — SUN이 ML-DSA를, SunJCE가 ML-KEM을 서비스하고 SunEC는
// 아무것도 서비스하지 않는다. 판은 셋 다 "21"이라 판으로는 21.0.12(둘 다 없음)와 가를 수 없다.
const attachOutputServices = `PQCOTA_PROVIDERS_BEGIN
1|SUN|21|sun.security.provider.Sun|ML-DSA,ML-DSA-44,ML-DSA-65,ML-DSA-87
2|SunRsaSign|21|sun.security.rsa.SunRsaSign|
3|SunEC|21|sun.security.ec.SunEC|
4|SunJSSE|21|sun.security.ssl.SunJSSE|
5|SunJCE|21|com.sun.crypto.provider.SunJCE|ML-KEM,ML-KEM-1024,ML-KEM-512,ML-KEM-768
PQCOTA_PROVIDERS_END`

func TestBuildResultPQCServices(t *testing.T) {
	c := jvm.ParseProviders(attachOutputServices)
	if !c.Providers[2].ServicesSeen || len(c.Providers[2].PQCServices) != 0 {
		t.Errorf("SunEC: services seen and empty expected, got %+v", c.Providers[2])
	}
	cbom := string(jvm.BuildResult("cmdb://n1", c).GetCbomCyclonedx())
	want := `{"name":"pqcota:jca.pqc_services","value":"SUN=ML-DSA|ML-DSA-44|ML-DSA-65|ML-DSA-87,SunRsaSign=,SunEC=,SunJSSE=,SunJCE=ML-KEM|ML-KEM-1024|ML-KEM-512|ML-KEM-768"}`
	if !strings.Contains(cbom, want) {
		t.Errorf("PQC services missing or wrong in the CycloneDX body:\n%s\nwant %s", cbom, want)
	}
}

// 서비스를 보지 않은 출력은 그 속성을 싣지 않는다. 빈 값으로 실으면 「봤는데 없다」로 읽힌다.
func TestBuildResultPQCServicesNotSeen(t *testing.T) {
	for name, out := range map[string]string{
		"four-field output of an older agent": attachOutput,
		"static fallback":                     fallbackOutput,
	} {
		c := jvm.ParseProviders(out)
		for _, p := range c.Providers {
			if p.ServicesSeen {
				t.Errorf("%s: %s marked as services seen", name, p.Name)
			}
		}
		if cbom := string(jvm.BuildResult("cmdb://n1", c).GetCbomCyclonedx()); strings.Contains(cbom, "pqcota:jca.pqc_services") {
			t.Errorf("%s: services were not observed, yet the property is present: %s", name, cbom)
		}
	}
}

func TestJvmServiceContract(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	// Runner 주입: 사이드카 실행 대신 픽스처 반환.
	discoveryv1.RegisterCollectorServer(srv, jvm.NewService(
		func(node string, _ map[string]string) (jvm.Collected, error) {
			return jvm.ParseProviders(attachOutput), nil
		}))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, _ := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	cli := discoveryv1.NewCollectorClient(conn)

	caps, err := cli.Describe(context.Background(), &discoveryv1.DescribeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if caps.GetCollectorId() != "jvm-collector" ||
		caps.GetCryptoRuntimes()[0] != commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA {
		t.Errorf("caps = %+v", caps)
	}

	stream, err := cli.Collect(context.Background(), &discoveryv1.CollectRequest{TargetNodeIds: []string{"cmdb://n1"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if res.GetEnvelope().GetCollectorId() != "jvm-collector" {
		t.Errorf("collector_id = %q", res.GetEnvelope().GetCollectorId())
	}
	if !strings.Contains(string(res.GetCbomCyclonedx()), "SUN,BC") {
		t.Error("the Collect result has no provider_set")
	}
}
