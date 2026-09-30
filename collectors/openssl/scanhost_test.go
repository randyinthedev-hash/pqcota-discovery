//go:build linux

package openssl_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/openssl"
	"google.golang.org/grpc"
)

type fakeStream struct {
	grpc.ServerStreamingServer[discoveryv1.CollectionResult]
	sent []*discoveryv1.CollectionResult
}

func (f *fakeStream) Send(r *discoveryv1.CollectionResult) error {
	f.sent = append(f.sent, r)
	return nil
}

// TD-OPENSSL-5 — 호스트 훑기. 실물 `/proc`을 걷는 자리라 리눅스에서만 돈다. 무엇이 잡히는지는
// 환경에 달렸으므로 개수를 단언하지 않고, **집계가 자기모순이 아닌지**와 관측하지 못한 것을
// 관측하지 못했다고 표시하는지를 본다(§2.6).
func TestScanHostStatsAreConsistent(t *testing.T) {
	dets, st := openssl.ScanHost(registry.DefaultForkSignatures)
	if st.ProcUnavailable {
		t.Skip("/proc is not readable — skipping the host-scan path")
	}
	if st.Accessible < 1 {
		t.Errorf("could not even read our own process: %+v", st)
	}
	if st.WithSSL > st.Accessible {
		t.Errorf("more libssl processes than reachable ones: %+v", st)
	}
	if st.WithSSL == 0 && len(dets) != 0 {
		t.Errorf("no libssl process, yet %d detections", len(dets))
	}
	for _, d := range dets {
		if d.Path == "" || d.Lib == "" {
			t.Errorf("a detection without a path or lib: %+v", d)
		}
		// 시스템 경로면 dynamic, 그 밖(벤더링된 wheel 등)이면 vendored — 그 둘뿐이다.
		if d.BindingMode != "dynamic" && d.BindingMode != "vendored" {
			t.Errorf("binding_mode is outside the vocabulary: %+v", d)
		}
	}
}

// 없는 PID는 오류로 돌려준다 — 빈 결과로 삼키면 "그 프로세스엔 없다"가 된다.
func TestDetectForPIDMissingProcess(t *testing.T) {
	if _, err := openssl.DetectForPID(1<<22, registry.DefaultForkSignatures); err == nil {
		t.Error("a nonexistent PID returned no error — unobserved and absent become indistinguishable")
	}
}

// 자기 프로세스는 읽을 수 있어야 한다(같은 UID). Go 테스트 바이너리가 libssl을 안 물 수도
// 있으므로 탐지 개수는 단언하지 않는다 — 읽기 자체가 되는지와 결과의 모양만 본다.
func TestDetectForPIDSelf(t *testing.T) {
	dets, err := openssl.DetectForPID(os.Getpid(), registry.DefaultForkSignatures)
	if err != nil {
		t.Fatalf("could not read our own /proc: %v", err)
	}
	for _, d := range dets {
		if !filepath.IsAbs(d.Path) {
			t.Errorf("the path must be absolute: %+v", d)
		}
	}
}

// ELF가 아닌 파일에서는 문자열을 지어내지 않고 오류로 돌려준다.
func TestExtractStringsRejectsNonELF(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-an-elf")
	if err := os.WriteFile(p, []byte("OpenSSL 3.0.13  BoringSSL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openssl.ExtractStrings(p, 6); err == nil {
		t.Error("strings were returned for a non-ELF file — that pollutes the input to fork detection")
	}
}

// 실물 ELF에서는 문자열이 나온다. 어느 바이너리든 .rodata에 인쇄가능 문자열이 있다.
func TestExtractStringsOnRealELF(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("could not resolve the executable path")
	}
	ss, err := openssl.ExtractStrings(self, 8)
	if err != nil {
		t.Skipf("the test binary is not an ELF: %v", err)
	}
	if len(ss) == 0 {
		t.Error("a real ELF yielded no strings at all — the fork matcher would always answer unknown")
	}
	for _, s := range ss {
		if len(s) < 8 {
			t.Errorf("a string shorter than minLen slipped in: %q", s)
		}
	}
}

// TD-CONTAINER-2 — 네임스페이스가 갈리거나 권한이 없어 대상 프로세스를 **관측하지 못한** 경우와, 봤는데
// OpenSSL이 **없던** 경우는 다르다. 한 문구로 뭉뚱그리면 결함이 갭처럼, 갭이 부재처럼
// 읽힌다(§2.6).
func TestCollectSeparatesUnseenFromAbsent(t *testing.T) {
	svc := openssl.NewService()
	collect := func(opts map[string]string) *discoveryv1.CollectionResult {
		fs := &fakeStream{}
		if err := svc.Collect(&discoveryv1.CollectRequest{
			TargetNodeIds: []string{"cmdb://n1"}, Options: opts}, fs); err != nil {
			t.Fatal(err)
		}
		if len(fs.sent) != 1 {
			t.Fatalf("%d results, want 1", len(fs.sent))
		}
		return fs.sent[0]
	}

	// ① 관측하지 못함 — 없는 PID. PROCESS는 커버되지 않고 갭으로 남아야 한다.
	unseen := collect(map[string]string{"pid": "4194304"})
	cu := unseen.GetCompleteness()
	if !strings.Contains(cu.GetNote(), "not visible") {
		t.Errorf("the reason for not observing is not reported: %q", cu.GetNote())
	}
	if hasLayer(cu.GetLayersCovered(), commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS) {
		t.Error("nothing was observed, yet PROCESS counts as covered — the gap disappears")
	}
	if !hasLayer(cu.GetLayersMissing(), commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS) {
		t.Errorf("an unobserved layer must remain as a gap: %v", cu.GetLayersMissing())
	}

	// ② 봤는데 없음 — 자기 프로세스(읽을 수 있다). PROCESS는 커버로 세야 한다.
	seen := collect(map[string]string{"pid": strconv.Itoa(os.Getpid())})
	cs := seen.GetCompleteness()
	if strings.Contains(cs.GetNote(), "not visible") {
		t.Errorf("the process was readable, yet it claims nothing was observed: %q", cs.GetNote())
	}
	if !hasLayer(cs.GetLayersCovered(), commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS) {
		t.Errorf("once observed, PROCESS must count as covered: %v", cs.GetLayersCovered())
	}

	// 원본이 없으면 형식 이름도 없어야 한다 — 이름만 있으면 재정규화할 원본이 있는 척이다.
	if unseen.GetRawFormat() != "" && len(unseen.GetRawCapture()) == 0 {
		t.Errorf("raw_format=%q but there is no raw capture", unseen.GetRawFormat())
	}
}

func hasLayer(ls []commonv1.CollectionLayer, want commonv1.CollectionLayer) bool {
	for _, l := range ls {
		if l == want {
			return true
		}
	}
	return false
}
