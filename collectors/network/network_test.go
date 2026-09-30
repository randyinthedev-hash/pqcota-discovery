package network_test

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/posture"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/network"
	"google.golang.org/grpc"
)

// ── 픽스처 빌더 (RFC 8446/4253 와이어 포맷; 파서와 독립적인 ground truth) ──

func u16b(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func vec16(data []byte) []byte { return append(u16b(uint16(len(data))), data...) }
func vec8(data []byte) []byte  { return append([]byte{byte(len(data))}, data...) }

func tlsRecord(handshake []byte) []byte {
	return append([]byte{0x16, 0x03, 0x01}, vec16(handshake)...)
}

func handshakeMsg(msgType byte, body []byte) []byte {
	l := len(body)
	return append([]byte{msgType, byte(l >> 16), byte(l >> 8), byte(l)}, body...)
}

func tlsExt(etype uint16, data []byte) []byte {
	return append(u16b(etype), vec16(data)...)
}

// clientHello — supported_groups [x25519, X25519MLKEM768] 담은 ClientHello 레코드.
func clientHelloMLKEM() []byte {
	groups := append(u16b(0x001d), u16b(0x11ec)...) // x25519, X25519MLKEM768
	sg := tlsExt(0x000a, vec16(groups))             // supported_groups: list_len(2)+groups
	sv := tlsExt(0x002b, vec8(u16b(0x0304)))        // supported_versions: list_len(1)+TLS1.3
	exts := append(sg, sv...)
	body := []byte{0x03, 0x03}                  // client_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, vec8(nil)...)           // session_id (empty)
	body = append(body, vec16(u16b(0x1301))...) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, vec8([]byte{0x00})...)  // compression_methods: null
	body = append(body, vec16(exts)...)         // extensions
	return tlsRecord(handshakeMsg(1, body))
}

// serverHelloX25519MLKEM — key_share=X25519MLKEM768 선택한 ServerHello 레코드.
func serverHelloX25519MLKEM() []byte {
	share := append(u16b(0x11ec), vec16(make([]byte, 32))...) // group + key_exchange(len2+key)
	ks := tlsExt(0x0033, share)                               // key_share (server_share)
	sv := tlsExt(0x002b, u16b(0x0304))                        // supported_versions: selected TLS1.3
	exts := append(sv, ks...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, vec8(nil)...)
	body = append(body, u16b(0x1301)...) // cipher_suite
	body = append(body, 0x00)            // compression_method
	body = append(body, vec16(exts)...)
	return tlsRecord(handshakeMsg(2, body))
}

// sshKexInitSntrup — sntrup761x25519 최선호로 담은 SSH KEXINIT 패킷.
func sshKexInitSntrup() []byte {
	kex := "sntrup761x25519-sha512,curve25519-sha256,ecdh-sha2-nistp256"
	// SSH_MSG_KEXINIT = 20 (RFC 4253 §12). 구현 상수를 빌려 쓰면 그 값이 틀려도 통과한다.
	payload := []byte{20}
	payload = append(payload, make([]byte, 16)...) // cookie
	nl := make([]byte, 4)
	binary.BigEndian.PutUint32(nl, uint32(len(kex)))
	payload = append(payload, nl...)
	payload = append(payload, []byte(kex)...)
	padLen := byte(0)
	pkt := make([]byte, 4)
	binary.BigEndian.PutUint32(pkt, uint32(len(payload)+1)) // packet_length = payload + padding_length byte
	pkt = append(pkt, padLen)
	pkt = append(pkt, payload...)
	return pkt
}

// ── TD-NETWORK-1: ClientHello supported_groups 추출 ──
func TestParseClientHello(t *testing.T) {
	hs, err := network.ParseTLSHandshake(clientHelloMLKEM())
	if err != nil {
		t.Fatal(err)
	}
	if hs.Protocol != "TLS" || hs.Role != "client" {
		t.Errorf("protocol/role = %s/%s", hs.Protocol, hs.Role)
	}
	if hs.Version != "TLS1.3" {
		t.Errorf("version = %s, want TLS1.3", hs.Version)
	}
	want := map[string]bool{"x25519": false, "X25519MLKEM768": false}
	for _, g := range hs.OfferedGroups {
		if _, ok := want[g]; ok {
			want[g] = true
		}
	}
	for g, seen := range want {
		if !seen {
			t.Errorf("supported_groups is missing %s: %v", g, hs.OfferedGroups)
		}
	}
}

// ── TD-NETWORK-2: ServerHello 선택 그룹·cipher·version → negotiated_group + 등급 연동 ──
func TestParseServerHello(t *testing.T) {
	hs, err := network.ParseTLSHandshake(serverHelloX25519MLKEM())
	if err != nil {
		t.Fatal(err)
	}
	if hs.Role != "server" {
		t.Errorf("role = %s, want server", hs.Role)
	}
	if hs.NegotiatedGroup != "X25519MLKEM768" {
		t.Errorf("negotiated_group = %q, want X25519MLKEM768", hs.NegotiatedGroup)
	}
	if hs.Cipher != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("cipher = %q", hs.Cipher)
	}
	if hs.Version != "TLS1.3" {
		t.Errorf("version = %q", hs.Version)
	}
	// 코어 등급 파생과 맞물리는지 교차 확인.
	if posture.Classify(hs.NegotiatedGroup, hs.Cipher) != discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID {
		t.Error("X25519MLKEM768 must map to PQC_HYBRID (🟢)")
	}
}

// ── TD-NETWORK-3: SSH KEXINIT sntrup761x25519 관측 ──
func TestParseSSHKexInit(t *testing.T) {
	hs, err := network.ParseSSHKexInit(sshKexInitSntrup())
	if err != nil {
		t.Fatal(err)
	}
	if hs.Protocol != "SSH" {
		t.Errorf("protocol = %s", hs.Protocol)
	}
	found := false
	for _, k := range hs.OfferedGroups {
		if k == "sntrup761x25519-sha512" {
			found = true
		}
	}
	if !found {
		t.Errorf("the kex list is missing sntrup761x25519-sha512: %v", hs.OfferedGroups)
	}
	// ★ KEXINIT 하나는 **제안**일 뿐이다 — 협상 결과로 채우면 안 된다(§2.1·§2.5).
	// (이전엔 "최선호 → 🟢"를 단언해 버그를 정답으로 못 박고 있었다. 그 단언을 뒤집는다.)
	if hs.NegotiatedGroup != "" {
		t.Errorf("a single KEXINIT must not fill negotiated (offered != negotiated): %q", hs.NegotiatedGroup)
	}
}

// 클라이언트가 sntrup761을 제안해도 **서버가 지원 안 하면 협상은 고전**이다.
// 실측에서 레거시 서버(OpenSSH 8.2, PQC KEX 없음)와의 SSH가 🟢 PQC로 잘못 보고됐다.
func TestNegotiateSSHKex(t *testing.T) {
	modern := []string{"sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "ecdh-sha2-nistp256"}
	legacy := []string{"curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"}

	// 레거시 서버 → 공통은 고전. 여기서 sntrup을 내면 "실제 협상"을 거짓 보고하는 것이다.
	if got := network.NegotiateSSHKex(modern, legacy); got != "curve25519-sha256" {
		t.Errorf("negotiation with a legacy server = %q, want curve25519-sha256 (🔴)", got)
	}
	if posture.Classify(network.NegotiateSSHKex(modern, legacy), "") == discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID {
		t.Error("the server supports no PQC KEX, so it must not be graded 🟢")
	}
	// 양쪽 다 현대 → 클라이언트 선호대로 PQC.
	if got := network.NegotiateSSHKex(modern, modern); got != "sntrup761x25519-sha512@openssh.com" {
		t.Errorf("modern-to-modern negotiation = %q, want sntrup761", got)
	}
	// 선호 순서는 **클라이언트**가 정한다(RFC 4253 §7.1) — 서버 순서가 반대여도 결과는 같다.
	rev := []string{"ecdh-sha2-nistp256", "curve25519-sha256", "sntrup761x25519-sha512@openssh.com"}
	if got := network.NegotiateSSHKex(modern, rev); got != "sntrup761x25519-sha512@openssh.com" {
		t.Errorf("the client preference must decide: %q", got)
	}
	// 한쪽만 관측 → 미상. 본 것만으로 협상을 지어내지 않는다(§2.5).
	for name, got := range map[string]string{
		"server not observed": network.NegotiateSSHKex(modern, nil),
		"client not observed": network.NegotiateSSHKex(nil, modern),
		"no common algorithm": network.NegotiateSSHKex([]string{"a"}, []string{"b"}),
	} {
		if got != "" {
			t.Errorf("%s: the negotiation must be unknown, got %q", name, got)
		}
	}
	// 미상은 ⚪로 분류되어야 한다(🟢/🔴 어느 쪽으로도 단정하지 않는다).
	if p := posture.Classify("", ""); p == discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID ||
		p == discoveryv1.QuantumPosture_QUANTUM_POSTURE_CLASSICAL {
		t.Errorf("an unknown negotiation must grade as unknown: %v", p)
	}
}

// ── TD-NETWORK-4: 파싱 → ObservedEdge 빌드 ──
func TestBuildEdge(t *testing.T) {
	hs, _ := network.ParseTLSHandshake(serverHelloX25519MLKEM())
	conn := network.ConnTuple{SrcNode: "web-01", DstAddr: "10.0.1.20:8443", Port: 8443}
	e := network.BuildEdge(conn, hs)
	if e.GetSrcNodeId() != "web-01" || e.GetPort() != 8443 {
		t.Errorf("tuple mapping failed: %+v", e)
	}
	if e.GetProtocol() != discoveryv1.NetworkProtocol_NETWORK_PROTOCOL_TLS {
		t.Errorf("protocol = %v", e.GetProtocol())
	}
	if e.GetRole() != discoveryv1.EdgeRole_EDGE_ROLE_SERVER {
		t.Errorf("role = %v, want SERVER(ServerHello)", e.GetRole())
	}
	if e.GetNegotiatedGroup() != "X25519MLKEM768" {
		t.Errorf("negotiated_group = %q", e.GetNegotiatedGroup())
	}
	if e.GetDetectionMethod() != commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION {
		t.Errorf("detection_method = %v", e.GetDetectionMethod())
	}
}

// ── TD-NETWORK-5: 암호화된 핸드셰이크(QUIC) → 그룹 불명, 고전 단정 금지 ──
func TestQUICUnknownPosture(t *testing.T) {
	hs := &network.Handshake{Protocol: "QUIC", NegotiatedGroup: ""} // 협상 파라미터 관측하지 못함
	e := network.BuildEdge(network.ConnTuple{SrcNode: "web", DstAddr: "203.0.113.5:443"}, hs)
	if e.GetNegotiatedGroup() != "" {
		t.Error("QUIC must leave the negotiated group unknown (empty string)")
	}
	if posture.Classify(e.GetNegotiatedGroup(), "") != discoveryv1.QuantumPosture_QUANTUM_POSTURE_UNSPECIFIED {
		t.Error("unknown means ⚪ UNSPECIFIED — never assume classical")
	}
}

// ── TD-NETWORK-6: BuildResult 관측 레인 — NETWORK 커버, crypto_runtime 미상(CBOM 없음) ──
func TestBuildResult(t *testing.T) {
	e := network.BuildEdge(network.ConnTuple{SrcNode: "web", DstAddr: "a:443"}, &network.Handshake{Protocol: "TLS", NegotiatedGroup: "x25519"})
	res := network.BuildResult("web", []*discoveryv1.ObservedEdge{e}, "")
	if len(res.GetObservedEdges()) != 1 {
		t.Fatalf("observed_edges = %d", len(res.GetObservedEdges()))
	}
	if len(res.GetCbomCyclonedx()) != 0 {
		t.Error("a network edge does not fill the node-internal CBOM (unknown)")
	}
	covered := res.GetCompleteness().GetLayersCovered()
	if len(covered) != 1 || covered[0] != commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK {
		t.Errorf("layers_covered = %v, want [NETWORK]", covered)
	}
}

// ── TD-NETWORK-7: 관측 구간 갭 note (미관측 ≠ 부재) ──
func TestBuildResult_windowNote(t *testing.T) {
	res := network.BuildResult("web", nil, "")
	if res.GetCompleteness().GetNote() == "" {
		t.Error("the window limit must be stated honestly in the completeness note (TD-NETWORK-7)")
	}
}

// ── TD-NETWORK-8: 자기참조 회피 ──
func TestShouldObserve_selfReference(t *testing.T) {
	self := map[string]bool{"web-01": true, "10.0.1.10:443": true}
	if network.ShouldObserve(network.ConnTuple{SrcNode: "web-01", DstNodeID: "web-01"}, self) {
		t.Error("a peer that is this node itself must be excluded")
	}
	if network.ShouldObserve(network.ConnTuple{SrcNode: "web-01", DstAddr: "10.0.1.10:443"}, self) {
		t.Error("a peer at this node's own address must be excluded")
	}
	if !network.ShouldObserve(network.ConnTuple{SrcNode: "web-01", DstAddr: "10.0.1.20:443"}, self) {
		t.Error("a normal peer must be observed")
	}
}

// ── TD-NETWORK-10: off-scope dst = 원시 주소(코어 등재판정 입력) ──
func TestBuildEdge_offScopeRawAddr(t *testing.T) {
	e := network.BuildEdge(network.ConnTuple{SrcNode: "web", DstNodeID: "", DstAddr: "203.0.113.5:443", Port: 443},
		&network.Handshake{Protocol: "TLS", NegotiatedGroup: "x25519"})
	if e.GetDstNodeId() != "" {
		t.Error("an unresolved peer must leave dst_node_id empty (the core decides registration)")
	}
	if e.GetDstAddr() != "203.0.113.5:443" {
		t.Errorf("dst_addr = %q", e.GetDstAddr())
	}
}

// ── TD-NETWORK-11: Describe 능력 신고 ──
func TestDescribe(t *testing.T) {
	caps, _ := network.NewService(nil, nil).Describe(context.Background(), &discoveryv1.DescribeRequest{})
	if caps.GetCollectorId() != "network-collector" {
		t.Errorf("collector_id = %q", caps.GetCollectorId())
	}
	if caps.GetInvasive() {
		t.Error("it must be passive and non-invasive (invasive=false)")
	}
	if len(caps.GetLayers()) != 1 || caps.GetLayers()[0] != commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK {
		t.Errorf("layers = %v, want [NETWORK]", caps.GetLayers())
	}
	if len(caps.GetCryptoRuntimes()) != 0 {
		t.Error("a network edge has an unknown runtime → crypto_runtimes must be empty")
	}
}

// ── Collect: self-reference 필터 + 노드별 스트림 ──
type sliceSource struct{ obs []network.Observation }

func (s sliceSource) Observe([]string, map[string]string) ([]network.Observation, error) {
	return s.obs, nil
}

type fakeStream struct {
	grpc.ServerStreamingServer[discoveryv1.CollectionResult]
	sent []*discoveryv1.CollectionResult
}

func (f *fakeStream) Send(r *discoveryv1.CollectionResult) error {
	f.sent = append(f.sent, r)
	return nil
}

func TestCollect_filtersSelf(t *testing.T) {
	hs, _ := network.ParseTLSHandshake(serverHelloX25519MLKEM())
	src := sliceSource{obs: []network.Observation{
		{Conn: network.ConnTuple{SrcNode: "web", DstAddr: "10.0.1.20:8443"}, HS: hs},
		{Conn: network.ConnTuple{SrcNode: "web", DstAddr: "127.0.0.1:8443"}, HS: hs}, // 자기참조
	}}
	svc := network.NewService(src, map[string]bool{"127.0.0.1:8443": true})
	fs := &fakeStream{}
	if err := svc.Collect(&discoveryv1.CollectRequest{TargetNodeIds: []string{"web"}}, fs); err != nil {
		t.Fatal(err)
	}
	if len(fs.sent) != 1 {
		t.Fatalf("%d results, want 1 (node web)", len(fs.sent))
	}
	if n := len(fs.sent[0].GetObservedEdges()); n != 1 {
		t.Errorf("%d edges, want 1 (self-reference excluded)", n)
	}
}

// ── 구간이 중단됐을 때: 중단과 무관측을 같은 얼굴로 내보내지 않는다 ──
type truncSource struct {
	sliceSource
	cause error
}

func (t truncSource) WindowTruncated() (bool, error) { return true, t.cause }

// TD-NETWORK-19 — 구간이 읽기 오류로 중단되면 결과가 구간 전체를 대표하지 않는다. 엣지가 하나도 없을
// 때가 특히 위험하다 — 아무 말도 안 하면 "핸드셰이크 없음"으로 읽혀 결함이 갭으로
// 위장된다(§2.6). 그래서 엣지가 없어도 노드별 결과를 내고 완전성 노트에 중단을 적는다.
func TestCollect_marksTruncatedWindow(t *testing.T) {
	const want = "observation window was cut short"
	cause := errors.New("recvfrom: input/output error")

	// ① 엣지가 하나도 없는데 구간이 중단된 경우.
	svc := network.NewService(truncSource{cause: cause}, nil)
	fs := &fakeStream{}
	if err := svc.Collect(&discoveryv1.CollectRequest{TargetNodeIds: []string{"web"}}, fs); err != nil {
		t.Fatal(err)
	}
	if len(fs.sent) != 1 {
		t.Fatalf("%d results — even with no edges, the truncation must be reported", len(fs.sent))
	}
	note := fs.sent[0].GetCompleteness().GetNote()
	if !strings.Contains(note, want) || !strings.Contains(note, cause.Error()) {
		t.Errorf("the truncation and its reason are missing from the completeness note: %q", note)
	}

	// ② 엣지가 있어도 그 결과 역시 구간 전체를 대표하지 않는다.
	hs, _ := network.ParseTLSHandshake(serverHelloX25519MLKEM())
	src := truncSource{sliceSource: sliceSource{obs: []network.Observation{
		{Conn: network.ConnTuple{SrcNode: "web", DstAddr: "10.0.1.20:8443"}, HS: hs}}}}
	fs2 := &fakeStream{}
	if err := network.NewService(src, nil).Collect(
		&discoveryv1.CollectRequest{TargetNodeIds: []string{"web"}}, fs2); err != nil {
		t.Fatal(err)
	}
	if len(fs2.sent) != 1 || !strings.Contains(fs2.sent[0].GetCompleteness().GetNote(), want) {
		t.Errorf("truncation must be reported even when edges exist: %+v", fs2.sent)
	}

	// ③ 중단되지 않은 소스는 이 문구가 뜨면 안 된다 — 매번 뜨는 경고는 읽히지 않는다.
	fs3 := &fakeStream{}
	if err := network.NewService(src.sliceSource, nil).Collect(
		&discoveryv1.CollectRequest{TargetNodeIds: []string{"web"}}, fs3); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fs3.sent[0].GetCompleteness().GetNote(), want) {
		t.Error("a truncation note appeared although nothing was truncated")
	}
}
