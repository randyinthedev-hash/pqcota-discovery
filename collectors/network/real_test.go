package network_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/posture"
	"github.com/randyinthedev-hash/pqcota-discovery/collectors/network"
)

// capRecorder — net.Conn을 감싸 읽은 바이트(상대→이쪽 방향)를 누적한다. 실 핸드셰이크 관측 모사.
type capRecorder struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *capRecorder) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.buf = append(c.buf, p[:n]...)
		c.mu.Unlock()
	}
	return n, err
}

func (c *capRecorder) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// TD-NETWORK-17: 실 crypto/tls 핸드셰이크를 관측 → 파서가 진짜 와이어 ClientHello/ServerHello를 읽는다.
// Go 1.24+는 X25519MLKEM768을 지원하므로 강제 협상해 실제 PQC 등급을 관측한다.
func TestRealTLSHandshake(t *testing.T) {
	cert := selfSignedCert(t)
	cli, srv := net.Pipe()
	cliRec := &capRecorder{Conn: cli} // 서버→클라이언트(ServerHello) 누적
	srvRec := &capRecorder{Conn: srv} // 클라이언트→서버(ClientHello) 누적

	curves := []tls.CurveID{tls.X25519MLKEM768}
	serverCfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   curves,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := tls.Server(srvRec, serverCfg)
		_ = s.Handshake()
	}()
	c := tls.Client(cliRec, clientCfg)
	if err := c.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	wg.Wait()
	// tls.Conn.Close()는 net.Pipe에서 close_notify write 5s 데드라인에 걸리므로 원시 파이프만 닫는다.
	cli.Close()
	srv.Close()

	// 서버가 읽은 첫 레코드 = 실제 ClientHello.
	ch, err := network.ParseTLSHandshake(srvRec.bytes())
	if err != nil {
		t.Fatalf("parsing the real ClientHello failed: %v", err)
	}
	if ch.Role != "client" {
		t.Errorf("role = %s, want client", ch.Role)
	}
	if !containsStr(ch.OfferedGroups, "X25519MLKEM768") {
		t.Errorf("X25519MLKEM768 missing from the real ClientHello supported_groups: %v", ch.OfferedGroups)
	}

	// 클라이언트가 읽은 첫 레코드 = 실제 ServerHello.
	sh, err := network.ParseTLSHandshake(cliRec.bytes())
	if err != nil {
		t.Fatalf("parsing the real ServerHello failed: %v", err)
	}
	if sh.NegotiatedGroup != "X25519MLKEM768" {
		t.Errorf("real ServerHello negotiated_group = %q, want X25519MLKEM768", sh.NegotiatedGroup)
	}
	if posture.Classify(sh.NegotiatedGroup, sh.Cipher) != discoveryv1.QuantumPosture_QUANTUM_POSTURE_PQC_HYBRID {
		t.Error("the real negotiated group must classify as PQC_HYBRID (🟢)")
	}
	t.Logf("real TLS observation: negotiated=%s cipher=%s version=%s", sh.NegotiatedGroup, sh.Cipher, sh.Version)
}

// TD-NETWORK-18: 로컬 sshd(실물)의 KEXINIT를 직접 수신해 파싱 → 실제 협상 등급 관측.
func TestRealSSHKexInit(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:22", 2*time.Second)
	if err != nil {
		t.Skip("no local sshd (:22) — skipping the real SSH observation")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 클라이언트 식별 문자열 전송(서버가 KEX 진행하도록).
	if _, err := conn.Write([]byte("SSH-2.0-pqcota-probe\r\n")); err != nil {
		t.Fatalf("ident write: %v", err)
	}
	br := bufio.NewReader(conn)
	// 서버 배너 라인.
	banner, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the banner: %v", err)
	}
	t.Logf("server banner: %s", strings.TrimSpace(banner))

	// 이어지는 바이트 = 첫 바이너리 패킷(KEXINIT). 넉넉히 읽어 파싱.
	buf := make([]byte, 4096)
	n, _ := br.Read(buf)
	hs, err := network.ParseSSHKexInit(buf[:n])
	if err != nil {
		t.Fatalf("parsing the real KEXINIT failed (%d bytes): %v", n, err)
	}
	if hs.Protocol != "SSH" || len(hs.OfferedGroups) == 0 {
		t.Fatalf("the KEX list is empty: %+v", hs)
	}
	t.Logf("real SSH KEX: %v", hs.OfferedGroups)
	if !containsSubstr(hs.OfferedGroups, "sntrup761x25519") {
		t.Errorf("OpenSSH 9.x is expected to offer sntrup761x25519, got %v", hs.OfferedGroups)
	}
	// 실물 서버의 제안을 봤어도 그것만으로 협상을 단정하지 않는다 — 상대 목록을 봐야 안다(§2.5).
	// (이 축을 안 봐서 "제안=협상" 결함이 실물 테스트도 통과했다.)
	if hs.NegotiatedGroup != "" {
		t.Errorf("negotiated was filled in from a single KEXINIT observation: %q", hs.NegotiatedGroup)
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqcota-test"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"pqcota-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsSubstr(s []string, sub string) bool {
	for _, x := range s {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}
