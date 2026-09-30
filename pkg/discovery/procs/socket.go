package procs

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Attribution — 엣지 하나가 어느 앱 것인지 짚은 결과.
//
// **Key가 비었다는 것은 "앱이 없다"가 아니라 "어느 앱인지 밝히지 못했다"이다.** 왜 못 했는지는 Reason에
// 적힌다 — 관측 갭을 "없음"으로 적지 않는 것과 같은 규칙이다(§2.6).
type Attribution struct {
	Key    string // app_key. 못 잡았으면 빈 값
	Kind   string // "systemd-unit" | "exe-path". Key가 비면 함께 빈다
	Reason string // Key가 빈 이유. 잡았으면 빈 값
}

// 어느 앱인지 밝히지 못한 이유 — 사유가 다르면 대응이 다르다.
const (
	// ReasonSocketGone — /proc을 읽는 시점에 그 소켓이 이미 없다. 짧게 붙었다 끊긴 연결이다.
	// 구현으로 틈을 좁힐 수는 있어도 없앨 수 없다.
	ReasonSocketGone = "socket closed between capture and lookup — short-lived connections are missed"
	// ReasonNoPermission — 소켓은 찾았는데 그것을 쥔 프로세스의 fd를 읽을 권한이 없다.
	// CAP_NET_RAW로는 부족하다.
	ReasonNoPermission = "no permission to read the process holding the socket — another user's /proc/PID/fd is unreadable"
	// ReasonAmbiguous — 같은 상대와 통신하는 소켓이 여럿이고 서로 다른 앱이다.
	// **기계가 하나를 고르지 않는다** — 앱을 잘못 짚으면 조치 대상이 바뀐다.
	ReasonAmbiguous = "several apps talk to the same peer — the machine does not pick one"
	// ReasonNoAppKey — 프로세스는 찾았는데 안정 키를 뽑지 못했다(cgroup·exe 둘 다 실패).
	ReasonNoAppKey = "process found but no stable key could be derived"
)

// AttributeRemote — 이 호스트에서 remote(ip:port)로 나간 연결을 연 앱을 찾는다.
//
// 흐름: /proc/net/tcp·tcp6에서 그 상대와 맺은 소켓 inode를 찾고 → /proc/*/fd에서 그 inode를 쥔
// PID들을 찾고 → 그중 **부모 체인에서 가장 얕은 것**을 골라 [AppKey]로 키를 뽑는다.
//
// 가장 얕은 것을 고르는 이유: fd는 상속되므로 부모가 연 연결을 자식들이 그대로 들고 있다.
// 먼저 찾은 PID를 쓰면 연결을 연 쪽이 아니라 그것을 물려받은 쪽을 짚게 된다.
func AttributeRemote(procRoot, remoteIP string, remotePort uint32) Attribution {
	// 한 번 쓰고 버리는 경로 — /proc을 그 자리에서 훑는다. 구간 안에서 여러 번 물을 거면
	// [Attributor]를 쓴다. 그쪽은 비싼 fd 스캔을 짧게 재사용한다.
	a := &Attributor{procRoot: procRoot, ttl: time.Second, now: time.Now}
	return a.Remote(remoteIP, remotePort)
}

// socketsTo — /proc/net/tcp·tcp6에서 remote와 맺은 소켓의 inode들.
func socketsTo(procRoot, remoteIP string, remotePort uint32) ([]uint64, error) {
	want, err := hexAddr(remoteIP, remotePort)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		f, err := os.Open(filepath.Join(procRoot, name))
		if err != nil {
			continue // tcp6가 없는 커널 구성이 있다
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // 헤더
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			if !strings.EqualFold(fields[2], want) {
				continue
			}
			if n, err := strconv.ParseUint(fields[9], 10, 64); err == nil && n != 0 {
				out = append(out, n)
			}
		}
		f.Close()
	}
	return out, nil
}

// hexAddr — "ip:port"를 /proc/net/tcp의 표기(리틀엔디언 hex)로 바꾼다.
func hexAddr(ip string, port uint32) (string, error) {
	b, err := parseIP(ip)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	// /proc/net/tcp는 4바이트 워드마다 호스트 바이트 순서로 적는다.
	for i := 0; i < len(b); i += 4 {
		for j := 3; j >= 0; j-- {
			fmt.Fprintf(&sb, "%02X", b[i+j])
		}
	}
	fmt.Fprintf(&sb, ":%04X", port)
	return sb.String(), nil
}

// scanOwners — /proc 전체를 훑어 **소켓 inode → 그것을 쥔 PID들**을 만든다.
// 두 번째 반환값은 권한 때문에 못 본 프로세스가 있었는지 — 그것도 "어느 앱인지 밝히지 못함"의 사유다.
func scanOwners(procRoot string) (map[uint64][]int, bool) {
	out := map[uint64][]int{}
	denied := false

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out, false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if os.IsPermission(err) {
				denied = true
			}
			continue
		}
		for _, fd := range fds {
			tgt, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			rest, ok := strings.CutPrefix(tgt, "socket:[")
			if !ok {
				continue
			}
			in, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
			if err == nil {
				out[in] = append(out[in], pid)
			}
		}
	}
	return out, denied
}

// shallowest — 같은 소켓을 쥔 PID 집합에서 **부모 체인의 가장 위**를 고른다.
// 집합 안에 조상이 있으면 그쪽이 그 소켓을 연 쪽이다. 뿌리가 여럿이면(예: SCM_RIGHTS로
// 남남끼리 소켓을 주고받은 경우) 결정론을 위해 가장 작은 PID를 고른다.
func shallowest(procRoot string, pids []int) int {
	in := map[int]bool{}
	for _, p := range pids {
		in[p] = true
	}
	roots := map[int]bool{}
	for _, p := range pids {
		cur := p
		for hops := 0; hops < 64; hops++ { // 체인이 집합 밖으로 나갈 때까지
			pp := ppid(procRoot, cur)
			if pp <= 0 || !in[pp] {
				break
			}
			cur = pp
		}
		roots[cur] = true
	}
	best := 0
	for r := range roots {
		if best == 0 || r < best {
			best = r
		}
	}
	return best
}

// parseIP — "1.2.3.4" 또는 IPv6 문자열을 바이트로. IPv4는 4바이트로 줄인다
// (/proc/net/tcp가 4바이트로 적기 때문 — 16바이트로 넘기면 tcp6 표기와 섞인다).
func parseIP(s string) ([]byte, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("not an IP: %q", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, nil
	}
	return ip.To16(), nil
}

// ppid — /proc/PID/status의 PPid. 못 읽으면 0.
func ppid(procRoot string, pid int) int {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "PPid:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				return 0
			}
			return n
		}
	}
	return 0
}

// Attributor — 수집 구간 하나 동안 앱을 짚는 데 쓴다.
//
// **왜 캐시가 필요한가** — 엣지마다 `/proc/*/fd`를 전부 훑으면 프로세스 수 × 엣지 수만큼 읽는다.
// 그렇다고 캡처가 끝난 뒤 한 번에 몰아 하면 짧은 연결을 더 놓친다([AttributeRemote]의 경합).
// 그래서 **엣지를 볼 때마다 즉시 앱을 짚되, 비싼 fd 스캔만 짧게 재사용한다.**
//
// ttl은 짧아야 한다. 길면 캡처 도중에 뜬 프로세스를 못 보고 "어느 앱인지 밝히지 못함"으로 적게 된다.
type Attributor struct {
	procRoot string
	ttl      time.Duration
	now      func() time.Time

	mu      sync.Mutex
	scanned time.Time
	owners  map[uint64][]int
	denied  bool
}

// NewAttributor — ttl이 0이면 1초를 쓴다.
func NewAttributor(procRoot string, ttl time.Duration) *Attributor {
	if ttl <= 0 {
		ttl = time.Second
	}
	return &Attributor{procRoot: procRoot, ttl: ttl, now: time.Now}
}

// Remote — [AttributeRemote]와 같은 답을 주되 fd 스캔을 재사용한다.
func (a *Attributor) Remote(remoteIP string, remotePort uint32) Attribution {
	inodes, err := socketsTo(a.procRoot, remoteIP, remotePort) // 이것은 매번 읽는다 — 파일 하나다
	if err != nil || len(inodes) == 0 {
		return Attribution{Reason: ReasonSocketGone}
	}
	owners, denied := a.scan()

	keys := map[string]string{}
	seen := false
	for _, in := range inodes {
		pids := owners[in]
		if len(pids) == 0 {
			continue
		}
		seen = true
		if k, kind := AppKey(a.procRoot, shallowest(a.procRoot, pids)); k != "" {
			keys[k] = kind
		}
	}
	switch {
	case !seen && denied:
		return Attribution{Reason: ReasonNoPermission}
	case !seen:
		return Attribution{Reason: ReasonSocketGone}
	case len(keys) == 0:
		return Attribution{Reason: ReasonNoAppKey}
	case len(keys) == 1:
		for k, kind := range keys {
			return Attribution{Key: k, Kind: kind}
		}
	}
	return Attribution{Reason: ReasonAmbiguous}
}

// scan — fd 스캔 결과를 ttl 동안 재사용한다.
func (a *Attributor) scan() (map[uint64][]int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.owners != nil && a.now().Sub(a.scanned) < a.ttl {
		return a.owners, a.denied
	}
	a.owners, a.denied = scanOwners(a.procRoot)
	a.scanned = a.now()
	return a.owners, a.denied
}
