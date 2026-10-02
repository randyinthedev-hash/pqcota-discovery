[English](README.md) · 한국어

# cmd/: 관측 실행 진입점


관측 단계의 CLI(Go 바이너리)입니다. 이름이 서로 비슷해서, 이 문서는 **언제 무엇을 쓰는가**에 따라 세 범주로 나눕니다. 모든 관측은 대상 머신에서 ②의 수집기가 합니다. 수집기가 만든 것을 중앙에 쌓는 일은 [pqcota-inventory cmd](https://github.com/randyinthedev-hash/pqcota-inventory/blob/main/cmd/README.ko.md)가 맡습니다.

## ① 접근 준비: 사용자의 hosts 파일로 관측 접근 설정하기
관측을 시작하기 전에, 대상 노드의 접속 정보를 **사용자가 직접 작성하는 hosts 파일**(CSV)에 정의합니다. 접근 비밀(계정, SSH 키)은 그 파일에만 있고 **pqcota 인벤토리에는 절대 적재되지 않습니다**.

### `pqcota-hosts`

```
pqcota-hosts [--ansible-out <path>] [--dsn <postgres>] <hosts.csv>
```

| 인자/옵션 | 하는 일 |
|---|---|
| `<hosts.csv>` | 접속 파일(사용자가 작성). 머리글은 필수이고 열 순서는 자유이며 필수는 `node_id`뿐입니다. **열 표와 그대로 실행할 수 있는 샘플**은 [examples/discovery](../examples/discovery/README.ko.md)([hosts.csv](../examples/discovery/hosts.csv))에 있습니다 |
| `--ansible-out <path>` | Ansible 인벤토리(ini)를 생성합니다. 계정과 키를 담으므로 **소유자만 읽도록**(`0600`) 씁니다. 이것으로 각 노드에서 ②를 실행합니다 |
| `--dsn <postgres>` | 엔드포인트를 pqcota 인벤토리에 upsert합니다. 계정과 키는 제외되며, 나중에 편집하고 재사용할 수 있습니다. `PQCOTA_ORG`가 지정한 조직으로 들어갑니다(설정하지 않으면 기본 조직) |

`<postgres>`는 Postgres 연결 문자열입니다. 드라이버가 pgx이므로 URL 형식과 key=value 형식을 모두 받습니다.

```
postgres://<user>:<password>@<host>:<port>/<db>     # e.g. postgres://postgres:pqcota@localhost:5432/pqcota
host=localhost port=5432 user=postgres dbname=pqcota
```

같은 문자열을 `PQCOTA_DSN` 환경변수로도 줄 수 있습니다(적재 명령과 조회 명령이 읽습니다).

옵션 없이 실행하면 안전한 엔드포인트(`node_id`, 이름, ip, 포트)를 표준 출력에 요약만 합니다.

### 이어서: 만든 인벤토리로 수집기 실행하기

`targets.ini`가 있다고 해서 관측이 시작되지는 않습니다. 그것은 **닿는 수단**일 뿐이며, 각 노드에서 수집기를 실제로 실행하는 것은 사용자의 Ansible이 하는 일입니다. 그 방법을 보여 주는 **참조 플레이북**이 리포지터리에 있습니다 → [`ansible/discover.yml`](../ansible/discover.yml)

```bash
ansible-playbook -i targets.ini ansible/discover.yml
```

네 가지를 합니다. **배포**(수집기 셋을 `/tmp/pqcota-collector`로) → **실행** → **회수**(결과 JSON을 컨트롤러로) → **정리**(실행이 실패 없이 끝나면 스테이징 디렉터리를 지웁니다. Java attach 경로에서 관측 대상 JVM이 자기 `/tmp`에 쓰는 파일은 지우지 않습니다). 수집기는 상주 에이전트가 아니라 끝나면 종료되는 CLI이므로 이런 일회성 방식이 맞습니다.

JVM 애드온(`collector.jar`)은 **모든 노드에 뿌리지 않습니다**. `pqcota-jvmscan --recon`이 먼저 그 노드에 JVM이 있는지 확인하고, JVM이 있는 노드에만 보냅니다.

사용자 인프라에서 쓰려면 플레이북의 `collector_bin_dir`을 사용자의 빌드 산출물(예를 들어 `dist/linux-amd64`)로 바꿉니다. 데모에만 해당하는 부분은 트래픽 생성 도우미뿐입니다.

### 필수인가: **아니요. 「여러 노드를 원격으로 스캔할 때」만 필요합니다**

이 단계는 관측의 전제 조건이 아니라 **원격으로 닿는 수단**입니다. 무엇을 하려는지에 따라 달라집니다.

| 하려는 일 | 접근 준비 |
|---|---|
| 노드 하나를 그 자리에서 스캔해 보기(`pqcota-nodescan --output table`) | **필요 없음**: SSH와 Ansible을 전혀 쓰지 않습니다 |
| 결과 JSON을 직접 모아 적재하기(`pqcota-ingest <dir>`) | **필요 없음**: 파일이면 충분합니다 |
| 컨트롤러에서 **SSH로 여러 노드에** 스캐너를 실행하기 | **필요함**: 노드에 닿으려면 Ansible 인벤토리가 있어야 합니다.<br>`targets.ini`를 손으로 써도 됩니다. `pqcota-hosts`는 CSV 하나로 그 ini를 만들고(계정과 키를 담으므로 소유자만 읽는 `0600`), pqcota 인벤토리에는 **`node_id`, 이름, ip, 포트만 넣습니다. 계정이나 키는 넣지 않습니다** |
| 인벤토리 보기에 **▸ 머신 머리글**(이름, ip:포트)을 표시하기 | **선택**: `--dsn`을 주어 엔드포인트를 넣으면 머리글이 나타나고, 주지 않으면 머리글만 빠집니다(자산과 연결 간선은 영향이 없습니다) |

노드 **등록 게이트**(`pqcota-ingest`의 범위 마스터 인자)도 마찬가지로 **선택**입니다. 생략하면 게이트를 건너뜁니다(로컬 실행, 데모). 등록은 관리 경계를 선언하고 싶을 때 하는 것이며, 적재의 전제 조건이 아닙니다.

## ② 수집기: 대상 머신에서 관측합니다

| 수집기 | 노드 OS | 무엇을 관측하는가 |
|---|---|---|
| `pqcota-nodescan` | **linux** | `/proc`에 로드된 OpenSSL(libssl/libcrypto) |
| `pqcota-jvmscan` | **linux** · windows | 실행 중인 JVM의 JCA provider 체인(`Security.getProviders()`). Windows에서는 범위가 **더 좁습니다**(아래) |
| `pqcota-netcap` | **linux** | TLS/SSH 핸드셰이크(AF_PACKET) |
| `pqcota-cngscan` | **windows** | 등록된 CNG provider와 머신이 열거하는 알고리즘(`bcrypt.dll`) |

`pqcota-jvmscan`은 두 OS에서 모두 프로세스를 열거하지만 **보이는 깊이는 다릅니다.** JDK 없이 동작하는 Go 네이티브 attach는 Linux에서만 되므로, Windows에서는 런타임 등록에 닿으려면 머신에 JDK가 있어야 합니다. 없으면 `java.security`만 읽는 정적 대체 경로로 내려가며(동적 등록은 사각지대로 남습니다) → jvm-collector.

넷 모두 `CollectionResult`를 냅니다. **표에 없는 OS에서 실행하면 빈 결과가 아니라 갭을 내며**, 종료 코드는 0입니다. 「그것이 없는 노드」와 「상태를 보지 못한 노드」는 구분되어야 하기 때문입니다.

**정적 바이너리는 릴리스에 첨부됩니다.** Linux용 셋은 `pqcota-linux-{amd64,arm64}.tar.gz`에, Windows용 둘(`pqcota-cngscan` · `pqcota-jvmscan`)은 `pqcota-windows-amd64.zip`에 들어 있습니다. 각각 `collectors/{openssl,jvm,network,cng}` 패키지를 감싼 얇은 진입점이므로, 새 관측 대상이 생기면 수집기를 하나 더 추가하고 코어는 그대로 둡니다.

여러 노드에서 한꺼번에 실행하는 방법 → [①의 참조 플레이북](#이어서-만든-인벤토리로-수집기-실행하기).

### `pqcota-nodescan`

```
pqcota-nodescan [--output json|table] [node-id]
```

| 인자/옵션 | 하는 일 |
|---|---|
| `[node-id]` | 기준이 되는 CMDB id입니다. 생략하면 머신 지문에서 결정적인 자기 id를 도출하고, 그것도 없으면 `host://local`을 씁니다 |
| `--output` | 출력 형식 → [아래 공통 항목](#--output-nodescan-jvmscan-cngscan-공통) |

`/proc`을 열 수 없으면 **빈 결과를 내지 않습니다.** 그것은 「OpenSSL이 없다」가 아니라 관측 자체가 불가능하다는 뜻이므로, 완전성 메모에 갭을 적고 표준 오류로 알립니다.

### `pqcota-jvmscan`

```
pqcota-jvmscan [--output json|table] [--pid N] [node-id]
pqcota-jvmscan --recon
```

| 인자/옵션 | 하는 일 |
|---|---|
| `[node-id]` | 생략하면 `host://local` |
| `--pid N` | 그 PID의 JVM만 관측합니다. 기본값은 recon이 찾은 모든 JVM입니다 |
| `--recon` | 정찰만 하고, 찾은 JVM을 JSON으로 냅니다(관측은 하지 않음) |
| `--output` | 출력 형식 → [아래 공통 항목](#--output-nodescan-jvmscan-cngscan-공통) |

`--pid`로 준 PID가 실행 중인 JVM에 없으면 **전체 스캔으로 되돌아가지 않고 실패합니다.** 관측하지 못한 것은 갭이지, 다른 대상으로 대체할 것이 아닙니다.

`--recon`은 오케스트레이터가 노드에 에이전트 JAR를 보낼지 정하는 근거입니다. JVM이 없으면 `[]`를 냅니다.

attach가 막힐 수 있습니다(`DisableAttachMechanism`, JEP 451, 권한). 그러면 실패로 끝나지 않고 정적 체인을 읽는 쪽으로 내려가며, **동적 등록은 사각지대로 남아 갭으로 보고됩니다.** 내려가는 순서는 jvm 수집기에 있습니다.

### `pqcota-netcap`

```
pqcota-netcap [--strict] <node-id> [iface] [window-seconds]
```

| 인자/옵션 | 기본값 | 하는 일 |
|---|---|---|
| `<node-id>` | `host://local` | 관측을 귀속시킬 노드 |
| `[iface]` | `eth0`(환경변수 `NETCAP_IFACE`) | 캡처할 인터페이스 |
| `[window-seconds]` | `8`(환경변수 `NETCAP_WINDOW_SEC`) | 관측 구간의 길이 |
| `--strict` | 꺼짐 | 관측이 불가능하면 종료 코드 1로 실패합니다 |

**`CAP_NET_RAW`가 없으면 관측이 없습니다.** 이 경우 netcap은 그 사실과 권한을 부여하는 방법(`setcap cap_net_raw+ep`)을 표준 오류로 알리고, 표준 출력으로는 `layers_missing=[NETWORK]`인 **갭 기록**을 냅니다. 기본 종료 코드는 **0**입니다.

0인 까닭은 그 갭이 중앙까지 전달되어야 하기 때문입니다. Ansible이 여러 노드를 실행할 때 종료 코드가 1이면 그 작업이 실패로 처리되어 결과 파일을 회수하지 못하고, 그 노드에 대해 중앙에는 **아무것도** 기록되지 않습니다. 그러면 인벤토리 보기에서 「이 노드에는 TLS 연결이 없다」로 읽히는데, 실제로는 관측하지 못했을 뿐입니다. 갭을 전달하는 것이 「관측하지 못함」과 「없음」을 구분해 줍니다.

직접 실행하면서 실패하게 하려면 `--strict`를 주세요(갭은 그래도 표준 출력으로 나갑니다).

### `pqcota-cngscan`

```
pqcota-cngscan [--output json|table] [node-id]
```

| 인자/옵션 | 기본값 | 하는 일 |
|---|---|---|
| `[node-id]` | 머신 지문에서 도출한 자기 id, 그것도 비어 있으면 `host://local` | 관측을 귀속시킬 노드 |
| `--output` | `json` | 출력 형식 → [아래 공통 항목](#--output-nodescan-jvmscan-cngscan-공통) |

**릴리스의 `pqcota-windows-amd64.zip`에 `pqcota-jvmscan`과 함께 들어 있습니다**(v0.6.3부터). 직접 빌드하려면 이렇게 합니다.

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/windows-amd64/ ./cmd/pqcota-cngscan
```

**Windows가 아닌 곳에서 실행하면 빈 결과가 아니라 갭을 내며**, 종료 코드는 **0**입니다. `CAP_NET_RAW`가 없을 때 netcap이 따르는 규칙과 같고 까닭도 같습니다. 「CNG가 없는 노드」와 「CNG를 보지 못한 노드」가 구분되도록 갭이 중앙에 닿아야 합니다.

`certutil`, PowerShell, WMI 대신 `bcrypt.dll`을 직접 호출합니다. 무엇을 어느 API로 보는지는 cng-collector에 있습니다.

### `--output`: nodescan, jvmscan, cngscan 공통

같은 수집이 실행되며, 달라지는 것은 **어느 층을 내보내는가**입니다.

| 값 | 내보내는 것 | 언제 |
|---|---|---|
| `json`(기본값) | **CollectionResult**: 수집기 고유의 원본(`raw_capture`)과 표준 CycloneDX 본문(`cbom_cyclonedx`)을 Envelope, 완전성 기록과 함께 하나의 메시지로 냅니다 | 중앙(③)이 회수해 쌓을 때 |
| `table` | 그 결과를 정규화해 **도출한 Finding[]**을 사람이 읽는 표로 냅니다 | 노드 하나를 그 자리에서 확인할 때 |

진행 상황과 경고는 두 경우 모두 표준 오류로 나갑니다. 표준 출력에는 요청한 것만 나옵니다.

**`table`은 아무것도 저장하지 않습니다.** 중앙이 하는 정규화를 메모리에서 한 번 똑같이 실행하고 버립니다. 이력과 스냅샷 비교는 ③에 쌓여야 비로소 생깁니다.

### 권한 · 환경변수

노드에서 실행할 때 필요한 것입니다. 권한이 부족하면 **보이는 범위가 줄거나, 그 명령을 아예 실행할 수 없습니다.** 관측하지 못한 것은 완전성 메모로 보고되지만, 처음부터 권한을 갖추는 편이 낫습니다.

| 명령 | 권한 | 환경변수 |
|---|---|---|
| `pqcota-nodescan` | 자기 프로세스는 그대로 동작합니다. **다른 사용자의 프로세스를 보려면 root**(또는 `CAP_SYS_PTRACE`)가 필요합니다 | `PQCOTA_SIGN_KEY`: 설정하면 결과에 서명합니다(선택) |
| `pqcota-netcap` | **`CAP_NET_RAW` 필수**(`setcap` 또는 root). 없으면 캡처가 시작되지 않습니다 | `NETCAP_IFACE`(기본값 `eth0`) · `NETCAP_WINDOW_SEC`(기본값 8초) |
| `pqcota-jvmscan` | 대상 JVM과 **같은 UID**(또는 root). 대상이 attach를 막으면 대상의 `java.security`를 읽는 쪽으로 내려갑니다 | `PQCOTA_JVM_AGENT`=collector.jar의 경로: 주면 attach 경로를 택합니다. **주지 않았고 실행 중인 JVM도 없으면** JVM을 하나 시작해 런처의 기본 provider 체인을 보고, **관측 범위가 제한된 대체 결과(degraded)**로 기록합니다(실행 중인 애플리케이션의 관측이 아닙니다) |
| `pqcota-cngscan` | 특별한 권한 없음: `bcrypt.dll` 열거 API는 읽기 전용 조회입니다 | `PQCOTA_SIGN_KEY`: 설정하면 결과에 서명합니다(선택) |

`PQCOTA_SIGN_KEY`의 키 쌍(그리고 중앙의 짝인 `PQCOTA_VERIFY_KEY`)은 [`pqcota-keygen`](https://github.com/randyinthedev-hash/pqcota-common/blob/main/cmd/README.ko.md#pqcota-keygen)으로 만듭니다. 이 명령은 계획 승인이 같은 종류의 키를 쓰므로 `pqcota-common`에 있습니다.


### 실행 요건: 커널과 권한

**커널 하한은 3.2입니다.** Go 툴체인이 정한 값(Go 1.24부터)이며, 이 리포지터리는 그보다 새로운 것을 요구하지 않습니다. 그 위에서는 배포판과 libc가 무관합니다. 바이너리가 정적으로 링크되기 때문입니다.

| 기능 | 커널 요건 | 그 아래에서는 |
|---|---|---|
| 노드 스캔 · 포크 판정 · JVM 정찰 | **3.2**(툴체인 하한) | 바이너리가 실행되지 않습니다 |
| 통신 연결 간선 관측 | 추가 요건 없음(`AF_PACKET`은 2.2 시대) | 해당 없음 |
| 앱 식별(systemd 유닛) | systemd가 동작하는 환경 | 식별이 유닛 이름 대신 **실행 파일 경로**로 되돌아갑니다(upstart 시대 배포판) |
| **컨테이너 안의 JVM attach** | **4.1**(`/proc/<pid>/status`의 `NSpid`) | 호스트 PID로 되돌아가며, 그 JVM만 관측되지 않습니다(갭으로 보고) |

하한 아래에서도 **아무 표시 없이 잘못 동작하는 일은 없습니다.** 관측하지 못한 것은 완전성 갭으로 나가고, `NSpid`가 없으면 호스트 PID를 그대로 씁니다.

**실측**(KVM VM에서. 컨테이너는 호스트 커널을 공유하므로 이 항목은 거기서 검증할 수 없습니다):

| 커널 | 배포판 | 결과 |
|---|---|---|
| **3.2.0** | Ubuntu 12.04 | 수집기 셋 모두 정상 종료했습니다. OpenSSL 1.0.0g를 탐지했고(fork=OpenSSL, 동적), 8초 구간 동안 AF_PACKET 관측에 성공했습니다. systemd가 없어 앱 식별은 **실행 파일 경로**(`/usr/sbin/sshd` 등)로 되돌아갔습니다 |
| **3.10.0** | CentOS 7.9 | 수집기 셋 모두 정상 종료했습니다. OpenSSL 1.0.2k를 탐지했고, cgroup v1에서 **systemd 유닛 식별에 성공했습니다**(`sshd.service` 등) |

두 커널 모두 `/proc/<pid>/status`에 **`NSpid` 줄이 없는데** 죽지 않고 호스트 PID 대체 경로가 동작했습니다. 4.1 경계가 실제 환경에서 확인된 것입니다.

> **PoC와 테스트 하네스는 여기에 없습니다.** openssl 수집기를 실제 `/proc`과 ELF에 대해 검증하는 CLI는 유일한 소비자인 통합 테스트 옆에 있습니다 → [`collectors/openssl/integration/probe`](../collectors/openssl/integration). 이 폴더(cmd/)에는 **제품의 관측 진입점만** 있습니다.

## ③ 그 밖: 수집기가 아닌 명령

**관측이 아닙니다.** `CollectionResult`를 내지 않으므로 중앙에 적재되는 것이 없습니다. `pqcota-procs`는 대상 머신에서 실행합니다.

### `pqcota-procs`

```
pqcota-procs [--unit UNIT] [--exe PATH] [--cmd REGEX]
```

| 옵션 | 하는 일 |
|---|---|
| `--unit UNIT` | systemd 유닛 이름(cgroup 매칭) |
| `--exe PATH` | 실행 파일 경로(정확히 일치) |
| `--cmd REGEX` | cmdline 정규식 |

**셋 중 적어도 하나**는 줘야 합니다(모두 비면 종료 코드 2). 다른 사용자의 프로세스를 보려면 root가 필요합니다.

전환물을 생성하기 직전에 **무엇을 재시작해야 하는지** 찾으려고 있습니다. PID는 변하기 쉬우므로 저장하지 않고 그 자리에서 조회합니다. 이것을 호출하는 자동 경로는 아직 없습니다(플레이북의 `activation.restart`는 사용자가 쓴 명령을 그대로 실행합니다).

---
**무엇을 쓸 것인가**
- 노드 여러 개를 관측해 인벤토리에 쌓기 → 각 노드에서 **②**를 실행하고(기본값 `--output json`) → [`pqcota-ingest`](https://github.com/randyinthedev-hash/pqcota-inventory/blob/main/cmd/README.ko.md)로 중앙에서 적재합니다.
- 노드 하나를 그 자리에서 확인만 하기 → **②**를 `--output table`로 실행합니다. 쌓이는 것은 없습니다.

> 모든 로직은 `pkg/inventory/`(정규화, 이력)와 `collectors/`(수집)에 있으며, 이 명령들은 그것을 조립하는 얇은 진입점입니다. 회수한 결과는 인벤토리의 `pqcota-ingest`가 **추가만 하는 이력에 쌓습니다**.
