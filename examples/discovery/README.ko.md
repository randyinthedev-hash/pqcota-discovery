[English](README.md) · 한국어

# examples/discovery: 접근 준비와 수집 경로 둘(① 직접 관측 · ② 위임한 CBOM)

```bash
./examples/discovery/run.sh
```

## 무슨 일이 일어나는가

### 1) `pqcota-hosts`: 사용자의 hosts 파일 → Ansible 인벤토리와 엔드포인트
입력은 [`hosts.csv`](hosts.csv)(사용자가 관리하는 파일)입니다.
```
node_id,name,ip,port,ssh_user,ssh_key,ssh_pass,os,connection
node-a,Web Frontend,10.0.0.2,22,deploy,/home/me/.ssh/id_ed25519,,,            ← SSH key (recommended)
node-b,Payments App (Java),10.0.0.3,22,deploy,,example-password,,             ← password
node-c,Payments DB,10.0.0.9,22,deploy,/home/me/.ssh/id_ed25519,,,
node-d,Payments Gateway (Windows),10.0.0.11,,Administrator,,example-password,windows,winrm
```
→ 두 가지를 만듭니다.
- `--ansible-out targets.ini`: 런타임에만 쓰는 **Ansible 인벤토리**입니다(접속 비밀을 담으므로 `0600`, 소유자만 읽을 수 있습니다). 각 노드에서 수집기를 실행할 때 씁니다. **pqcota 인벤토리에 저장되지 않습니다.**
- 표준 출력: **안전한 엔드포인트**(node_id, 이름, ip와 포트이며 **비밀은 제외**). `--dsn`을 주면 재사용하고 편집할 수 있는 기록으로 인벤토리(Postgres)에 upsert합니다.

> 접근 비밀(키, 비밀번호, 계정)은 **hosts.csv(사용자의 파일)와 생성된 targets.ini(런타임)에만** 있으며 pqcota 인벤토리에는 절대 적재되지 않습니다.

#### 인증: SSH 키(권장) 또는 비밀번호
머리글은 필수이고 열 순서는 자유이며, **호스트마다 독립적**입니다. 필수인 것은 `node_id`뿐입니다.

| 열 | 의미 |
|---|---|
| `ssh_user` | 로그인 계정(예: `deploy`, `root`) |
| `ssh_key` | **미리 만든 SSH 개인 키의 경로** → `ansible_ssh_private_key_file`(권장) |
| `ssh_pass` | 비밀번호 → `ansible_ssh_pass`(지원하지만 권장하지 않음) |
| `os` | `linux`(기본값) 또는 `windows`. 그 노드에서 어느 수집기를 실행할지 정합니다 |
| `connection` | `ssh`(기본값) 또는 `winrm`. 그 노드에 **접속하는 방법**입니다 |

- **키**(node-a와 node-c): `ssh_key`에 개인 키 경로를 적고 `ssh_pass`는 비워 둡니다.
- **비밀번호**(node-b): `ssh_pass`에 비밀번호를 넣고 `ssh_key`는 비워 둡니다. ⚠️ Ansible이 비밀번호로 접속하려면 컨트롤러에 **`sshpass`가 설치되어** 있어야 합니다(`apt install sshpass`). 평문 비밀번호가 targets.ini에 들어가므로 키를 권장합니다.
- 섞어 쓸 수 있습니다(위 예처럼 노드마다 다릅니다).

#### `os`: 어느 수집기를 보낼지 정합니다

`linux`는 `pqcota-nodescan`, `pqcota-netcap`, `pqcota-jvmscan`을 받고, `windows`는 `pqcota-cngscan`과 `pqcota-jvmscan`을 받습니다. 비어 있으면 `linux`이고, 둘 다 아닌 값은 **오류**입니다. 확인하지 않고 Linux로 받아들이면 Windows 노드에 Linux 수집기가 올라가고 실패는 한참 뒤에야 드러납니다.

**관측하는 것이 아니라 적어 두는 것입니다.** OS는 수집기를 보내기 *전에* 알아야 하는데, 알아내려면 이미 무언가를 보내야 합니다. hosts.csv는 사용자가 관리하는 파일이므로 대개 사용자가 알고 있습니다. (플레이북이 `gather_facts`로 한 번 더 확인합니다. 적힌 것과 다르면 그 노드는 건너뜁니다.)

`os`가 만드는 것은 인벤토리 **그룹**입니다. `[targets_linux]`와 `[targets_windows]`, 그리고 그 부모인 `[targets]`입니다. `hosts: targets`를 쓰던 플레이북은 고치지 않아도 그대로 실행됩니다.

#### `connection`: 접속하는 방법

**여기에 적는 까닭은 `targets.ini`가 실행할 때마다 덮어쓰이기 때문입니다.** 손으로 더한 접속 설정은 다음 실행에서 지워집니다. 접속 방법은 지워지지 않는 곳에 있어야 하고, 그곳이 이 파일입니다.

| 값 | 인벤토리에 들어가는 것 | 계정과 비밀 |
|---|---|---|
| `ssh`(기본값) | Linux는 그대로입니다. **Windows는 `ansible_shell_type=powershell`**: 셸이 sh가 아니기 때문입니다 | `ssh_key`(권장) 또는 `ssh_pass` |
| `winrm` | `ansible_connection=winrm`, 포트 기본값은 **5985** | `ssh_pass` → `ansible_password`. **키로는 접속하지 않습니다** |

`port`를 적었으면 그 값이 우선합니다(HTTPS는 `5986`). `connection=winrm`인데 `os`가 `windows`가 아니거나 `ssh_key`가 있으면 **오류**입니다. 접속할 때에야 드러날 불일치를 파일을 읽는 시점에 오류로 멈춥니다.

> **사이트마다 다른 값 둘은 임의로 채우지 않습니다.** SSH의 `ansible_shell_type=cmd`(sshd의 기본 셸이 cmd일 때만)와 WinRM의 `ansible_winrm_transport`입니다. 생성된 ini의 주석이 이 값들이 들어갈 자리를 알려 주며, 값은 `group_vars/targets_windows.yml`에 둡니다.
>
> 인증서 검증처럼 winrm 플러그인이 **선언하지 않은** 설정은 `ansible_winrm_<option>`으로 적으면 pywinrm에 그대로 전달됩니다(`ansible_winrm_server_cert_validation` 등). Ansible 옵션이 아니라 pywinrm의 이름이므로 `ansible-doc`에서는 찾을 수 없습니다.

#### SSH 키 만들고 대상에 등록하기
키를 쓰려면 개인 키와 공개 키 쌍을 만들고 **공개 키를 대상의 `authorized_keys`에 등록**합니다.
```bash
# 1) generate the key pair (once): private key ~/.ssh/id_ed25519, public key ~/.ssh/id_ed25519.pub
ssh-keygen -t ed25519 -C "pqcota-discovery" -f ~/.ssh/id_ed25519

# 2) register the public key on each target (once per target): afterwards you connect without a password
ssh-copy-id -i ~/.ssh/id_ed25519.pub deploy@10.0.0.2
ssh-copy-id -i ~/.ssh/id_ed25519.pub deploy@10.0.0.3
ssh-copy-id -i ~/.ssh/id_ed25519.pub deploy@10.0.0.9

# 3) check the connection
ssh -i ~/.ssh/id_ed25519 deploy@10.0.0.2 true && echo OK
```
그런 다음 `hosts.csv`의 `ssh_key`에 **개인 키 경로**(`~/.ssh/id_ed25519`)를 적습니다. `ssh-copy-id`를 쓰지 않는다면 공개 키(`.pub`)의 내용을 대상의 `~/.ssh/authorized_keys`에 한 줄로 더합니다(권한: `.ssh`는 700, `authorized_keys`는 600).

> 이 예제(`run.sh`)는 실제로 접속하지 않으므로 **키 파일이 없어도 동작합니다.** `pqcota-hosts`는 경로 문자열을 targets.ini에 복사할 뿐입니다. 키는 나중에 실제 `ansible-playbook` 단계에서 쓰입니다.

### 2) `pqcota-ingest`: 회수한 결과 → 범위 게이트 → 정규화 → 적재
[`../data/results`](https://github.com/randyinthedev-hash/pqcota-inventory/tree/main/examples/data)의 `CollectionResult` JSON 파일을 읽어 파생 `Finding`으로 정규화하고 적재합니다. `PQCOTA_DSN`이 없으면 **메모리 안의 요약**(스냅샷, 노드별 자산과 연결 간선 수)이 나오고, 있으면 Postgres에 추가만 하는 방식으로 영속 저장됩니다. 서명 검증은 `PQCOTA_VERIFY_KEY`를 설정했을 때만 일어납니다.

`node-a-openssl.json`의 디코딩한 CBOM에는 여러 앱이 붙은 공유 라이브러리 하나가 들어 있습니다.
```json
{"name":"pqcota:openssl.lib","value":"libssl.so.3"},
{"name":"pqcota:app_keys","value":"/opt/apps/api-gw,/opt/apps/payment-gw"}
```

## 실행 중인 JVM 관측하기(정찰 → attach)
JCA provider 체인은 **실행 중인 JVM에 attach**해야만 실제로 있는 것(런타임의 `addProvider` 포함)을 보여 줍니다. 이는 별도 예제로 분리되어 있습니다(Go만이 아니라 JDK와 Docker가 필요합니다). **[jvm/](jvm/README.ko.md)**가 `/proc` 정찰 → attach → 동적 BC 포착 → JSONL 적재를 최소한으로 보여 줍니다.

## 실제 노드 스캔하기(Linux)
샘플이 아닌 실제 관측을 만들려면 관측 대상 호스트에서 이렇게 실행합니다.
```bash
go run ./cmd/pqcota-nodescan <node-id>   # the loaded OpenSSL (libssl/libcrypto) from /proc: Linux only
```
결과 JSON 파일을 모아 그 디렉터리를 `pqcota-ingest`에 줍니다. JVM은 [jvm/](jvm/README.ko.md)를 보세요. 모든 명령의 지도: [cmd/README](../../cmd/README.ko.md).
