[English](README.md) · 한국어

# ansible/: 참조 플레이북

준비된 노드들에서 수집기를 한꺼번에 실행하는 **참조 구현**입니다. 데모가 이것을 그대로 쓰며, 사용자 인프라로 그대로 가져가 쓸 수 있도록 여기에 두었습니다.

```bash
pqcota-hosts --ansible-out targets.ini hosts.csv     # ① prepare access
ansible-playbook -i targets.ini ansible/discover.yml
```

| 파일 | 하는 일 |
|---|---|
| [`discover.yml`](discover.yml) | **배포 → 실행 → 회수 → 정리**: 수집기를 스테이징 디렉터리에 두고 실행한 뒤, 결과 JSON을 컨트롤러로 가져오고 노드에서 모두 지웁니다 |

**노드의 OS에 따라 분기합니다.** `gather_facts`가 보고하는 `os_family`에 따라 Linux에서는 수집기 셋을, Windows에서는 둘(`pqcota-cngscan`과 `pqcota-jvmscan`)을 실행합니다. 그 밖의 OS에서는 아무것도 하지 않습니다. 결과가 없다는 뜻이며, 「그 노드에 아무것도 없다」는 뜻과는 다릅니다.

**Windows 노드를 실행하려면 두 가지가 더 필요합니다.**

```bash
ansible-galaxy collection install ansible.windows            # the win_copy and win_command modules
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/windows-amd64/ \
  ./cmd/pqcota-cngscan ./cmd/pqcota-jvmscan
```

다른 사용자로 실행 중인 JVM이 보이려면 Windows 노드에 **관리자 계정으로 접속해야** 합니다(측정값: 일반 사용자로는 265개 중 163개를 열 수 없었습니다). 이는 Linux 블록의 `become: true`에 해당합니다.

접속 방법은 `hosts.csv`의 `connection` 열(`ssh` 또는 `winrm`)이 정합니다. `targets.ini`는 실행할 때마다 덮어쓰이므로 손으로 더한 설정은 남지 않습니다 → [작성 방법](../examples/discovery/README.ko.md). 사이트마다 다른 값(WinRM 전송 방식과 인증서 검증, 기본 셸이 cmd인 sshd)만 `group_vars/targets_windows.yml`에 둡니다.

> **실제 환경에서 한 번 실행해 보았습니다**(TD-WIN-1·2): Win32-OpenSSH와 키로 접속해 배포, 관측, 회수, 정리가 끝까지 실행됐고 노드에는 아무것도 남지 않았습니다. 다만 **데모는 이 경로를 검증하지 않습니다.** 데모에는 Linux 컨테이너만 있으므로 Windows 분기에는 실행할 때마다 확인하는 게이트가 없습니다.

**노드에 아무것도 남지 않습니다.** 수집기는 상주 에이전트가 아니라 실행 후 종료되는 CLI이므로 이런 일회성 방식이 맞습니다.

**JVM 애드온(`collector.jar`)은 모든 노드에 뿌리지 않습니다.** `pqcota-jvmscan --recon`이 먼저 노드에 JVM이 있는지 확인하고, 애드온은 JVM이 있는 노드에만 갑니다.

## 사용자 인프라에서 쓰려면

`collector_bin_dir`(Linux)과 `collector_bin_dir_win`(Windows)을 사용자의 빌드 산출물로 바꿉니다 → [pqcota 빌드 안내](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/build.ko.md#빌드). `become: true`가 Linux 블록에만 있는 까닭은 `pqcota-netcap`의 `CAP_NET_RAW`와 모든 프로세스에 걸친 `/proc` 범위 때문입니다.

**플레이북을 대규모로 만들어 내는 생성기는 없습니다.** 이 모델은 자체 원격 실행 엔진을 만들지 않습니다. 실행에는 사용자가 이미 쓰는 기반(Ansible, Salt 등)을 씁니다.
