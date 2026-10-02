[English](README.md) · 한국어

# examples/discovery/jvm: 실행 중인 JVM의 정찰 → attach

```bash
./examples/discovery/jvm/run.sh
```

> **전제 조건: Go 툴체인과 Docker.** 다른 관측 예제는 Go만으로 실행되지만, 이 예제는 **실행 중인 JVM**(정찰과 attach의 대상)이 필요하므로 컨테이너로 분리했습니다.

## 보여 주는 것

openssl 수집기가 `/proc`을 훑어 로드된 라이브러리를 스스로 찾듯이, **jvm 수집기도 실행 중인 JVM을 스스로 정찰합니다.** 이 예제는 그 흐름을 처음부터 끝까지 최소한으로 보여 줍니다.

1. **정찰**(`ScanJVMs`): `/proc`으로 실행 중인 JVM을 찾아 각각의 PID, JAVA_HOME, 버전, 앱을 얻습니다. 호출하는 쪽이 PID나 JDK를 미리 알 필요가 없습니다.
2. **attach**: 찾은 PID에 attach해 `Security.getProviders()`가 **실제로 반환하는 것**을 관측합니다.
3. **동적 등록 포착**: 예제 애플리케이션은 `java.security`에 BC를 **정적으로 등록하지 않고** 실행 중에 `addProvider(BouncyCastle)`만 호출합니다. **정적 스캔(probe)은 이것을 관측할 수 없습니다. attach만 잡아냅니다**(`detection=runtime-introspection`).
4. **JSON Lines 적재**: attach 경로는 JVM마다 한 줄씩 냅니다(여러 개인 경우). `pqcota-ingest`가 `*.jsonl`을 읽어 적재합니다.

## 핵심: probe 대 attach

| | 정적 probe | **attach** |
|---|---|---|
| 보는 것 | `java.security`에 정적으로 등록된 체인 | 실행 중인 JVM이 **실제로 가진 것**(동적 `addProvider` 포함) |
| 이 예제의 동적 BC | ❌ 관측되지 않음 | ✅ 포착됨 |

`PQCOTA_JVM_AGENT`(수집기 JAR)가 있으면 attach하고, 없으면 probe로 되돌아가며, 그렇게 내려갔다는 사실을 기록합니다.

## JVM이 여러 개일 때

노드에 JVM이 여러 개 있으면 각각이 **서로 다른 발견 항목**이 됩니다. 식별자는 PID가 아니라 **앱**(메인 클래스 또는 `-jar`)이므로, 같은 JDK의 두 앱이 하나로 합쳐지지 않고 다시 스캔해도 이력이 끊기지 않습니다. 설계와 경계는 `collectors/jvm/`의 수집기 소스를 보세요.

## 전체 흐름

Ansible/SSH, 여러 노드, Postgres 적재는 [demo/](https://github.com/randyinthedev-hash/pqcota/tree/main/demo)의 여섯 단계를 보세요(그 두 번째 단계가 이 정찰 → attach를 실제 노드에서 실행합니다).
