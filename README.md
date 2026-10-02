# pqcota-discovery — observation (stage 1)

Observes **which cryptographic algorithms a running system actually uses** — not the cryptography itself (no ciphertext, no keys), but **which libraries, providers, and algorithms are loaded, registered, and negotiated**. It captures the **runtime reality** that static document and source scans cannot see (providers registered at runtime, libraries actually loaded, groups actually negotiated on the wire), and attaches a quantum posture to each asset (🟢 PQC/hybrid · 🔴 classical = quantum-vulnerable · ⚪ unknown).

**Why runtime** — configuration (`openssl.cnf`, `java.security`, nginx `ssl_ciphers`) is an *allow list*, so it diverges from reality. A PQC group written there falls back to classical if the peer does not support it, and an app may register a provider at runtime that never appears in `java.security`. So the evidence comes from **libraries loaded in the running process** and **algorithms negotiated in the handshake**. When the runtime cannot be reached, it falls back to configuration — but then `evidence_strength` is lowered and the gap is recorded.

It is one of five repositories that make up [pqcota](https://github.com/randyinthedev-hash/pqcota): `pqcota-common`, `pqcota-inventory`, `pqcota-discovery`, `pqcota-provisioning`, and the integration repository `pqcota` (demo, examples, release bundles, contributing guide).

## At a glance

```mermaid
flowchart LR
    H["hosts.csv<br/>access info"] --> T["targets.ini"] --> C["three collectors<br/>run on each node"]
    C --> J["CollectionResult<br/>JSON"] --> I["ingested into the inventory"]
```

## What it consists of

| Piece | What it is |
|---|---|
| **Access prep** — `pqcota-hosts` | builds an Ansible inventory from the `hosts.csv` you wrote |
| **The three collectors** | listed below. They run on the observed machine and emit a `CollectionResult` |
| **Reference playbook** — [`ansible/`](ansible) | ships, runs, retrieves, and cleans up collectors across prepared nodes |

| Collector | What it observes | How |
|---|---|---|
| **openssl** | loaded libcrypto/libssl, fork, app attribution | parses `/proc` and ELF **itself** (Linux) — no dependency on `ldd` or `readelf` |
| **jvm** ★ | the **actual** live JCA provider chain (registration order included) | JVM attach → `getProviders()` (pure-Java sidecar) |
| **network** | TLS/SSH handshake groups → communication edges | passive AF_PACKET capture (Linux), no decryption |

★ The **killer capability** of this stage is that jvm attach catches **dynamically registered providers** (BouncyCastle added via `addProvider` at runtime, for instance) that static scanning cannot see — a gap no dedicated OSS filled.

## Try it quickly

**A single node, right where it is** — nothing to install, no Ansible needed.

> The commands below are for a **Linux** node. On Windows it is `pqcota-cngscan` and `pqcota-jvmscan` — which collector runs on which OS is in the [command reference](cmd/README.md).

```bash
pqcota-nodescan --output table            # a table on screen (nothing is stored)
pqcota-nodescan node-01 > result.json     # JSON (when accumulating centrally)
```

**Several nodes** — write down the access info and run them all through the reference playbook.

```bash
pqcota-hosts --ansible-out targets.ini hosts.csv
ansible-playbook -i targets.ini ansible/discover.yml
pqcota-ingest ./results                   # ingest the retrieved results into the inventory
```

Arguments, privileges, and environment variables per command → [cmd/README](cmd/README.md).

## When it doesn't work — symptom and cause

| Symptom | Cause |
|---|---|
| `could not open /proc, so nothing was observed` | not Linux. The result goes out as a **gap, not as empty** |
| only the scanning process's own assets show up | not root — another user's `/proc` is unreadable (whatever was not observed is reported as a gap) |
| `no CAP_NET_RAW — could not observe` | `setcap cap_net_raw+ep`, or root. The exit code is 0 on purpose — so the gap reaches the center |
| JVM providers show **only the static chain** | attach was blocked and it fell back (`DisableAttachMechanism`, JEP 451, permissions). Runtime-registered providers are a blind spot there, and that is reported as a gap |
| zero observed edges | no handshake flowed during the observation window. Idle links are invisible in production too — this is **not absence, it is not-observed** |

## What is here

| Path | What |
|---|---|
| `collectors/` | the collectors: `openssl`, `jvm` (with the Java sidecar), `network`, `cng` |
| `cmd/` | the commands: `pqcota-nodescan`, `pqcota-jvmscan`, `pqcota-netcap`, `pqcota-cngscan`, `pqcota-hosts`, `pqcota-procs` |
| [`ansible/`](ansible/README.md) | the reference playbook that runs the collectors across prepared nodes |
| `pkg/discovery/procs/` | process attribution shared by the collectors |
| `examples/` | runnable examples: access prep, ingest of collected results, and the JVM reconnaissance → attach |

## Depends on

`pqcota-common` and `pqcota-inventory`. Inside this module the collectors import only `pqcota-common` and `pkg/discovery/procs`, because they are built into binaries that go onto the observed nodes.

## Build and test

```bash
make            # every check of this repository
go test ./...   # unit tests only
```

`make build-jar` builds the Java attach sidecar (`build/collector.jar`, needs JDK 11+). `make build` also cross-compiles for linux/amd64 and windows/amd64, since the collectors' core is Linux-only code behind build tags.

`go.mod` reads the sibling repositories from `../` through `replace` directives (`../pqcota-common` and so on), so clone the repositories side by side. The `replace` lines stay: they are the local link between the repositories, while the `require` lines point at the release tag (currently `v0.10.2`), which is what a consumer outside this workspace receives. See the [build guide](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/build.md#get-the-source).

## See also

process-attribution library [`pkg/discovery/procs`](pkg/discovery/procs) · normalization and history libraries [`pkg/inventory/`](https://github.com/randyinthedev-hash/pqcota-inventory/tree/main/pkg/inventory) · runnable examples [`examples/discovery/`](examples/discovery)

## Contributing · security · license

Contributing and security reporting are described in the [pqcota repository](https://github.com/randyinthedev-hash/pqcota). Licensed under [Apache-2.0](https://github.com/randyinthedev-hash/pqcota/blob/main/LICENSE).
