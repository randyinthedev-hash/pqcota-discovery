# cmd/ — discovery execution entry points


The CLIs (Go binaries) of the discovery stage. The names look alike, so this page sorts them into three categories by **which one to use when**. All observation is done by the collectors in ② on the target machine; accumulating what they produce centrally is [pqcota-inventory cmd](https://github.com/randyinthedev-hash/pqcota-inventory/blob/main/cmd/README.md)'s job.

## ① Access prep — setting up discovery access from the user's hosts file
Before discovery starts, the connection details for the target nodes are defined in a **hosts file the user writes themselves** (CSV). Access secrets (accounts, SSH keys) live only in that file and are **never ingested into the pqcota inventory**.

### `pqcota-hosts`

```
pqcota-hosts [--ansible-out <path>] [--dsn <postgres>] <hosts.csv>
```

| Argument/option | What it does |
|---|---|
| `<hosts.csv>` | the connection file (written by the user). A header is required, column order is free, and only `node_id` is mandatory — the **column table and a sample you can run as-is** are in [examples/discovery](../examples/discovery/README.md) ([hosts.csv](../examples/discovery/hosts.csv)) |
| `--ansible-out <path>` | generates an Ansible inventory (ini) — it holds accounts and keys, so it is written **owner-readable only** (`0600`). You run ② on each node with it |
| `--dsn <postgres>` | upserts the endpoints into the pqcota inventory — accounts and keys excluded; editable and reusable later. They go to the organization named by `PQCOTA_ORG` (the default organization when it is unset) |

`<postgres>` is a Postgres connection string. The driver is pgx, so both the URL form and the key=value form are accepted:

```
postgres://<user>:<password>@<host>:<port>/<db>     # e.g. postgres://postgres:pqcota@localhost:5432/pqcota
host=localhost port=5432 user=postgres dbname=pqcota
```

The same string can be given through the `PQCOTA_DSN` environment variable (the ingest and query commands read it).

Run with no options and it just summarizes the safe endpoints (`node_id`, name, ip, port) on stdout.

### Then — running the collectors with the inventory you made

A `targets.ini` existing does not start any observation. It is only **a means of reach**; actually running the collectors on each node is your Ansible's job. A **reference playbook** showing how is in the repo → [`ansible/discover.yml`](../ansible/discover.yml)

```bash
ansible-playbook -i targets.ini ansible/discover.yml
```

It does four things — **ship** (the three collectors into `/tmp/pqcota-collector`) → **run** → **retrieve** (the result JSON back to the controller) → **clean up** (nothing is left on the node). A collector is not a resident agent but a CLI that exits when done, so this one-shot pattern fits.

The JVM add-on (`collector.jar`) is **not sprayed onto every node** — `pqcota-jvmscan --recon` first checks whether that node has a JVM, and it is sent only to those that do.

To use it on your own infrastructure, point the playbook's `collector_bin_dir` at your own build output (`dist/linux-amd64`, say). The only demo-specific piece is the traffic generation helper.

### Is it required — **no. Only "when scanning several nodes remotely"**

This step is not a precondition of observation but **a means of remote reach**. It depends on what you are trying to do:

| What you want | Access prep |
|---|---|
| scan and view one node right where it is (`pqcota-nodescan --output table`) | **not needed** — SSH and Ansible are not used at all |
| collect result JSON yourself and ingest it (`pqcota-ingest <dir>`) | **not needed** — the files are enough |
| run the scanners **over SSH on several nodes** from a controller | **needed** — reaching the nodes requires an Ansible inventory.<br>You can write `targets.ini` by hand. `pqcota-hosts` builds that ini from one CSV (owner-only `0600`, since it holds accounts and keys) and puts **only `node_id`, name, ip, and port — no account or key — into the pqcota inventory** |
| show the **▸ machine header** (name, ip:port) in the inventory view | **optional** — pass `--dsn` to insert the endpoints and the header appears; without it only the header is omitted (assets and edges are unaffected) |

The node **registration gate** (the scope-master argument to `pqcota-ingest`) is likewise **optional** — omit it and the gate is skipped (local runs, the demo). Registration is for when you want to declare the managed boundary; it is not a precondition of ingesting.

## ② Collectors — they observe on the target machine

| Collector | Node OS | What it observes |
|---|---|---|
| `pqcota-nodescan` | **linux** | the loaded OpenSSL in `/proc` (libssl/libcrypto) |
| `pqcota-jvmscan` | **linux** · windows | a live JVM's JCA provider chain (`Security.getProviders()`). Coverage on Windows is **narrower** (below) |
| `pqcota-netcap` | **linux** | TLS/SSH handshakes (AF_PACKET) |
| `pqcota-cngscan` | **windows** | the registered CNG providers and the algorithms the machine enumerates (`bcrypt.dll`) |

`pqcota-jvmscan` enumerates processes on both, but **sees a different depth on each.** The Go-native attach that works without a JDK is Linux-only, so on Windows the machine needs a JDK to reach runtime registrations; without one it drops to the static fallback that only reads `java.security` (dynamic registrations stay a blind spot) → jvm-collector.

All four emit a `CollectionResult`. **Run one on an OS not in the table and it emits a gap, not an empty result**, with exit code 0 — "a node that has none" and "a node whose state was not seen" must stay apart.

**Static binaries are attached to the release**: the three Linux ones in `pqcota-linux-{amd64,arm64}.tar.gz`, the two Windows ones (`pqcota-cngscan` · `pqcota-jvmscan`) in `pqcota-windows-amd64.zip`. Each is a thin entry point wrapping the `collectors/{openssl,jvm,network,cng}` package, so when a new observation target appears you add one more collector — the core stays as it is.

How to run them across many nodes at once → [the reference playbook in ①](#then--running-the-collectors-with-the-inventory-you-made).

### `pqcota-nodescan`

```
pqcota-nodescan [--output json|table] [node-id]
```

| Argument/option | What it does |
|---|---|
| `[node-id]` | the authoritative CMDB id. Omitted, it derives a deterministic self-id from the machine fingerprint, and failing that uses `host://local` |
| `--output` | output format → [shared, below](#--output--shared-by-nodescan-jvmscan-and-cngscan) |

If `/proc` cannot be opened it **does not emit an empty result** — that is not "no OpenSSL" but an inability to observe at all, so it records a gap in the completeness note and says so on stderr.

### `pqcota-jvmscan`

```
pqcota-jvmscan [--output json|table] [--pid N] [node-id]
pqcota-jvmscan --recon
```

| Argument/option | What it does |
|---|---|
| `[node-id]` | omitted, `host://local` |
| `--pid N` | observe only the JVM with that PID. The default is every one recon finds |
| `--recon` | only reconnoiter, emitting the JVMs found as JSON (no observation) |
| `--output` | output format → [shared, below](#--output--shared-by-nodescan-jvmscan-and-cngscan) |

If the PID given by `--pid` is not among the running JVMs it **fails instead of falling back to scanning everything** — what was not observed is a gap, not something to substitute another target for.

`--recon` is the basis on which an orchestrator decides whether to send the agent JAR to a node. With no JVM it emits `[]`.

Attach can be blocked (`DisableAttachMechanism`, JEP 451, permissions). Then it does not end in failure but degrades to reading the static chain, and **dynamic registration stays a blind spot and is reported as a gap** — the order it degrades in is in the jvm collector.

### `pqcota-netcap`

```
pqcota-netcap [--strict] <node-id> [iface] [window-seconds]
```

| Argument/option | Default | What it does |
|---|---|---|
| `<node-id>` | `host://local` | the node the observations are attributed to |
| `[iface]` | `eth0` (env `NETCAP_IFACE`) | the interface to capture on |
| `[window-seconds]` | `8` (env `NETCAP_WINDOW_SEC`) | the length of the observation window |
| `--strict` | off | fail with exit code 1 when observation is impossible |

**Without `CAP_NET_RAW` there is no observation.** In that case netcap reports the fact and how to grant it (`setcap cap_net_raw+ep`) on stderr, and emits on stdout a **gap record** with `layers_missing=[NETWORK]`. The default exit code is **0**.

It is 0 because that gap has to reach the center. When Ansible drives many nodes, an exit code of 1 makes the task a failure, so the result file is not retrieved and **nothing at all** is recorded centrally for that node. Then the inventory view reads as "this node has no TLS links" — when in fact it simply was not observed. Carrying the gap through is what keeps "not observed" apart from "not there".

If you are running it by hand and want it to fail, pass `--strict` (the gap still goes to stdout).

### `pqcota-cngscan`

```
pqcota-cngscan [--output json|table] [node-id]
```

| Argument/option | Default | What it does |
|---|---|---|
| `[node-id]` | the self-id derived from the machine fingerprint, or `host://local` if that is empty too | the node the observation is attached to |
| `--output` | `json` | output format → [shared, below](#--output--shared-by-nodescan-jvmscan-and-cngscan) |

**It ships in the release's `pqcota-windows-amd64.zip` together with `pqcota-jvmscan`** (since v0.6.3). To build it yourself:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/windows-amd64/ ./cmd/pqcota-cngscan
```

**Run anywhere other than Windows and it emits a gap, not an empty result**, with exit code **0**. This is the same rule netcap follows when `CAP_NET_RAW` is missing, for the same reason — the gap has to reach the centre for "a node with no CNG" and "a node whose CNG was not seen" to stay apart.

It calls `bcrypt.dll` directly instead of `certutil`, PowerShell or WMI. What it looks at, through which API → cng-collector.

### `--output` — shared by nodescan, jvmscan and cngscan

The same collection runs; what differs is **which layer is emitted**.

| Value | What it emits | When |
|---|---|---|
| `json` (default) | a **CollectionResult** — the collector's native original (`raw_capture`) and the standard CycloneDX body (`cbom_cyclonedx`) in one message together with the Envelope and completeness map | the center (③) retrieves and accumulates it |
| `table` | the **Finding[] derived by normalizing** that result, as a human-readable table | checking one node right where it is |

Progress and warnings go to stderr in both cases — stdout carries only what you asked for.

**`table` stores nothing.** It runs the same normalization the center does, in memory, once, and throws it away — history and snapshot diffs only exist once things accumulate in ③.

### Privileges · environment variables

What you need when running on a node. Insufficient privilege means **the visible range shrinks, or that command cannot run at all**. What was not observed is reported through the completeness map, but it is better to have the privilege in the first place.

| Command | Privilege | Environment variables |
|---|---|---|
| `pqcota-nodescan` | its own process works as-is. **Seeing other users' requires root** (or `CAP_SYS_PTRACE`) | `PQCOTA_SIGN_KEY` — if set, results are signed (optional) |
| `pqcota-netcap` | **`CAP_NET_RAW` required** (`setcap` or root) — without it capture never starts | `NETCAP_IFACE` (default `eth0`) · `NETCAP_WINDOW_SEC` (default 8s) |
| `pqcota-jvmscan` | **the same UID** as the target JVM (or root). If the target blocks attach it degrades to reading the target's `java.security` | `PQCOTA_JVM_AGENT`=path to collector.jar — given, it takes the attach path. **Without it, and with no JVM running**, it starts one to see the launcher's default provider chain, recorded as **degraded** (not an observation of a running app) |
| `pqcota-cngscan` | no special privilege — the `bcrypt.dll` enumeration APIs are read-only queries | `PQCOTA_SIGN_KEY` — if set, results are signed (optional) |

The key pair for `PQCOTA_SIGN_KEY` (and the matching `PQCOTA_VERIFY_KEY` at the centre) comes from [`pqcota-keygen`](https://github.com/randyinthedev-hash/pqcota-common/blob/main/cmd/README.md#pqcota-keygen), which lives in `pqcota-common` because plan approval uses the same kind of key.


### Runtime requirements — kernel and privileges

**The kernel floor is 3.2.** That is the value the Go toolchain sets (since Go 1.24), and this repo requires nothing newer. Above that, distro and libc do not matter — the binaries are statically linked.

| Capability | Kernel requirement | Below it |
|---|---|---|
| node scan · fork determination · JVM recon | **3.2** (the toolchain floor) | the binary does not run |
| communication edge observation | no extra requirement (`AF_PACKET` is 2.2-era) | — |
| app attribution (systemd units) | an environment where systemd runs | attribution falls back to the **executable path** instead of a unit name (upstart-era distros) |
| **JVM attach inside a container** | **4.1** (`NSpid` in `/proc/<pid>/status`) | falls back to the host PID — only that JVM goes unobserved (reported as a gap) |

Even below the floor it **never goes silently wrong**. What was not observed goes out as a completeness gap, and without `NSpid` the host PID is used as-is.

**Measured** (in KVM VMs — containers share the host kernel, so this item cannot be verified there):

| Kernel | Distro | Result |
|---|---|---|
| **3.2.0** | Ubuntu 12.04 | all three collectors exited cleanly. OpenSSL 1.0.0g detected (fork=OpenSSL, dynamic), AF_PACKET observed successfully over an 8-second window. With no systemd, app attribution fell back to the **executable path** (`/usr/sbin/sshd` and so on) |
| **3.10.0** | CentOS 7.9 | all three collectors exited cleanly. OpenSSL 1.0.2k detected, and on cgroup v1 **systemd unit attribution succeeded** (`sshd.service` and so on) |

Neither kernel has an **`NSpid` line** in `/proc/<pid>/status`, and the host-PID fallback worked instead of dying — which confirms the 4.1 boundary against the real thing.

> **The PoC/test harness is not here.** The CLI that verifies the openssl collector against real `/proc` and ELF lives co-located with its only consumer, the integration test — [`collectors/openssl/integration/probe`](../collectors/openssl/integration). This folder (cmd/) holds **only product discovery entry points**.

## ③ Other — commands that are not collectors

**They are not observation.** They emit no `CollectionResult`, so nothing is ingested centrally. `pqcota-procs` runs on the target machine.

### `pqcota-procs`

```
pqcota-procs [--unit UNIT] [--exe PATH] [--cmd REGEX]
```

| Option | What it does |
|---|---|
| `--unit UNIT` | a systemd unit name (cgroup matching) |
| `--exe PATH` | the executable path (exact match) |
| `--cmd REGEX` | a cmdline regular expression |

**At least one of the three** must be given (all empty → exit code 2). Seeing other users' processes requires root.

It exists to find **what to restart** right before provisioning — a PID is volatile, so it is not stored but looked up on the spot. There is no automatic path calling it yet (the playbook's `activation.restart` runs the command the user wrote, verbatim).

---
**When to use what**
- Observing several nodes and accumulating them into the inventory → run **②** on each node (default `--output json`) → ingest centrally with [`pqcota-ingest`](https://github.com/randyinthedev-hash/pqcota-inventory/blob/main/cmd/README.md).
- Just checking one node in place → run **②** with `--output table`. Nothing accumulates.

> All the logic lives in `pkg/inventory/` (normalization, history) and `collectors/` (collection); these commands are thin entry points that assemble it. Retrieved results are **accumulated into an append-only history** by the inventory's `pqcota-ingest`.
