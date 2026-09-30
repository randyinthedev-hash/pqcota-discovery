# pqcota-discovery

The discovery stage of the pqcota platform: observe which cryptography is in use on running systems.

It holds the collectors (OpenSSL, JVM, network, Windows CNG), their commands, the reference Ansible playbook, and the Java attach sidecar. It is one of five repositories that make up [pqcota](https://github.com/randyinthedev-hash/pqcota): `pqcota-common`, `pqcota-inventory`, `pqcota-discovery`, `pqcota-provisioning`, and the integration repository `pqcota` (demo, examples, release bundles, contributing guide).

## What is here

| Path | What |
|---|---|
| `discovery/collectors/` | the collectors: `openssl`, `jvm` (with the Java sidecar), `network`, `cng` |
| `discovery/cmd/` | the commands: `pqcota-nodescan`, `pqcota-jvmscan`, `pqcota-netcap`, `pqcota-cngscan`, `pqcota-hosts`, `pqcota-procs` |
| `discovery/ansible/` | the reference playbook that runs the collectors across prepared nodes |
| `pkg/discovery/procs/` | process attribution shared by the collectors |
| `examples/` | runnable examples: access prep, ingest of collected results, and the JVM reconnaissance → attach |
| `discovery/README.md` | what the stage does and how to use it |

## Depends on

`pqcota-common` and `pqcota-inventory`. Inside this module the collectors import only `pqcota-common` and `pkg/discovery/procs`, because they are built into binaries that go onto the observed nodes.

## Build and test

```bash
make            # every check of this repository
go test ./...   # unit tests only
```

`make build-jar` builds the Java attach sidecar (`build/collector.jar`, needs JDK 11+). `make build` also cross-compiles for linux/amd64 and windows/amd64, since the collectors' core is Linux-only code behind build tags.

Until the modules are tagged, `go.mod` points at the sibling repositories with `replace` directives (`../pqcota-common` and so on), so clone the repositories side by side. Remove the `replace` lines and raise the `require` versions once the tags exist.

## Contributing · security · license

Contributing and security reporting are described in the [pqcota repository](https://github.com/randyinthedev-hash/pqcota). Licensed under [Apache-2.0](https://github.com/randyinthedev-hash/pqcota/blob/main/LICENSE).
