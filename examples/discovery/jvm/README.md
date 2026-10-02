English · [한국어](README.ko.md)

# examples/discovery/jvm: reconnaissance → attach on a running JVM

```bash
./examples/discovery/jvm/run.sh
```

> **Prerequisites: the Go toolchain + Docker.** The other discovery examples run on Go alone, but this one needs a **live JVM** (the target of reconnaissance and attach), so it is isolated in a container.

## What it shows

Just as the openssl collector sweeps `/proc` and finds the loaded libraries itself, **the jvm collector also reconnoitres running JVMs on its own**. This example shows that end to end at minimum:

1. **Reconnaissance** (`ScanJVMs`): finds running JVMs through `/proc` and gets each one's PID, JAVA_HOME, version and app. The caller does not need to know the PID or the JDK in advance.
2. **Attach**: attaches to the PID it found and observes what `Security.getProviders()` **actually returns**.
3. **Catching dynamic registration**: the example app does **not register BC statically** in `java.security` and only calls `addProvider(BouncyCastle)` at run time. **A static scan (the probe) cannot observe this. Only attach catches it** (`detection=runtime-introspection`).
4. **JSON Lines loading**: the attach path emits one line per JVM (in case of several). `pqcota-ingest` reads `*.jsonl` and loads it.

## The key point: probe vs attach

| | Static probe | **Attach** |
|---|---|---|
| What it sees | the statically registered chain in `java.security` | what the running JVM **actually has** (including dynamic `addProvider`) |
| The dynamic BC in this example | ❌ not observed | ✅ caught |

If `PQCOTA_JVM_AGENT` (the collector JAR) is present it attaches, and if not it falls back to the probe and records the downgrade.

## Several JVMs

When a node has several JVMs, each becomes a **distinct finding**. The identifier is the **app** (main class or `-jar`), not the PID, so two apps on the same JDK are not merged into one and the history does not break on a rescan. Design and boundary: see the collector source under `collectors/jvm/`.

## The whole flow

For Ansible/SSH, several nodes and loading into Postgres, see the six steps of [demo/](https://github.com/randyinthedev-hash/pqcota/tree/main/demo) (its second step runs this reconnaissance → attach on real nodes).
