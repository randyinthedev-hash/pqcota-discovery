# examples/discovery: access prep + two intake paths (① direct observation · ② delegated CBOM)

```bash
./examples/discovery/run.sh
```

## What happens

### 1) `pqcota-hosts`: the user's hosts file → an Ansible inventory + endpoints
The input is [`hosts.csv`](hosts.csv) (a file the user manages):
```
node_id,name,ip,port,ssh_user,ssh_key,ssh_pass,os,connection
node-a,Web Frontend,10.0.0.2,22,deploy,/home/me/.ssh/id_ed25519,,,            ← SSH key (recommended)
node-b,Payments App (Java),10.0.0.3,22,deploy,,example-password,,             ← password
node-c,Payments DB,10.0.0.9,22,deploy,/home/me/.ssh/id_ed25519,,,
node-d,Payments Gateway (Windows),10.0.0.11,,Administrator,,example-password,windows,winrm
```
→ It produces two things:
- `--ansible-out targets.ini`: a runtime-only **Ansible inventory** (it carries connection secrets, so it is `0600`, readable only by the owner). Use it to run the collectors on each node. **It is not persisted into the pqcota inventory.**
- stdout: **safe endpoints** (node_id, name, ip and port, with **secrets excluded**). With `--dsn`, they are upserted into the inventory (Postgres) as reusable and editable records.

> Access secrets (keys, passwords, accounts) exist **only in hosts.csv (the user's file) and the generated targets.ini (runtime)** and are never loaded into the pqcota inventory.

#### Authentication: an SSH key (recommended) or a password
The header is required and the column order is free, and each **host is independent**. Only `node_id` is required.

| Column | Meaning |
|---|---|
| `ssh_user` | the login account (e.g. `deploy`, `root`) |
| `ssh_key` | **the path of a private SSH key you made in advance** → `ansible_ssh_private_key_file` (recommended) |
| `ssh_pass` | a password → `ansible_ssh_pass` (supported but not recommended) |
| `os` | `linux` (default) or `windows`. It decides which collectors run on that node |
| `connection` | `ssh` (default) or `winrm`. **How to connect** to that node |

- **Key** (node-a and node-c): write the private key path in `ssh_key` and leave `ssh_pass` empty.
- **Password** (node-b): put the password in `ssh_pass` and leave `ssh_key` empty. ⚠️ For Ansible to connect with a password, the controller needs **`sshpass` installed** (`apt install sshpass`). A plaintext password ends up in targets.ini, so we recommend keys.
- You can mix them (each node differs, as in the example above).

#### `os`: decides which collectors to send

`linux` gets `pqcota-nodescan`, `pqcota-netcap` and `pqcota-jvmscan`; `windows` gets `pqcota-cngscan` and `pqcota-jvmscan`. If empty it is `linux`, and any value that is neither is an **error**. Accepting it as Linux without checking would put Linux collectors on a Windows node and the failure would only show up much later.

**It is written down, not observed.** The OS has to be known *before* a collector is shipped, but finding it out would require shipping something already. hosts.csv is a file the user manages, so they usually know. (The playbook checks once more with `gather_facts`. If it differs from what is written, that node is skipped.)

What `os` produces is inventory **groups**: `[targets_linux]` and `[targets_windows]`, plus their parent `[targets]`. A playbook that used `hosts: targets` runs unchanged.

#### `connection`: how to connect

**It is written here because `targets.ini` is overwritten on every run.** A connection setting added by hand is erased on the next run. How to connect has to live somewhere that is not erased, which is this file.

| Value | What goes into the inventory | Account and secret |
|---|---|---|
| `ssh` (default) | as is for Linux. **For Windows, `ansible_shell_type=powershell`**: the shell is not sh | `ssh_key` (recommended) or `ssh_pass` |
| `winrm` | `ansible_connection=winrm`, port defaults to **5985** | `ssh_pass` → `ansible_password`. **It does not connect with a key** |

If you wrote `port`, it wins (`5986` for HTTPS). It is an **error** if `connection=winrm` while `os` is not `windows`, or if `ssh_key` is present. A mismatch that would only show up at connection time is stopped as an error at the point the file is read.

> **Two values that differ per site are not invented**: SSH's `ansible_shell_type=cmd` (only when sshd's default shell is cmd) and WinRM's `ansible_winrm_transport`. A comment in the generated ini shows where they go, and the values belong in `group_vars/targets_windows.yml`.
>
> A setting the winrm plugin **does not declare**, such as certificate validation, is passed straight through to pywinrm when written as `ansible_winrm_<option>` (`ansible_winrm_server_cert_validation` and so on). It is pywinrm's name, not an Ansible option, so `ansible-doc` will not find it.

#### Making an SSH key and registering it on the target
To use keys, make a private/public key pair and **register the public key in the target's `authorized_keys`**:
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
Then write the **private key path** (`~/.ssh/id_ed25519`) in `ssh_key` of `hosts.csv`. Without `ssh-copy-id`, add the contents of the public key (`.pub`) as one line to the target's `~/.ssh/authorized_keys` (permissions: `.ssh` 700, `authorized_keys` 600).

> This example (`run.sh`) does not actually connect, so it **works even without a key file**. `pqcota-hosts` only copies the path string into targets.ini. The key is used later, in the real `ansible-playbook` step.

### 2) `pqcota-ingest`: retrieved results → scope gate → normalization → loading
It reads the `CollectionResult` JSON files in [`../data/results`](https://github.com/randyinthedev-hash/pqcota-inventory/tree/main/examples/data), normalizes them into derived `Finding`s and loads them. Without `PQCOTA_DSN` you get an **in-memory summary** (snapshots, and asset and edge counts per node); with it, the data is persisted append-only in Postgres. Signature verification happens only when `PQCOTA_VERIFY_KEY` is set.

The decoded CBOM of `node-a-openssl.json` contains one shared library with several apps attached:
```json
{"name":"pqcota:openssl.lib","value":"libssl.so.3"},
{"name":"pqcota:app_keys","value":"/opt/apps/api-gw,/opt/apps/payment-gw"}
```

## Observing a running JVM (reconnaissance → attach)
The JCA provider chain shows what is really there (including a runtime `addProvider`) only if you **attach to a live JVM**. It is isolated in a separate example (it needs a JDK and Docker, not just Go): **[jvm/](jvm/README.md)** shows `/proc` reconnaissance → attach → catching the dynamic BC → JSONL loading at minimum.

## To scan a real node (Linux)
To produce real observations instead of the samples, run this on the observed host:
```bash
go run ./cmd/pqcota-nodescan <node-id>   # the loaded OpenSSL (libssl/libcrypto) from /proc: Linux only
```
Collect the result JSON files and give that directory to `pqcota-ingest`. For the JVM see [jvm/](jvm/README.md). The map of all commands: [cmd/README](../../cmd/README.md).
