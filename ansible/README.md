English · [한국어](README.ko.md)

# ansible/: the reference playbook

A **reference implementation** that runs the collectors on prepared nodes all at once. The demo uses it as it is, and it is here so you can carry it over to your own infrastructure unchanged.

```bash
pqcota-hosts --ansible-out targets.ini hosts.csv     # ① prepare access
ansible-playbook -i targets.ini ansible/discover.yml
```

| File | What it does |
|---|---|
| [`discover.yml`](discover.yml) | **Ship → run → retrieve → clean up**: puts the collectors in a staging directory and runs them, brings the result JSON back to the controller, then removes the staging directory from the node |

**It branches on the node's OS.** Using the `os_family` that `gather_facts` reports, it runs the three collectors on Linux and two (`pqcota-cngscan` and `pqcota-jvmscan`) on Windows. On anything else it does nothing. That means there is no result, which is not the same as "that node has nothing".

**Running Windows nodes needs two more things:**

```bash
ansible-galaxy collection install ansible.windows            # the win_copy and win_command modules
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/windows-amd64/ \
  ./cmd/pqcota-cngscan ./cmd/pqcota-jvmscan
```

A Windows node has to be **reached with an administrator account** for JVMs running as other users to be visible (measured: 163 of 265 could not be opened as an ordinary user). This is the counterpart of `become: true` in the Linux block.

How to connect is decided by the `connection` column of `hosts.csv` (`ssh` or `winrm`). `targets.ini` is overwritten on every run, so settings added by hand do not survive → [how to write it](../examples/discovery/README.md). Only the values that differ per site (WinRM transport and certificate validation, an sshd whose default shell is cmd) go in `group_vars/targets_windows.yml`.

> **It has been run once on the real thing** (TD-WIN-1·2): connected with Win32-OpenSSH and a key, ship, observe, retrieve and clean-up all ran to the end, and the staging directory was gone from the node afterwards. Note, though, that **the demo does not verify this path**. The demo has only Linux containers, so the Windows branch has no gate that is checked on every run.

**The staging directory is removed when a run completes without failure.** A collector is not a resident agent but a CLI that exits after it runs, so this one-shot pattern fits. Two things stay behind. If a run fails partway, the staging directory stays too, because the clean-up step does not run. And on a node where the Java attach path is used, the observed JVM writes its observation to `/tmp/pqcota-providers-<pid>.txt` in its own `/tmp`, and nothing deletes it.

**The JVM add-on (`collector.jar`) is not sprayed onto every node.** `pqcota-jvmscan --recon` first checks whether the node has a JVM, and the add-on goes only to nodes that do.

## To use it on your own infrastructure

Change `collector_bin_dir` (Linux) and `collector_bin_dir_win` (Windows) to your own build output → [pqcota build guide](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/build.md#build). The reason only the Linux block carries `become: true` is `pqcota-netcap`'s `CAP_NET_RAW` and the `/proc` coverage of every process.

**There is no generator that builds playbooks at fleet scale.** The model does not build its own remote execution engine: the user's existing substrate (Ansible, Salt and so on) does the running.
