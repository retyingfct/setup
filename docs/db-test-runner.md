# Database Test Runner

Run `db-test-runner.py` as the normal Ubuntu endpoint user, not with `sudo`.

```bash
python3 db-test-runner.py status
```

Inspect actual automation coverage without connecting to the lab:

```bash
python3 db-test-runner.py coverage --database postgresql
```

```bash
python3 db-test-runner.py prepare
```

```bash
python3 db-test-runner.py run
```

When `--database` is omitted, the runner displays a numbered PostgreSQL, MySQL, MariaDB, and Oracle menu. `--database postgresql` remains available for non-interactive selection.

The runner prompts for the receiver IP/hostname, SSH username/password, and receiver sudo password. Credentials remain in memory and are redacted from evidence. Password SSH requires `python3-paramiko`.

Evidence is written to `evidence/<database>/<run-id>/`. Resume an interrupted run with:

```bash
python3 db-test-runner.py run --resume
```

Run one scenario when reproducing a result:

```bash
python3 db-test-runner.py run --database postgresql --scenario C5a
```

Normal runs include safe, configuration, and restorable disruptive cases such as controlled receiver or database outages. Use this option when only safe/configuration cases should run:

```bash
python3 db-test-runner.py run --safe-only
```

Destructive cases remain skipped by default. With no risk flags, the runner asks only whether to include destructive clone-only cases; approval requires typing `CLONE`. Non-interactive clone execution requires `--include-destructive --confirm-clone`. The constrained lab uses five-minute stability/outage windows; reports record the shorter duration against the upstream specification.

Version `0.4.3-draft` contains all 400 management rows. Executable adapters are PostgreSQL 90/102, MySQL 90/107, MariaDB 75/91, and Oracle 80/100. Every other row is explicitly classified as environment-dependent, manual, or not applicable; no row remains generic pending work. PostgreSQL CSV assertions are evaluated after standards-compliant CSV decoding. Implemented adapters are not test results: only an actual evidence run can mark a scenario Pass or Fail.

The G9 multi-megabyte test first reads the receiver's configured imrelp `maxDataSize`. A known limit below the generated record makes the scenario `Inconclusive` instead of falsely blaming the collector. Configure at least 2112 KiB; the companion `receiver.sh` defaults to 4096 KiB.

For destructive scenarios, manually create and boot a full dedicated clone of the Ubuntu client, then run this same runner inside the clone. The script does not control VMware or create nested VMs. Do not run destructive scenarios on the original client VM. Oracle installation remains manual because media, licensing, edition, SID, and layout are site-specific. The current Oracle adapter targets a native host installation; it does not execute through Docker or translate container ADR/audit paths to host bind mounts.

Copyright © Forensic CyberTech Pvt. Ltd.
