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

The runner prompts for the receiver IP/hostname, SSH username/password, receiver sudo password, and receiver log hostname. Normally accept the local-hostname default. On a renamed full clone whose encrypted Agent ID was copied from the original, enter the original Agent ID/receiver directory name. Credentials remain in memory and are redacted from evidence. Password SSH requires `python3-paramiko`.

Evidence is written to `evidence/<database>/<run-id>/`. Resume an interrupted run with:

```bash
python3 db-test-runner.py run --resume
```

Run one scenario or a comma-separated ordered group when reproducing results:

```bash
python3 db-test-runner.py run --database postgresql --scenario C5a
```

```bash
python3 db-test-runner.py run --database mysql --scenario D2,D2a,D2d,D2f
```

Normal runs include safe, configuration, and restorable disruptive cases such as controlled receiver or database outages. Use this option when only safe/configuration cases should run:

```bash
python3 db-test-runner.py run --safe-only
```

Destructive cases remain skipped by default. With no risk flags, the runner asks only whether to include destructive clone-only cases; approval requires typing `CLONE`. Non-interactive clone execution requires `--include-destructive --confirm-clone`. The constrained lab uses one-minute stability, outage, and soak windows when success is already demonstrated; reports record the shortened duration against the upstream specification.

Version `0.4.18-draft` contains all 400 management rows. Executable adapters are PostgreSQL 90/102, MySQL 90/107, MariaDB 75/91, and Oracle 80/100. Every other row is explicitly classified as environment-dependent, manual, or not applicable and is shown in console output; no row remains generic pending work. PostgreSQL CSV assertions are evaluated after standards-compliant CSV decoding. A13 caps a misbehaving setup wizard transcript at 64 KiB and enforces a short hard timeout. Clone runs can map a unique OS hostname to the copied collector Agent ID used as the receiver directory. MySQL-family SQL snapshots are headerless, and the temporary slow-log and JSON error-sink settings changed by D4b, D4c, and D7a are restored to their captured values. MySQL marker queries preserve SQL comments and set `long_query_time=0` for their own connection only so the slow log records correlation markers without altering the server-global threshold. Constrained stability, outage, and soak checks use one-minute lab windows, with generated counts and result text derived from that duration. The MySQL-family G9 generator uses shell-safe query fragments, preserves its correlation comments, and sets a session-local zero slow-query threshold. MySQL D4b/D4c select a disposable database before table operations, and G15 preserves generated marker comments. The `--scenario` option accepts a comma-separated list and preserves the requested execution order. MySQL D2f evaluates its own format scope against the complete correlated receiver block rather than inheriting D2 severity. MySQL D1b writes real include-file newlines under `/etc/mysql`, resets systemd's failure counter before restarting, edits the regular `mysql.cnf` target, and retains its backup until MySQL restarts successfully. A9 retries its freshly installed health endpoint for up to 15 seconds to avoid a service-start race. Implemented adapters are not test results: only an actual evidence run can mark a scenario Pass or Fail.

The G9 multi-megabyte test uses the lower effective value of imrelp `maxDataSize` and global `maxMessageSize`. A known limit below the generated record makes the scenario `Inconclusive` instead of falsely blaming the collector. Configure both to at least 2112 KiB; the companion `receiver.sh` defaults both to 4096 KiB. Receiver-outage scenarios stop `syslog.socket` and `rsyslog.service` and verify RELP port 2514 is closed before testing.

For destructive scenarios, manually create and boot a full dedicated clone of the Ubuntu client, then run this same runner inside the clone. The script does not control VMware or create nested VMs. Do not run destructive scenarios on the original client VM. Oracle installation remains manual because media, licensing, edition, SID, and layout are site-specific. The current Oracle adapter targets a native host installation; it does not execute through Docker or translate container ADR/audit paths to host bind mounts.

Copyright © Forensic CyberTech Pvt. Ltd.
