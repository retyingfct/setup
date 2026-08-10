# Database Test Runner

`db-test-runner.py` runs on the Ubuntu database endpoint and coordinates receiver validation over password-authenticated SSH. Run it as the normal endpoint user, not with `sudo`.

## Run from GitHub

Use Bash process substitution so interactive prompts continue reading from the terminal:

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/retyingfct/setup/main/db-test-runner.py) run
```

The runner displays a numbered menu for PostgreSQL, MySQL, MariaDB, and Oracle. The optional `--database` argument can still select an engine directly.

## Commands

Check readiness without changing the endpoint:

```bash
python3 db-test-runner.py status
```

Offer interactive package preparation when the selected database is missing:

```bash
python3 db-test-runner.py prepare
```

Run every applicable automated scenario:

```bash
python3 db-test-runner.py run
```

Reproduce one scenario:

```bash
python3 db-test-runner.py run --database postgresql --scenario C5a
```

Resume the latest incomplete run:

```bash
python3 db-test-runner.py run --resume
```

Apply pending recovery actions after an interrupted configuration-changing scenario:

```bash
python3 db-test-runner.py restore
```

Disruptive receiver/database outage cases are skipped unless enabled:

```bash
python3 db-test-runner.py run --include-disruptive
```

Destructive cases are excluded by default and require `--include-destructive`.

## Interactive connection

The runner prompts for:

- Receiver IP address or hostname
- Receiver SSH port and username
- Receiver SSH password
- Receiver sudo password, with an option to reuse the SSH password

Credentials remain in memory and are redacted from evidence. The script checks for `python3-paramiko`; if absent, it simulates the APT operation and asks before installation. SSH host keys require explicit trust on first connection.

## Workflow and safeguards

The client database and collector are tested locally. Receiver evidence is queried through SSH under `/var/log/clients/<client-hostname>/<source>.log`.

Before testing, the runner verifies Ubuntu resources, the selected database, `log-collector`, its health endpoint, receiver rsyslog, RELP port `2514`, and receiver storage. Tests run sequentially for low-memory lab endpoints.

Configuration-changing scenarios record restoration actions before making changes and restore values in `finally` cleanup. Receiver outage tests schedule an independent rsyslog recovery before stopping the service. Product failures do not stop later scenarios; infrastructure failures are reported as `Inconclusive`.

The constrained lab uses five-minute B4 stability and B5 outage windows. A successful five-minute run is treated as Pass by the approved lab methodology, while evidence records the difference from the upstream duration.

## Evidence

Evidence is stored beneath the directory where the runner is launched:

```text
evidence/<database>/<run-id>/
├── environment.json
├── results.tsv
├── run-summary.md
├── SHA256SUMS
└── scenarios/<scenario-id>/
    ├── result.json
    ├── commands.log
    └── command-*.json
```

Statuses are `Pass`, `Fail`, `Not Tested`, `Inconclusive`, and `Cleanup Failed`. Unique run markers prevent earlier receiver records from causing false passes. Disposable secrets used for redaction testing are removed from stored output.

## Current automation scope

The script includes every applicable management scenario ID: PostgreSQL 102, MySQL 107, MariaDB 91, and Oracle 100. PostgreSQL core scenarios are executable. MySQL, MariaDB, and Oracle currently have readiness and catalog support; scenarios without a safe executable adapter are explicitly recorded as `Not Tested`, never omitted or reported as passing.

MySQL and MariaDB must be tested from separate VMware snapshot states. The runner will not uninstall one engine to replace the other. Oracle installation remains manual because its media, licensing, edition, SID, and filesystem layout are site-specific.

Copyright © Forensic CyberTech Pvt. Ltd.
