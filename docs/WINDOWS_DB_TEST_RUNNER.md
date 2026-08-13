# Windows Database Test Runner

Run `windows-db-test-runner.py` from a Linux or WSL management machine. Python is not required on the Windows endpoint.

Install the management-side dependency:

```bash
python3 -m pip install paramiko
```

Run the current Windows PostgreSQL suite:

```bash
python3 windows-db-test-runner.py run --database postgresql --windows-host <windows-host> --receiver-host <receiver-host>
```

Or run it directly from GitHub:

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/retyingfct/setup/main/windows-db-test-runner.py) run --database postgresql --windows-host <windows-host> --receiver-host <receiver-host>
```

The runner prompts for the Windows and receiver SSH passwords. It executes encoded PowerShell over SSH on Windows, queries the receiver over SSH, and stores evidence on the management machine under `remote-evidence/windows/postgresql/` by default.

Run selected scenarios with a comma-separated list:

```bash
python3 windows-db-test-runner.py run --database postgresql --scenario B1,B2,B3 --windows-host <windows-host> --receiver-host <receiver-host>
```

The current draft covers Windows PostgreSQL only. It does not install databases, create VMware snapshots, revert VMs, or provide Windows MySQL, MariaDB, or Oracle adapters.

Use only against an authorized disposable lab. Preserve a clean VM snapshot before state-changing scenarios and keep uninstall scenario I9 last.

Copyright © Forensic CyberTech Pvt. Ltd.
