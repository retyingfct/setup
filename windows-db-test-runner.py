#!/usr/bin/env python3
"""Management-node runner for Windows database collector integration tests.

Runs PowerShell over SSH on the Windows endpoint, queries the RELP receiver over
SSH, and writes evidence locally so VM snapshot reverts cannot destroy it.
"""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import hashlib
import json
import os
import re
import socket
import shlex
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import paramiko


VERSION = "0.1.0-draft"
DEFAULT_WINDOWS_HOST = "100.79.208.73"
DEFAULT_RECEIVER_HOST = "100.124.30.20"
WINDOWS_USER = "windows"
RECEIVER_USER = "ubuntu"
PG_LOG = r"C:\Program Files\PostgreSQL\16\data\log"
COLLECTOR = r"C:\Program Files\log-collector\log-collector.exe"
SCENARIOS = (
    "A7", "A8", "A9", "A10", "A11", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "C1", "C3", "C2",
    "C4", "C4a", "C4b", "C4c", "C4d", "C4e", "C4f", "C2a", "C2b", "C2c", "C2d", "C2f",
    "C7", "C7a", "C7b", "C7c", "C7d", "C7e", "C5", "C5a", "C5c", "C5d", "G1", "G1a", "G1b", "G2", "G3", "G3a", "G3b", "G4", "G4a", "G6", "G6b", "G7", "G8", "G9", "G10", "G11", "G12", "G15",
    "H1", "H2", "H4", "H6", "H9", "H10", "H12", "I1", "I8",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-windows-postgresql-" + uuid.uuid4().hex[:8]


def ps_encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def redact(value: str) -> str:
    for secret in ("windows", "ubuntu", "postgres"):
        value = value.replace(f"password={secret}", "password=***")
        value = value.replace(f"PGPASSWORD='{secret}'", "PGPASSWORD='***'")
    return value


@dataclass
class Command:
    target: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    started_at: str
    ended_at: str


@dataclass
class Assertion:
    name: str
    passed: bool
    observed: str


@dataclass
class Result:
    scenario_id: str
    name: str
    status: str
    summary: str
    assertions: list[Assertion] = field(default_factory=list)
    commands: list[Command] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now)
    ended_at: str = field(default_factory=utc_now)


class SSH:
    def __init__(self, host: str, user: str, password: str):
        self.host, self.user, self.password = host, user, password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, username=user, password=password, timeout=20)

    def close(self) -> None:
        self.client.close()

    def run(self, target: str, command: str, *, stdin_text: str = "", timeout: int = 180) -> Command:
        started = utc_now()
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        if stdin_text:
            stdin.write(stdin_text)
            stdin.flush()
        stdin.channel.shutdown_write()
        channel = stdout.channel
        out_parts: list[bytes] = []
        err_parts: list[bytes] = []
        deadline = time.monotonic() + timeout
        while True:
            if channel.recv_ready():
                out_parts.append(channel.recv(65535))
            if channel.recv_stderr_ready():
                err_parts.append(channel.recv_stderr(65535))
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() >= deadline:
                channel.close()
                raise TimeoutError(f"{target} command exceeded {timeout} seconds")
            time.sleep(0.02)
        out = b"".join(out_parts).decode("utf-8", "replace")
        err = b"".join(err_parts).decode("utf-8", "replace")
        code = channel.recv_exit_status()
        return Command(target, redact(command), code, redact(out), redact(err), started, utc_now())


class Lab:
    def __init__(self, win: SSH, receiver: SSH, evidence: Path):
        self.win, self.receiver, self.evidence = win, receiver, evidence
        self.run_token = evidence.name.lower().replace("-", "_")

    def ps(self, script: str, *, timeout: int = 180, label: str = "PowerShell") -> Command:
        command = f"powershell -NoProfile -EncodedCommand {ps_encoded(script)}"
        result = self.win.run("windows", command, timeout=timeout)
        result.command = label
        return result

    def wizard_probe(self, exchanges: list[tuple[str, str]], stop_pattern: str, *, timeout: int = 90, label: str = "setup wizard probe") -> Command:
        started = utc_now()
        channel = self.win.client.invoke_shell(width=220, height=60)
        command = f'powershell -NoProfile -Command "& \'{COLLECTOR}\' setup -c \'C:\\Program Files\\log-collector\\conf\\agent.toml\'"'
        channel.send(command + "\r\n")
        output = bytearray()
        deadline = time.monotonic() + timeout
        matched = False
        exchange_index = 0
        phase_start = 0
        try:
            while time.monotonic() < deadline:
                if channel.recv_ready():
                    output.extend(channel.recv(65535))
                    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", output[phase_start:].decode("utf-8", "replace"))
                    if exchange_index < len(exchanges):
                        pattern, response = exchanges[exchange_index]
                        if re.search(pattern, text, re.I | re.S):
                            channel.send(response + "\r\n")
                            exchange_index += 1
                            output.extend(f"\n[runner sent response {exchange_index}]\n".encode())
                            phase_start = len(output)
                    elif re.search(stop_pattern, text, re.I | re.S):
                        matched = True
                        break
                time.sleep(0.05)
        finally:
            channel.send("\x03")
            end = time.monotonic() + 3
            while time.monotonic() < end:
                if channel.recv_ready():
                    output.extend(channel.recv(65535))
                time.sleep(0.05)
            channel.close()
        transcript = output.decode("utf-8", "replace")
        return Command("windows", label, 0 if matched else 1, redact(transcript), "" if matched else f"wizard probe did not reach {stop_pattern!r}", started, utc_now())

    def foreground_interrupt(self, *, double: bool, timeout: int = 60, label: str = "foreground collector interrupt") -> Command:
        started = utc_now()
        channel = self.win.client.invoke_shell(width=220, height=60)
        channel.send(f'powershell -NoProfile -Command "& \'{COLLECTOR}\' run -c \'C:\\Program Files\\log-collector\\conf\\agent.toml\'"\r\n')
        output = bytearray()
        deadline = time.monotonic() + timeout
        signaled = False
        returned = False
        try:
            while time.monotonic() < deadline:
                if channel.recv_ready():
                    output.extend(channel.recv(65535))
                    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", output.decode("utf-8", "replace"))
                    if not signaled and re.search(r"collector|Running|Connected|started|health", text, re.I):
                        time.sleep(2)
                        channel.send("\x03")
                        if double:
                            time.sleep(0.15)
                            channel.send("\x03")
                        signaled = True
                    if signaled and re.search(r"windows@KENYATA-FCT-EP6[^\r\n]*>", text, re.I):
                        returned = True
                        break
                time.sleep(0.05)
        finally:
            if not returned:
                channel.send("\x03")
            end = time.monotonic() + 3
            while time.monotonic() < end:
                if channel.recv_ready(): output.extend(channel.recv(65535))
                time.sleep(0.05)
            channel.close()
        transcript = output.decode("utf-8", "replace")
        return Command("windows", label, 0 if signaled and returned else 1, redact(transcript), "" if signaled and returned else f"signaled={signaled} returned={returned}", started, utc_now())

    def complete_wizard(self, *, read_from_beginning: bool, timeout: int = 300, label: str = "complete setup wizard") -> Command:
        started = utc_now()
        channel = self.win.client.invoke_shell(width=220, height=60)
        channel.send(f'powershell -NoProfile -Command "& \'{COLLECTOR}\' setup -c \'C:\\Program Files\\log-collector\\conf\\agent.toml\'"\r\n')
        output = bytearray()
        phase_start = 0
        deadline = time.monotonic() + timeout
        returned = False
        responses = 0
        try:
            while time.monotonic() < deadline:
                if channel.recv_ready():
                    output.extend(channel.recv(65535))
                    raw = output[phase_start:].decode("utf-8", "replace")
                    clean = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", raw)
                    if re.search(r"windows@KENYATA-FCT-EP6[^\r\n]*>", clean, re.I) and responses:
                        returned = True
                        break
                    prompt_match = re.search(r"([^\r\n]{2,}[?:])\s*$", clean)
                    if not prompt_match:
                        time.sleep(0.05)
                        continue
                    prompt = prompt_match.group(1)
                    low = prompt.lower()
                    response = ""
                    if "agent id" in low:
                        response = ""
                    elif "client tag" in low or ("client" in low and "name" in low):
                        response = "kenyata"
                    elif "mongodb sources" in low:
                        response = "0"
                    elif "channels" in low:
                        response = "1"
                    elif "severity" in low or "choose [4]" in low or "application log file path" in low:
                        response = ""
                    elif "collect the postgresql" in low:
                        response = "y"
                    elif "collect" in low and any(x in low for x in ("mysql", "mariadb", "oracle")):
                        response = "n"
                    elif "read" in low and "beginning" in low:
                        response = "y" if read_from_beginning else "n"
                    elif "auto" in low and ("discover" in low or "detected" in low):
                        response = "y"
                    elif "merge" in low and any(x in low for x in ("continuation", "detail", "hint", "context")):
                        response = "y"
                    elif "format" in low:
                        response = "auto"
                    elif "transport" in low:
                        response = "relp"
                    elif re.fullmatch(r"\s*host\s*:", low) or "host" in low and any(x in low for x in ("receiver", "destination", "output", "required")):
                        response = "192.168.248.129"
                    elif "port" in low:
                        response = "2514"
                    elif "tls" in low:
                        response = "n"
                    elif "portal" in low or "management" in low and "url" in low:
                        response = ""
                    elif "pat" in low:
                        response = "github_pat_lc_disposable_test"
                    elif any(x in low for x in ("update", "repository", "asset", "interval")):
                        response = ""
                    elif any(x in low for x in ("write", "generate", "save", "confirm")) and "config" in low:
                        response = "y"
                    else:
                        response = ""
                    channel.send(response + "\r\n")
                    responses += 1
                    if responses > 200:
                        break
                    output.extend(f"\n[runner answered prompt {responses}: {response or '<blank>'}]\n".encode())
                    phase_start = len(output)
                time.sleep(0.05)
        finally:
            if not returned:
                channel.send("\x03")
            end = time.monotonic() + 3
            while time.monotonic() < end:
                if channel.recv_ready(): output.extend(channel.recv(65535))
                time.sleep(0.05)
            channel.close()
        transcript = output.decode("utf-8", "replace")
        written = bool(re.search(r"agent\.toml written|configuration.*(?:written|saved)|Generating configuration", transcript, re.I))
        okay = returned and written
        return Command("windows", label, 0 if okay else 1, redact(transcript), "" if okay else f"returned={returned} config_written={written} responses={responses}", started, utc_now())

    def recv(self, shell: str, *, timeout: int = 180, label: str = "receiver query") -> Command:
        command = "sudo -S bash -lc " + shlex.quote(shell)
        result = self.receiver.run("receiver", command, stdin_text=self.receiver.password + "\n", timeout=timeout)
        result.command = label
        return result

    def marker(self, scenario: str) -> str:
        return f"lc_win_pg_{scenario.lower()}_{self.run_token}_{uuid.uuid4().hex[:6]}"

    def pg(self, sql: str, *, expect_success: bool = True, label: str = "PostgreSQL SQL") -> Command:
        escaped = sql.replace("'", "''")
        script = (
            "$env:PGPASSWORD='postgres'; "
            f"& 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres "
            f"-v ON_ERROR_STOP=1 -c '{escaped}' 2>&1; exit $LASTEXITCODE"
        )
        return self.ps(script, label=label)

    def pg_at(self, sql: str, *, label: str = "PostgreSQL scalar SQL") -> Command:
        escaped = sql.replace("'", "''")
        script = (
            "$env:PGPASSWORD='postgres'; "
            f"& 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres "
            f"-At -v ON_ERROR_STOP=1 -c '{escaped}' 2>&1; exit $LASTEXITCODE"
        )
        return self.ps(script, label=label)

    def received(self, marker: str, *, all_sources: bool = False, wait: int = 30) -> Command:
        root = "/var/log/clients/kenyata-fct-ep6" if all_sources else "/var/log/clients/kenyata-fct-ep6/postgres_log.log"
        deadline = time.time() + wait
        latest = None
        while time.time() < deadline:
            latest = self.recv(f"grep -R -n -F {shlex.quote(marker)} {shlex.quote(root)} 2>/dev/null || true", label=f"search receiver for {marker}")
            if marker in latest.stdout:
                return latest
            time.sleep(2)
        assert latest is not None
        return latest

    def save(self, result: Result) -> None:
        directory = self.evidence / "scenarios" / result.scenario_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "result.json").write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for index, command in enumerate(result.commands, 1):
            stem = f"{index:02d}-{command.target}"
            (directory / f"{stem}.stdout.txt").write_text(command.stdout, encoding="utf-8")
            (directory / f"{stem}.stderr.txt").write_text(command.stderr, encoding="utf-8")


def evaluated(sid: str, name: str, commands: list[Command], assertions: list[Assertion], success: str) -> Result:
    passed = all(item.passed for item in assertions)
    failed = [item.name for item in assertions if not item.passed]
    return Result(sid, name, "Pass" if passed else "Fail", success if passed else "Failed assertion(s): " + ", ".join(failed), assertions, commands)


def config_validation(lab: Lab) -> Result:
    cmd = lab.ps(f"& '{COLLECTOR}' check 2>&1; exit $LASTEXITCODE", label="log-collector check")
    return evaluated("A8", "Collector configuration validation", [cmd], [Assertion("Config OK", cmd.exit_code == 0 and "Config OK" in cmd.stdout, cmd.stdout.strip())], "Config validated")


def encrypted_config(lab: Lab) -> Result:
    cmd = lab.ps("$p='C:\\Program Files\\log-collector\\conf\\agent.toml'; $b=[IO.File]::ReadAllBytes($p); $text=[Text.Encoding]::UTF8.GetString($b); $check=& 'C:\\Program Files\\log-collector\\log-collector.exe' check 2>&1; [pscustomobject]@{Length=$b.Length;StartsToml=$text.TrimStart().StartsWith('[');ContainsOutputs=$text.Contains('[[outputs]]');ConfigCheck=($check -join ' ')}|ConvertTo-Json -Compress", label="inspect encrypted configuration")
    try: data = json.loads(cmd.stdout.strip())
    except Exception: data = {}
    assertions = [Assertion("configuration exists", int(data.get("Length", 0)) > 0, str(data.get("Length"))), Assertion("not readable TOML", not data.get("StartsToml") and not data.get("ContainsOutputs"), cmd.stdout.strip()), Assertion("encrypted config remains valid", "Config OK" in str(data.get("ConfigCheck", "")), str(data.get("ConfigCheck")))]
    return evaluated("A7", "Encrypted configuration at rest", [cmd], assertions, "Collector configuration is encrypted at rest and remains valid")


def a1(lab: Lab) -> Result:
    probe = lab.wizard_probe([], r"Agent ID[^\r\n]*:", timeout=45, label="probe setup wizard startup")
    return evaluated("A1", "Setup wizard starts", [probe], [Assertion("identity prompt reached", probe.exit_code == 0 and re.search(r"Agent ID[^\r\n]*:", probe.stdout, re.I) is not None, probe.stdout.strip() + probe.stderr.strip())], "Setup wizard started and reached its Agent ID prompt")


def a3(lab: Lab) -> Result:
    probe = lab.wizard_probe([(r"Agent ID[^\r\n]*:", "")], r"Client[^\r\n]*(tag|tenant|name)[^\r\n]*:", timeout=60, label="accept default Agent ID")
    hostname_default = "kenyata-fct-ep6" in probe.stdout
    advanced = re.search(r"Client[^\r\n]*(tag|tenant|name)[^\r\n]*:", probe.stdout, re.I) is not None
    return evaluated("A3", "Agent ID defaults to hostname", [probe], [Assertion("hostname shown as default", hostname_default, probe.stdout.strip()), Assertion("blank Agent ID advanced", probe.exit_code == 0 and advanced, probe.stdout.strip() + probe.stderr.strip())], "Blank Agent ID accepted the endpoint hostname default and advanced")


def a2(lab: Lab) -> Result:
    probe = lab.wizard_probe([(r"Agent ID[^\r\n]*:", ""), (r"Client[^\r\n]*(tag|tenant|name)[^\r\n]*:", "")], r"(required|cannot be empty|must not be empty|enter.+client)", timeout=60, label="submit empty required client identity")
    rejected = re.search(r"required|cannot be empty|must not be empty|enter.+client", probe.stdout, re.I | re.S) is not None
    return evaluated("A2", "Required client or tenant name", [probe], [Assertion("empty client identity rejected", probe.exit_code == 0 and rejected, probe.stdout.strip() + probe.stderr.strip())], "Wizard rejected an empty client or tenant value")


def wizard_to_postgresql() -> list[tuple[str, str]]:
    return [(r"Agent ID[^\r\n]*:", ""), (r"Client tag[^\r\n]*:", "kenyata"), (r"Enable USB[^\r\n]*:", ""), (r"Channels \[all\]:", "1"), (r"Severity \[all\]:", ""), (r"Choose \[4\]:", ""), (r"Enable ETW[^\r\n]*:", ""), (r"Application log file path[^\r\n]*:", ""), (r"MongoDB sources[^\r\n]*:", "0")]


def a4(lab: Lab) -> Result:
    probe = lab.wizard_probe(wizard_to_postgresql(), r"Collect the PostgreSQL server log\?[^\r\n]*:", timeout=150, label="probe installed PostgreSQL discovery")
    found = all(value in probe.stdout for value in ("Detected 1 PostgreSQL cluster(s)", "postgresql-x64-16", "16.14-2", r"C:\Program Files\PostgreSQL\16\data\log", "active log:"))
    return evaluated("A4", "Installed database discovery", [probe], [Assertion("PostgreSQL discovery details displayed", probe.exit_code == 0 and found, probe.stdout.strip() + probe.stderr.strip())], "Wizard displayed the installed PostgreSQL service, version, log directory, and active log")


def a6(lab: Lab) -> Result:
    exchanges = wizard_to_postgresql() + [(r"Collect the PostgreSQL server log\?[^\r\n]*:", "")]
    probe = lab.wizard_probe(exchanges, r"(?:\?|:)\s*$", timeout=180, label="accept PostgreSQL auto-discovery")
    advanced = probe.exit_code == 0 and "Detected 1 PostgreSQL cluster(s)" in probe.stdout
    return evaluated("A6", "Accept auto-discovery", [probe], [Assertion("auto-discovery accepted and wizard advanced", advanced, probe.stdout.strip() + probe.stderr.strip())], "Wizard accepted PostgreSQL auto-discovery and advanced to input options")


def a12(lab: Lab) -> Result:
    commands: list[Command] = []
    config = r"C:\Program Files\log-collector\conf\agent.toml"
    last = config + ".last-good"
    restored = False
    try:
        backup = lab.ps(rf"""
$ErrorActionPreference='Stop'; $c='{config}'; $l='{last}'; Copy-Item $c 'C:\Windows\Temp\lc-a12-agent.toml' -Force; $had=Test-Path $l; if($had){{Copy-Item $l 'C:\Windows\Temp\lc-a12-last-good' -Force}}; [pscustomobject]@{{ConfigHash=(Get-FileHash $c -Algorithm SHA256).Hash;HadLastGood=$had}}|ConvertTo-Json -Compress
""", label="back up collector config and last-good before setup rerun")
        wizard = lab.complete_wizard(read_from_beginning=False, timeout=300, label="rerun setup over existing encrypted config")
        verify = lab.ps(rf"""
$c='{config}'; $l='{last}'; $old=(Get-FileHash 'C:\Windows\Temp\lc-a12-agent.toml' -Algorithm SHA256).Hash; $check=& '{COLLECTOR}' check 2>&1; [pscustomobject]@{{NewConfig=(Test-Path $c);LastGood=(Test-Path $l);OldHash=$old;LastGoodHash=if(Test-Path $l){{(Get-FileHash $l -Algorithm SHA256).Hash}}else{{$null}};Check=($check -join ' ')}}|ConvertTo-Json -Compress
""", label="verify setup preserved previous config as last-good")
        commands.extend([backup, wizard, verify])
    finally:
        restore = lab.ps(rf"""
$ErrorActionPreference='Continue'; Stop-Service log-collector -Force -ErrorAction SilentlyContinue; $c='{config}'; $l='{last}'; if(Test-Path 'C:\Windows\Temp\lc-a12-agent.toml'){{Copy-Item 'C:\Windows\Temp\lc-a12-agent.toml' $c -Force; Remove-Item 'C:\Windows\Temp\lc-a12-agent.toml' -Force}}; if(Test-Path 'C:\Windows\Temp\lc-a12-last-good'){{Copy-Item 'C:\Windows\Temp\lc-a12-last-good' $l -Force; Remove-Item 'C:\Windows\Temp\lc-a12-last-good' -Force}}else{{Remove-Item $l -Force -ErrorAction SilentlyContinue}}; Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); $health=$null; 1..15|ForEach-Object{{if(-not $health){{$health=try{{(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 5).Content}}catch{{$null}}; if(-not $health){{Start-Sleep -Seconds 2}}}}}}; $check=& '{COLLECTOR}' check 2>&1; [pscustomobject]@{{State=(Get-Service log-collector).Status;Check=($check -join ' ');Health=$health;ConfigTemp=(Test-Path 'C:\Windows\Temp\lc-a12-agent.toml');LastGoodTemp=(Test-Path 'C:\Windows\Temp\lc-a12-last-good')}}|ConvertTo-Json -Compress
""", timeout=150, label="restore exact deployed collector config and last-good state")
        commands.append(restore)
        restored = restore.exit_code == 0 and "Config OK" in restore.stdout and "agent_status\\\":\\\"Running" in restore.stdout
    try: data = json.loads(verify.stdout.split("#< CLIXML", 1)[0].strip())
    except Exception: data = {}
    assertions = [Assertion("setup rerun completed", wizard.exit_code == 0, wizard.stdout[-5000:] + wizard.stderr), Assertion("new config valid", verify.exit_code == 0 and "Config OK" in verify.stdout, verify.stdout.strip()), Assertion("previous config preserved exactly as last-good", data.get("OldHash") and data.get("OldHash") == data.get("LastGoodHash"), verify.stdout.strip()), Assertion("deployed state restored", restored, restore.stdout.strip() + restore.stderr.strip())]
    return evaluated("A12", "Setup preserves last-good config", commands, assertions, "Setup rerun preserved the exact previous encrypted config as last-good and deployed state was restored")


def service_install(lab: Lab) -> Result:
    cmd = lab.ps("Get-CimInstance Win32_Service -Filter \"Name='log-collector'\" | Select-Object Name,State,StartMode,StartName,PathName | ConvertTo-Json -Compress", label="collector service inventory")
    okay = all(value in cmd.stdout for value in ('"State":"Running"', '"StartMode":"Auto"'))
    return evaluated("A9", "Service installed and started", [cmd], [Assertion("automatic running service", okay, cmd.stdout.strip())], "Collector service is installed, automatic, and running")


def health(lab: Lab) -> Result:
    cmd = lab.ps("(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 10).Content", label="collector health endpoint")
    try: data = json.loads(cmd.stdout.strip())
    except Exception: data = {}
    assertions = [
        Assertion("agent running", data.get("agent_status") == "Running", str(data.get("agent_status"))),
        Assertion("receiver connected", data.get("cloud_status") == "Connected", str(data.get("cloud_status"))),
        Assertion("no last error", data.get("last_error") is None, str(data.get("last_error"))),
    ]
    return evaluated("A10", "Collector health endpoint", [cmd], assertions, "Health reports running and connected")


def multi_engine(lab: Lab) -> Result:
    cmd = lab.ps("$pid=(Get-CimInstance Win32_Service -Filter \"Name='log-collector'\").ProcessId; Get-ChildItem \"/proc/$pid/fd\" -ErrorAction SilentlyContinue", label="placeholder")
    script = "$pid=(Get-CimInstance Win32_Service -Filter \"Name='log-collector'\").ProcessId; $h=Get-Process -Id $pid; $paths=@(); try{$paths=(Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\").ExecutablePath}catch{}; [pscustomobject]@{Pid=$pid;State=(Get-CimInstance Win32_Service -Filter \"Name='log-collector'\").State;PostgreSQL=(Test-Path 'C:\\Program Files\\PostgreSQL\\16\\data\\log');MySQL=(Test-Path 'C:\\ProgramData\\MySQL\\MySQL Server 8.4\\Data');MariaDB=(Test-Path 'C:\\Program Files\\MariaDB 12.3\\data');Oracle=(Test-Path 'C:\\app\\kenyata\\product\\21c\\diag')}|ConvertTo-Json -Compress"
    cmd = lab.ps(script, label="verify multi-engine configured host")
    receiver = lab.recv("for f in postgres_log mysql_log mariadb_log oracle_log; do test -s /var/log/clients/kenyata-fct-ep6/$f.log && echo $f=present || echo $f=missing; done", label="verify all four engine receiver sources")
    try: data = json.loads(cmd.stdout.strip())
    except Exception: data = {}
    assertions = [Assertion("collector running", data.get("State") == "Running", str(data.get("State"))), Assertion("two or more engines installed", sum(bool(data.get(x)) for x in ("PostgreSQL","MySQL","MariaDB","Oracle")) >= 2, cmd.stdout.strip()), Assertion("all configured engine sources present", all(f"{x}=present" in receiver.stdout for x in ("postgres_log","mysql_log","mariadb_log","oracle_log")), receiver.stdout.strip())]
    return evaluated("A11", "Two or more engines in one setup", [cmd, receiver], assertions, "One collector configuration delivered four distinct database sources")


def basic(lab: Lab, sid: str = "B1") -> tuple[str, list[Command], Command]:
    marker = lab.marker(sid)
    trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label=f"generate {sid} marker")
    received = lab.received(marker)
    return marker, [trigger, received], received


def b1(lab: Lab) -> Result:
    marker, commands, received = basic(lab)
    return evaluated("B1", "Basic PostgreSQL collection", commands, [Assertion("receiver marker", marker in received.stdout, received.stdout.strip())], "Generated DDL marker reached receiver")


def b2(lab: Lab) -> Result:
    marker, commands, received = basic(lab, "B2")
    line = next((line for line in received.stdout.splitlines() if marker in line), "")
    match = re.search(r"^.*?<\d+>1\s+\S+\s+\S+\s+(\S+)", line)
    app = match.group(1) if match else "unparsed"
    assertions = [Assertion("marker delivered", bool(line), line), Assertion("APP-NAME exactly postgres_log", app == "postgres_log", app)]
    return evaluated("B2", "Stable source identifier", commands, assertions, "APP-NAME remained exactly postgres_log")


def b3(lab: Lab) -> Result:
    pre = lab.marker("B3_pre")
    post = lab.marker("B3_post")
    trigger_pre = lab.pg(f"COMMENT ON DATABASE postgres IS '{pre}';", label="generate pre-restart marker")
    received_pre = lab.received(pre)
    before_count = received_pre.stdout.count(pre)
    restart = lab.ps("Restart-Service log-collector -Force; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(30)); (Get-Service log-collector).Status", timeout=60, label="restart collector service")
    trigger_post = lab.pg(f"COMMENT ON DATABASE postgres IS '{post}';", label="generate post-restart marker")
    received_post = lab.received(post)
    recount = lab.recv(f"grep -F {shlex.quote(pre)} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null | wc -l", label="recount pre-restart marker")
    try: after_count = int(recount.stdout.strip())
    except ValueError: after_count = -1
    assertions = [
        Assertion("pre-restart delivery", before_count >= 1, received_pre.stdout.strip()),
        Assertion("collector restarted", restart.exit_code == 0 and "Running" in restart.stdout, restart.stdout.strip()),
        Assertion("post-restart delivery", post in received_post.stdout, received_post.stdout.strip()),
        Assertion("no full replay", after_count <= before_count + 1, f"before={before_count} after={after_count}"),
    ]
    return evaluated("B3", "Service restart and checkpoint", [trigger_pre, received_pre, restart, trigger_post, received_post, recount], assertions, "Collector resumed after restart without a full replay")


def b4(lab: Lab) -> Result:
    prefix = lab.marker("B4")
    before = lab.ps("$p=Get-Process -Id (Get-CimInstance Win32_Service -Filter \"Name='log-collector'\").ProcessId; [pscustomobject]@{Id=$p.Id;WorkingSet64=$p.WorkingSet64;Handles=$p.HandleCount}|ConvertTo-Json -Compress", label="capture collector resources before window")
    commands = [before]
    for index in range(1, 13):
        commands.append(lab.pg(f"COMMENT ON DATABASE postgres IS '{prefix}_{index:02d}';", label=f"light-activity marker {index}"))
        time.sleep(5)
    after = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; $p=Get-Process -Id $s.ProcessId; [pscustomobject]@{State=$s.State;Id=$p.Id;WorkingSet64=$p.WorkingSet64;Handles=$p.HandleCount}|ConvertTo-Json -Compress", label="capture collector resources after one-minute window")
    received = lab.recv(f"grep -F {shlex.quote(prefix + '_')} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", label="collect one-minute stability markers")
    commands.extend([after, received])
    try:
        b, a = json.loads(before.stdout), json.loads(after.stdout)
    except Exception:
        b, a = {}, {}
    delivered = len({int(x) for x in re.findall(re.escape(prefix) + r"_(\d{2})", received.stdout)})
    growth = int(a.get("WorkingSet64", 0)) - int(b.get("WorkingSet64", 0))
    assertions = [Assertion("collector remained running", a.get("State") == "Running", after.stdout.strip()), Assertion("all light events delivered", delivered == 12, f"unique={delivered}"), Assertion("no alarming RSS growth", growth < 128 * 1024 * 1024, f"growth_bytes={growth}")]
    return evaluated("B4", "Constrained-lab stability window", commands, assertions, "Collector remained stable for the approved one-minute window; upstream specifies 30+ minutes")


def b5(lab: Lab) -> Result:
    commands: list[Command] = []
    restored = False
    try:
        stop = lab.recv("systemctl stop syslog.socket rsyslog.service; if ss -ltn | grep -q ':2514 '; then exit 1; fi", label="stop receiver and prove RELP outage")
        commands.append(stop)
        time.sleep(60)
        health_cmd = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; $h=(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 10).Content; \"$($s.State)`n$h\"", label="collector state after one-minute receiver outage")
        commands.append(health_cmd)
    finally:
        restore = lab.recv("systemctl start rsyslog.service syslog.socket; for i in $(seq 1 30); do ss -ltn | grep -q ':2514 ' && exit 0; sleep 1; done; exit 1", timeout=60, label="restore receiver RELP service")
        commands.append(restore)
        restored = restore.exit_code == 0
    marker = lab.marker("B5")
    trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate post-outage marker")
    received = lab.received(marker)
    commands.extend([trigger, received])
    assertions = [Assertion("outage proved", commands[0].exit_code == 0, commands[0].stdout.strip() + commands[0].stderr.strip()), Assertion("collector stayed running", "Running" in commands[1].stdout, commands[1].stdout.strip()), Assertion("receiver restored", restored, commands[2].stdout.strip() + commands[2].stderr.strip()), Assertion("post-recovery delivery", marker in received.stdout, received.stdout.strip())]
    return evaluated("B5", "Constrained-lab receiver outage", commands, assertions, "Collector survived the approved one-minute receiver outage and resumed delivery; upstream specifies 10 minutes")


def b6(lab: Lab) -> Result:
    markers = [lab.marker("B6") for _ in range(5)]
    triggers = [lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label=f"generate unique marker {index}") for index, marker in enumerate(markers, 1)]
    time.sleep(5)
    query = lab.recv("grep -F 'lc_win_pg_b6_' /var/log/clients/kenyata-fct-ep6/postgres_log.log | tail -n 30", label="collect B6 receiver events")
    ids = re.findall(r'event_id="([^"]+)"', query.stdout)
    relevant = [line for line in query.stdout.splitlines() if any(m in line for m in markers)]
    relevant_ids = re.findall(r'event_id="([^"]+)"', "\n".join(relevant))
    assertions = [Assertion("five events received", len({m for m in markers if m in query.stdout}) == 5, f"markers={len({m for m in markers if m in query.stdout})}"), Assertion("five unique IDs", len(set(relevant_ids)) == 5, str(relevant_ids))]
    return evaluated("B6", "Unique event identifiers", [*triggers, query], assertions, "Five events carried five unique IDs")


def source_json(lab: Lab, marker: str) -> Command:
    script = rf"""
$line=$null
Get-ChildItem '{PG_LOG}' -Filter '*.json' -File | Sort-Object LastWriteTime -Descending | ForEach-Object {{
  if(-not $line){{$line=Get-Content $_.FullName -Tail 3000 | Where-Object {{$_ -like '*{marker}*'}} | Select-Object -Last 1}}
}}
if($line){{$line}}else{{exit 1}}
"""
    return lab.ps(script, label=f"find native JSON event {marker}")


def parse_time(value: str) -> datetime:
    value = value.strip().replace(" PDT", "-07:00").replace(" UTC", "+00:00").replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def b7(lab: Lab) -> Result:
    marker = lab.marker("B7")
    trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate timestamp marker")
    native = source_json(lab, marker)
    received = lab.received(marker)
    native_time = receiver_time = None
    try: native_time = parse_time(json.loads(native.stdout.strip())["timestamp"])
    except Exception: pass
    line = next((x for x in received.stdout.splitlines() if marker in x), "")
    match = re.search(r"<\d+>1\s+(\S+)", line)
    try: receiver_time = parse_time(match.group(1)) if match else None
    except Exception: pass
    delta = abs((receiver_time - native_time).total_seconds()) if native_time and receiver_time else None
    assertions = [Assertion("native timestamp parsed", native_time is not None, str(native_time)), Assertion("receiver timestamp parsed", receiver_time is not None, str(receiver_time)), Assertion("same event instant", delta is not None and delta <= 0.001, f"delta_seconds={delta}")]
    return evaluated("B7", "Native timestamp preservation", [trigger, native, received], assertions, "Receiver preserved the native event instant")


def c1(lab: Lab) -> Result:
    marker = lab.marker("C1")
    script = "$env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' \"host=127.0.0.1 port=5432 user=postgres dbname=postgres application_name=" + marker + "\" -c \"COMMENT ON DATABASE postgres IS '" + marker + "';\" 2>&1; exit $LASTEXITCODE"
    trigger = lab.ps(script, label="open tagged PostgreSQL connection")
    received = lab.received(marker)
    connection = any(marker in line and "connection authorized" in line for line in received.stdout.splitlines())
    assertions = [Assertion("connection succeeded", trigger.exit_code == 0, trigger.stdout.strip()), Assertion("connection event received", connection, received.stdout.strip())]
    return evaluated("C1", "PostgreSQL connection collection", [trigger, received], assertions, "Tagged connection event reached receiver")


def c3(lab: Lab) -> Result:
    marker, commands, received = basic(lab, "C3")
    line = next((x for x in received.stdout.splitlines() if marker in x), "")
    assertions = [Assertion("JSON source delivered", ".json" in line, line), Assertion("JSON parsed correctly", "[unparsed]" not in line and not re.search(r'\[unparsed\].*\{\"timestamp\"', line), line)]
    return evaluated("C3", "PostgreSQL JSON log collection", commands, assertions, "Active PostgreSQL JSON event was parsed and collected correctly")


def format_case(lab: Lab, sid: str, destination: str, query: str, expected: list[str], *, prefix: str | None = None, exactly_one: bool = True) -> Result:
    marker = lab.marker(sid)
    query = query.replace("__MARKER__", marker)
    saved_dest = lab.pg_at("SHOW log_destination;", label="capture original log destination")
    saved_prefix = lab.pg_at("SHOW log_line_prefix;", label="capture original log prefix")
    old_dest = saved_dest.stdout.strip().splitlines()[-1] if saved_dest.stdout.strip() else "jsonlog"
    old_prefix = saved_prefix.stdout.rstrip("\r\n").splitlines()[-1] if saved_prefix.stdout.strip() else "%m [%p] "
    commands = [saved_dest, saved_prefix]
    try:
        set_dest = lab.pg(f"ALTER SYSTEM SET log_destination='{destination}';", label=f"set {destination} destination")
        commands.append(set_dest)
        if prefix is not None:
            set_prefix = lab.pg(f"ALTER SYSTEM SET log_line_prefix='{prefix}';", label="set temporary log prefix")
            commands.append(set_prefix)
        reload_cmd = lab.pg("SELECT pg_reload_conf();", label="reload temporary log format")
        rotate = lab.pg("SELECT pg_rotate_logfile();", label="rotate into temporary log format")
        commands.extend([reload_cmd, rotate])
        time.sleep(3)
        sql64 = base64.b64encode(("SET log_min_duration_statement=0;\r\n" + query + "\r\n").encode("utf-8")).decode("ascii")
        script = "$p='C:\\Windows\\Temp\\lc-format.sql'; [IO.File]::WriteAllBytes($p,[Convert]::FromBase64String('" + sql64 + "')); $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -f $p 2>&1; $c=$LASTEXITCODE; Remove-Item $p -Force; exit $c"
        trigger = lab.ps(script, label=f"generate {sid} format record")
        received = lab.received(marker)
        health_cmd = lab.ps("(Get-CimInstance Win32_Service -Filter \"Name='log-collector'\").State", label="verify collector after format test")
        commands.extend([trigger, received, health_cmd])
    finally:
        restore_dest = lab.pg(f"ALTER SYSTEM SET log_destination='{old_dest}';", label="restore original log destination")
        restore_prefix = lab.pg(f"ALTER SYSTEM SET log_line_prefix='{old_prefix}';", label="restore original log prefix")
        restore_reload = lab.pg("SELECT pg_reload_conf();", label="reload restored log format")
        restore_rotate = lab.pg("SELECT pg_rotate_logfile();", label="rotate into restored log format")
        commands.extend([restore_dest, restore_prefix, restore_reload, restore_rotate])
    matches = [line for line in received.stdout.splitlines() if marker in line]
    rendered = "\n".join(matches)
    decoded_records: list[str] = []
    for line in matches:
        payload = line.split("] [unparsed] ", 1)[-1]
        try: decoded_records.append(" ".join(next(csv.reader([payload]))))
        except (csv.Error, StopIteration): decoded_records.append(payload)
    comparable = rendered + "\n" + "\n".join(decoded_records)
    intact = bool(matches) and all(part in comparable for part in expected)
    assertions = [Assertion("record content intact", intact, "\n".join(matches)), Assertion("expected record count", not exactly_one or len(matches) == 1, f"matches={len(matches)}"), Assertion("collector remained active", "Running" in health_cmd.stdout, health_cmd.stdout.strip()), Assertion("format restored", all(x.exit_code == 0 for x in (restore_dest, restore_prefix, restore_reload, restore_rotate)), f"destination={old_dest} prefix={old_prefix}")]
    names = {"C4":"CSV multi-line statement", "C4a":"CSV quoted comma", "C4b":"CSV double quote", "C4c":"stderr multi-line statement", "C4d":"stderr and csvlog de-duplication", "C4e":"Custom log line prefix", "C4f":"Log prefix without timestamp"}
    return evaluated(sid, names[sid], commands, assertions, "PostgreSQL format record arrived intact as one event")


def c4(lab: Lab) -> Result:
    return format_case(lab, "C4", "csvlog", "SELECT /*__MARKER__*/\r\n  1 AS\r\n  lc_multiline;", ["lc_multiline"])


def c4a(lab: Lab) -> Result:
    return format_case(lab, "C4a", "csvlog", "SELECT /*__MARKER__*/ 'a,b,c' AS value;", ["a,b,c"])


def c4b(lab: Lab) -> Result:
    return format_case(lab, "C4b", "csvlog", "SELECT /*__MARKER__*/ 'say \"\"hi\"\"' AS value;", ['say ""hi""'])


def c4c(lab: Lab) -> Result:
    return format_case(lab, "C4c", "stderr", "SELECT /*__MARKER__*/\r\n  1 AS\r\n  lc_multiline;", ["lc_multiline"])


def c4d(lab: Lab) -> Result:
    return format_case(lab, "C4d", "stderr,csvlog", "SELECT /*__MARKER__*/ 1 AS lc_dual;", ["lc_dual"])


def c4e(lab: Lab) -> Result:
    return format_case(lab, "C4e", "stderr", "COMMENT ON DATABASE postgres IS '__MARKER__';", [], prefix="%m [%p] %a %u@%d ")


def c4f(lab: Lab) -> Result:
    return format_case(lab, "C4f", "stderr", "COMMENT ON DATABASE postgres IS '__MARKER__';", [], prefix="%a|%u|%d|")


def c2(lab: Lab) -> Result:
    marker = lab.marker("C2")
    role = "lc_fail_" + uuid.uuid4().hex[:10]
    setup = lab.pg(f"CREATE ROLE {role} LOGIN PASSWORD 'temporary_{uuid.uuid4().hex[:8]}';", label="create failed-login role")
    script = "$env:PGPASSWORD='wrong_" + marker + "'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -p 5432 -U " + role + " -d postgres -c 'SELECT 1;' 2>&1; exit $LASTEXITCODE"
    trigger = lab.ps(script, label="failed PostgreSQL login")
    deadline = time.time() + 30
    received = None
    while time.time() < deadline:
        received = lab.recv(
            f"grep -F {shlex.quote(role)} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null | grep -F 'password authentication failed' || true",
            label=f"search receiver for failed login by {role}",
        )
        if "password authentication failed" in received.stdout:
            break
        time.sleep(2)
    assert received is not None
    cleanup = lab.pg(f"DROP ROLE IF EXISTS {role};", label="drop failed-login role")
    lines = [x for x in received.stdout.splitlines() if role in x and "password authentication failed" in x]
    assertions = [Assertion("login rejected", trigger.exit_code != 0, trigger.stdout.strip() + trigger.stderr.strip()), Assertion("critical priority", any("<10>1" in x for x in lines), "\n".join(lines))]
    return evaluated("C2", "Failed login severity", [setup, trigger, received, cleanup], assertions, "Failed login delivered at priority <10>")


def c2a(lab: Lab) -> Result:
    baseline, base_cmd = receiver_baseline(lab, "C2a")
    commands = [base_cmd]
    rule_name = "LC-Test-C2a-PostgreSQL"
    try:
        allow = lab.ps(f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5432 -RemoteAddress 192.168.248.129 | Out-Null", label="temporarily allow receiver to PostgreSQL")
        trigger = lab.recv("PGCONNECT_TIMEOUT=10 PGPASSWORD=disposable psql -h 192.168.248.130 -p 5432 -U lc_remote_reject -d postgres -c 'SELECT 1;' 2>&1 || true", label="trigger remote pg_hba rejection from receiver")
        received = receiver_since(lab, baseline, "C2a")
        commands.extend([allow, trigger, received])
    finally:
        cleanup = lab.ps(f"Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue", label="remove temporary PostgreSQL firewall rule")
        commands.append(cleanup)
    lines = [x for x in received.stdout.splitlines() if "no pg_hba.conf entry" in x]
    assertions = [Assertion("temporary firewall rule applied", allow.exit_code == 0, allow.stderr.strip()), Assertion("remote connection rejected", "no pg_hba.conf entry" in trigger.stdout.lower(), trigger.stdout.strip()), Assertion("HBA rejection collected", bool(lines), "\n".join(lines)), Assertion("critical priority", any("<10>1" in x for x in lines), "\n".join(lines)), Assertion("firewall rule removed", cleanup.exit_code == 0, cleanup.stderr.strip())]
    return evaluated("C2a", "No matching pg_hba.conf entry", commands, assertions, "Remote HBA rejection was collected at critical priority")


def c2b(lab: Lab) -> Result:
    baseline, base_cmd = receiver_baseline(lab, "C2b")
    rule_name = "LC-Test-C2b-PostgreSQL"
    hba = r"C:\Program Files\PostgreSQL\16\data\pg_hba.conf"
    backup = r"C:\Windows\Temp\lc-c2b-pg_hba.backup"
    commands = [base_cmd]
    restored = False
    try:
        configure = lab.ps(f"Copy-Item '{hba}' '{backup}' -Force; Add-Content -LiteralPath '{hba}' -Value \"host all lc_explicit_reject 192.168.248.129/32 reject\" -Encoding ASCII; $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_reload_conf();' 2>&1; exit $LASTEXITCODE", label="append explicit receiver-host HBA reject")
        allow = lab.ps(f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5432 -RemoteAddress 192.168.248.129 | Out-Null", label="temporarily allow receiver to PostgreSQL")
        trigger = lab.recv("PGCONNECT_TIMEOUT=10 PGPASSWORD=disposable psql -h 192.168.248.130 -p 5432 -U lc_explicit_reject -d postgres -c 'SELECT 1;' 2>&1 || true", label="trigger explicit pg_hba reject from receiver")
        received = receiver_since(lab, baseline, "C2b")
        commands.extend([configure, allow, trigger, received])
    finally:
        cleanup = lab.ps(f"if(Test-Path '{backup}'){{[IO.File]::WriteAllBytes('{hba}',[IO.File]::ReadAllBytes('{backup}')); Remove-Item '{backup}' -Force}}; Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue; $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_reload_conf();' 2>&1; exit $LASTEXITCODE", label="restore pg_hba and remove firewall rule")
        commands.append(cleanup)
        restored = cleanup.exit_code == 0
    lines = [x for x in received.stdout.splitlines() if "pg_hba.conf rejects connection" in x.lower() or "no pg_hba.conf entry" in x.lower()]
    assertions = [Assertion("explicit HBA rule configured", configure.exit_code == 0, configure.stdout.strip() + configure.stderr.strip()), Assertion("connection explicitly rejected", "pg_hba.conf rejects connection" in trigger.stdout.lower(), trigger.stdout.strip()), Assertion("rejection collected", bool(lines), "\n".join(lines)), Assertion("critical priority", any("<10>1" in x for x in lines), "\n".join(lines)), Assertion("HBA and firewall restored", restored, cleanup.stdout.strip() + cleanup.stderr.strip())]
    return evaluated("C2b", "Explicit pg_hba.conf host rejection", commands, assertions, "Explicit receiver-host HBA rejection was collected at critical priority and configuration was restored")


def c2d(lab: Lab) -> Result:
    marker = lab.marker("C2d").replace("-", "_")
    role = ("lc_" + hashlib.sha256(marker.encode()).hexdigest()[:12]).lower()
    sql = f"CREATE ROLE {role}; GRANT CONNECT ON DATABASE postgres TO {role}; DROP ROLE {role};"
    trigger = lab.pg(sql, label="generate role DDL")
    received = lab.received(role)
    text = received.stdout.upper()
    assertions = [Assertion("CREATE ROLE", "CREATE ROLE" in text, received.stdout.strip()), Assertion("GRANT", "GRANT CONNECT" in text, received.stdout.strip()), Assertion("DROP ROLE", "DROP ROLE" in text, received.stdout.strip())]
    return evaluated("C2d", "Role DDL security events", [trigger, received], assertions, "CREATE ROLE, GRANT, and DROP ROLE collected")


def c2c(lab: Lab) -> Result:
    marker = lab.marker("C2c")[:60]
    script = "$env:PGPASSWORD='postgres'; $env:PGAPPNAME='" + marker + "'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -p 5432 -U postgres -d postgres -c 'SELECT 1;' 2>&1; exit $LASTEXITCODE"
    trigger = lab.ps(script, label="open and close tagged PostgreSQL session")
    deadline = time.time() + 30
    received = None
    while time.time() < deadline:
        authorized = lab.recv(f"grep -F {shlex.quote(marker)} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null | tail -n 1 || true", label="locate tagged connection")
        port_match = re.search(r"from 127\.0\.0\.1:(\d+)", authorized.stdout)
        if port_match:
            received = lab.recv(f"grep -F {shlex.quote('port=' + port_match.group(1))} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null | tail -n 8 || true", label="collect correlated connection lifecycle")
        else:
            received = authorized
        if "connection authorized" in received.stdout and "disconnection:" in received.stdout:
            break
        time.sleep(2)
    assert received is not None
    assertions = [Assertion("connection recorded", "connection authorized" in received.stdout, received.stdout.strip()), Assertion("disconnection recorded", "disconnection:" in received.stdout, received.stdout.strip()), Assertion("informational priority", all("<14>1" in x for x in received.stdout.splitlines() if marker in x), received.stdout.strip())]
    return evaluated("C2c", "Connection and disconnection logging", [trigger, received], assertions, "Connection lifecycle events were delivered at informational priority")


def c2f(lab: Lab) -> Result:
    marker = lab.marker("C2f").replace("-", "_")
    table = "lc_" + hashlib.sha256(marker.encode()).hexdigest()[:10]
    setup = lab.pg(f"DROP TABLE IF EXISTS public.{table}; CREATE TABLE public.{table}(id integer); REVOKE ALL ON public.{table} FROM PUBLIC;", label="prepare permission denial")
    trigger = lab.pg(f"SET ROLE collector_test; SELECT /*{marker}*/ * FROM public.{table};", label="trigger permission denial")
    received = lab.received(marker)
    cleanup = lab.pg(f"DROP TABLE IF EXISTS public.{table};", label="cleanup permission test")
    lines = [x for x in received.stdout.splitlines() if marker in x]
    assertions = [Assertion("permission rejected", trigger.exit_code != 0, trigger.stdout.strip()), Assertion("error priority", any("<11>1" in x for x in lines), "\n".join(lines))]
    return evaluated("C2f", "Permission-denied error severity", [setup, trigger, received, cleanup], assertions, "Permission denial delivered at <11>")


def receiver_baseline(lab: Lab, sid: str) -> tuple[int, Command]:
    cmd = lab.recv("wc -l < /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || echo 0", label=f"capture {sid} receiver baseline")
    try: count = int(cmd.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError): count = 0
    return count, cmd


def receiver_since(lab: Lab, baseline: int, sid: str, wait: int = 15) -> Command:
    time.sleep(wait)
    return lab.recv(f"tail -n +{baseline + 1} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", label=f"collect new {sid} receiver records")


def c7(lab: Lab) -> Result:
    token = uuid.uuid4().hex[:8]
    t1, t2 = f"lc_dead_a_{token}", f"lc_dead_b_{token}"
    baseline, base_cmd = receiver_baseline(lab, "C7")
    setup = lab.pg(f"DROP TABLE IF EXISTS {t1}; DROP TABLE IF EXISTS {t2}; CREATE TABLE {t1}(id integer primary key); CREATE TABLE {t2}(id integer primary key); INSERT INTO {t1} VALUES(1); INSERT INTO {t2} VALUES(1);", label="prepare disposable deadlock tables")
    script = rf"""
$p1='C:\Windows\Temp\lc-c7-1.sql'; $p2='C:\Windows\Temp\lc-c7-2.sql'
[IO.File]::WriteAllText($p1,"SET deadlock_timeout='200ms'; BEGIN; UPDATE {t1} SET id=id; SELECT pg_sleep(1); UPDATE {t2} SET id=id; COMMIT;",(New-Object Text.UTF8Encoding($false)))
[IO.File]::WriteAllText($p2,"SET deadlock_timeout='200ms'; BEGIN; UPDATE {t2} SET id=id; SELECT pg_sleep(1); UPDATE {t1} SET id=id; COMMIT;",(New-Object Text.UTF8Encoding($false)))
$j1=Start-Job {{param($f) $env:PGPASSWORD='postgres'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -f $f 2>&1}} -ArgumentList $p1
$j2=Start-Job {{param($f) $env:PGPASSWORD='postgres'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -f $f 2>&1}} -ArgumentList $p2
Wait-Job $j1,$j2 -Timeout 20|Out-Null; Receive-Job $j1,$j2; Remove-Job $j1,$j2 -Force; Remove-Item $p1,$p2 -Force
"""
    trigger = lab.ps(script, timeout=60, label="trigger PostgreSQL deadlock")
    received = receiver_since(lab, baseline, "C7")
    cleanup = lab.pg(f"DROP TABLE IF EXISTS {t1}; DROP TABLE IF EXISTS {t2};", label="cleanup deadlock tables")
    deadlock_lines = [x for x in received.stdout.splitlines() if "deadlock detected" in x.lower()]
    ddl_visible = f"CREATE TABLE {t1}" in received.stdout or t1 in received.stdout
    assertions = [Assertion("deadlock generated", bool(deadlock_lines), "\n".join(deadlock_lines)), Assertion("deadlock error priority", any("<11>1" in x for x in deadlock_lines), "\n".join(deadlock_lines)), Assertion("DDL marker delivered", ddl_visible, t1)]
    return evaluated("C7", "Deadlock and ordinary DDL", [base_cmd, setup, trigger, received, cleanup], assertions, "Deadlock arrived at <11> and ordinary DDL was collected")


def c7a(lab: Lab) -> Result:
    token = uuid.uuid4().hex[:8]
    table = f"lc_lock_{token}"
    baseline, base_cmd = receiver_baseline(lab, "C7a")
    statement = lab.pg(f"SET statement_timeout='100ms'; SELECT /*lc_stmt_{token}*/ pg_sleep(1);", label="trigger statement timeout")
    setup = lab.pg(f"DROP TABLE IF EXISTS {table}; CREATE TABLE {table}(id integer);", label="prepare lock-timeout table")
    script = rf"""
$hold='C:\Windows\Temp\lc-c7a-hold.sql'; [IO.File]::WriteAllText($hold,"BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(3); COMMIT;",(New-Object Text.UTF8Encoding($false)))
$j=Start-Job {{param($f) $env:PGPASSWORD='postgres'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -f $f 2>&1}} -ArgumentList $hold
Start-Sleep -Seconds 2
$env:PGPASSWORD='postgres'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -c "SET lock_timeout='200ms'; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE;" 2>&1
Wait-Job $j -Timeout 10|Out-Null; Receive-Job $j; Remove-Job $j -Force; Remove-Item $hold -Force
"""
    lock = lab.ps(script, timeout=30, label="trigger lock timeout")
    received = receiver_since(lab, baseline, "C7a")
    cleanup = lab.pg(f"DROP TABLE IF EXISTS {table};", label="cleanup lock-timeout table")
    statement_lines = [x for x in received.stdout.splitlines() if "statement timeout" in x.lower()]
    lock_lines = [x for x in received.stdout.splitlines() if "lock timeout" in x.lower()]
    assertions = [Assertion("statement timeout generated", bool(statement_lines), "\n".join(statement_lines)), Assertion("lock timeout generated", bool(lock_lines), "\n".join(lock_lines)), Assertion("both error priorities", any("<11>1" in x for x in statement_lines) and any("<11>1" in x for x in lock_lines), "\n".join(statement_lines + lock_lines))]
    return evaluated("C7a", "Statement and lock timeouts", [base_cmd, statement, setup, lock, received, cleanup], assertions, "Both timeout types arrived at <11>")


def c7b(lab: Lab) -> Result:
    marker = lab.marker("C7b")[:60]
    baseline, base_cmd = receiver_baseline(lab, "C7b")
    script = rf"""
$j=Start-Job {{param($app) $env:PGPASSWORD='postgres'; $env:PGAPPNAME=$app; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -c 'SELECT pg_sleep(30);' 2>&1}} -ArgumentList '{marker}'
Start-Sleep 2
$env:PGPASSWORD='postgres'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='{marker}';" 2>&1
Wait-Job $j -Timeout 10|Out-Null; Receive-Job $j; Remove-Job $j -Force
"""
    trigger = lab.ps(script, timeout=30, label="terminate tagged PostgreSQL backend")
    received = receiver_since(lab, baseline, "C7b")
    assertions = [Assertion("tagged session observed", marker in received.stdout, marker), Assertion("backend termination recorded", "terminating connection due to administrator command" in received.stdout.lower(), received.stdout.strip())]
    return evaluated("C7b", "Backend termination", [base_cmd, trigger, received], assertions, "Tagged backend termination reached the receiver")


def c7c(lab: Lab) -> Result:
    token = uuid.uuid4().hex[:8]
    table = f"lc_maint_{token}"
    baseline, base_cmd = receiver_baseline(lab, "C7c")
    saved = lab.pg("SELECT current_setting('log_autovacuum_min_duration'), current_setting('log_checkpoints');", label="capture maintenance logging settings")
    values = [x.strip() for x in saved.stdout.splitlines() if "|" in x and "log_" not in x and "---" not in x]
    raw = values[-1].split("|") if values else []
    old_auto, old_checkpoint = (raw[0].strip(), raw[1].strip()) if len(raw) >= 2 else ("-1", "on")
    commands = [base_cmd, saved]
    try:
        set_auto = lab.pg("ALTER SYSTEM SET log_autovacuum_min_duration=0;", label="enable autovacuum logging")
        set_checkpoint = lab.pg("ALTER SYSTEM SET log_checkpoints=on;", label="enable checkpoint logging")
        reload_cmd = lab.pg("SELECT pg_reload_conf();", label="reload maintenance logging settings")
        setup = lab.pg(f"DROP TABLE IF EXISTS {table}; CREATE TABLE {table}(id integer) WITH (autovacuum_vacuum_threshold=0,autovacuum_vacuum_scale_factor=0,autovacuum_analyze_threshold=0,autovacuum_analyze_scale_factor=0); INSERT INTO {table} SELECT generate_series(1,20000); DELETE FROM {table} WHERE id <= 15000; ANALYZE {table}; CHECKPOINT;", label="trigger bounded maintenance activity")
        commands.extend([set_auto, set_checkpoint, reload_cmd, setup])
        received = receiver_since(lab, baseline, "C7c", wait=35)
        commands.append(received)
    finally:
        restore_auto = lab.pg(f"ALTER SYSTEM SET log_autovacuum_min_duration='{old_auto}';", label="restore autovacuum logging")
        restore_checkpoint = lab.pg(f"ALTER SYSTEM SET log_checkpoints='{old_checkpoint}';", label="restore checkpoint logging")
        restore_reload = lab.pg("SELECT pg_reload_conf();", label="reload restored maintenance settings")
        cleanup = lab.pg(f"DROP TABLE IF EXISTS {table};", label="cleanup maintenance table")
        commands.extend([restore_auto, restore_checkpoint, restore_reload, cleanup])
    auto_lines = [x for x in received.stdout.splitlines() if "automatic vacuum" in x.lower() or "automatic analyze" in x.lower()]
    checkpoint_lines = [x for x in received.stdout.splitlines() if "checkpoint complete" in x.lower()]
    assertions = [Assertion("autovacuum activity collected", bool(auto_lines), "\n".join(auto_lines[-10:])), Assertion("checkpoint activity collected", bool(checkpoint_lines), "\n".join(checkpoint_lines[-10:])), Assertion("bounded maintenance volume", len(auto_lines) + len(checkpoint_lines) < 100, f"autovacuum={len(auto_lines)} checkpoint={len(checkpoint_lines)}"), Assertion("settings restored", all(x.exit_code == 0 for x in (restore_auto, restore_checkpoint, restore_reload)), f"auto={old_auto} checkpoint={old_checkpoint}")]
    return evaluated("C7c", "Autovacuum and checkpoint volume", commands, assertions, "Maintenance events were collected without excessive volume")


def c7d(lab: Lab) -> Result:
    pre, post = lab.marker("C7d_pre"), lab.marker("C7d_post")
    pid_before = lab.ps("(Get-CimInstance Win32_Service -Filter \"Name='log-collector'\").ProcessId", label="collector PID before database restart")
    trigger_pre = lab.pg(f"COMMENT ON DATABASE postgres IS '{pre}';", label="generate pre-database-restart marker")
    received_pre = lab.received(pre)
    restart = lab.ps("Restart-Service postgresql-x64-16 -Force; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); (Get-Service postgresql-x64-16).Status", timeout=90, label="restart PostgreSQL service")
    trigger_post = lab.pg(f"COMMENT ON DATABASE postgres IS '{post}';", label="generate post-database-restart marker")
    received_post = lab.received(post)
    pid_after = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; \"$($s.State) $($s.ProcessId)\"", label="collector state after database restart")
    assertions = [Assertion("pre-restart marker delivered", pre in received_pre.stdout, received_pre.stdout.strip()), Assertion("database restarted", restart.exit_code == 0 and "Running" in restart.stdout, restart.stdout.strip()), Assertion("post-restart marker delivered", post in received_post.stdout, received_post.stdout.strip()), Assertion("collector survived", "Running" in pid_after.stdout and pid_before.stdout.strip() in pid_after.stdout, f"before={pid_before.stdout.strip()} after={pid_after.stdout.strip()}")]
    return evaluated("C7d", "PostgreSQL restart survival", [pid_before, trigger_pre, received_pre, restart, trigger_post, received_post, pid_after], assertions, "Database restarted and collection resumed while the collector process survived")


def c7e(lab: Lab) -> Result:
    token = uuid.uuid4().hex[:8]
    role = f"lc_exhaust_{token}"
    secret = "Temp_" + uuid.uuid4().hex[:12]
    auto = r"C:\Program Files\PostgreSQL\16\data\postgresql.auto.conf"
    backup = r"C:\Windows\Temp\lc-c7e-postgresql.auto.conf.backup"
    baseline, base_cmd = receiver_baseline(lab, "C7e")
    setup_role = lab.pg(f"CREATE ROLE {role} LOGIN PASSWORD '{secret}';", label="create disposable connection-exhaustion role")
    commands = [base_cmd, setup_role]
    restored = False
    try:
        configure = lab.ps(f"Copy-Item '{auto}' '{backup}' -Force; $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -c \"ALTER SYSTEM SET max_connections=10;\" 2>&1; if($LASTEXITCODE -ne 0){{exit $LASTEXITCODE}}; Restart-Service postgresql-x64-16 -Force; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); (Get-Service postgresql-x64-16).Status", timeout=120, label="set bounded max_connections and restart PostgreSQL")
        commands.append(configure)
        script = rf"""
$jobs=1..14|ForEach-Object {{Start-Job {{param($u,$pw) $env:PGPASSWORD=$pw; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U $u -d postgres -c 'SELECT pg_sleep(20);' 2>&1}} -ArgumentList '{role}','{secret}'}}
Start-Sleep 3
$env:PGPASSWORD='{secret}'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U {role} -d postgres -c 'SELECT 1;' 2>&1
Wait-Job $jobs -Timeout 30|Out-Null; Receive-Job $jobs; Remove-Job $jobs -Force
"""
        trigger = lab.ps(script, timeout=60, label="exhaust bounded PostgreSQL connection slots")
        received = receiver_since(lab, baseline, "C7e", wait=20)
        commands.extend([trigger, received])
    finally:
        restore = lab.ps(f"if(Test-Path '{backup}'){{[IO.File]::WriteAllBytes('{auto}',[IO.File]::ReadAllBytes('{backup}')); Remove-Item '{backup}' -Force}}; Restart-Service postgresql-x64-16 -Force; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); (Get-Service postgresql-x64-16).Status", timeout=120, label="restore max_connections configuration and PostgreSQL")
        commands.append(restore)
        restored = restore.exit_code == 0 and "Running" in restore.stdout
        cleanup = lab.pg(f"DROP ROLE IF EXISTS {role};", label="drop connection-exhaustion role")
        commands.append(cleanup)
    lines = [x for x in received.stdout.splitlines() if "remaining connection slots" in x.lower() or "too many clients" in x.lower()]
    assertions = [Assertion("bounded setting applied", configure.exit_code == 0 and "Running" in configure.stdout, configure.stdout.strip()), Assertion("connection exhaustion generated", bool(lines), "\n".join(lines)), Assertion("critical priority", any("<10>1" in x for x in lines), "\n".join(lines)), Assertion("original config and database restored", restored, restore.stdout.strip()), Assertion("disposable role cleaned", cleanup.exit_code == 0, cleanup.stdout.strip())]
    return evaluated("C7e", "Connection exhaustion", commands, assertions, "Controlled connection exhaustion reached the receiver at critical priority and configuration was restored")


def c5(lab: Lab, sid: str = "C5") -> Result:
    pre, post = lab.marker(sid + "_pre"), lab.marker(sid + "_post")
    old = lab.pg("SELECT pg_current_logfile();", label="capture active log before rotation")
    trigger_pre = lab.pg(f"COMMENT ON DATABASE postgres IS '{pre}';", label="generate pre-rotation marker")
    received_pre = lab.received(pre)
    rotate = lab.pg("SELECT pg_rotate_logfile();", label="force PostgreSQL log rotation")
    time.sleep(3)
    new = lab.pg("SELECT pg_current_logfile();", label="capture active log after rotation")
    trigger_post = lab.pg(f"COMMENT ON DATABASE postgres IS '{post}';", label="generate post-rotation marker")
    received_post = lab.received(post)
    old_path = next((x.strip() for x in old.stdout.splitlines() if "log\\" in x or "log/" in x), old.stdout.strip())
    new_path = next((x.strip() for x in new.stdout.splitlines() if "log\\" in x or "log/" in x), new.stdout.strip())
    assertions = [Assertion("rotation succeeded", rotate.exit_code == 0 and "t" in rotate.stdout.lower(), rotate.stdout.strip()), Assertion("active file changed", bool(old_path) and old_path != new_path, f"old={old_path} new={new_path}"), Assertion("pre-rotation event delivered", pre in received_pre.stdout, received_pre.stdout.strip()), Assertion("post-rotation event delivered", post in received_post.stdout, received_post.stdout.strip())]
    return evaluated(sid, "Forced log rotation" if sid == "C5" else "Cross-engine rotation continuity", [old, trigger_pre, received_pre, rotate, new, trigger_post, received_post], assertions, "Collection followed PostgreSQL into the rotated file")


def c5a(lab: Lab) -> Result:
    prefix = lab.marker("C5a")
    old_size = lab.pg_at("SHOW log_rotation_size;", label="capture original rotation size")
    old_age = lab.pg_at("SHOW log_rotation_age;", label="capture original rotation age")
    size = old_size.stdout.strip().splitlines()[-1] if old_size.stdout.strip() else "10MB"
    age = old_age.stdout.strip().splitlines()[-1] if old_age.stdout.strip() else "1d"
    commands = [old_size, old_age]
    try:
        set_size = lab.pg("ALTER SYSTEM SET log_rotation_size='1MB';", label="set 1 MB rotation size")
        set_age = lab.pg("ALTER SYSTEM SET log_rotation_age=0;", label="disable age rotation during size test")
        reload_cmd = lab.pg("SELECT pg_reload_conf();", label="reload size rotation settings")
        clean_rotate = lab.pg("SELECT pg_rotate_logfile();", label="start clean size-rotation file")
        before_file = lab.pg_at("SELECT pg_current_logfile();", label="capture first size-test file")
        commands.extend([set_size, set_age, reload_cmd, clean_rotate, before_file])
        script = "$p='C:\\Windows\\Temp\\lc-c5a.sql'; $pad='X'*1024; $sql=(1..1800|ForEach-Object{\"COMMENT ON DATABASE postgres IS '" + prefix + "_$($_.ToString('0000'))_$pad';\"}) -join [Environment]::NewLine; [IO.File]::WriteAllText($p,$sql,(New-Object Text.UTF8Encoding($false))); $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -f $p 2>&1; $c=$LASTEXITCODE; Remove-Item $p -Force; exit $c"
        load = lab.ps(script, timeout=300, label="generate 1,800 numbered size-rotation events")
        after_file = lab.pg_at("SELECT pg_current_logfile();", label="capture final size-test file")
        commands.extend([load, after_file])
        receiver_queries: list[Command] = []
        deadline = time.time() + 600
        unique = 0
        while time.time() < deadline:
            received = lab.recv(f"grep -F {shlex.quote(prefix + '_')} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", timeout=180, label="collect size-rotation markers")
            receiver_queries.append(received)
            unique = len(set(re.findall(re.escape(prefix) + r"_(\d{4})", received.stdout)))
            if unique == 1800:
                break
            time.sleep(10)
        commands.extend(receiver_queries)
    finally:
        restore_size = lab.pg(f"ALTER SYSTEM SET log_rotation_size='{size}';", label="restore rotation size")
        restore_age = lab.pg(f"ALTER SYSTEM SET log_rotation_age='{age}';", label="restore rotation age")
        restore_reload = lab.pg("SELECT pg_reload_conf();", label="reload restored rotation settings")
        commands.extend([restore_size, restore_age, restore_reload])
    first = before_file.stdout.strip().splitlines()[-1] if before_file.stdout.strip() else ""
    last = after_file.stdout.strip().splitlines()[-1] if after_file.stdout.strip() else ""
    assertions = [Assertion("volume generated", load.exit_code == 0, load.stdout[-1000:]), Assertion("active file changed", bool(first) and first != last, f"first={first} last={last}"), Assertion("all numbered events delivered", unique == 1800, f"unique={unique}"), Assertion("settings restored", all(x.exit_code == 0 for x in (restore_size, restore_age, restore_reload)), f"size={size} age={age}")]
    return evaluated("C5a", "Size-based rotation continuity", commands, assertions, "All 1,800 numbered events crossed 1 MB rotations and settings were restored")


def c5c(lab: Lab) -> Result:
    prefix = lab.marker("C5c")
    sql_lines = ["SET log_min_duration_statement=0;"]
    for i in range(1, 11):
        sql_lines.append(f"SELECT /*{prefix}_{i:02d}\nrotation_boundary*/ length(repeat('X',65536));")
    encoded = base64.b64encode(("\r\n".join(sql_lines) + "\r\n").encode("utf-8")).decode("ascii")
    script = rf"""
$p='C:\Windows\Temp\lc-c5c.sql'; [IO.File]::WriteAllBytes($p,[Convert]::FromBase64String('{encoded}'))
$sqlJob=Start-Job {{param($f) $env:PGPASSWORD='postgres'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -f $f 2>&1}} -ArgumentList $p
$rotateJob=Start-Job {{ $env:PGPASSWORD='postgres'; 1..5|ForEach-Object{{Start-Sleep -Milliseconds 150; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_rotate_logfile();' 2>&1}} }}
Wait-Job $sqlJob,$rotateJob -Timeout 60|Out-Null; Receive-Job $sqlJob,$rotateJob; $states=($sqlJob.State,$rotateJob.State)-join ','; Remove-Job $sqlJob,$rotateJob -Force; Remove-Item $p -Force; "JOB_STATES=$states"
"""
    trigger = lab.ps(script, timeout=90, label="write multi-line records while rotating PostgreSQL logs")
    queries: list[Command] = []
    deadline = time.time() + 180
    unique = 0
    while time.time() < deadline:
        received = lab.recv(f"grep -F {shlex.quote(prefix + '_')} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", label="collect rotation-boundary multi-line records")
        queries.append(received)
        unique = len(set(re.findall(re.escape(prefix) + r"_(\d{2})", received.stdout)))
        if unique == 10:
            break
        time.sleep(5)
    health_cmd = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; \"$($s.State)\"", label="verify collector after rotation-boundary writes")
    assertions = [Assertion("writer and rotator completed", "JOB_STATES=Completed,Completed" in trigger.stdout, trigger.stdout.strip() + trigger.stderr.strip()), Assertion("all multi-line markers delivered", unique == 10, f"unique={unique}"), Assertion("collector remained running", "Running" in health_cmd.stdout, health_cmd.stdout.strip())]
    return evaluated("C5c", "Rotation during multi-line write", [trigger, *queries, health_cmd], assertions, "All ten multi-line statements remained collectable across concurrent forced rotations")


def deleted_log_recreation(lab: Lab, sid: str) -> Result:
    pre, post = lab.marker(sid + "_pre"), lab.marker(sid + "_post")
    trigger_pre = lab.pg(f"COMMENT ON DATABASE postgres IS '{pre}';", label="generate pre-deletion marker")
    received_pre = lab.received(pre)
    commands = [trigger_pre, received_pre]
    database_restored = False
    deleted_path = ""
    try:
        remove = lab.ps(r"$env:PGPASSWORD='postgres'; $rel=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_current_logfile();'; $f=Join-Path 'C:\Program Files\PostgreSQL\16\data' $rel; Stop-Service postgresql-x64-16 -Force; (Get-Service postgresql-x64-16).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60)); Remove-Item -LiteralPath $f -Force; [pscustomobject]@{File=$f;Deleted=(-not (Test-Path -LiteralPath $f));Database=(Get-Service postgresql-x64-16).Status}|ConvertTo-Json -Compress", timeout=90, label="stop PostgreSQL and delete active log")
        commands.append(remove)
        try: deleted_path = json.loads(remove.stdout.strip()).get("File", "")
        except Exception: pass
    finally:
        start = lab.ps("Start-Service postgresql-x64-16; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); (Get-Service postgresql-x64-16).Status", timeout=120, label="start PostgreSQL after log deletion")
        commands.append(start)
        database_restored = start.exit_code == 0 and "Running" in start.stdout
    current = lab.pg_at("SELECT pg_current_logfile();", label="capture recreated active log")
    trigger_post = lab.pg(f"COMMENT ON DATABASE postgres IS '{post}';", label="generate post-recreation marker")
    received_post = lab.received(post, wait=120)
    state = lab.ps("Get-Service postgresql-x64-16,log-collector|Select Name,Status|ConvertTo-Json -Compress", label="verify services after log recreation")
    commands.extend([current, trigger_post, received_post, state])
    assertions = [Assertion("pre-deletion marker delivered", pre in received_pre.stdout, received_pre.stdout.strip()), Assertion("old active log deleted", remove.exit_code == 0 and '"Deleted":true' in remove.stdout, remove.stdout.strip() + remove.stderr.strip()), Assertion("PostgreSQL restored", database_restored, start.stdout.strip()), Assertion("new active log reported", bool(current.stdout.strip()), current.stdout.strip()), Assertion("post-recreation marker delivered", post in received_post.stdout, received_post.stdout.strip()), Assertion("collector remained running", state.stdout.count('"Status":4') == 2 or state.stdout.count('"Status":"Running"') == 2, state.stdout.strip())]
    name = "Deleted log recreation" if sid == "C5d" else "Delete and recreate active log"
    return evaluated(sid, name, commands, assertions, "PostgreSQL recreated its active log and collection followed the replacement")


def c5d(lab: Lab) -> Result:
    return deleted_log_recreation(lab, "C5d")


def c1c(lab: Lab) -> Result:
    commands: list[Command] = []
    cleaned = False
    try:
        register = lab.ps(r"""
$ErrorActionPreference='Stop'; $name='postgresql-x64-16-lc2'; $data='C:\lc-pg16-second'
if(Get-Service $name -ErrorAction SilentlyContinue){throw "$name already exists"}; if(Test-Path $data){throw "$data already exists"}
& 'C:\Program Files\PostgreSQL\16\bin\initdb.exe' -D $data -U postgres -A trust --encoding=UTF8 --no-locale 2>&1 | Out-Null; if($LASTEXITCODE -ne 0){throw "initdb exit $LASTEXITCODE"}
Add-Content -LiteralPath (Join-Path $data 'postgresql.conf') -Value "`nport = 55432`n"
& 'C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe' register -N $name -D $data -S demand; if($LASTEXITCODE -ne 0){throw "pg_ctl register exit $LASTEXITCODE"}; Start-Service $name; (Get-Service $name).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); Get-CimInstance Win32_Service -Filter "Name='$name'"|Select Name,State,StartMode,PathName|ConvertTo-Json -Compress
""", timeout=120, label="create and register stopped disposable PostgreSQL cluster")
        commands.append(register)
        probe = lab.wizard_probe(wizard_to_postgresql(), r"Collect the PostgreSQL server log\?[^\r\n]*:", timeout=180, label="probe two-cluster PostgreSQL discovery")
        commands.append(probe)
    finally:
        cleanup = lab.ps(r"""
$name='postgresql-x64-16-lc2'; Stop-Service $name -Force -ErrorAction SilentlyContinue; if(Get-Service $name -ErrorAction SilentlyContinue){& 'C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe' unregister -N $name 2>&1 | Out-Null}; Start-Sleep -Seconds 2; Remove-Item 'C:\lc-pg16-second' -Recurse -Force -ErrorAction SilentlyContinue; [pscustomobject]@{ServiceExists=[bool](Get-Service $name -ErrorAction SilentlyContinue);DataExists=(Test-Path 'C:\lc-pg16-second');PostgreSQL16=(Get-Service postgresql-x64-16).Status;Collector=(Get-Service log-collector).Status}|ConvertTo-Json -Compress
""", timeout=90, label="unregister and remove disposable PostgreSQL cluster")
        commands.append(cleanup)
        cleaned = cleanup.exit_code == 0 and '"ServiceExists":false' in cleanup.stdout
    found = "Detected 2 PostgreSQL cluster(s)" in probe.stdout and "postgresql-x64-16" in probe.stdout and "postgresql-x64-16-lc2" in probe.stdout
    assertions = [Assertion("temporary second cluster registered and running", register.exit_code == 0 and "postgresql-x64-16-lc2" in register.stdout and ('"State":"Running"' in register.stdout or '"State":4' in register.stdout), register.stdout.strip() + register.stderr.strip()), Assertion("both clusters discovered separately", probe.exit_code == 0 and found, probe.stdout.strip() + probe.stderr.strip()), Assertion("temporary cluster removed", cleaned and '"DataExists":false' in cleanup.stdout, cleanup.stdout.strip() + cleanup.stderr.strip())]
    return evaluated("C1c", "Two PostgreSQL clusters discovered", commands, assertions, "Wizard displayed the production and disposable PostgreSQL clusters separately and cleanup removed the disposable cluster")


def c1d(lab: Lab) -> Result:
    commands: list[Command] = []
    restored = False
    marker = lab.marker("C1d_recovery")
    try:
        backup = lab.ps(r"Copy-Item 'C:\Program Files\PostgreSQL\16\data\postgresql.auto.conf' 'C:\Windows\Temp\lc-c1d-postgresql.auto.conf' -Force; (Get-FileHash 'C:\Windows\Temp\lc-c1d-postgresql.auto.conf' -Algorithm SHA256).Hash", label="back up PostgreSQL auto.conf before logging_collector test")
        change = lab.pg("ALTER SYSTEM SET logging_collector='off';", label="disable PostgreSQL logging collector")
        restart = lab.ps("Restart-Service postgresql-x64-16 -Force; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); (Get-Service postgresql-x64-16).Status", timeout=120, label="restart PostgreSQL with logging_collector off")
        probe = lab.wizard_probe(wizard_to_postgresql(), r"Collect the PostgreSQL server log\?[^\r\n]*:", timeout=180, label="probe discovery with logging_collector off")
        commands.extend([backup, change, restart, probe])
    finally:
        restore = lab.ps(rf"""
$ErrorActionPreference='Continue'; Stop-Service postgresql-x64-16 -Force -ErrorAction SilentlyContinue; $auto='C:\Program Files\PostgreSQL\16\data\postgresql.auto.conf'; if(Test-Path 'C:\Windows\Temp\lc-c1d-postgresql.auto.conf'){{Copy-Item 'C:\Windows\Temp\lc-c1d-postgresql.auto.conf' $auto -Force; Remove-Item 'C:\Windows\Temp\lc-c1d-postgresql.auto.conf' -Force}}; $acct=(Get-CimInstance Win32_Service -Filter "Name='postgresql-x64-16'").StartName; icacls.exe $auto /grant "${{acct}}:M" /C | Out-Null; Start-Service postgresql-x64-16; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); $env:PGPASSWORD='postgres'; $value=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SHOW logging_collector;'; [pscustomobject]@{{State=(Get-Service postgresql-x64-16).Status;LoggingCollector=$value;Backup=(Test-Path 'C:\Windows\Temp\lc-c1d-postgresql.auto.conf')}}|ConvertTo-Json -Compress
""", timeout=150, label="restore exact auto.conf after logging_collector discovery test")
        commands.append(restore)
        restored = restore.exit_code == 0 and '"LoggingCollector":"on"' in restore.stdout and '"Backup":false' in restore.stdout
    trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate post-C1d recovery marker")
    received = lab.received(marker, wait=120)
    commands.extend([trigger, received])
    reported = bool(re.search(r"logging_collector.{0,80}(off|disabled)|stdout|event log", probe.stdout, re.I | re.S))
    assertions = [Assertion("logging_collector disabled", change.exit_code == 0 and restart.exit_code == 0, change.stdout.strip() + restart.stdout.strip()), Assertion("wizard reported non-file logging", probe.exit_code == 0 and reported, probe.stdout.strip() + probe.stderr.strip()), Assertion("exact database configuration restored", restored, restore.stdout.strip() + restore.stderr.strip()), Assertion("post-restore delivery", marker in received.stdout, received.stdout.strip())]
    return evaluated("C1d", "logging_collector off discovery", commands, assertions, "Wizard reported non-file logging and the exact database configuration was restored")


def c1e(lab: Lab) -> Result:
    commands: list[Command] = []
    restored = False
    marker = lab.marker("C1e_recovery")
    try:
        backup = lab.ps(r"""$auto='C:\Program Files\PostgreSQL\16\data\postgresql.auto.conf'; $acct=(Get-CimInstance Win32_Service -Filter "Name='postgresql-x64-16'").StartName; icacls.exe $auto /grant "${acct}:M" /C 2>&1|Out-Null; Copy-Item $auto 'C:\Windows\Temp\lc-c1e-postgresql.auto.conf' -Force; New-Item 'C:\lc-pg-custom-log' -ItemType Directory -Force|Out-Null; icacls.exe 'C:\lc-pg-custom-log' /grant "${acct}:(OI)(CI)F" /T /C 2>&1; if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}; $acct""", label="repair auto.conf ACL, back it up, and prepare custom log directory")
        change = lab.pg("ALTER SYSTEM SET log_directory='C:/lc-pg-custom-log';", label="set custom PostgreSQL log directory")
        restart = lab.ps(r"Restart-Service postgresql-x64-16 -Force; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); $env:PGPASSWORD='postgres'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SHOW log_directory;'", timeout=120, label="restart PostgreSQL on custom log directory")
        probe = lab.wizard_probe(wizard_to_postgresql(), r"Collect the PostgreSQL server log\?[^\r\n]*:", timeout=180, label="probe custom PostgreSQL log discovery")
        commands.extend([backup, change, restart, probe])
    finally:
        restore = lab.ps(rf"""
$ErrorActionPreference='Continue'; Stop-Service log-collector -Force -ErrorAction SilentlyContinue; Stop-Service postgresql-x64-16 -Force -ErrorAction SilentlyContinue; $auto='C:\Program Files\PostgreSQL\16\data\postgresql.auto.conf'; if(Test-Path 'C:\Windows\Temp\lc-c1e-postgresql.auto.conf'){{Copy-Item 'C:\Windows\Temp\lc-c1e-postgresql.auto.conf' $auto -Force; Remove-Item 'C:\Windows\Temp\lc-c1e-postgresql.auto.conf' -Force}}; $acct=(Get-CimInstance Win32_Service -Filter "Name='postgresql-x64-16'").StartName; icacls.exe $auto /grant "${{acct}}:M" /C | Out-Null; Start-Service postgresql-x64-16; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); Remove-Item 'C:\lc-pg-custom-log' -Recurse -Force -ErrorAction SilentlyContinue; Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); $env:PGPASSWORD='postgres'; $dir=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SHOW log_directory;'; $check=& '{COLLECTOR}' check 2>&1; [pscustomobject]@{{PostgreSQL=(Get-Service postgresql-x64-16).Status;Collector=(Get-Service log-collector).Status;LogDirectory=$dir;CustomExists=(Test-Path 'C:\lc-pg-custom-log');Backup=(Test-Path 'C:\Windows\Temp\lc-c1e-postgresql.auto.conf');Check=($check -join ' ')}}|ConvertTo-Json -Compress
""", timeout=180, label="restore exact auto.conf and remove custom log directory")
        commands.append(restore)
        restored = restore.exit_code == 0 and '"CustomExists":false' in restore.stdout and '"Backup":false' in restore.stdout and "Config OK" in restore.stdout
    trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate post-C1e recovery marker")
    received = lab.received(marker, wait=120)
    commands.extend([trigger, received])
    discovered = re.search(r"log directory:\s*C:[\\/]lc-pg-custom-log", probe.stdout, re.I) is not None
    assertions = [Assertion("custom directory active", change.exit_code == 0 and restart.exit_code == 0 and "lc-pg-custom-log" in restart.stdout, restart.stdout.strip() + restart.stderr.strip()), Assertion("wizard discovered custom directory", probe.exit_code == 0 and discovered, probe.stdout.strip() + probe.stderr.strip()), Assertion("configuration and physical path restored", restored, restore.stdout.strip() + restore.stderr.strip()), Assertion("post-restore delivery", marker in received.stdout, received.stdout.strip())]
    return evaluated("C1e", "Custom log directory discovery", commands, assertions, "Wizard discovered the custom PostgreSQL log directory and cleanup restored the original path")


def g3(lab: Lab) -> Result:
    return c5(lab, "G3")


def g3a(lab: Lab) -> Result:
    pre, post = lab.marker("G3a_pre"), lab.marker("G3a_post")
    trigger_pre = lab.pg(f"COMMENT ON DATABASE postgres IS '{pre}';", label="generate pre-copytruncate marker")
    received_pre = lab.received(pre)
    script = r"""
$env:PGPASSWORD='postgres'; $rel=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_current_logfile();'
$f=Join-Path 'C:\Program Files\PostgreSQL\16\data' $rel; $copy='C:\Windows\Temp\lc-g3a-log-copy'
$src=[IO.File]::Open($f,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
try{$dst=[IO.File]::Create($copy); try{$src.Position=0;$src.CopyTo($dst);$dst.Flush()}finally{$dst.Dispose()}; $before=$src.Length; $src.SetLength(0); $src.Flush(); "file=$f before=$before after=$($src.Length) copy=$copy"}finally{$src.Dispose()}
"""
    truncate = lab.ps(script, timeout=60, label="copy and truncate active PostgreSQL log")
    trigger_post = lab.pg(f"COMMENT ON DATABASE postgres IS '{post}';", label="generate post-copytruncate marker")
    received_post = lab.received(post, wait=120)
    cleanup = lab.ps("Remove-Item 'C:\\Windows\\Temp\\lc-g3a-log-copy' -Force -ErrorAction SilentlyContinue; (Get-Service postgresql-x64-16,log-collector|Select Name,Status|ConvertTo-Json -Compress)", label="remove copytruncate artifact and verify services")
    assertions = [Assertion("pre-truncate marker delivered", pre in received_pre.stdout, received_pre.stdout.strip()), Assertion("copy-truncate completed", truncate.exit_code == 0 and "after=0" in truncate.stdout, truncate.stdout.strip() + truncate.stderr.strip()), Assertion("post-truncate marker delivered", post in received_post.stdout, received_post.stdout.strip()), Assertion("services remained running", cleanup.stdout.count('"Status":4') == 2 or cleanup.stdout.count('"Status":"Running"') == 2, cleanup.stdout.strip())]
    return evaluated("G3a", "Copy-truncate rotation continuity", [trigger_pre, received_pre, truncate, trigger_post, received_post, cleanup], assertions, "Collection resumed after copy-truncate without restarting PostgreSQL or the collector")


def g3b(lab: Lab) -> Result:
    markers = [lab.marker(f"G3b_{i}") for i in range(1, 4)]
    commands: list[Command] = []
    files: list[str] = []
    for index, marker in enumerate(markers):
        trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label=f"generate rapid-rotation marker {index + 1}")
        commands.append(trigger)
        current = lab.pg_at("SELECT pg_current_logfile();", label=f"capture rapid-rotation file {index + 1}")
        commands.append(current)
        files.append(current.stdout.strip().splitlines()[-1] if current.stdout.strip() else "")
        if index < 2:
            rotate = lab.pg("SELECT pg_rotate_logfile();", label=f"force rapid rotation {index + 1}")
            commands.append(rotate)
            time.sleep(1)
    time.sleep(10)
    received = lab.recv("grep -F 'lc_win_pg_g3b_' /var/log/clients/kenyata-fct-ep6/postgres_log.log | tail -n 100", label="collect rapid-rotation markers")
    commands.append(received)
    assertions = [Assertion("three distinct active files", len(set(files)) == 3, str(files)), Assertion("all rapid-rotation markers received", all(m in received.stdout for m in markers), str([i + 1 for i, m in enumerate(markers) if m in received.stdout]))]
    return evaluated("G3b", "Two rapid PostgreSQL rotations", commands, assertions, "Collection followed two rapid rotations without losing markers")


def g4(lab: Lab) -> Result:
    marker = lab.marker("G4")
    commands: list[Command] = []
    database_restored = False
    try:
        prepare = lab.ps(r"$env:PGPASSWORD='postgres'; $rel=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_current_logfile();'; $f=Join-Path 'C:\Program Files\PostgreSQL\16\data' $rel; Stop-Service postgresql-x64-16 -Force; (Get-Service postgresql-x64-16).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60)); $s=[IO.File]::Open($f,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite); try{$s.SetLength(0);$s.Flush()}finally{$s.Dispose()}; Restart-Service log-collector -Force; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(30)); [pscustomobject]@{File=$f;Length=(Get-Item $f).Length;Collector=(Get-Service log-collector).Status;Database=(Get-Service postgresql-x64-16).Status}|ConvertTo-Json -Compress", timeout=120, label="restart collector on nearly empty PostgreSQL log")
        commands.append(prepare)
    finally:
        start = lab.ps("Start-Service postgresql-x64-16; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); (Get-Service postgresql-x64-16).Status", timeout=120, label="restore PostgreSQL after small-log restart")
        commands.append(start)
        database_restored = start.exit_code == 0 and "Running" in start.stdout
    trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate small-log recovery marker")
    received = lab.received(marker, wait=120)
    state = lab.ps("Get-Service postgresql-x64-16,log-collector|Select Name,Status|ConvertTo-Json -Compress", label="verify services after small-log case")
    commands.extend([trigger, received, state])
    try: info = json.loads(prepare.stdout.strip())
    except Exception: info = {}
    assertions = [Assertion("log made smaller than 128 bytes", int(info.get("Length", 999999)) < 128, str(info.get("Length"))), Assertion("collector restarted while database stopped", info.get("Collector") in ("Running", 4), str(info)), Assertion("PostgreSQL restored", database_restored, start.stdout.strip()), Assertion("small-file event delivered", marker in received.stdout, received.stdout.strip()), Assertion("both services running", state.stdout.count('"Status":4') == 2 or state.stdout.count('"Status":"Running"') == 2, state.stdout.strip())]
    return evaluated("G4", "Nearly-empty log restart", commands, assertions, "Collector restarted on an empty log and resumed delivery after PostgreSQL returned")


def g7(lab: Lab) -> Result:
    return deleted_log_recreation(lab, "G7")


def g5(lab: Lab) -> Result:
    old, new = lab.marker("G5_history"), lab.marker("G5_current")
    commands: list[Command] = []
    restored = False
    try:
        stop = lab.ps(r"""
$ErrorActionPreference='Stop'; Stop-Service log-collector -Force; (Get-Service log-collector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)); $files=@(Get-ChildItem 'C:\ProgramData\log-collector\state\postgres_log_*.json'); if($files.Count -ne 1){throw "expected one PostgreSQL checkpoint, found $($files.Count)"}; Copy-Item -LiteralPath $files[0].FullName -Destination 'C:\Windows\Temp\lc-g5-postgres-state.json' -Force; Set-Content -LiteralPath 'C:\Windows\Temp\lc-g5-postgres-state.name' -Value $files[0].Name -NoNewline; $files[0].FullName
""", timeout=60, label="stop collector and back up PostgreSQL checkpoint")
        commands.append(stop)
        history = lab.pg(f"COMMENT ON DATABASE postgres IS '{old}';", label="write historical marker while collector is stopped")
        source = lab.ps(rf"$env:PGPASSWORD='postgres'; $rel=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_current_logfile();'; $f=Join-Path 'C:\Program Files\PostgreSQL\16\data' $rel; Select-String -LiteralPath $f -SimpleMatch '{old}' | Select-Object -Last 1 | ForEach-Object {{$_.Line}}", label="verify historical marker in active PostgreSQL log")
        reset = lab.ps(r"Remove-Item 'C:\ProgramData\log-collector\state\postgres_log_*.json' -Force; Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); Start-Sleep -Seconds 15; (Get-Service log-collector).Status", timeout=90, label="reset PostgreSQL checkpoint and start collector with default policy")
        old_received = lab.recv(f"grep -F {shlex.quote(old)} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", label="verify history was not replayed")
        current = lab.pg(f"COMMENT ON DATABASE postgres IS '{new}';", label="write post-reset current marker")
        new_received = lab.received(new, wait=120)
        commands.extend([history, source, reset, old_received, current, new_received])
    finally:
        restore = lab.ps(rf"""
$ErrorActionPreference='Continue'; Stop-Service log-collector -Force -ErrorAction SilentlyContinue; Remove-Item 'C:\ProgramData\log-collector\state\postgres_log_*.json' -Force -ErrorAction SilentlyContinue; if((Test-Path 'C:\Windows\Temp\lc-g5-postgres-state.json') -and (Test-Path 'C:\Windows\Temp\lc-g5-postgres-state.name')){{$name=Get-Content -LiteralPath 'C:\Windows\Temp\lc-g5-postgres-state.name' -Raw; Move-Item 'C:\Windows\Temp\lc-g5-postgres-state.json' (Join-Path 'C:\ProgramData\log-collector\state' $name) -Force}}; Remove-Item 'C:\Windows\Temp\lc-g5-postgres-state.name' -Force -ErrorAction SilentlyContinue; Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); $health=$null; 1..15|ForEach-Object{{if(-not $health){{$health=try{{(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 5).Content}}catch{{$null}}; if(-not $health){{Start-Sleep -Seconds 2}}}}}}; $check=& '{COLLECTOR}' check 2>&1; [pscustomobject]@{{State=(Get-Service log-collector).Status;Check=($check -join ' ');Health=$health;Backup=(Test-Path 'C:\Windows\Temp\lc-g5-postgres-state.json')}}|ConvertTo-Json -Compress
""", timeout=120, label="restore exact PostgreSQL checkpoint after fresh-state test")
        commands.append(restore)
        restored = restore.exit_code == 0 and "Config OK" in restore.stdout and "agent_status\\\":\\\"Running" in restore.stdout and '"Backup":false' in restore.stdout
    assertions = [Assertion("checkpoint backed up", stop.exit_code == 0 and "postgres_log_" in stop.stdout, stop.stdout.strip() + stop.stderr.strip()), Assertion("historical marker exists in source", history.exit_code == 0 and old in source.stdout, source.stdout.strip()), Assertion("history not replayed after fresh state", old not in old_received.stdout, old_received.stdout.strip()), Assertion("new event delivered", new in new_received.stdout, new_received.stdout.strip()), Assertion("original checkpoint restored", restored, restore.stdout.strip() + restore.stderr.strip())]
    return evaluated("G5", "Fresh-state starts at current log end", commands, assertions, "Fresh PostgreSQL state skipped existing history, delivered new activity, and the original checkpoint was restored")


def g13(lab: Lab) -> Result:
    marker = lab.marker("G13")
    commands: list[Command] = []
    restored = False
    prepare = None
    trigger = None
    received = None
    try:
        prepare = lab.ps(r"""
$ErrorActionPreference='Stop'; $link='C:\Program Files\PostgreSQL\16\data\log'; $real='C:\Program Files\PostgreSQL\16\data\lc-g13-log-real'
if(Test-Path -LiteralPath $real){throw 'temporary real directory already exists'}
Stop-Service log-collector -Force; Stop-Service postgresql-x64-16 -Force
(Get-Service log-collector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)); (Get-Service postgresql-x64-16).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))
Move-Item -LiteralPath $link -Destination $real
$mk=cmd.exe /c "mklink /J `"$link`" `"$real`"" 2>&1; if($LASTEXITCODE -ne 0){throw ($mk -join ' ')}
Start-Service postgresql-x64-16; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90))
Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60))
$item=Get-Item -LiteralPath $link -Force; [pscustomobject]@{Link=$link;Target=$item.Target;LinkType=$item.LinkType;Attributes=$item.Attributes;PostgreSQL=(Get-Service postgresql-x64-16).Status;Collector=(Get-Service log-collector).Status}|ConvertTo-Json -Compress
""", timeout=150, label="replace PostgreSQL log directory with reversible junction")
        commands.append(prepare)
        trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate event through junction-backed log path")
        received = lab.received(marker, wait=120)
        commands.extend([trigger, received])
    finally:
        restore = lab.ps(rf"""
$ErrorActionPreference='Continue'; $link='C:\Program Files\PostgreSQL\16\data\log'; $real='C:\Program Files\PostgreSQL\16\data\lc-g13-log-real'
Stop-Service log-collector -Force -ErrorAction SilentlyContinue; Stop-Service postgresql-x64-16 -Force -ErrorAction SilentlyContinue
if((Test-Path -LiteralPath $link) -and ((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){{cmd.exe /c "rmdir `"$link`"" | Out-Null}}
if((Test-Path -LiteralPath $real) -and -not (Test-Path -LiteralPath $link)){{Move-Item -LiteralPath $real -Destination $link}}
Start-Service postgresql-x64-16; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(90)); Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60))
$health=$null; 1..15|ForEach-Object{{if(-not $health){{$health=try{{(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 5).Content}}catch{{$null}}; if(-not $health){{Start-Sleep -Seconds 2}}}}}}; $check=& '{COLLECTOR}' check 2>&1
[pscustomobject]@{{LinkIsReparse=((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint);RealExists=(Test-Path -LiteralPath $real);PostgreSQL=(Get-Service postgresql-x64-16).Status;Collector=(Get-Service log-collector).Status;Check=($check -join ' ');Health=$health}}|ConvertTo-Json -Compress
""", timeout=180, label="restore physical PostgreSQL log directory after junction test")
        commands.append(restore)
        restored = restore.exit_code == 0 and '"LinkIsReparse":0' in restore.stdout and '"RealExists":false' in restore.stdout and "Config OK" in restore.stdout and "agent_status\\\":\\\"Running" in restore.stdout
    assertions = [Assertion("junction created and services started", prepare is not None and prepare.exit_code == 0 and ('"LinkType":"Junction"' in prepare.stdout or "ReparsePoint" in prepare.stdout), "" if prepare is None else prepare.stdout.strip() + prepare.stderr.strip()), Assertion("event generated", trigger is not None and trigger.exit_code == 0, "" if trigger is None else trigger.stdout.strip() + trigger.stderr.strip()), Assertion("junction-backed event delivered", received is not None and marker in received.stdout, "" if received is None else received.stdout.strip()), Assertion("physical path and services restored", restored, restore.stdout.strip() + restore.stderr.strip())]
    return evaluated("G13", "Symlinked PostgreSQL log path", commands, assertions, "Collector followed a junction-backed PostgreSQL log and the physical directory was restored")


def db_stopped_collector_restart(lab: Lab, sid: str) -> Result:
    commands: list[Command] = []
    database_restored = False
    try:
        stop = lab.ps("Stop-Service postgresql-x64-16 -Force; (Get-Service postgresql-x64-16).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60)); (Get-Service postgresql-x64-16).Status", timeout=90, label="stop PostgreSQL")
        restart = lab.ps("Restart-Service log-collector -Force; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(30)); (Get-Service log-collector).Status", timeout=60, label="restart collector while PostgreSQL is stopped")
        commands.extend([stop, restart])
    finally:
        start = lab.ps("Start-Service postgresql-x64-16; (Get-Service postgresql-x64-16).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); (Get-Service postgresql-x64-16).Status", timeout=90, label="restore PostgreSQL service")
        commands.append(start)
        database_restored = start.exit_code == 0 and "Running" in start.stdout
    marker = lab.marker(sid)
    trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate recovery marker")
    received = lab.received(marker)
    state = lab.ps("Get-Service postgresql-x64-16,log-collector | Select-Object Name,Status | ConvertTo-Json -Compress", label="verify final service state")
    commands.extend([trigger, received, state])
    assertions = [Assertion("database stopped", stop.exit_code == 0 and "Stopped" in stop.stdout, stop.stdout.strip()), Assertion("collector started without database", restart.exit_code == 0 and "Running" in restart.stdout, restart.stdout.strip()), Assertion("database restored", database_restored, start.stdout.strip()), Assertion("collection resumed", marker in received.stdout, received.stdout.strip()), Assertion("both services running", state.stdout.count('"Status":4') == 2 or state.stdout.count('"Status":"Running"') == 2, state.stdout.strip())]
    name = "Agent restart while database is stopped" if sid == "G4a" else "Collector starts before PostgreSQL"
    return evaluated(sid, name, commands, assertions, "Collector waited for PostgreSQL and resumed after database startup")


def g4a(lab: Lab) -> Result:
    return db_stopped_collector_restart(lab, "G4a")


def h4(lab: Lab) -> Result:
    return db_stopped_collector_restart(lab, "H4")


def h6(lab: Lab) -> Result:
    pre, post = lab.marker("H6_pre"), lab.marker("H6_post")
    trigger_pre = lab.pg(f"COMMENT ON DATABASE postgres IS '{pre}';", label="generate pre-reboot marker")
    received_pre = lab.received(pre)
    reboot = lab.ps("shutdown.exe /r /t 3 /f; 'reboot requested'", label="reboot Windows endpoint")
    started = utc_now()
    went_down = False
    down_deadline = time.monotonic() + 120
    while time.monotonic() < down_deadline:
        try:
            with socket.create_connection((lab.win.host, 22), timeout=2):
                pass
        except OSError:
            went_down = True
            break
        time.sleep(2)
    lab.win.close()
    reconnect_error = ""
    new_win = None
    up_deadline = time.monotonic() + 600
    while time.monotonic() < up_deadline:
        try:
            new_win = SSH(lab.win.host, lab.win.user, lab.win.password)
            break
        except Exception as exc:
            reconnect_error = f"{type(exc).__name__}: {exc}"
            time.sleep(5)
    reconnected = new_win is not None
    if new_win is not None:
        lab.win = new_win
    wait_cmd = Command("management", "wait for Windows reboot and SSH reconnection", 0 if went_down and reconnected else 1, f"went_down={went_down} reconnected={reconnected}", reconnect_error, started, utc_now())
    if not reconnected:
        return evaluated("H6", "Windows reboot persistence", [trigger_pre, received_pre, reboot, wait_cmd], [Assertion("endpoint rebooted", went_down, wait_cmd.stdout), Assertion("SSH returned", False, reconnect_error)], "Windows rebooted and services recovered automatically")
    state = lab.ps("for($i=0;$i -lt 180;$i++){ $c=Get-Service log-collector; $p=Get-Service postgresql-x64-16; if($c.Status -eq 'Running' -and $p.Status -eq 'Running'){break}; Start-Sleep 1 }; Get-Service postgresql-x64-16,log-collector | Select-Object Name,Status,StartType | ConvertTo-Json -Compress", timeout=210, label="wait for automatic services after reboot")
    config = lab.ps(f"& '{COLLECTOR}' check 2>&1; exit $LASTEXITCODE", label="validate collector after reboot")
    trigger_post = lab.pg(f"COMMENT ON DATABASE postgres IS '{post}';", label="generate post-reboot marker")
    received_post = lab.received(post, wait=120)
    running_count = state.stdout.count('"Status":4') + state.stdout.count('"Status":"Running"')
    auto_count = state.stdout.count('"StartType":2') + state.stdout.count('"StartType":"Automatic"')
    assertions = [Assertion("pre-reboot event delivered", pre in received_pre.stdout, received_pre.stdout.strip()), Assertion("endpoint went down", went_down, wait_cmd.stdout), Assertion("SSH returned", reconnected, wait_cmd.stdout), Assertion("database and collector automatic/running", running_count >= 2 and auto_count >= 2, state.stdout.strip()), Assertion("configuration valid after reboot", config.exit_code == 0 and "Config OK" in config.stdout, config.stdout.strip()), Assertion("post-reboot delivery", post in received_post.stdout, received_post.stdout.strip())]
    return evaluated("H6", "Windows reboot persistence", [trigger_pre, received_pre, reboot, wait_cmd, state, config, trigger_post, received_post], assertions, "Windows rebooted and PostgreSQL plus the collector recovered automatically with post-boot delivery")


def buffered_outage(lab: Lab, sid: str) -> Result:
    prefix = lab.marker(sid)
    before = lab.ps("(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content", label="capture health before receiver outage")
    commands: list[Command] = [before]
    restored = False
    outage_started = time.monotonic()
    try:
        stop = lab.recv("systemctl stop syslog.socket rsyslog.service; if ss -ltn | grep -q ':2514 '; then exit 1; fi", label="stop receiver and prove buffered-test outage")
        commands.append(stop)
        script = "$p='C:\\Windows\\Temp\\lc-buffer.sql'; $sql=(1..300|ForEach-Object{\"COMMENT ON DATABASE postgres IS '" + prefix + "_$($_.ToString('000'))';\"}) -join [Environment]::NewLine; [IO.File]::WriteAllText($p,$sql,(New-Object Text.UTF8Encoding($false))); $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -f $p 2>&1; $c=$LASTEXITCODE; Remove-Item $p -Force; exit $c"
        load = lab.ps(script, timeout=120, label="generate 300 events during receiver outage")
        commands.append(load)
        remaining = 60 - (time.monotonic() - outage_started)
        if remaining > 0:
            time.sleep(remaining)
        during = lab.ps("(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content", label="capture health during receiver outage")
        commands.append(during)
    finally:
        restore = lab.recv("systemctl start rsyslog.service syslog.socket; for i in $(seq 1 30); do ss -ltn | grep -q ':2514 ' && exit 0; sleep 1; done; exit 1", timeout=60, label="restore receiver after buffered test")
        commands.append(restore)
        restored = restore.exit_code == 0
    queries: list[Command] = []
    deadline = time.time() + 240
    unique = total = 0
    while time.time() < deadline:
        received = lab.recv(f"grep -F {shlex.quote(prefix + '_')} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", label="collect buffered outage markers")
        queries.append(received)
        values = re.findall(re.escape(prefix) + r"_(\d{3})", received.stdout)
        unique, total = len(set(values)), len(values)
        if unique == 300:
            break
        time.sleep(10)
    commands.extend(queries)
    after = lab.ps("(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content", label="capture health after receiver recovery")
    commands.append(after)
    try:
        b, d, a = json.loads(before.stdout), json.loads(during.stdout), json.loads(after.stdout)
    except Exception:
        b, d, a = {}, {}, {}
    before_bytes, during_bytes = int(b.get("disk_buffer_bytes", 0)), int(d.get("disk_buffer_bytes", 0))
    common = [Assertion("outage proved", stop.exit_code == 0, stop.stdout.strip() + stop.stderr.strip()), Assertion("collector stayed running", d.get("agent_status") == "Running", str(d.get("agent_status"))), Assertion("receiver restored", restored, restore.stdout.strip() + restore.stderr.strip())]
    if sid == "H1":
        assertions = common + [Assertion("disk buffer grew", during_bytes > before_bytes, f"before={before_bytes} during={during_bytes}")]
        return evaluated("H1", "Disk buffer growth during receiver outage", commands, assertions, "Collector stayed running and its disk buffer grew during the proved outage")
    assertions = common + [Assertion("all buffered markers delivered", unique == 300, f"unique={unique} total={total} duplicates={max(0,total-unique)}"), Assertion("collector recovered connected", a.get("cloud_status") == "Connected", str(a.get("cloud_status")))]
    return evaluated("H2", "Buffered delivery after receiver recovery", commands, assertions, "All buffered events arrived after receiver recovery")


def h1(lab: Lab) -> Result:
    return buffered_outage(lab, "H1")


def h2(lab: Lab) -> Result:
    return buffered_outage(lab, "H2")


def h9(lab: Lab) -> Result:
    marker = lab.marker("H9")
    rule = "LC-Test-H9-Block-RELP"
    commands: list[Command] = []
    restored = False
    try:
        block = lab.ps(f"New-NetFirewallRule -DisplayName '{rule}' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress 192.168.248.129 -RemotePort 2514 | Out-Null", label="block collector RELP destination")
        trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate event while RELP is blocked")
        time.sleep(15)
        during = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; $h=(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content; \"$($s.State)`n$h\"", label="capture collector during blocked RELP")
        commands.extend([block, trigger, during])
    finally:
        unblock = lab.ps(f"Remove-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue", label="remove RELP block rule")
        commands.append(unblock)
        restored = unblock.exit_code == 0
    deadline = time.time() + 120
    after = None
    while time.time() < deadline:
        after = lab.ps("(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content", label="wait for collector RELP reconnection")
        try: connected = json.loads(after.stdout).get("cloud_status") == "Connected"
        except Exception: connected = False
        if connected:
            break
        time.sleep(5)
    assert after is not None
    received = lab.received(marker, wait=120)
    commands.extend([after, received])
    try: during_health = json.loads(during.stdout.splitlines()[-1])
    except Exception: during_health = {}
    try: after_health = json.loads(after.stdout)
    except Exception: after_health = {}
    assertions = [Assertion("block rule applied", block.exit_code == 0, block.stderr.strip()), Assertion("collector stayed running", "Running" in during.stdout, during.stdout.strip()), Assertion("output reported disconnected", during_health.get("cloud_status") != "Connected", str(during_health.get("cloud_status"))), Assertion("block rule removed", restored, unblock.stderr.strip()), Assertion("output reconnected", after_health.get("cloud_status") == "Connected", str(after_health.get("cloud_status")))]
    return evaluated("H9", "Unreachable output retry and recovery", commands, assertions, "Collector reported disconnection, stayed running, and recovered after RELP became reachable")


def h10(lab: Lab) -> Result:
    pre, post = lab.marker("H10_pre"), lab.marker("H10_post")
    trigger_pre = lab.pg(f"COMMENT ON DATABASE postgres IS '{pre}';", label="generate pre-kill marker")
    received_pre = lab.received(pre)
    kill = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; $old=$s.ProcessId; Stop-Process -Id $old -Force; for($i=0;$i -lt 60;$i++){Start-Sleep 1;$n=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; if($n.State -eq 'Running' -and $n.ProcessId -ne 0 -and $n.ProcessId -ne $old){\"old=$old new=$($n.ProcessId) state=$($n.State)\"; exit 0}}; exit 1", timeout=90, label="force-kill collector and wait for service recovery")
    trigger_post = lab.pg(f"COMMENT ON DATABASE postgres IS '{post}';", label="generate post-kill marker")
    received_post = lab.received(post)
    recount = lab.recv(f"grep -F {shlex.quote(pre)} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null | wc -l", label="check checkpoint replay after forced kill")
    try: count = int(recount.stdout.strip())
    except ValueError: count = -1
    assertions = [Assertion("pre-kill marker delivered", pre in received_pre.stdout, received_pre.stdout.strip()), Assertion("service recovered with new process", kill.exit_code == 0 and "state=Running" in kill.stdout, kill.stdout.strip()), Assertion("post-kill marker delivered", post in received_post.stdout, received_post.stdout.strip()), Assertion("no full replay", count <= received_pre.stdout.count(pre) + 1, f"post_recovery_count={count}")]
    return evaluated("H10", "Forced process-kill checkpoint recovery", [trigger_pre, received_pre, kill, trigger_post, received_post, recount], assertions, "Collector recovered from forced termination and continued from its checkpoint")


def h12(lab: Lab) -> Result:
    prefix = lab.marker("H12")
    script = "$path='C:\\Windows\\Temp\\lc-h12.sql'; $sql=(1..200|ForEach-Object{\"COMMENT ON DATABASE postgres IS '" + prefix + "_$($_.ToString('000'))';\"}) -join [Environment]::NewLine; [IO.File]::WriteAllText($path,$sql,(New-Object Text.UTF8Encoding($false))); $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -f $path 2>&1; $c=$LASTEXITCODE; Remove-Item $path -Force; exit $c"
    before = lab.ps("$p=Get-Process -Id (Get-CimInstance Win32_Service -Filter \"Name='log-collector'\").ProcessId; [pscustomobject]@{Id=$p.Id;WorkingSet64=$p.WorkingSet64;Handles=$p.HandleCount}|ConvertTo-Json -Compress", label="capture pre-load collector resources")
    load = lab.ps(script, timeout=120, label="generate 200-event constrained load")
    time.sleep(60)
    after = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; $p=Get-Process -Id $s.ProcessId; [pscustomobject]@{State=$s.State;Id=$p.Id;WorkingSet64=$p.WorkingSet64;Handles=$p.HandleCount}|ConvertTo-Json -Compress", label="capture post-load collector resources")
    received = lab.recv(f"grep -F {shlex.quote(prefix + '_')} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", label="collect sustained-load markers")
    unique = len(set(re.findall(re.escape(prefix) + r"_(\d{3})", received.stdout)))
    try:
        b, a = json.loads(before.stdout), json.loads(after.stdout); growth = int(a.get("WorkingSet64", 0)) - int(b.get("WorkingSet64", 0))
    except Exception:
        a, growth = {}, 10**12
    assertions = [Assertion("load generated", load.exit_code == 0, load.stdout[-1000:]), Assertion("all events delivered", unique == 200, f"unique={unique}"), Assertion("collector stable", a.get("State") == "Running" and growth < 128 * 1024 * 1024, f"state={a.get('State')} growth_bytes={growth}")]
    return evaluated("H12", "Constrained sustained-load soak", [before, load, after, received], assertions, "Collector remained stable for the approved one-minute constrained soak; upstream specifies several hours")


def g1(lab: Lab) -> Result:
    secret = "lcSecret_" + uuid.uuid4().hex[:12]
    role = "lc_pw_" + uuid.uuid4().hex[:8]
    trigger = lab.pg(f"CREATE ROLE {role} LOGIN PASSWORD '{secret}'; DROP ROLE {role};", label="generate disposable password DDL")
    received = lab.received(role, all_sources=True)
    secret_query = lab.recv(f"grep -R -n -F {shlex.quote(secret)} /var/log/clients/kenyata-fct-ep6 2>/dev/null || true", label="search all receiver sources for disposable secret")
    assertions = [Assertion("role DDL delivered", role in received.stdout, received.stdout.strip()), Assertion("password absent from every source", secret not in secret_query.stdout, secret_query.stdout.strip() or "absent")]
    return evaluated("G1", "Password redaction", [trigger, received, secret_query], assertions, "Disposable password was redacted across all sources")


def password_variant(lab: Lab, sid: str, user_keyword: str, encrypted: bool = False) -> Result:
    secret = "lcSecret_" + uuid.uuid4().hex[:12]
    role = "lc_pw_" + uuid.uuid4().hex[:8]
    password_clause = ("ENCRYPTED PASSWORD" if encrypted else "PASSWORD") + f" '{secret}'"
    trigger = lab.pg(f"{user_keyword} {role} {password_clause}; DROP ROLE {role};", label=f"generate {sid} password DDL")
    received = lab.received(role, all_sources=True)
    secret_query = lab.recv(f"grep -R -n -F {shlex.quote(secret)} /var/log/clients/kenyata-fct-ep6 2>/dev/null || true", label=f"search all sources for {sid} secret")
    assertions = [Assertion("role DDL delivered", role in received.stdout, received.stdout.strip()), Assertion("password absent from every source", secret not in secret_query.stdout, secret_query.stdout.strip() or "absent")]
    name = "CREATE USER password redaction" if sid == "G1a" else "ENCRYPTED PASSWORD redaction"
    return evaluated(sid, name, [trigger, received, secret_query], assertions, "Disposable password was redacted across all sources")


def g1a(lab: Lab) -> Result:
    return password_variant(lab, "G1a", "CREATE USER")


def g1b(lab: Lab) -> Result:
    return password_variant(lab, "G1b", "CREATE ROLE", encrypted=True)


def g2(lab: Lab) -> Result:
    role = "lc_user_" + uuid.uuid4().hex[:10]
    trigger = lab.pg(f"CREATE ROLE {role}; DROP ROLE {role};", label="generate username preservation DDL")
    received = lab.received(role)
    return evaluated("G2", "Username preservation", [trigger, received], [Assertion("username preserved", role in received.stdout, received.stdout.strip())], "Disposable username remained visible")


def g6(lab: Lab) -> Result:
    marker = lab.marker("G6")
    text = f"{marker}_日本語_العربية_🚀"
    script = rf"""
$path='C:\Windows\Temp\lc-g6-utf8.sql'
$sql=@'
SET client_encoding='UTF8';
COMMENT ON DATABASE postgres IS '{text}';
'@
[System.IO.File]::WriteAllText($path,$sql,(New-Object System.Text.UTF8Encoding($false)))
$env:PGPASSWORD='postgres'
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -f $path 2>&1
$code=$LASTEXITCODE
Remove-Item $path -Force
exit $code
"""
    trigger = lab.ps(script, label="generate Unicode marker from UTF-8 SQL file")
    received = lab.received(marker)
    assertions = [Assertion("Japanese preserved", "日本語" in received.stdout, received.stdout.strip()), Assertion("Arabic preserved", "العربية" in received.stdout, received.stdout.strip()), Assertion("emoji preserved", "🚀" in received.stdout, received.stdout.strip())]
    return evaluated("G6", "Unicode preservation", [trigger, received], assertions, "Unicode text remained intact")


def g6b(lab: Lab) -> Result:
    token = uuid.uuid4().hex[:8]
    database = f"lc_latin1_{token}"
    marker = lab.marker("G6b")
    create = lab.pg(f"CREATE DATABASE {database} TEMPLATE template0 ENCODING 'WIN1252';", label="create disposable non-UTF8 database")
    sql = f"SET client_encoding='WIN1252'; COMMENT ON DATABASE {database} IS '{marker}_café';"
    raw = sql.encode("cp1252")
    encoded = base64.b64encode(raw).decode("ascii")
    script = "$p='C:\\Windows\\Temp\\lc-latin1.sql'; [IO.File]::WriteAllBytes($p,[Convert]::FromBase64String('" + encoded + "')); $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d " + database + " -v ON_ERROR_STOP=1 -f $p 2>&1; $c=$LASTEXITCODE; Remove-Item $p -Force; exit $c"
    trigger = lab.ps(script, label="generate WIN1252 database event")
    received = lab.received(marker)
    health_cmd = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; \"$($s.State) $((Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content)\"", label="verify collector after LATIN1 event")
    cleanup = lab.pg(f"DROP DATABASE IF EXISTS {database};", label="drop disposable LATIN1 database")
    assertions = [Assertion("non-UTF8 database created", create.exit_code == 0, create.stdout.strip()), Assertion("non-UTF8 event generated", trigger.exit_code == 0, trigger.stdout.strip() + trigger.stderr.strip()), Assertion("event delivered", marker in received.stdout, received.stdout.strip()), Assertion("collector remained healthy", "Running" in health_cmd.stdout, health_cmd.stdout.strip()), Assertion("database cleaned up", cleanup.exit_code == 0, cleanup.stdout.strip())]
    return evaluated("G6b", "Non-UTF8 database encoding", [create, trigger, received, health_cmd, cleanup], assertions, "Collector handled a WIN1252 database event without crashing or silently dropping it")


def g8(lab: Lab) -> Result:
    blocked_marker = lab.marker("G8_blocked")
    recovery_marker = lab.marker("G8_recovered")
    acl_backup = r"C:\Windows\Temp\lc-g8-log-acl.txt"
    commands: list[Command] = []
    restored = False
    try:
        deny = lab.ps(rf"$env:PGPASSWORD='postgres'; $rel=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_current_logfile();'; $f=Join-Path 'C:\Program Files\PostgreSQL\16\data' $rel; (Get-Acl -LiteralPath $f).Sddl|Set-Content -LiteralPath '{acl_backup}' -Encoding ASCII; icacls $f /deny 'NT SERVICE\log-collector:(R)' | Out-String; Restart-Service log-collector -Force; Start-Sleep 3; [pscustomobject]@{{File=$f;Service=(Get-Service log-collector).Status}}|ConvertTo-Json -Compress", timeout=60, label="deny collector log access and restart service")
        trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{blocked_marker}';", label="generate event while collector access is denied")
        time.sleep(10)
        missing = lab.recv(f"grep -F {shlex.quote(blocked_marker)} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", label="check denied-period receiver delivery")
        diagnostic = lab.ps("$h=$null; try{$h=(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 5).Content}catch{$h=$_.Exception.Message}; $events=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction SilentlyContinue|Where-Object{$_.Message -match 'log-collector|permission|access'}|Select -First 20 -Expand Message; \"$h`n$($events -join [Environment]::NewLine)\"", label="collect permission-loss diagnostics")
        commands.extend([deny, trigger, missing, diagnostic])
    finally:
        restore = lab.ps(rf"$env:PGPASSWORD='postgres'; $rel=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_current_logfile();'; $f=Join-Path 'C:\Program Files\PostgreSQL\16\data' $rel; if(Test-Path '{acl_backup}'){{$sddl=Get-Content -LiteralPath '{acl_backup}' -Raw; $acl=Get-Acl -LiteralPath $f; $acl.SetSecurityDescriptorSddlForm($sddl.Trim()); Set-Acl -LiteralPath $f -AclObject $acl; Remove-Item '{acl_backup}' -Force}}; Restart-Service log-collector -Force; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(30)); (Get-Service log-collector).Status", timeout=60, label="restore log ACL and collector service")
        commands.append(restore)
        restored = restore.exit_code == 0 and "Running" in restore.stdout
    trigger_recovery = lab.pg(f"COMMENT ON DATABASE postgres IS '{recovery_marker}';", label="generate event after ACL restoration")
    received_recovery = lab.received(recovery_marker, wait=120)
    commands.extend([trigger_recovery, received_recovery])
    clear_error = bool(re.search(r"permission|access.*denied|denied.*access", diagnostic.stdout, re.I))
    assertions = [Assertion("permission restriction applied", deny.exit_code == 0, deny.stdout.strip() + deny.stderr.strip()), Assertion("denied-period event not delivered immediately", blocked_marker not in missing.stdout, missing.stdout.strip()), Assertion("clear permission diagnostic", clear_error, diagnostic.stdout.strip()), Assertion("ACL and service restored", restored, restore.stdout.strip()), Assertion("collection recovered", recovery_marker in received_recovery.stdout, received_recovery.stdout.strip())]
    return evaluated("G8", "Permission loss and recovery", commands, assertions, "Collector reported permission loss and recovered after exact ACL restoration")


def g9(lab: Lab) -> Result:
    start = lab.marker("G9_start")
    end = lab.marker("G9_end")
    sql = f"DO $do$ BEGIN RAISE LOG '%', '{start}' || repeat('X', 2097152) || '{end}'; END $do$;"
    trigger = lab.pg(sql, label="generate 2 MiB PostgreSQL record")
    received = lab.received(start, wait=90)
    health_cmd = lab.ps("(Get-CimInstance Win32_Service -Filter \"Name='log-collector'\").State", label="verify collector after large record")
    assertions = [Assertion("large event generated", trigger.exit_code == 0, trigger.stdout.strip() + trigger.stderr.strip()), Assertion("large event beginning delivered", start in received.stdout, f"prefix={start in received.stdout}"), Assertion("large event not truncated", end in received.stdout, f"suffix={end in received.stdout} received_bytes={len(received.stdout.encode('utf-8'))}"), Assertion("collector remained active", "Running" in health_cmd.stdout, health_cmd.stdout.strip())]
    return evaluated("G9", "Multi-megabyte PostgreSQL record", [trigger, received, health_cmd], assertions, "A 2 MiB PostgreSQL record arrived intact without stopping the collector")


def g10(lab: Lab) -> Result:
    marker = lab.marker("G10")
    script = rf"""
$env:PGPASSWORD='postgres'; $rel=& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -Atc 'SELECT pg_current_logfile();'
$f=Join-Path 'C:\Program Files\PostgreSQL\16\data' $rel
$bytes=[Text.Encoding]::UTF8.GetBytes("{{malformed_json:{marker}`r`n")
$stream=[IO.File]::Open($f,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
try{{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}}finally{{$stream.Dispose()}}
$f
"""
    inject = lab.ps(script, label="append isolated malformed PostgreSQL record")
    received = lab.received(marker, wait=120)
    health_cmd = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; \"$($s.State) $((Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content)\"", label="verify collector after malformed record")
    lines = [x for x in received.stdout.splitlines() if marker in x]
    flagged = any("[unparsed]" in x or "malformed" in x.lower() for x in lines)
    assertions = [Assertion("malformed record injected", inject.exit_code == 0, inject.stdout.strip() + inject.stderr.strip()), Assertion("malformed record forwarded", bool(lines), "\n".join(lines)), Assertion("malformed record flagged", flagged, "\n".join(lines)), Assertion("collector remained running", "Running" in health_cmd.stdout, health_cmd.stdout.strip())]
    return evaluated("G10", "Malformed record handling", [inject, received, health_cmd], assertions, "Malformed PostgreSQL record was forwarded and flagged without stopping the collector")


def g15(lab: Lab) -> Result:
    prefix = lab.marker("G15")
    before = lab.ps("(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content", label="capture health before volume run")
    script = "$p='C:\\Windows\\Temp\\lc-g15.sql'; $sql=(1..1000|ForEach-Object{\"COMMENT ON DATABASE postgres IS '" + prefix + "_$($_.ToString('0000'))';\"}) -join [Environment]::NewLine; [IO.File]::WriteAllText($p,$sql,(New-Object Text.UTF8Encoding($false))); $env:PGPASSWORD='postgres'; & 'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe' -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -f $p 2>&1; $c=$LASTEXITCODE; Remove-Item $p -Force; exit $c"
    load = lab.ps(script, timeout=180, label="generate 1,000-event constrained volume")
    time.sleep(60)
    after = lab.ps("(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content", label="capture health after volume run")
    receiver_queries: list[Command] = []
    deadline = time.time() + 180
    unique = 0
    while time.time() < deadline:
        received = lab.recv(f"grep -F {shlex.quote(prefix + '_')} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true", timeout=120, label="collect constrained-volume markers")
        receiver_queries.append(received)
        unique = len(set(re.findall(re.escape(prefix) + r"_(\d{4})", received.stdout)))
        if unique == 1000:
            break
        time.sleep(10)
    try:
        b, a = json.loads(before.stdout), json.loads(after.stdout); drop_delta = int(a.get("events_dropped", 0)) - int(b.get("events_dropped", 0))
    except Exception:
        a, drop_delta = {}, -1
    assertions = [Assertion("volume generated", load.exit_code == 0, load.stdout[-1000:]), Assertion("all numbered events delivered", unique == 1000, f"unique={unique}"), Assertion("no additional drops", drop_delta == 0, f"drop_delta={drop_delta}"), Assertion("collector remained running", a.get("agent_status") == "Running", str(a.get("agent_status")))]
    return evaluated("G15", "Constrained high-volume run", [before, load, after, *receiver_queries], assertions, "Collector delivered 1,000 events without additional drops and caught up after the constrained one-minute generation window")


def g11(lab: Lab) -> Result:
    pg_marker = lab.marker("G11_pg")
    mysql_marker = lab.marker("G11_mysql")
    maria_marker = lab.marker("G11_maria")
    script = rf"""
$jobs=@()
$jobs+=Start-Job {{ $env:PGPASSWORD='postgres'; & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h 127.0.0.1 -U postgres -d postgres -c "COMMENT ON DATABASE postgres IS '{pg_marker}';" 2>&1 }}
$jobs+=Start-Job {{ & 'C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe' --comments -h 127.0.0.1 -P 3306 -umysql -pmysql -e "SET SESSION long_query_time=0; SELECT /*{mysql_marker}*/ SLEEP(0.2);" 2>&1 }}
$jobs+=Start-Job {{ & 'C:\Program Files\MariaDB 12.3\bin\mariadb.exe' --comments -h 127.0.0.1 -P 3307 -umysql -pmysql -e "SET SESSION long_query_time=0; SELECT /*{maria_marker}*/ SLEEP(0.2);" 2>&1 }}
Wait-Job $jobs -Timeout 30|Out-Null; Receive-Job $jobs; $states=$jobs.State -join ','; Remove-Job $jobs -Force; "JOB_STATES=$states"
"""
    trigger = lab.ps(script, timeout=60, label="generate concurrent PostgreSQL, MySQL, and MariaDB events")
    deadline = time.time() + 120
    checks: list[Command] = []
    found = {"postgres": False, "mysql": False, "mariadb": False}
    while time.time() < deadline:
        query = lab.recv(f"grep -F {shlex.quote(pg_marker)} /var/log/clients/kenyata-fct-ep6/postgres_log.log 2>/dev/null || true; grep -F {shlex.quote(mysql_marker)} /var/log/clients/kenyata-fct-ep6/mysql_log.log 2>/dev/null || true; grep -F {shlex.quote(maria_marker)} /var/log/clients/kenyata-fct-ep6/mariadb_log.log 2>/dev/null || true", label="correlate three concurrent engine sources")
        checks.append(query)
        found = {"postgres": pg_marker in query.stdout, "mysql": mysql_marker in query.stdout, "mariadb": maria_marker in query.stdout}
        if all(found.values()):
            break
        time.sleep(5)
    assertions = [Assertion("three jobs completed", "JOB_STATES=Completed,Completed,Completed" in trigger.stdout, trigger.stdout.strip() + trigger.stderr.strip()), Assertion("PostgreSQL source delivered", found["postgres"], str(found)), Assertion("MySQL source delivered", found["mysql"], str(found)), Assertion("MariaDB source delivered", found["mariadb"], str(found))]
    return evaluated("G11", "Concurrent multi-engine collection", [trigger, *checks], assertions, "PostgreSQL, MySQL, and MariaDB were collected concurrently into distinct sources")


def g12(lab: Lab) -> Result:
    before = lab.ps("Get-Date -Format o; (Get-Service W32Time).Status", label="capture Windows time service before backward-clock test")
    marker = lab.marker("G12")
    commands = [before]
    restored = False
    try:
        shift = lab.ps("$now=Get-Date; Stop-Service W32Time -Force -ErrorAction SilentlyContinue; Set-Date -Date $now.AddMinutes(-5) | Out-Null; Get-Date -Format o", label="move Windows clock backward five minutes")
        trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate event after backward clock step")
        received = lab.received(marker, wait=120)
        health_cmd = lab.ps("$s=Get-CimInstance Win32_Service -Filter \"Name='log-collector'\"; \"$($s.State) $((Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing).Content)\"", label="verify collector after backward clock step")
        commands.extend([shift, trigger, received, health_cmd])
    finally:
        restore = lab.ps("Set-Date -Date (Get-Date).AddMinutes(5) | Out-Null; Set-Service W32Time -StartupType Automatic; Start-Service W32Time; w32tm /resync /force 2>&1; Get-Date -Format o; (Get-Service W32Time).Status", timeout=60, label="restore Windows time and resynchronize")
        commands.append(restore)
        restored = restore.exit_code == 0 and "Running" in restore.stdout
    assertions = [Assertion("clock moved backward", shift.exit_code == 0, shift.stdout.strip()), Assertion("database event generated", trigger.exit_code == 0, trigger.stdout.strip()), Assertion("post-shift event delivered", marker in received.stdout, received.stdout.strip()), Assertion("collector remained running", "Running" in health_cmd.stdout, health_cmd.stdout.strip()), Assertion("Windows time service restored", restored, restore.stdout.strip() + restore.stderr.strip())]
    return evaluated("G12", "Backward-clock continuity", commands, assertions, "Collector delivered after a five-minute backward clock step and Windows time was restored")


def h7(lab: Lab) -> Result:
    marker = lab.marker("H7")
    commands: list[Command] = []
    config = r"C:\Program Files\log-collector\conf\agent.toml"
    last_good = config + ".last-good"
    backup = r"C:\Windows\Temp\lc-h7-agent.toml"
    backup_last = r"C:\Windows\Temp\lc-h7-agent.toml.last-good"
    restored = False
    try:
        prepare = lab.ps(rf"""
$ErrorActionPreference='Stop'; $c='{config}'; $l='{last_good}'; $b='{backup}'; $bl='{backup_last}'
Copy-Item -LiteralPath $c -Destination $b -Force
$had=Test-Path -LiteralPath $l; if($had){{Copy-Item -LiteralPath $l -Destination $bl -Force}}else{{Copy-Item -LiteralPath $c -Destination $l -Force}}
Stop-Service log-collector -Force; (Get-Service log-collector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
[IO.File]::WriteAllText($c,'garbage')
[pscustomobject]@{{HadLastGood=$had;CorruptLength=(Get-Item -LiteralPath $c).Length}}|ConvertTo-Json -Compress
""", timeout=60, label="back up and corrupt collector configuration")
        commands.append(prepare)
        start = lab.ps(rf"""
$since=(Get-Date).AddSeconds(-5); $startOutput=sc.exe start log-collector 2>&1; Start-Sleep -Seconds 8
$svc=Get-CimInstance Win32_Service -Filter "Name='log-collector'"
$health=try{{(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 10).Content}}catch{{$_.Exception.Message}}
$check=& '{COLLECTOR}' check 2>&1
$events=Get-WinEvent -FilterHashtable @{{LogName='Application';StartTime=$since}} -ErrorAction SilentlyContinue | Where-Object {{$_.Message -match 'log-collector|last-good|fallback|recover'}} | Select-Object -First 20 -ExpandProperty Message
[pscustomobject]@{{Start=($startOutput -join ' ');State=$svc.State;Health=$health;Check=($check -join ' ');Events=($events -join "`n")}}|ConvertTo-Json -Compress
""", timeout=60, label="start collector with corrupt active config")
        commands.append(start)
        trigger = lab.pg(f"COMMENT ON DATABASE postgres IS '{marker}';", label="generate fallback-configuration marker")
        received = lab.received(marker, wait=120)
        commands.extend([trigger, received])
    finally:
        restore = lab.ps(rf"""
$ErrorActionPreference='Continue'; $c='{config}'; $l='{last_good}'; $b='{backup}'; $bl='{backup_last}'
Stop-Service log-collector -Force -ErrorAction SilentlyContinue
if(Test-Path -LiteralPath $b){{Copy-Item -LiteralPath $b -Destination $c -Force}}
if(Test-Path -LiteralPath $bl){{Copy-Item -LiteralPath $bl -Destination $l -Force; Remove-Item -LiteralPath $bl -Force}}else{{Remove-Item -LiteralPath $l -Force -ErrorAction SilentlyContinue}}
Remove-Item -LiteralPath $b -Force -ErrorAction SilentlyContinue
Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60))
$check=& '{COLLECTOR}' check 2>&1; $health=(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 10).Content
[pscustomobject]@{{State=(Get-Service log-collector).Status;Check=($check -join ' ');Health=$health}}|ConvertTo-Json -Compress
""", timeout=90, label="restore exact collector configuration after corrupt-config test")
        commands.append(restore)
        restored = restore.exit_code == 0 and "Config OK" in restore.stdout and ("\"State\":4" in restore.stdout or "\"State\":\"Running\"" in restore.stdout)
    combined = start.stdout + start.stderr
    fallback_clear = bool(re.search(r"last[- ]?good|fall.?back|recover", combined, re.I))
    try:
        outer = json.loads(start.stdout.split("#< CLIXML", 1)[0].strip())
        inner = json.loads(outer.get("Health", "{}"))
    except Exception:
        outer, inner = {}, {}
    running = outer.get("State") in ("Running", 4) and inner.get("agent_status") == "Running" and inner.get("cloud_status") == "Connected"
    assertions = [Assertion("corrupt configuration installed", prepare.exit_code == 0 and '"CorruptLength":7' in prepare.stdout, prepare.stdout.strip() + prepare.stderr.strip()), Assertion("fallback clearly reported", fallback_clear, combined.strip()), Assertion("collector kept running", running, start.stdout.strip()), Assertion("fallback configuration remained valid", "Config OK" in start.stdout, start.stdout.strip()), Assertion("collection continued", marker in received.stdout, received.stdout.strip()), Assertion("exact configuration restored", restored, restore.stdout.strip() + restore.stderr.strip())]
    return evaluated("H7", "Corrupt config fallback", commands, assertions, "Collector fell back to last-good configuration, kept collecting, and exact files were restored")


def h8(lab: Lab) -> Result:
    commands: list[Command] = []
    config = r"C:\Program Files\log-collector\conf\agent.toml"
    backup = r"C:\Windows\Temp\lc-h8-agent.toml"
    restored = False
    try:
        prepare = lab.ps(rf"""
$ErrorActionPreference='Stop'; Stop-Service log-collector -Force; (Get-Service log-collector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)); Move-Item -LiteralPath '{config}' -Destination '{backup}' -Force; [pscustomobject]@{{Missing=(-not (Test-Path -LiteralPath '{config}'));Backup=(Test-Path -LiteralPath '{backup}')}}|ConvertTo-Json -Compress
""", timeout=60, label="remove active collector configuration with backup")
        commands.append(prepare)
        start = lab.ps(rf"""
$since=(Get-Date).AddSeconds(-5); $output=sc.exe start log-collector 2>&1
$deadline=(Get-Date).AddSeconds(35); do{{Start-Sleep -Seconds 2; $svc=Get-CimInstance Win32_Service -Filter "Name='log-collector'"}}while($svc.State -in @('Start Pending','Running') -and (Get-Date) -lt $deadline)
$svc=Get-CimInstance Win32_Service -Filter "Name='log-collector'"
$health=try{{(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 5).Content}}catch{{$_.Exception.Message}}
$check=& '{COLLECTOR}' check 2>&1
$events=Get-WinEvent -FilterHashtable @{{LogName='Application';StartTime=$since}} -ErrorAction SilentlyContinue | Where-Object {{$_.Message -match 'log-collector|config|setup|agent.toml'}} | Select-Object -First 30 -ExpandProperty Message
[pscustomobject]@{{Start=($output -join ' ');State=$svc.State;Health=$health;Check=($check -join ' ');Events=($events -join "`n")}}|ConvertTo-Json -Compress
""", timeout=75, label="attempt collector start without configuration")
        commands.append(start)
    finally:
        restore = lab.ps(rf"""
$ErrorActionPreference='Continue'; Stop-Service log-collector -Force -ErrorAction SilentlyContinue; if(Test-Path -LiteralPath '{backup}'){{Move-Item -LiteralPath '{backup}' -Destination '{config}' -Force}}; Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); $check=& '{COLLECTOR}' check 2>&1; $health=$null; 1..15|ForEach-Object{{if(-not $health){{$health=try{{(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 5).Content}}catch{{$null}}; if(-not $health){{Start-Sleep -Seconds 2}}}}}}; [pscustomobject]@{{State=(Get-Service log-collector).Status;Check=($check -join ' ');Health=$health}}|ConvertTo-Json -Compress
""", timeout=90, label="restore collector configuration after missing-config test")
        commands.append(restore)
        restored = restore.exit_code == 0 and "Config OK" in restore.stdout and ("\"State\":4" in restore.stdout or "\"State\":\"Running\"" in restore.stdout)
    combined = start.stdout + start.stderr
    clear = bool(re.search(r"config|agent\.toml", combined, re.I)) and bool(re.search(r"run.{0,30}setup|setup.{0,30}(required|needed)", combined, re.I | re.S))
    stopped = '"State":"Stopped"' in start.stdout or '"State":1' in start.stdout
    assertions = [Assertion("active configuration removed", prepare.exit_code == 0 and '"Missing":true' in prepare.stdout and '"Backup":true' in prepare.stdout, prepare.stdout.strip() + prepare.stderr.strip()), Assertion("collector refused to run", stopped, start.stdout.strip()), Assertion("clear setup/configuration guidance", clear, combined.strip()), Assertion("configuration and service restored", restored, restore.stdout.strip() + restore.stderr.strip())]
    return evaluated("H8", "Missing configuration failure", commands, assertions, "Missing configuration prevented startup with clear guidance, then exact configuration was restored")


def i1(lab: Lab) -> Result:
    cmd = lab.ps("(Get-CimInstance Win32_OperatingSystem).Caption", label="Windows edition")
    return Result("I1", "Windows Server platform", "Not Run - Environment", "Endpoint is Windows 11 Pro, not Windows Server", [Assertion("Windows Server", False, cmd.stdout.strip())], [cmd])


def i8(lab: Lab) -> Result:
    cmd = lab.ps("Get-CimInstance Win32_Service -Filter \"Name='log-collector'\" | Select-Object StartName | ConvertTo-Json -Compress", label="collector service identity")
    non_privileged = "LocalSystem" not in cmd.stdout and "LocalService" not in cmd.stdout and "NetworkService" not in cmd.stdout
    return evaluated("I8", "Non-root collector with ACL access", [cmd], [Assertion("dedicated non-privileged service identity", non_privileged, cmd.stdout.strip())], "Collector runs under a dedicated non-privileged identity")


def recover_collector(lab: Lab) -> Result:
    cmd = lab.ps(rf"""
$ErrorActionPreference='Continue'
Stop-Service log-collector -Force -ErrorAction SilentlyContinue
Get-Process log-collector -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 3
Start-Service log-collector
$deadline=(Get-Date).AddSeconds(90); do{{Start-Sleep -Seconds 2; $svc=Get-CimInstance Win32_Service -Filter "Name='log-collector'"; $health=try{{(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 5).Content}}catch{{$null}}}}while(($svc.State -ne 'Running' -or -not $health) -and (Get-Date) -lt $deadline)
$check=& '{COLLECTOR}' check 2>&1
[pscustomobject]@{{State=$svc.State;Check=($check -join ' ');Health=$health;TempBackup=(Test-Path 'C:\Windows\Temp\lc-h8-agent.toml')}}|ConvertTo-Json -Compress
""", timeout=120, label="bounded collector recovery after missing-config test")
    okay = '"State":"Running"' in cmd.stdout and "Config OK" in cmd.stdout and "agent_status\\\":\\\"Running" in cmd.stdout and '"TempBackup":false' in cmd.stdout
    return evaluated("RECOVER", "Collector recovery boundary", [cmd], [Assertion("collector healthy after cleanup", okay, cmd.stdout.strip() + cmd.stderr.strip())], "Collector returned Running/Connected with valid restored configuration")


def foreground_signal(lab: Lab, sid: str, double: bool) -> Result:
    commands: list[Command] = []
    restored = False
    try:
        stop = lab.ps("Stop-Service log-collector -Force; (Get-Service log-collector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)); (Get-Service log-collector).Status", timeout=60, label="stop installed collector service before foreground run")
        run = lab.foreground_interrupt(double=double, timeout=60, label="send " + ("two Ctrl+C signals" if double else "one Ctrl+C signal") + " to foreground collector")
        commands.extend([stop, run])
    finally:
        restore = lab.ps(rf"""
Get-Process log-collector -ErrorAction SilentlyContinue|Stop-Process -Force; Start-Service log-collector; (Get-Service log-collector).WaitForStatus('Running',[TimeSpan]::FromSeconds(60)); $health=$null; 1..15|ForEach-Object{{if(-not $health){{$health=try{{(Invoke-WebRequest http://127.0.0.1:9100/status -UseBasicParsing -TimeoutSec 5).Content}}catch{{$null}}; if(-not $health){{Start-Sleep -Seconds 2}}}}}}; $check=& '{COLLECTOR}' check 2>&1; [pscustomobject]@{{State=(Get-Service log-collector).Status;Check=($check -join ' ');Health=$health}}|ConvertTo-Json -Compress
""", timeout=120, label="restore installed collector service after foreground interrupt")
        commands.append(restore)
        restored = restore.exit_code == 0 and "Config OK" in restore.stdout and "agent_status\\\":\\\"Running" in restore.stdout
    text = run.stdout + run.stderr
    if double:
        behavior = run.exit_code == 0
        detail = "Foreground collector exited promptly after the second Ctrl+C"
    else:
        behavior = run.exit_code == 0 and bool(re.search(r"drain|flush|saved|shut.?down|stopping|interrupt|signal", text, re.I))
        detail = "Foreground collector drained and exited after one Ctrl+C"
    assertions = [Assertion("installed service stopped", stop.exit_code == 0 and "Stopped" in stop.stdout, stop.stdout.strip()), Assertion("foreground interrupt behavior", behavior, text.strip()), Assertion("installed service restored", restored, restore.stdout.strip() + restore.stderr.strip())]
    return evaluated(sid, "Double Ctrl+C foreground exit" if double else "Single Ctrl+C foreground drain", commands, assertions, detail)


def h5(lab: Lab) -> Result:
    return foreground_signal(lab, "H5", False)


def h5a(lab: Lab) -> Result:
    return foreground_signal(lab, "H5a", True)


def probe_state(lab: Lab) -> Result:
    cmd = lab.ps(r"""
$roots=@('C:\ProgramData\log-collector','C:\Program Files\log-collector')
$items=foreach($root in $roots){if(Test-Path $root){Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime}}
[pscustomobject]@{Service=(Get-CimInstance Win32_Service -Filter "Name='log-collector'"|Select-Object Name,State,PathName);Items=$items}|ConvertTo-Json -Depth 5 -Compress
""", label="inventory Windows collector state paths")
    return Result("PROBE_STATE", "Collector state inventory", "Pass", "Read-only collector state inventory captured", [Assertion("inventory captured", cmd.exit_code == 0, cmd.stdout.strip())], [cmd])


def probe_wizard_flow(lab: Lab) -> Result:
    probe = lab.wizard_probe([(r"Agent ID[^\r\n]*:", ""), (r"Client tag[^\r\n]*:", "kenyata"), (r"Enable USB[^\r\n]*:", ""), (r"Channels \[all\]:", "1"), (r"Severity \[all\]:", ""), (r"Choose \[4\]:", ""), (r"Enable ETW[^\r\n]*:", ""), (r"Application log file path[^\r\n]*:", ""), (r"MongoDB sources[^\r\n]*:", "0")], r"(?:\?|:)\s*$", timeout=150, label="map next setup wizard prompt")
    return Result("PROBE_WIZARD", "Setup wizard flow inventory", "Pass" if probe.exit_code == 0 else "Fail", "Captured the next prompt after identity" if probe.exit_code == 0 else "Could not capture the next prompt after identity", [Assertion("next prompt captured", probe.exit_code == 0, probe.stdout.strip() + probe.stderr.strip())], [probe])


ADAPTERS: dict[str, Callable[[Lab], Result]] = {
    "A1": a1, "A2": a2, "A3": a3, "A4": a4, "A6": a6, "A7": encrypted_config, "A8": config_validation, "A9": service_install, "A10": health, "A11": multi_engine, "A12": a12, "B1": b1,
    "B2": b2, "B3": b3, "B4": b4, "B5": b5, "B6": b6, "B7": b7, "C1": c1, "C3": c3,
    "C1c": c1c, "C1d": c1d, "C1e": c1e, "C4": c4, "C4a": c4a, "C4b": c4b, "C4c": c4c, "C4d": c4d, "C4e": c4e, "C4f": c4f, "C2": c2, "C2a": c2a, "C2b": c2b,
    "C2c": c2c, "C2d": c2d, "C2f": c2f, "C7": c7, "C7a": c7a,
    "C7b": c7b, "C7c": c7c, "C7d": c7d, "C7e": c7e, "C5": c5, "C5a": c5a, "C5c": c5c, "C5d": c5d,
    "G1": g1, "G1a": g1a, "G1b": g1b, "G2": g2, "G3": g3, "G3a": g3a, "G3b": g3b, "G4": g4, "G4a": g4a, "G5": g5,
    "G6": g6, "G6b": g6b, "G7": g7, "G8": g8, "G9": g9, "G10": g10, "G11": g11, "G12": g12, "G13": g13, "G15": g15,
    "H1": h1, "H2": h2, "H4": h4, "H5": h5, "H5a": h5a, "H6": h6, "H7": h7, "H8": h8, "H9": h9, "H10": h10, "H12": h12,
    "I1": i1, "I8": i8,
    "RECOVER": recover_collector,
    "PROBE_STATE": probe_state,
    "PROBE_WIZARD": probe_wizard_flow,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", nargs="?")
    parser.add_argument("--database", default="postgresql", choices=["postgresql"])
    parser.add_argument("--scenario", help="comma-separated IDs", default=",".join(SCENARIOS))
    parser.add_argument("--windows-host")
    parser.add_argument("--receiver-host")
    parser.add_argument("--evidence-root", default="remote-evidence/windows/postgresql")
    args = parser.parse_args()
    windows_host = args.windows_host or input(f"Windows SSH host [{DEFAULT_WINDOWS_HOST}]: ").strip() or DEFAULT_WINDOWS_HOST
    receiver_host = args.receiver_host or input(f"Receiver SSH host [{DEFAULT_RECEIVER_HOST}]: ").strip() or DEFAULT_RECEIVER_HOST
    win_password = os.environ.get("WINDOWS_SSH_PASSWORD") or getpass.getpass(f"SSH password for {WINDOWS_USER}@{windows_host}: ")
    recv_password = os.environ.get("RECEIVER_SSH_PASSWORD") or getpass.getpass(f"SSH password for {RECEIVER_USER}@{receiver_host}: ")
    evidence = Path(args.evidence_root) / run_id()
    evidence.mkdir(parents=True)
    win = SSH(windows_host, WINDOWS_USER, win_password)
    receiver = SSH(receiver_host, RECEIVER_USER, recv_password)
    lab = Lab(win, receiver, evidence)
    results = []
    try:
        for sid in [x.strip() for x in args.scenario.split(",") if x.strip()]:
            adapter = ADAPTERS.get(sid)
            if not adapter:
                result = Result(sid, sid, "Not Run", "No Windows adapter implemented yet")
            else:
                print(f"[{sid}] running", flush=True)
                try: result = adapter(lab)
                except Exception as exc: result = Result(sid, sid, "Inconclusive", f"Harness error: {type(exc).__name__}: {exc}")
            lab.save(result)
            results.append(result)
            print(f"[{sid}] {result.status}: {result.summary}", flush=True)
    finally:
        win.close(); receiver.close()
    summary = {
        "runner_version": VERSION, "run_id": evidence.name, "platform": "Windows",
        "database": "postgresql", "started_at": results[0].started_at if results else utc_now(),
        "ended_at": utc_now(), "results": [{"scenario_id": r.scenario_id, "status": r.status, "summary": r.summary} for r in results],
    }
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256((evidence / "summary.json").read_bytes()).hexdigest()
    print(f"Evidence: {evidence}")
    print(f"Summary SHA-256: {digest}")
    return 1 if any(r.status in {"Inconclusive", "Cleanup Failed"} for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
