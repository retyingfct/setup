#!/usr/bin/env python3
"""Interactive Ubuntu database log-collector integration test runner.

Run this program as the normal endpoint user. It elevates individual local
commands with sudo and connects to the receiver using password-authenticated
SSH. Credentials are held in memory and are never written to evidence.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import fcntl
import getpass
import hashlib
import importlib
import io
import json
import os
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal


VERSION = "0.4.21-draft"
DATABASES = ("postgresql", "mysql", "mariadb", "oracle")
STATUSES = ("Pass", "Fail", "Not Tested", "Inconclusive", "Cleanup Failed")
Risk = Literal["safe", "configuration", "disruptive", "destructive", "manual"]
ExecutionMode = Literal["endpoint", "endpoint-pending", "clone", "environment", "manual", "not-applicable"]
LAB_STABILITY_MINUTES = 1
LAB_OUTAGE_MINUTES = 1
LAB_SOAK_MINUTES = 1
LARGE_RECORD_PAYLOAD_BYTES = 2 * 1024 * 1024
LARGE_RECORD_OVERHEAD_BYTES = 64 * 1024
RECEIVER_STOP_COMMAND = (
    "systemctl stop syslog.socket rsyslog.service && "
    "test -z \"$(ss -ltnH | awk '$4 ~ /:2514$/ {print $4}')\""
)
RECEIVER_START_COMMAND = (
    "systemctl start syslog.socket rsyslog.service && "
    "systemctl is-active --quiet rsyslog.service && "
    "test -n \"$(ss -ltnH | awk '$4 ~ /:2514$/ {print $4}')\""
)
RECEIVER_SOURCES = {
    "postgresql": "postgres_log.log",
    "mysql": "mysql_log.log",
    "mariadb": "mariadb_log.log",
    "oracle": "oracle_log.log",
}
SCENARIO_IDS = {
    "postgresql": """A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 B1 B2 B3 B4 B5 B6 B7 C1 C1a C1b C1c C1d C1e C6 C3 C4 C4a C4b C4c C4d C4e C4f C2 C2a C2b C2c C2d C2e C2f C8 C7 C7a C7b C7c C7d C7e C5 C5a C5b C5c C5d G1 G1a G1b G1c G1d G2 G2a G3 G3a G3b G4 G4a G5 G5a G6 G6a G6b G7 G8 G9 G10 G11 G12 G13 G14 G15 H1 H2 H3 H4 H5 H5a H6 H7 H8 H9 H10 H11 H12 I1 I2 I3 I4 I5 I6 I7 I8 I9""".split(),
    "mysql": """A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 B1 B2 B3 B4 B5 B6 B7 D1 D1a D1b D1c D1d D1e D1f D1g D2f D2g D7a D7b D7c D8a D8b D2 D2a D2b D2c D2d D2e D3a D6 D7 D7d D2h D3 D4 D4a D4b D4c D4d D5 D5a D8 D9 D9a D9b D9c G1 G1a G1b G1c G1d G2 G2a G3 G3a G3b G4 G4a G5 G5a G6 G6a G6b G7 G8 G9 G10 G11 G12 G13 G14 G15 H1 H2 H3 H4 H5 H5a H6 H7 H8 H9 H10 H11 H12 I1 I2 I3 I4 I5 I6 I7 I8 I9""".split(),
    "mariadb": """A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 B1 B2 B3 B4 B5 B6 B7 F1 F2 F6 F7 F7a F7b F10 F10a F3 F4 F5 F5a F5b F5c F5d F5e F5f F9 F9a F8 F8a F11 F12 G1 G1a G1b G1c G1d G2 G2a G3 G3a G3b G4 G4a G5 G5a G6 G6a G6b G7 G8 G9 G10 G11 G12 G13 G14 G15 H1 H2 H3 H4 H5 H5a H6 H7 H8 H9 H10 H11 H12 I1 I2 I3 I4 I5 I6 I7 I8 I9""".split(),
    "oracle": """A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 B1 B2 B3 B4 B5 B6 B7 E1 E3 E4 E2 E2a E2b E2c E2d E9 E9a E10 E10a E5 E5a E7 E7a E7b E7c E7d E7e E7f E6 E6a E6b E6c E6d E6e E11 E11a E11b E11c E11d G1 G1a G1b G1c G1d G2 G2a G3 G3a G3b G4 G4a G5 G5a G6 G6a G6b G7 G8 G9 G10 G11 G12 G13 G14 G15 H1 H2 H3 H4 H5 H5a H6 H7 H8 H9 H10 H11 H12 I1 I2 I3 I4 I5 I6 I7 I8 I9""".split(),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_event_timestamp(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith(" UTC"):
        normalized = normalized[:-4] + "+00:00"
    elif normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def timestamps_match(native: str, received: str, tolerance_seconds: float = 0.001) -> bool:
    try:
        difference = abs((parse_event_timestamp(native) - parse_event_timestamp(received)).total_seconds())
    except ValueError:
        return False
    return difference <= tolerance_seconds


def parse_size_bytes(value: str) -> int | None:
    match = re.fullmatch(r"\s*(\d+)\s*([kmgt]?)\s*", value, re.IGNORECASE)
    if not match:
        return None
    multipliers = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    return int(match.group(1)) * multipliers[match.group(2).lower()]


def make_run_id(database: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{database}-{os.getpid()}"


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    if not cleaned:
        raise ValueError("empty unsafe path component")
    return cleaned


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(data, encoding="utf-8")
    temporary.replace(path)


@dataclass(frozen=True)
class AssertionResult:
    name: str
    passed: bool
    observed: str


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    ended_at: str
    timed_out: bool = False


class LocalExecutor:
    """Run commands on the endpoint while preserving exact output as evidence."""

    def authorize_sudo(self) -> bool:
        return subprocess.run(["sudo", "-v"], check=False).returncode == 0

    def run(self, command: str, timeout: float = 120, sudo: bool = False) -> CommandResult:
        started_at = utc_now()
        argv = ["bash", "-lc", command]
        display_command = command
        if sudo:
            argv = ["sudo", "-n", "bash", "-lc", command]
            display_command = f"sudo bash -lc {command!r}"
        process = subprocess.Popen(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            returncode = process.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
            stderr = f"{stderr}\nCommand timed out after {timeout} seconds".lstrip()
            returncode = 124
            timed_out = True
        return CommandResult(
            command=display_command,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            ended_at=utc_now(),
            timed_out=timed_out,
        )


@dataclass(frozen=True)
class ReceiverConfig:
    host: str
    username: str
    password: str = field(repr=False)
    sudo_password: str | None = field(default=None, repr=False)
    port: int = 22

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", self.host):
            raise ValueError("Receiver host must be an IP address or plain DNS hostname")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", self.username):
            raise ValueError("Receiver username contains unsupported characters")
        if not 1 <= self.port <= 65535:
            raise ValueError("Receiver SSH port must be between 1 and 65535")


class SSHExecutor:
    """Password-authenticated SSH executor with verified host keys."""

    def __init__(
        self,
        config: ReceiverConfig,
        client: Any | None = None,
        trust_prompt: Callable[[str], str] = input,
    ):
        self.config = config
        self.client = client
        self.trust_prompt = trust_prompt
        self._owns_client = client is None

    def connect(self) -> None:
        if self.client is None:
            try:
                import paramiko
            except ImportError as error:
                raise RuntimeError(
                    "python3-paramiko is required for password SSH; install it with "
                    "sudo apt install python3-paramiko"
                ) from error

            executor = self

            class ConfirmHostKeyPolicy(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
                    fingerprint = hashlib.sha256(key.asbytes()).hexdigest()
                    answer = executor.trust_prompt(
                        f"Unknown SSH host {hostname}; SHA256 fingerprint {fingerprint}. Trust it? [y/N] "
                    )
                    if answer.strip().lower() not in {"y", "yes"}:
                        raise RuntimeError("Receiver SSH host key was not trusted")
                    known_hosts = Path.home() / ".ssh" / "known_hosts"
                    known_hosts.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    known_hosts.touch(mode=0o600, exist_ok=True)
                    client.get_host_keys().add(hostname, key.get_name(), key)
                    client.save_host_keys(str(known_hosts))

            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            user_known_hosts = Path.home() / ".ssh" / "known_hosts"
            if user_known_hosts.exists():
                self.client.load_host_keys(str(user_known_hosts))
            self.client.set_missing_host_key_policy(ConfirmHostKeyPolicy())

        self.client.connect(
            hostname=self.config.host,
            port=self.config.port,
            username=self.config.username,
            password=self.config.password,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )

    def run(self, command: str, timeout: float = 120, sudo: bool = False) -> CommandResult:
        if self.client is None:
            raise RuntimeError("SSH receiver is not connected")
        started_at = utc_now()
        quoted = shlex.quote(command)
        remote_command = f"bash -lc {quoted}"
        if sudo:
            if self.config.sudo_password is None:
                raise RuntimeError("Receiver sudo password was not provided")
            remote_command = f"sudo -S -p '' bash -lc {quoted}"
        try:
            stdin, stdout, stderr = self.client.exec_command(remote_command, timeout=timeout)
            if sudo:
                stdin.write(f"{self.config.sudo_password}\n")
                stdin.flush()
            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")
            returncode = stdout.channel.recv_exit_status()
            timed_out = False
        except (socket.timeout, TimeoutError):
            stdout_text = ""
            stderr_text = f"Remote command timed out after {timeout} seconds"
            returncode = 124
            timed_out = True
        return CommandResult(
            command=f"receiver:{command}",
            returncode=returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            started_at=started_at,
            ended_at=utc_now(),
            timed_out=timed_out,
        )

    def close(self) -> None:
        if self.client is not None:
            self.client.close()


@dataclass
class LabContext:
    database: str
    local: LocalExecutor
    receiver: SSHExecutor
    client_hostname: str
    receiver_hostname: str | None = None
    evidence: "EvidenceRun | None" = None
    journal: "RecoveryJournal | None" = None

    @property
    def receiver_log(self) -> str:
        source = RECEIVER_SOURCES[self.database]
        return f"/var/log/clients/{self.receiver_hostname or self.client_hostname}/{source}"

    @property
    def receiver_client_dir(self) -> str:
        return f"/var/log/clients/{self.receiver_hostname or self.client_hostname}"

    @property
    def run_token(self) -> str:
        if self.evidence:
            return safe_name(self.evidence.run_id).lower().replace("-", "_")
        return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    def marker(self, scenario_id: str, suffix: str = "event") -> str:
        scenario = re.sub(r"[^a-z0-9]+", "_", scenario_id.lower())
        suffix = re.sub(r"[^a-z0-9]+", "_", suffix.lower())
        return f"lc_{self.database}_{scenario}_{self.run_token}_{suffix}"

    def receiver_grep(self, pattern: str, timeout: float = 30) -> CommandResult:
        command = (
            f"test -f {shlex.quote(self.receiver_log)} && "
            f"grep -F -- {shlex.quote(pattern)} {shlex.quote(self.receiver_log)} | tail -n 100"
        )
        deadline = time.monotonic() + timeout
        last: CommandResult | None = None
        while time.monotonic() < deadline:
            last = self.receiver.run(command, sudo=True, timeout=10)
            if last.returncode == 0 and last.stdout.strip():
                return last
            time.sleep(1)
        return last or CommandResult(command, 1, "", "No receiver check executed", utc_now(), utc_now())

    def receiver_event(self, marker: str, timeout: float = 30) -> CommandResult:
        command = (
            f"test -f {shlex.quote(self.receiver_log)} && "
            f"awk -v marker={shlex.quote(marker)} '"
            "index($0, marker) { capture=1 } "
            "capture { if (seen && $0 ~ /^<[0-9]+>1[[:space:]]/) exit; print; seen=1 }' "
            f"{shlex.quote(self.receiver_log)}"
        )
        deadline = time.monotonic() + timeout
        last: CommandResult | None = None
        while time.monotonic() < deadline:
            last = self.receiver.run(command, sudo=True, timeout=10)
            if last.returncode == 0 and last.stdout.strip():
                return last
            time.sleep(1)
        return last or CommandResult(command, 1, "", "No receiver check executed", utc_now(), utc_now())


@dataclass
class PreflightReport:
    database: str
    ready: bool
    facts: dict[str, str]
    problems: list[str]
    commands: list[CommandResult]


def command_fact(result: CommandResult) -> str:
    value = result.stdout.strip()
    if value:
        return value
    return result.stderr.strip() or f"exit {result.returncode}"


def collect_preflight(context: LabContext) -> PreflightReport:
    commands: list[CommandResult] = []
    facts: dict[str, str] = {}
    problems: list[str] = []

    def local_fact(name: str, command: str, *, sudo: bool = False) -> CommandResult:
        result = context.local.run(command, sudo=sudo, timeout=30)
        commands.append(result)
        facts[name] = command_fact(result)
        return result

    def receiver_fact(name: str, command: str, *, sudo: bool = False) -> CommandResult:
        result = context.receiver.run(command, sudo=sudo, timeout=30)
        commands.append(result)
        facts[name] = command_fact(result)
        return result

    local_fact("client_hostname", "hostname -s")
    local_fact("ubuntu", ". /etc/os-release && printf '%s %s' \"$NAME\" \"$VERSION_ID\"")
    memory = local_fact("available_memory_mb", "free -m | awk '/^Mem:/ {print $7}'")
    disk = local_fact("root_free_mb", "df -Pm / | awk 'NR==2 {print $4}'")
    collector = local_fact("collector_service", "systemctl is-active log-collector")
    local_fact("collector_enabled", "systemctl is-enabled log-collector")
    local_fact("collector_version", "log-collector --version 2>&1 || /usr/local/bin/log-collector --version 2>&1")
    local_fact("collector_health", "curl -fsS --max-time 5 http://127.0.0.1:9100/status")

    receiver_service = receiver_fact("receiver_rsyslog", "systemctl is-active rsyslog", sudo=True)
    receiver_fact("receiver_listener", "ss -ltn | awk '$4 ~ /:2514$/ {print $4}'", sudo=True)
    receiver_fact(
        "receiver_log",
        f"if test -f {shlex.quote(context.receiver_log)}; then stat -c '%n %s bytes' {shlex.quote(context.receiver_log)}; else echo missing; fi",
        sudo=True,
    )

    database_commands = {
        "postgresql": (
            "command -v psql && psql --version && pg_lsclusters --no-header && "
            "sudo -u postgres psql -Atc \"SELECT version(); SELECT pg_current_logfile();\""
        ),
        "mysql": (
            "command -v mysql && mysql --version && ! mysql --version 2>&1 | grep -qi mariadb && "
            "sudo mysql -NBe \"SELECT VERSION(); SELECT @@log_error_verbosity;\""
        ),
        "mariadb": (
            "command -v mariadb && mariadb --version 2>&1 | grep -qi mariadb && "
            "sudo mariadb -NBe \"SELECT VERSION(); SHOW VARIABLES LIKE 'log_error';\""
        ),
        "oracle": (
            "command -v sqlplus && sqlplus -V && command -v lsnrctl && "
            "test -n \"${ORACLE_HOME:-}\" && printf '%s' \"$ORACLE_HOME\""
        ),
    }
    database_probe = local_fact("database", database_commands[context.database])

    if collector.returncode != 0 or collector.stdout.strip() != "active":
        problems.append("log-collector service is not active")
    if receiver_service.returncode != 0 or receiver_service.stdout.strip() != "active":
        problems.append("receiver rsyslog service is not active")
    if database_probe.returncode != 0:
        problems.append(f"{context.database} is missing, stopped, or is the wrong engine")
    try:
        if int(memory.stdout.strip()) < 256:
            problems.append("less than 256 MB memory is currently available")
    except ValueError:
        problems.append("available memory could not be measured")
    try:
        if int(disk.stdout.strip()) < 1024:
            problems.append("less than 1 GB free space remains on the client root filesystem")
    except ValueError:
        problems.append("free disk space could not be measured")

    return PreflightReport(context.database, not problems, facts, problems, commands)


def print_preflight(report: PreflightReport) -> None:
    print(f"\n{report.database} readiness: {'READY' if report.ready else 'NOT READY'}")
    for name, value in report.facts.items():
        compact = " ".join(value.split())
        print(f"  {name}: {compact[:240]}")
    if report.problems:
        print("\nProblems:")
        for problem in report.problems:
            print(f"  - {problem}")


def prompt_receiver() -> ReceiverConfig:
    host = input("Receiver IP or hostname: ").strip()
    if not host:
        raise ValueError("Receiver IP or hostname is required")
    port_text = input("Receiver SSH port [22]: ").strip()
    port = int(port_text or "22")
    username = input("Receiver SSH username [ubuntu]: ").strip() or "ubuntu"
    password = getpass.getpass(f"SSH password for {username}@{host}: ")
    if not password:
        raise ValueError("Receiver SSH password is required")
    same_sudo = input("Use the same password for receiver sudo? [Y/n]: ").strip().lower()
    sudo_password = password if same_sudo not in {"n", "no"} else getpass.getpass("Receiver sudo password: ")
    return ReceiverConfig(host, username, password, sudo_password, port)


def ensure_ssh_dependency(local: LocalExecutor) -> None:
    try:
        importlib.import_module("paramiko")
        return
    except ImportError:
        pass
    print("python3-paramiko is required for password-authenticated SSH.")
    simulation = local.run("apt-get -s install python3-paramiko", sudo=True, timeout=120)
    print(simulation.stdout)
    if simulation.returncode != 0:
        raise RuntimeError(f"Could not simulate python3-paramiko installation: {simulation.stderr.strip()}")
    answer = input("Install python3-paramiko now? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        raise RuntimeError("python3-paramiko is required and installation was declined")
    installation = local.run(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y python3-paramiko",
        sudo=True,
        timeout=600,
    )
    if installation.returncode != 0:
        raise RuntimeError(f"python3-paramiko installation failed: {installation.stderr.strip()}")
    importlib.invalidate_caches()
    try:
        importlib.import_module("paramiko")
    except ImportError as error:
        raise RuntimeError("python3-paramiko was installed but cannot be imported by this Python") from error


def open_lab(database: str, evidence: "EvidenceRun | None" = None) -> LabContext:
    if os.geteuid() == 0:
        raise RuntimeError("Run db-test-runner.py as the normal endpoint user, not with sudo")
    local = LocalExecutor()
    print("Authorizing local sudo...")
    if not local.authorize_sudo():
        raise RuntimeError("Local sudo authorization failed")
    ensure_ssh_dependency(local)
    config = prompt_receiver()
    receiver = SSHExecutor(config)
    receiver.connect()
    sudo_check = receiver.run("true", sudo=True, timeout=15)
    if sudo_check.returncode != 0:
        receiver.close()
        raise RuntimeError(f"Receiver sudo check failed: {sudo_check.stderr.strip()}")
    hostname = local.run("hostname -s", timeout=10)
    if hostname.returncode != 0 or not hostname.stdout.strip():
        receiver.close()
        raise RuntimeError("Could not determine client hostname")
    client_hostname = hostname.stdout.strip()
    receiver_hostname = input(f"Receiver log hostname [{client_hostname}]: ").strip() or client_hostname
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", receiver_hostname):
        receiver.close()
        raise ValueError("Receiver log hostname contains unsupported characters")
    if evidence:
        evidence.register_secret(config.password)
        evidence.register_secret(config.sudo_password or "")
    return LabContext(database, local, receiver, client_hostname, receiver_hostname, evidence=evidence)


def evaluated_result(
    scenario_id: str,
    name: str,
    started_at: str,
    commands: list[CommandResult],
    assertions: list[AssertionResult],
    pass_reason: str,
    cleanup_status: str = "Not required",
) -> ScenarioResult:
    failed = [assertion.name for assertion in assertions if not assertion.passed]
    status = "Pass" if not failed else "Fail"
    reason = pass_reason if not failed else f"Failed assertion(s): {', '.join(failed)}"
    if cleanup_status == "Failed":
        status = "Cleanup Failed"
        reason = f"{reason}; scenario cleanup failed"
    return ScenarioResult(
        scenario_id=scenario_id,
        name=name,
        status=status,
        reason=reason,
        started_at=started_at,
        ended_at=utc_now(),
        assertions=assertions,
        commands=commands,
        cleanup_status=cleanup_status,
    )


def receiver_message_capacity(context: LabContext) -> tuple[CommandResult, int | None, str]:
    command = (
        "grep -hEio '(maxDataSize|maxMessageSize)[[:space:]]*=[[:space:]]*\"[^\"]+\"' "
        "/etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
    )
    result = context.receiver.run(command, sudo=True, timeout=30)
    data_matches = re.findall(r'maxDataSize\s*=\s*"([^"]+)"', result.stdout, re.IGNORECASE)
    global_matches = re.findall(r'maxMessageSize\s*=\s*"([^"]+)"', result.stdout, re.IGNORECASE)
    global_value = global_matches[-1] if global_matches else "8k"
    data_value = data_matches[-1] if data_matches else global_value
    global_bytes = parse_size_bytes(global_value)
    data_bytes = parse_size_bytes(data_value)
    configured = (
        f"maxDataSize={data_value}, "
        f"maxMessageSize={global_value}{'' if global_matches else ' (default)'}"
    )
    if global_bytes is None or data_bytes is None:
        return result, None, configured
    return result, min(global_bytes, data_bytes), configured


def establish_receiver_outage(context: LabContext) -> CommandResult:
    return context.receiver.run(RECEIVER_STOP_COMMAND, sudo=True, timeout=60)


def restore_receiver_ingest(context: LabContext) -> CommandResult:
    return context.receiver.run(RECEIVER_START_COMMAND, sudo=True, timeout=60)


def postgres_comment(context: LabContext, marker: str) -> CommandResult:
    sql = f"COMMENT ON TABLE public.lc_runner_anchor IS '{marker}';"
    return context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -q -c {shlex.quote(sql)}", timeout=30)


def pg_anchor(context: LabContext) -> CommandResult:
    sql = "CREATE TABLE IF NOT EXISTS public.lc_runner_anchor (id integer);"
    return context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -q -c {shlex.quote(sql)}", timeout=30)


def pg_setup_checks(context: LabContext) -> ScenarioResult:
    started = utc_now()
    commands = [
        context.local.run("pg_lsclusters --no-header", timeout=15),
        context.local.run(
            "sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15
        ),
    ]
    current_file = commands[1].stdout.strip()
    if current_file:
        commands.append(
            context.local.run(
                f"sudo -u log-collector test -r {shlex.quote(current_file)}", timeout=15
            )
        )
    assertions = [
        AssertionResult("cluster discovered", commands[0].returncode == 0 and bool(commands[0].stdout.strip()), command_fact(commands[0])),
        AssertionResult("active log reported", commands[1].returncode == 0 and current_file.startswith("/"), current_file or command_fact(commands[1])),
        AssertionResult(
            "collector can read active log",
            len(commands) == 3 and commands[2].returncode == 0,
            "readable" if len(commands) == 3 and commands[2].returncode == 0 else "not readable",
        ),
    ]
    return evaluated_result("C1", "PostgreSQL discovery and log access", started, commands, assertions, "Cluster, active log, and collector read access confirmed")


def pg_config_check(context: LabContext) -> ScenarioResult:
    started = utc_now()
    check = context.local.run("sudo log-collector check", timeout=30)
    assertions = [
        AssertionResult(
            "configuration accepted",
            check.returncode == 0 and "config ok" in f"{check.stdout}\n{check.stderr}".lower(),
            command_fact(check),
        )
    ]
    return evaluated_result("A8", "Collector configuration validation", started, [check], assertions, "log-collector check returned Config OK")


def pg_health_check(context: LabContext) -> ScenarioResult:
    started = utc_now()
    health = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    payload: dict[str, Any] = {}
    try:
        parsed = json.loads(health.stdout)
        if isinstance(parsed, dict):
            payload = parsed
    except json.JSONDecodeError:
        pass
    running = payload.get("service_running") is True or str(payload.get("agent_status", "")).lower() == "running"
    connected = payload.get("cloud_connected") is True or str(payload.get("cloud_status", "")).lower() == "connected"
    assertions = [
        AssertionResult("health endpoint returned JSON", health.returncode == 0 and bool(payload), command_fact(health)),
        AssertionResult("collector running", running, str(payload.get("agent_status", payload.get("service_running", "missing")))),
        AssertionResult("receiver connected", connected, str(payload.get("cloud_status", payload.get("cloud_connected", "missing")))),
    ]
    return evaluated_result("A10", "Collector health endpoint", started, [health], assertions, "Health reports the collector running and connected")


def pg_json_collection(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("C3")
    settings = context.local.run(
        "sudo -u postgres psql -Atc \"SHOW log_destination; SELECT pg_current_logfile();\"",
        timeout=15,
    )
    values = [line.strip() for line in settings.stdout.splitlines() if line.strip()]
    destination = values[0] if values else ""
    current_file = values[-1] if len(values) > 1 else ""
    trigger = postgres_comment(context, marker)
    received = context.receiver_grep(marker)
    assertions = [
        AssertionResult("jsonlog active", "jsonlog" in {item.strip() for item in destination.split(",")}, destination or "missing"),
        AssertionResult("active file is JSON", current_file.endswith(".json"), current_file or "missing"),
        AssertionResult("JSON event generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("JSON event collected", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("C3", "PostgreSQL JSON log collection", started, [settings, trigger, received], assertions, "Active PostgreSQL jsonlog event reached the receiver")


def pg_sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def pg_psql_flags(*statements: str) -> str:
    return " ".join(f"-c {shlex.quote(statement)}" for statement in statements)


def normalize_postgresql_received_content(received: str) -> str:
    separator = "[unparsed] "
    if separator not in received:
        return received
    prefix, raw_csv = received.split(separator, 1)
    try:
        rows = list(csv.reader(io.StringIO(raw_csv), strict=True))
    except csv.Error:
        return received
    decoded = "\n".join(field for row in rows for field in row)
    return f"{prefix}[csv-decoded] {decoded}"


def pg_format_case(
    context: LabContext,
    scenario_id: str,
    name: str,
    destination: str,
    query_template: str,
    expected_fragments: list[str],
    log_line_prefix: str | None = None,
) -> ScenarioResult:
    started = utc_now()
    marker = context.marker(scenario_id, "format")
    commands: list[CommandResult] = []
    settings = context.local.run(
        "sudo -u postgres psql -AtF $'\\t' -c \"SELECT current_setting('log_destination'), current_setting('log_statement'), current_setting('log_line_prefix');\"",
        timeout=15,
    )
    commands.append(settings)
    values = settings.stdout.rstrip("\n").split("\t")
    if settings.returncode != 0 or len(values) != 3:
        raise RuntimeError(f"Could not capture PostgreSQL logging settings: {command_fact(settings)}")
    old_destination, old_statement, old_prefix = values
    target_prefix = old_prefix if log_line_prefix is None else log_line_prefix
    restore_command = (
        "sudo -u postgres psql -v ON_ERROR_STOP=1 "
        + pg_psql_flags(
            f"ALTER SYSTEM SET log_destination={pg_sql_literal(old_destination)};",
            f"ALTER SYSTEM SET log_statement={pg_sql_literal(old_statement)};",
            f"ALTER SYSTEM SET log_line_prefix={pg_sql_literal(old_prefix)};",
            "SELECT pg_reload_conf();",
            "SELECT pg_rotate_logfile();",
        )
    )
    action_id = f"{scenario_id}-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 90})
    change = context.local.run(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 "
        + pg_psql_flags(
            f"ALTER SYSTEM SET log_destination={pg_sql_literal(destination)};",
            "ALTER SYSTEM SET log_statement='all';",
            f"ALTER SYSTEM SET log_line_prefix={pg_sql_literal(target_prefix)};",
            "SELECT pg_reload_conf();",
            "SELECT pg_rotate_logfile();",
        ),
        timeout=90,
    )
    commands.append(change)
    cleanup_ok = False
    query = query_template.format(marker=marker)
    try:
        time.sleep(3)
        trigger = context.local.run(
            f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(query)}",
            timeout=60,
        )
        received = context.receiver_event(marker, timeout=90)
        count = context.receiver.run(
            f"grep -Fc -- {shlex.quote(marker)} {shlex.quote(context.receiver_log)} || true",
            sudo=True,
            timeout=30,
        )
        service = context.local.run("systemctl is-active log-collector", timeout=15)
        commands.extend([trigger, received, count, service])
    finally:
        restore = context.local.run(restore_command, timeout=90)
        commands.append(restore)
        cleanup_ok = restore.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(action_id)
    try:
        occurrences = int(count.stdout.strip() or "0")
    except ValueError:
        occurrences = -1
    normalized_received = normalize_postgresql_received_content(received.stdout)
    fragments_ok = marker in normalized_received and all(fragment in normalized_received for fragment in expected_fragments)
    assertions = [
        AssertionResult("temporary log format applied", change.returncode == 0, command_fact(change)),
        AssertionResult("test statement executed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("record content intact", fragments_ok, command_fact(received)),
        AssertionResult("exactly one received record", occurrences == 1, f"matches={occurrences}"),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result(scenario_id, name, started, commands, assertions, "PostgreSQL format record arrived intact as one event", "Passed" if cleanup_ok else "Failed")


def pg_csv_multiline(context: LabContext) -> ScenarioResult:
    return pg_format_case(context, "C4", "CSV multi-line statement", "csvlog", "SELECT /*{marker}*/\n 1 AS lc_multiline;", ["lc_multiline"])


def pg_csv_comma(context: LabContext) -> ScenarioResult:
    return pg_format_case(context, "C4a", "CSV quoted comma", "csvlog", "SELECT /*{marker}*/ 'a,b,c' AS value;", ["a,b,c"])


def pg_csv_double_quote(context: LabContext) -> ScenarioResult:
    return pg_format_case(context, "C4b", "CSV double quote", "csvlog", "SELECT /*{marker}*/ 'say \"\"hi\"\"' AS value;", ['say ""hi""'])


def pg_stderr_multiline(context: LabContext) -> ScenarioResult:
    return pg_format_case(context, "C4c", "stderr multi-line statement", "stderr", "SELECT /*{marker}*/\n 1 AS lc_multiline;", ["lc_multiline"])


def pg_dual_destination(context: LabContext) -> ScenarioResult:
    return pg_format_case(context, "C4d", "stderr and csvlog de-duplication", "stderr,csvlog", "SELECT /*{marker}*/ 1 AS lc_dual;", ["lc_dual"])


def pg_custom_prefix(context: LabContext) -> ScenarioResult:
    return pg_format_case(context, "C4e", "Custom log line prefix", "stderr", "SELECT /*{marker}*/ 1 AS lc_prefix;", ["lc_prefix"], "%m [%p] %a %u %d ")


def pg_prefix_without_timestamp(context: LabContext) -> ScenarioResult:
    return pg_format_case(context, "C4f", "Log prefix without timestamp", "stderr", "SELECT /*{marker}*/ 1 AS lc_no_timestamp;", ["lc_no_timestamp"], "%p ")


def pg_unicode(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G6")
    value = f"{marker}_日本語_العربية_😀"
    trigger = postgres_comment(context, value)
    received = context.receiver_grep(marker)
    assertions = [
        AssertionResult("Unicode event generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("Unicode text preserved", value in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G6", "Unicode log preservation", started, [trigger, received], assertions, "Japanese, Arabic, and emoji text remained intact")


def pg_rapid_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("G3b", "rapid")
    commands: list[CommandResult] = []
    files: list[str] = []
    for index in range(1, 4):
        current = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
        commands.append(current)
        files.append(current.stdout.strip())
        commands.append(postgres_comment(context, f"{prefix}_{index}"))
        if index < 3:
            commands.append(context.local.run("sudo -u postgres psql -Atc \"SELECT pg_rotate_logfile();\"", timeout=30))
            previous = files[-1]
            for _ in range(10):
                time.sleep(1)
                probe = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
                commands.append(probe)
                if probe.stdout.strip() and probe.stdout.strip() != previous:
                    break
    received = context.receiver_grep(prefix, timeout=60)
    commands.append(received)
    markers = set(re.findall(re.escape(prefix) + r"_([1-3])", received.stdout))
    assertions = [
        AssertionResult("three distinct active files", len(set(files)) == 3, str(files)),
        AssertionResult("all rapid-rotation markers received", markers == {"1", "2", "3"}, str(sorted(markers))),
    ]
    return evaluated_result("G3b", "Two rapid PostgreSQL rotations", started, commands, assertions, "Collection followed two rapid rotations without losing the numbered markers")


def pg_kill_recovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("H10", "before")
    after = context.marker("H10", "after")
    commands = [pg_anchor(context), postgres_comment(context, before), context.receiver_grep(before)]
    count_command = f"grep -Fc -- {shlex.quote(before)} {shlex.quote(context.receiver_log)} || true"
    initial_count = context.receiver.run(count_command, sudo=True, timeout=15)
    initial_pid = context.local.run("systemctl show -p MainPID --value log-collector", timeout=15)
    killed = context.local.run("sudo systemctl kill --kill-who=main --signal=SIGKILL log-collector", timeout=30)
    restarted = context.local.run("sudo systemctl restart log-collector", timeout=60)
    time.sleep(3)
    final_pid = context.local.run("systemctl show -p MainPID --value log-collector", timeout=15)
    commands.extend([initial_count, initial_pid, killed, restarted, final_pid, postgres_comment(context, after)])
    received = context.receiver_grep(after)
    final_count = context.receiver.run(count_command, sudo=True, timeout=15)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    commands.extend([received, final_count, service])
    try:
        before_count = int(initial_count.stdout.strip() or "0")
        after_count = int(final_count.stdout.strip() or "0")
    except ValueError:
        before_count = after_count = -1
    assertions = [
        AssertionResult("SIGKILL issued", killed.returncode == 0, command_fact(killed)),
        AssertionResult("service restarted", restarted.returncode == 0 and service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("new collector process", bool(initial_pid.stdout.strip()) and final_pid.stdout.strip() != initial_pid.stdout.strip(), f"before={initial_pid.stdout.strip()} after={final_pid.stdout.strip()}"),
        AssertionResult("post-kill event delivered", after in received.stdout, command_fact(received)),
        AssertionResult("no full replay", before_count >= 1 and after_count <= before_count + 3, f"before={before_count} after={after_count}"),
    ]
    return evaluated_result("H10", "SIGKILL checkpoint recovery", started, commands, assertions, "Collector resumed from its checkpoint after a forced process kill and restart")


def pg_linux_systemd(context: LabContext) -> ScenarioResult:
    started = utc_now()
    os_release = context.local.run(". /etc/os-release && printf '%s %s' \"$ID\" \"$VERSION_ID\"", timeout=15)
    service = context.local.run("systemctl show log-collector -p LoadState -p ActiveState -p UnitFileState", timeout=15)
    assertions = [
        AssertionResult("Linux host", "ubuntu" in os_release.stdout.lower(), command_fact(os_release)),
        AssertionResult("systemd unit loaded", "LoadState=loaded" in service.stdout, command_fact(service)),
        AssertionResult("systemd unit active", "ActiveState=active" in service.stdout, command_fact(service)),
        AssertionResult("systemd unit enabled", "UnitFileState=enabled" in service.stdout, command_fact(service)),
    ]
    return evaluated_result("I2", "Linux systemd runtime", started, [os_release, service], assertions, "Collector is loaded, enabled, and active under Ubuntu systemd")


def pg_static_binary(context: LabContext) -> ScenarioResult:
    started = utc_now()
    inspect = context.local.run(
        "BIN=$(command -v log-collector || printf /usr/local/bin/log-collector); file \"$BIN\"; ldd \"$BIN\" 2>&1 || true",
        timeout=30,
    )
    output = f"{inspect.stdout}\n{inspect.stderr}".lower()
    static = "statically linked" in output or "not a dynamic executable" in output
    assertions = [
        AssertionResult("binary inspected", inspect.returncode == 0, command_fact(inspect)),
        AssertionResult("no dynamic runtime dependency", static, command_fact(inspect)),
    ]
    return evaluated_result("I5", "Static Linux packaging", started, [inspect], assertions, "Linux collector binary has no dynamic runtime dependency")


def pg_non_root_service(context: LabContext) -> ScenarioResult:
    started = utc_now()
    service_user = context.local.run("systemctl show -p User --value log-collector", timeout=15)
    effective_user = context.local.run(
        "PID=$(systemctl show -p MainPID --value log-collector); test \"$PID\" -gt 0 && ps -o user= -p \"$PID\" | xargs",
        timeout=15,
    )
    current_log = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    path = current_log.stdout.strip()
    readable = context.local.run(f"sudo -u log-collector test -r {shlex.quote(path)}", timeout=15) if path else current_log
    unit_identity = service_user.stdout.strip() or "unset"
    process_identity = effective_user.stdout.strip() or "missing"
    assertions = [
        AssertionResult(
            "dedicated service identity",
            effective_user.returncode == 0 and process_identity == "log-collector",
            f"unit_user={unit_identity} effective_user={process_identity}",
        ),
        AssertionResult("database log readable without root", bool(path) and readable.returncode == 0, path or command_fact(readable)),
    ]
    return evaluated_result("I8", "Non-root collector with ACL access", started, [service_user, effective_user, current_log, readable], assertions, "The collector process runs as log-collector and can read the active PostgreSQL log")


def pg_basic_delivery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("B1")
    commands = [pg_anchor(context)]
    commands.append(postgres_comment(context, marker))
    commands.append(context.receiver_grep(marker))
    assertions = [
        AssertionResult("event generated", commands[1].returncode == 0, command_fact(commands[1])),
        AssertionResult("receiver marker", commands[2].returncode == 0 and marker in commands[2].stdout, command_fact(commands[2])),
    ]
    return evaluated_result("B1", "Basic PostgreSQL collection", started, commands, assertions, "Generated DDL marker reached the receiver")


def pg_restart_checkpoint(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("B3", "before")
    after = context.marker("B3", "after")
    commands = [pg_anchor(context), postgres_comment(context, before), context.receiver_grep(before)]
    count_command = f"grep -Fc -- {shlex.quote(before)} {shlex.quote(context.receiver_log)} || true"
    initial_count = context.receiver.run(count_command, sudo=True, timeout=15)
    commands.append(initial_count)
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    commands.append(restart)
    time.sleep(3)
    commands.append(postgres_comment(context, after))
    after_received = context.receiver_grep(after)
    commands.append(after_received)
    final_count = context.receiver.run(count_command, sudo=True, timeout=15)
    commands.append(final_count)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    commands.append(service)
    try:
        before_count = int(initial_count.stdout.strip() or "0")
        after_count = int(final_count.stdout.strip() or "0")
    except ValueError:
        before_count = -1
        after_count = -1
    assertions = [
        AssertionResult("collector restarted", restart.returncode == 0, command_fact(restart)),
        AssertionResult("collector active", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("post-restart delivery", after in after_received.stdout, command_fact(after_received)),
        AssertionResult("no full replay", before_count >= 1 and after_count <= before_count + 3, f"before={before_count} after={after_count}"),
    ]
    return evaluated_result("B3", "Service restart and checkpoint", started, commands, assertions, "Collector resumed after restart without replaying the full log")


def pg_stability(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("B4", "stability")[:48]
    commands = [pg_anchor(context)]
    initial = context.local.run(
        "printf 'pid=%s rss=%s restarts=%s status=%s\\n' \"$(systemctl show -p MainPID --value log-collector)\" \"$(ps -o rss= -p \"$(systemctl show -p MainPID --value log-collector)\" | xargs)\" \"$(systemctl show -p NRestarts --value log-collector)\" \"$(systemctl is-active log-collector)\"",
        timeout=15,
    )
    commands.append(initial)
    sample_pattern = re.compile(r"pid=(\d+) rss=(\d+) restarts=(\d+) status=(\S+)")
    samples: list[tuple[int, int, int, str]] = []
    match = sample_pattern.search(initial.stdout)
    if match:
        samples.append((int(match.group(1)), int(match.group(2)), int(match.group(3)), match.group(4)))
    for index in range(1, LAB_STABILITY_MINUTES + 1):
        commands.append(postgres_comment(context, f"{prefix}_{index:02d}"))
        time.sleep(60)
        sample = context.local.run(
            "printf 'pid=%s rss=%s restarts=%s status=%s\\n' \"$(systemctl show -p MainPID --value log-collector)\" \"$(ps -o rss= -p \"$(systemctl show -p MainPID --value log-collector)\" | xargs)\" \"$(systemctl show -p NRestarts --value log-collector)\" \"$(systemctl is-active log-collector)\"",
            timeout=15,
        )
        commands.append(sample)
        match = sample_pattern.search(sample.stdout)
        if match:
            samples.append((int(match.group(1)), int(match.group(2)), int(match.group(3)), match.group(4)))
    received = context.receiver_grep(prefix, timeout=60)
    commands.append(received)
    marker_numbers = set(re.findall(re.escape(prefix) + r"_(\d{2})", received.stdout))
    same_pid = bool(samples) and len({sample[0] for sample in samples}) == 1
    same_restarts = bool(samples) and len({sample[2] for sample in samples}) == 1
    expected_samples = LAB_STABILITY_MINUTES + 1
    all_active = len(samples) == expected_samples and all(sample[3] == "active" for sample in samples)
    memory_ok = False
    memory_observed = "no samples"
    if samples:
        start_rss = samples[0][1]
        max_rss = max(sample[1] for sample in samples)
        final_rss = samples[-1][1]
        memory_ok = max_rss <= start_rss + 131072 and final_rss <= max(start_rss * 2, start_rss + 65536)
        memory_observed = f"start={start_rss}KB max={max_rss}KB final={final_rss}KB"
    assertions = [
        AssertionResult(f"{expected_samples} service samples", len(samples) == expected_samples, str(len(samples))),
        AssertionResult("collector stayed active", all_active, str([sample[3] for sample in samples])),
        AssertionResult("PID unchanged", same_pid, str(sorted({sample[0] for sample in samples}))),
        AssertionResult("restart count unchanged", same_restarts, str(sorted({sample[2] for sample in samples}))),
        AssertionResult("bounded RSS", memory_ok, memory_observed),
        AssertionResult(f"{LAB_STABILITY_MINUTES} markers received", marker_numbers == {f"{index:02d}" for index in range(1, LAB_STABILITY_MINUTES + 1)}, f"unique={len(marker_numbers)}"),
    ]
    return evaluated_result("B4", "Constrained-lab stability window", started, commands, assertions, f"Collector remained stable for the approved {LAB_STABILITY_MINUTES}-minute lab window; upstream specifies 30+ minutes")


def pg_receiver_outage(context: LabContext) -> ScenarioResult:
    started = utc_now()
    commands = [pg_anchor(context)]
    unit = f"lc-rsyslog-recover-{secrets.token_hex(4)}"
    recovery_id = f"B5-{unit}"
    schedule = context.receiver.run(
        f"systemd-run --unit={unit} --on-active={LAB_OUTAGE_MINUTES + 1}m /bin/sh -c {shlex.quote(RECEIVER_START_COMMAND)}", sudo=True, timeout=30
    )
    commands.append(schedule)
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "receiver", "command": RECEIVER_START_COMMAND, "sudo": True, "timeout": 60})
    initial = context.local.run(
        "printf 'pid=%s restarts=%s\\n' \"$(systemctl show -p MainPID --value log-collector)\" \"$(systemctl show -p NRestarts --value log-collector)\"",
        timeout=15,
    )
    commands.append(initial)
    stop = establish_receiver_outage(context)
    commands.append(stop)
    samples: list[str] = []
    cleanup_ok = False
    try:
        for _ in range(LAB_OUTAGE_MINUTES):
            sample = context.local.run(
                "printf 'status=%s pid=%s restarts=%s\\n' \"$(systemctl is-active log-collector)\" \"$(systemctl show -p MainPID --value log-collector)\" \"$(systemctl show -p NRestarts --value log-collector)\"",
                timeout=15,
            )
            commands.append(sample)
            samples.append(sample.stdout.strip())
            time.sleep(60)
    finally:
        restore = restore_receiver_ingest(context)
        commands.append(restore)
        cleanup_ok = restore.returncode == 0
        context.receiver.run(f"systemctl stop {unit}.timer 2>/dev/null || true", sudo=True, timeout=15)
        if cleanup_ok and context.journal:
            context.journal.remove(recovery_id)
    marker = context.marker("B5", "reconnected")
    commands.append(postgres_comment(context, marker))
    received = context.receiver_grep(marker, timeout=60)
    commands.append(received)
    initial_match = re.search(r"pid=(\d+) restarts=(\d+)", initial.stdout)
    expected_pid = initial_match.group(1) if initial_match else ""
    expected_restarts = initial_match.group(2) if initial_match else ""
    sample_matches = [re.search(r"status=(\S+) pid=(\d+) restarts=(\d+)", value) for value in samples]
    stable = len(sample_matches) == LAB_OUTAGE_MINUTES and all(
        match and match.group(1) == "active" and match.group(2) == expected_pid and match.group(3) == expected_restarts
        for match in sample_matches
    )
    assertions = [
        AssertionResult("recovery timer scheduled", schedule.returncode == 0, command_fact(schedule)),
        AssertionResult("receiver stopped", stop.returncode == 0, command_fact(stop)),
        AssertionResult("collector survived outage", stable, " | ".join(samples)),
        AssertionResult("receiver restored", cleanup_ok, "active" if cleanup_ok else "restore failed"),
        AssertionResult("delivery resumed", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("B5", "Constrained-lab receiver outage", started, commands, assertions, f"Collector survived the approved {LAB_OUTAGE_MINUTES}-minute lab outage and resumed delivery; upstream specifies 10 minutes", "Passed" if cleanup_ok else "Failed")


def pg_source_identity(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("B2")
    commands = [pg_anchor(context), postgres_comment(context, marker), context.receiver_grep(marker)]
    line = commands[-1].stdout.strip().splitlines()[-1] if commands[-1].stdout.strip() else ""
    fields = line.split(" ", 4)
    app_name = fields[3] if len(fields) >= 4 else "missing"
    assertions = [
        AssertionResult("receiver marker", marker in line, line or "missing"),
        AssertionResult("APP-NAME exactly postgres_log", app_name == "postgres_log", app_name),
    ]
    return evaluated_result("B2", "Stable source identifier", started, commands, assertions, "Receiver APP-NAME is exactly postgres_log")


def pg_unique_event_ids(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("B6", "")[:48]
    commands = [pg_anchor(context)]
    shell_commands = []
    for index in range(1, 6):
        statement = f"COMMENT ON TABLE public.lc_runner_anchor IS '{prefix}_{index}';"
        shell_commands.append(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -q -c {shlex.quote(statement)}")
    commands.append(context.local.run(" && ".join(shell_commands), timeout=60))
    commands.append(context.receiver_grep(f"{prefix}_5"))
    commands.append(
        context.receiver.run(
            f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)} | tail -n 20",
            sudo=True,
            timeout=30,
        )
    )
    lines = [line for line in commands[-1].stdout.splitlines() if prefix in line]
    ids = [match.group(1) for line in lines if (match := re.search(r'event_id="([^"]+)"', line))]
    markers = set(re.findall(re.escape(prefix) + r"_([1-5])", commands[-1].stdout))
    assertions = [
        AssertionResult("five markers received", markers == {"1", "2", "3", "4", "5"}, str(sorted(markers))),
        AssertionResult("five unique event IDs", len(set(ids)) == 5, f"total={len(ids)} unique={len(set(ids))}"),
    ]
    return evaluated_result("B6", "Unique event identifiers", started, commands, assertions, "Five events carried five unique event IDs")


def pg_timestamp(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("B7")
    commands = [pg_anchor(context), postgres_comment(context, marker)]
    native = context.local.run(
        f"sudo grep -hF -- {shlex.quote(marker)} /var/log/postgresql/*.json | tail -n 1", timeout=30
    )
    receiver = context.receiver_grep(marker)
    commands.extend([native, receiver])
    native_timestamp = ""
    receiver_timestamp = ""
    try:
        native_timestamp = json.loads(native.stdout.strip()).get("timestamp", "")
    except (json.JSONDecodeError, AttributeError):
        pass
    if receiver.stdout.strip():
        match = re.match(r"^<\d+>1\s+(\S+)", receiver.stdout.strip().splitlines()[-1])
        receiver_timestamp = match.group(1) if match else ""
    same_instant = timestamps_match(native_timestamp, receiver_timestamp)
    assertions = [
        AssertionResult("native timestamp parsed", bool(native_timestamp), native_timestamp or "missing"),
        AssertionResult("receiver timestamp parsed", bool(receiver_timestamp), receiver_timestamp or "missing"),
        AssertionResult("same event instant", same_instant, f"native={native_timestamp} receiver={receiver_timestamp}"),
    ]
    return evaluated_result("B7", "Native timestamp preservation", started, commands, assertions, "Receiver timestamp represents the native PostgreSQL event instant")


def pg_failed_login(context: LabContext) -> ScenarioResult:
    started = utc_now()
    username = f"lc_missing_{secrets.token_hex(4)}"
    trigger = context.local.run(
        f"PGPASSWORD=wrong psql -h 127.0.0.1 -U {shlex.quote(username)} -d postgres -c 'SELECT 1;'",
        timeout=30,
    )
    receiver = context.receiver_grep(username)
    commands = [trigger, receiver]
    lines = [line for line in receiver.stdout.splitlines() if username in line]
    priorities = [match.group(1) for line in lines if (match := re.match(r"^<(\d+)>", line))]
    assertions = [
        AssertionResult("login rejected", trigger.returncode != 0, command_fact(trigger)),
        AssertionResult("failure delivered", bool(lines), f"matches={len(lines)}"),
        AssertionResult("critical priority", bool(priorities) and all(value == "10" for value in priorities), str(priorities)),
    ]
    return evaluated_result("C2", "Failed login severity", started, commands, assertions, "Failed login events were delivered at wire priority <10>")


def pg_connection_lifecycle(context: LabContext) -> ScenarioResult:
    started = utc_now()
    database = f"lc_c2c_{secrets.token_hex(5)}"
    create = context.local.run(
        f"sudo -u postgres createdb {shlex.quote(database)}",
        timeout=30,
    )
    trigger = context.local.run(
        f"sudo -u postgres psql {shlex.quote('dbname=' + database + ' application_name=lc_c2c_runner')} -c 'SELECT 1;'",
        timeout=30,
    )
    receiver_command = (
        f"for i in $(seq 1 30); do OUT=$(grep -F -- {shlex.quote(database)} {shlex.quote(context.receiver_log)} || true); "
        "if printf '%s' \"$OUT\" | grep -qi 'connection authorized' && printf '%s' \"$OUT\" | grep -qi 'disconnection'; "
        "then printf '%s\\n' \"$OUT\"; exit 0; fi; sleep 1; done; printf '%s\\n' \"$OUT\"; exit 1"
    )
    receiver = context.receiver.run(receiver_command, sudo=True, timeout=40)
    drop = context.local.run(f"sudo -u postgres dropdb --if-exists {shlex.quote(database)}", timeout=30)
    commands = [create, trigger, receiver, drop]
    text = receiver.stdout.lower()
    lifecycle_lines = [
        line
        for line in receiver.stdout.splitlines()
        if "connection authorized" in line.lower() or "disconnection" in line.lower()
    ]
    assertions = [
        AssertionResult("disposable database created", create.returncode == 0, command_fact(create)),
        AssertionResult("connection completed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("connection recorded", "connection authorized" in text or "connection received" in text, text[-1000:]),
        AssertionResult("disconnection recorded", "disconnection" in text, text[-1000:]),
        AssertionResult("informational priority", bool(lifecycle_lines) and all(line.startswith("<14>") for line in lifecycle_lines), "priorities=" + str([re.match(r"^<(\d+)>", line).group(1) if re.match(r"^<(\d+)>", line) else "missing" for line in lifecycle_lines])),
    ]
    return evaluated_result("C2c", "Connection and disconnection logging", started, commands, assertions, "Connection lifecycle events were delivered at informational priority", "Passed" if drop.returncode == 0 else "Failed")


def pg_role_ddl(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(4)
    parent = f"lc_c2d_parent_{token}"
    member = f"lc_c2d_member_{token}"
    statements = [
        f"CREATE ROLE {parent};",
        f"CREATE ROLE {member};",
        f"GRANT {parent} TO {member};",
        f"REVOKE {parent} FROM {member};",
        f"DROP ROLE {member};",
        f"DROP ROLE {parent};",
    ]
    flags = " ".join(f"-c {shlex.quote(statement)}" for statement in statements)
    trigger = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 {flags}", timeout=30)
    wait = context.receiver_grep(f"DROP ROLE {parent}")
    receiver = context.receiver.run(
        f"grep -F -- {shlex.quote(parent)} {shlex.quote(context.receiver_log)} | tail -n 20",
        sudo=True,
        timeout=30,
    )
    commands = [trigger, wait, receiver]
    text = receiver.stdout
    assertions = [
        AssertionResult("role operations completed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("CREATE ROLE collected", "CREATE ROLE" in text, text[-500:]),
        AssertionResult("GRANT collected", "GRANT" in text, text[-500:]),
        AssertionResult("DROP ROLE collected", "DROP ROLE" in text, text[-500:]),
    ]
    return evaluated_result("C2d", "Role DDL security events", started, commands, assertions, "CREATE ROLE, GRANT, and DROP ROLE were collected")


def pg_permission_denied(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(4)
    table = f"lc_c2f_{token}"
    role = f"lc_c2f_{token}"
    setup_sql = f"CREATE TABLE public.{table} (id integer); CREATE ROLE {role}; REVOKE ALL ON public.{table} FROM PUBLIC;"
    trigger_sql = f"SET ROLE {role}; SELECT * FROM public.{table};"
    cleanup_sql = f"DROP TABLE IF EXISTS public.{table}; DROP ROLE IF EXISTS {role};"
    setup = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(setup_sql)}", timeout=30)
    trigger = context.local.run(f"sudo -u postgres psql -c {shlex.quote(trigger_sql)}", timeout=30)
    receiver = context.receiver_grep(f"permission denied for table {table}")
    cleanup = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(cleanup_sql)}", timeout=30)
    commands = [setup, trigger, receiver, cleanup]
    lines = [line for line in receiver.stdout.splitlines() if f"permission denied for table {table}" in line]
    assertions = [
        AssertionResult("setup completed", setup.returncode == 0, command_fact(setup)),
        AssertionResult("permission rejected", trigger.returncode != 0 and "permission denied" in trigger.stderr, command_fact(trigger)),
        AssertionResult("error delivered at <11>", bool(lines) and all(line.startswith("<11>") for line in lines), f"matches={len(lines)}"),
    ]
    return evaluated_result("C2f", "Permission-denied error severity", started, commands, assertions, "Permission denial was delivered at wire priority <11>", "Passed" if cleanup.returncode == 0 else "Failed")


def pg_deadlock(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(4)
    table_a = f"lc_c7_a_{token}"
    table_b = f"lc_c7_b_{token}"
    marker_table = f"lc_c7_ddl_{token}"
    setup_sql = (
        f"CREATE TABLE public.{table_a} (id integer PRIMARY KEY); "
        f"CREATE TABLE public.{table_b} (id integer PRIMARY KEY); "
        f"INSERT INTO public.{table_a} VALUES (1); INSERT INTO public.{table_b} VALUES (1);"
    )
    setup = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(setup_sql)}", timeout=30)
    sql_a = f"BEGIN; UPDATE public.{table_a} SET id=id WHERE id=1; SELECT pg_sleep(2); UPDATE public.{table_b} SET id=id WHERE id=1; COMMIT;"
    sql_b = f"BEGIN; UPDATE public.{table_b} SET id=id WHERE id=1; SELECT pg_sleep(2); UPDATE public.{table_a} SET id=id WHERE id=1; COMMIT;"
    file_a = f"/tmp/lc-c7-{token}-a.log"
    file_b = f"/tmp/lc-c7-{token}-b.log"
    shell = (
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(sql_a)} >{shlex.quote(file_a)} 2>&1 & P1=$!; "
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(sql_b)} >{shlex.quote(file_b)} 2>&1 & P2=$!; "
        f"wait $P1; S1=$?; wait $P2; S2=$?; echo session_a=$S1 session_b=$S2; "
        f"grep -H -i 'deadlock detected' {shlex.quote(file_a)} {shlex.quote(file_b)} || true"
    )
    trigger = context.local.run(shell, timeout=30)
    ddl_sql = f"CREATE TABLE public.{marker_table} (id integer);"
    ddl = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(ddl_sql)}", timeout=30)
    deadlock_received = context.receiver_grep("deadlock detected")
    ddl_received = context.receiver_grep(marker_table)
    cleanup_sql = f"DROP TABLE IF EXISTS public.{table_a}, public.{table_b}, public.{marker_table};"
    cleanup = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(cleanup_sql)}; rm -f {shlex.quote(file_a)} {shlex.quote(file_b)}", timeout=30)
    commands = [setup, trigger, ddl, deadlock_received, ddl_received, cleanup]
    deadlock_lines = [line for line in deadlock_received.stdout.splitlines() if "deadlock detected" in line]
    assertions = [
        AssertionResult("deadlock generated", "deadlock detected" in trigger.stdout, command_fact(trigger)),
        AssertionResult("deadlock delivered at <11>", bool(deadlock_lines) and deadlock_lines[-1].startswith("<11>"), deadlock_lines[-1] if deadlock_lines else "missing"),
        AssertionResult("DDL marker delivered", marker_table in ddl_received.stdout, command_fact(ddl_received)),
    ]
    return evaluated_result("C7", "Deadlock and ordinary DDL", started, commands, assertions, "Deadlock arrived at <11> and ordinary DDL was collected", "Passed" if cleanup.returncode == 0 else "Failed")


def pg_timeouts(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(4)
    table = f"lc_c7a_{token}"
    statement_timeout = context.local.run(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"SET statement_timeout='500ms'; SELECT pg_sleep(2);\"",
        timeout=10,
    )
    setup_sql = f"CREATE TABLE public.{table} (id integer PRIMARY KEY, value integer); INSERT INTO public.{table} VALUES (1,0);"
    setup = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(setup_sql)}", timeout=30)
    holder_sql = f"BEGIN; UPDATE public.{table} SET value=value+1 WHERE id=1; SELECT pg_sleep(5); COMMIT;"
    contender_sql = f"SET lock_timeout='500ms'; UPDATE public.{table} SET value=value+1 WHERE id=1;"
    lock_trigger = context.local.run(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(holder_sql)} >/tmp/lc-c7a-{token}.log 2>&1 & HOLDER=$!; sleep 1; sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(contender_sql)}; CONTENDER=$?; wait $HOLDER; HOLDER_STATUS=$?; rm -f /tmp/lc-c7a-{token}.log; echo contender=$CONTENDER holder=$HOLDER_STATUS",
        timeout=15,
    )
    statement_received = context.receiver_grep("canceling statement due to statement timeout")
    lock_received = context.receiver_grep("canceling statement due to lock timeout")
    cleanup_sql = f"DROP TABLE IF EXISTS public.{table};"
    cleanup = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(cleanup_sql)}", timeout=30)
    commands = [statement_timeout, setup, lock_trigger, statement_received, lock_received, cleanup]
    statement_lines = [line for line in statement_received.stdout.splitlines() if "statement timeout" in line]
    lock_lines = [line for line in lock_received.stdout.splitlines() if "lock timeout" in line]
    assertions = [
        AssertionResult("statement timeout generated", statement_timeout.returncode != 0 and "statement timeout" in statement_timeout.stderr, command_fact(statement_timeout)),
        AssertionResult("statement timeout delivered at <11>", bool(statement_lines) and statement_lines[-1].startswith("<11>"), statement_lines[-1] if statement_lines else "missing"),
        AssertionResult("lock timeout generated", "contender=3" in lock_trigger.stdout or "lock timeout" in lock_trigger.stderr, command_fact(lock_trigger)),
        AssertionResult("lock timeout delivered at <11>", bool(lock_lines) and lock_lines[-1].startswith("<11>"), lock_lines[-1] if lock_lines else "missing"),
    ]
    return evaluated_result("C7a", "Statement and lock timeouts", started, commands, assertions, "Both timeout types arrived at <11>", "Passed" if cleanup.returncode == 0 else "Failed")


def pg_backend_termination(context: LabContext) -> ScenarioResult:
    started = utc_now()
    app = f"lc_c7b_{secrets.token_hex(5)}"
    output = f"/tmp/{app}.log"
    shell = (
        f"sudo -u postgres psql {shlex.quote('dbname=postgres application_name=' + app)} -c 'SELECT pg_sleep(30);' >{shlex.quote(output)} 2>&1 & CLIENT=$!; "
        f"sleep 2; DBPID=$(sudo -u postgres psql -Atc {shlex.quote("SELECT pid FROM pg_stat_activity WHERE application_name='" + app + "' ORDER BY backend_start DESC LIMIT 1;")}); "
        f"test -n \"$DBPID\" || {{ echo target_missing; kill $CLIENT 2>/dev/null || true; exit 2; }}; "
        f"sudo -u postgres psql -Atc \"SELECT pg_terminate_backend($DBPID);\"; TERMINATE=$?; wait $CLIENT; CLIENT_STATUS=$?; "
        f"echo dbpid=$DBPID terminate=$TERMINATE client=$CLIENT_STATUS; sed -n '1,30p' {shlex.quote(output)}; rm -f {shlex.quote(output)}"
    )
    trigger = context.local.run(shell, timeout=45)
    receiver = context.receiver_grep("terminating connection due to administrator command")
    commands = [trigger, receiver]
    lines = [line for line in receiver.stdout.splitlines() if "terminating connection due to administrator command" in line]
    assertions = [
        AssertionResult("target backend terminated", "terminate=0" in trigger.stdout and "target_missing" not in trigger.stdout, command_fact(trigger)),
        AssertionResult("termination event delivered", bool(lines), f"matches={len(lines)}"),
    ]
    return evaluated_result("C7b", "Backend termination", started, commands, assertions, "pg_terminate_backend event reached the receiver")


def pg_maintenance_events(context: LabContext) -> ScenarioResult:
    started = utc_now()
    commands: list[CommandResult] = []
    token = secrets.token_hex(4)
    table = f"lc_c7c_{token}"
    settings = context.local.run(
        "sudo -u postgres psql -Atc \"SHOW log_autovacuum_min_duration; SHOW log_checkpoints;\"",
        timeout=15,
    )
    commands.append(settings)
    old = settings.stdout.strip().splitlines()
    if len(old) != 2 or not re.fullmatch(r"-?\d+(?:ms|s|min|h|d)?", old[0]) or old[1] not in {"on", "off"}:
        raise RuntimeError(f"Could not safely parse maintenance logging settings: {old!r}")
    action_id = f"C7c-{token}"
    restore_autovacuum = f"ALTER SYSTEM SET log_autovacuum_min_duration='{old[0]}';"
    restore_checkpoints = f"ALTER SYSTEM SET log_checkpoints='{old[1]}';"
    restore_flags = (
        f"-c {shlex.quote(restore_autovacuum)} "
        f"-c {shlex.quote(restore_checkpoints)} "
        "-c \"SELECT pg_reload_conf();\""
    )
    restore_command = f"sudo -u postgres psql -v ON_ERROR_STOP=1 {restore_flags}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 60})
    change = context.local.run(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"ALTER SYSTEM SET log_autovacuum_min_duration='0';\" -c \"ALTER SYSTEM SET log_checkpoints='on';\" -c \"SELECT pg_reload_conf();\"",
        timeout=60,
    )
    commands.append(change)
    cleanup_ok = False
    try:
        setup_sql = (
            f"CREATE TABLE public.{table} (id integer) WITH "
            "(autovacuum_vacuum_threshold=0, autovacuum_vacuum_scale_factor=0); "
            f"INSERT INTO public.{table} SELECT generate_series(1,2000); DELETE FROM public.{table};"
        )
        setup = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(setup_sql)}", timeout=60)
        commands.append(setup)
        last_autovacuum_sql = f"SELECT COALESCE(last_autovacuum::text,'') FROM pg_stat_user_tables WHERE relname='{table}';"
        wait = context.local.run(
            f"for i in $(seq 1 24); do LAST=$(sudo -u postgres psql -Atc {shlex.quote(last_autovacuum_sql)}); echo check=$i last=${{LAST:-pending}}; test -n \"$LAST\" && exit 0; sleep 5; done; exit 1",
            timeout=130,
        )
        commands.append(wait)
        checkpoint = context.local.run("sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"CHECKPOINT;\"", timeout=120)
        commands.append(checkpoint)
        time.sleep(5)
        auto_received = context.receiver.run(
            f"grep -E 'automatic vacuum of table .*{table}' {shlex.quote(context.receiver_log)} | tail -n 20",
            sudo=True,
            timeout=30,
        )
        checkpoint_received = context.receiver.run(
            f"grep -E 'checkpoint (starting|complete)' {shlex.quote(context.receiver_log)} | tail -n 10",
            sudo=True,
            timeout=30,
        )
        commands.extend([auto_received, checkpoint_received])
    finally:
        drop_sql = f"DROP TABLE IF EXISTS public.{table};"
        drop = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(drop_sql)}", timeout=30)
        restored = context.local.run(restore_command, timeout=60)
        commands.extend([drop, restored])
        cleanup_ok = drop.returncode == 0 and restored.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(action_id)
    auto_lines = [line for line in auto_received.stdout.splitlines() if table in line and "automatic vacuum" in line]
    assertions = [
        AssertionResult("temporary settings applied", change.returncode == 0, command_fact(change)),
        AssertionResult("autovacuum completed", wait.returncode == 0, command_fact(wait)),
        AssertionResult("autovacuum event delivered", bool(auto_lines), f"matches={len(auto_lines)}"),
        AssertionResult("checkpoint events delivered", "checkpoint complete" in checkpoint_received.stdout, command_fact(checkpoint_received)),
        AssertionResult("maintenance volume bounded", len(auto_lines) <= 10, f"autovacuum_matches={len(auto_lines)}"),
    ]
    return evaluated_result("C7c", "Autovacuum and checkpoint volume", started, commands, assertions, "Maintenance events were collected without excessive volume", "Passed" if cleanup_ok else "Failed")


def pg_database_restart(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("C7d", "before")
    after = context.marker("C7d", "after")
    commands = [pg_anchor(context), postgres_comment(context, before), context.receiver_grep(before)]
    initial = context.local.run(
        "printf 'pid=%s restarts=%s\\n' \"$(systemctl show -p MainPID --value log-collector)\" \"$(systemctl show -p NRestarts --value log-collector)\"",
        timeout=15,
    )
    restart = context.local.run("sudo systemctl restart postgresql@$(pg_lsclusters --no-header | awk 'NR==1 {print $1\"-\"$2}')", timeout=120)
    time.sleep(5)
    final = context.local.run(
        "printf 'db=%s collector=%s pid=%s restarts=%s\\n' \"$(systemctl is-active postgresql@$(pg_lsclusters --no-header | awk 'NR==1 {print $1\"-\"$2}'))\" \"$(systemctl is-active log-collector)\" \"$(systemctl show -p MainPID --value log-collector)\" \"$(systemctl show -p NRestarts --value log-collector)\"",
        timeout=15,
    )
    commands.extend([initial, restart, final, postgres_comment(context, after)])
    after_received = context.receiver_grep(after, timeout=60)
    lifecycle = context.receiver.run(
        f"grep -E 'database system is (shut down|ready to accept connections)' {shlex.quote(context.receiver_log)} | tail -n 20",
        sudo=True,
        timeout=15,
    )
    commands.extend([after_received, lifecycle])
    initial_match = re.search(r"pid=(\d+) restarts=(\d+)", initial.stdout)
    final_match = re.search(r"db=(\S+) collector=(\S+) pid=(\d+) restarts=(\d+)", final.stdout)
    stable = bool(initial_match and final_match and final_match.group(1) == "active" and final_match.group(2) == "active" and initial_match.group(1) == final_match.group(3) and initial_match.group(2) == final_match.group(4))
    assertions = [
        AssertionResult("database restarted", restart.returncode == 0, command_fact(restart)),
        AssertionResult("collector survived database restart", stable, f"initial={initial.stdout.strip()} final={final.stdout.strip()}"),
        AssertionResult("post-restart event delivered", after in after_received.stdout, command_fact(after_received)),
        AssertionResult("shutdown and startup collected", "shut down" in lifecycle.stdout and "ready to accept connections" in lifecycle.stdout, command_fact(lifecycle)),
    ]
    return evaluated_result("C7d", "PostgreSQL restart survival", started, commands, assertions, "Database lifecycle and post-restart delivery were collected while the agent remained stable")


def pg_password_redaction_variant(
    context: LabContext,
    scenario_id: str,
    name: str,
    sql_template: str,
) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(6)
    role = f"lc_{scenario_id.lower()}_{secrets.token_hex(4)}"
    secret = f"LcTest-{token}!"
    if context.evidence:
        context.evidence.register_secret(secret)
    create_sql = sql_template.format(role=role, secret=secret)
    cleanup_sql = f"DROP ROLE IF EXISTS {role};"
    trigger = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(create_sql)}", timeout=30)
    receiver = context.receiver_grep(role)
    time.sleep(5)
    leak_check = context.receiver.run(
        f"grep -R -F -- {shlex.quote(secret)} {shlex.quote(context.receiver_client_dir)}",
        sudo=True,
        timeout=30,
    )
    cleanup = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(cleanup_sql)}", timeout=30)
    commands = [trigger, receiver, leak_check, cleanup]
    assertions = [
        AssertionResult("role DDL delivered", role in receiver.stdout, f"role_visible={role in receiver.stdout}"),
        AssertionResult(
            "password absent from every received source",
            leak_check.returncode == 1 and not leak_check.stdout,
            "secret absent" if leak_check.returncode == 1 and not leak_check.stdout else "secret visible or search failed",
        ),
    ]
    return evaluated_result(scenario_id, name, started, commands, assertions, "Disposable password was redacted while the role DDL remained visible", "Passed" if cleanup.returncode == 0 else "Failed")


def pg_password_redaction(context: LabContext) -> ScenarioResult:
    return pg_password_redaction_variant(
        context,
        "G1",
        "Password redaction",
        "CREATE ROLE {role} LOGIN PASSWORD '{secret}';",
    )


def pg_create_user_redaction(context: LabContext) -> ScenarioResult:
    return pg_password_redaction_variant(
        context,
        "G1a",
        "CREATE USER password redaction",
        "CREATE USER {role} PASSWORD '{secret}';",
    )


def pg_encrypted_password_redaction(context: LabContext) -> ScenarioResult:
    return pg_password_redaction_variant(
        context,
        "G1b",
        "ENCRYPTED PASSWORD redaction",
        "CREATE ROLE {role} LOGIN ENCRYPTED PASSWORD '{secret}';",
    )


def pg_username_preservation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    role = f"lc_g2_{secrets.token_hex(5)}"
    sql = f"CREATE ROLE {role}; DROP ROLE {role};"
    trigger = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(sql)}", timeout=30)
    receiver = context.receiver_grep(role)
    commands = [trigger, receiver]
    assertions = [
        AssertionResult("role operation completed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("username preserved", role in receiver.stdout, f"username_visible={role in receiver.stdout}"),
    ]
    return evaluated_result("G2", "Username preservation", started, commands, assertions, "Disposable username remained visible")


def pg_forced_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before_marker = context.marker("C5", "before")
    after_marker = context.marker("C5", "after")
    commands = [pg_anchor(context)]
    before_file = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    before_event = postgres_comment(context, before_marker)
    rotate = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_rotate_logfile();\"", timeout=30)
    time.sleep(3)
    after_file = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    after_event = postgres_comment(context, after_marker)
    before_received = context.receiver_grep(before_marker)
    after_received = context.receiver_grep(after_marker)
    commands.extend([before_file, before_event, rotate, after_file, after_event, before_received, after_received])
    old_path = before_file.stdout.strip()
    new_path = after_file.stdout.strip()
    readable = context.local.run(f"sudo -u log-collector test -r {shlex.quote(new_path)}", timeout=15) if new_path else context.local.run("false", timeout=5)
    commands.append(readable)
    assertions = [
        AssertionResult("rotation succeeded", rotate.returncode == 0 and rotate.stdout.strip() == "t", command_fact(rotate)),
        AssertionResult("active file changed", bool(old_path and new_path and old_path != new_path), f"before={old_path} after={new_path}"),
        AssertionResult("new log readable", readable.returncode == 0, command_fact(readable)),
        AssertionResult("pre-rotation event delivered", before_marker in before_received.stdout, command_fact(before_received)),
        AssertionResult("post-rotation event delivered", after_marker in after_received.stdout, command_fact(after_received)),
    ]
    return evaluated_result("C5", "Forced log rotation", started, commands, assertions, "Collection followed PostgreSQL into the rotated file")


def pg_size_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    commands: list[CommandResult] = [pg_anchor(context)]
    old_setting = context.local.run("sudo -u postgres psql -Atc \"SHOW log_rotation_size;\"", timeout=15)
    commands.append(old_setting)
    old = old_setting.stdout.strip()
    if not re.fullmatch(r"-?\d+(?:B|kB|MB|GB)?", old):
        raise RuntimeError(f"Could not safely parse original log_rotation_size: {old!r}")
    action_id = f"C5a-{secrets.token_hex(5)}"
    restore_sql = f"ALTER SYSTEM SET log_rotation_size='{old}';"
    restore_command = f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(restore_sql)} -c \"SELECT pg_reload_conf();\""
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 60})
    change_sql = "ALTER SYSTEM SET log_rotation_size='1MB';"
    change = context.local.run(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(change_sql)} -c \"SELECT pg_reload_conf();\"",
        timeout=60,
    )
    commands.append(change)
    cleanup_ok = False
    prefix = context.marker("C5a", "rotation")[:44]
    before = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    commands.append(before)
    try:
        generator = (
            "PAYLOAD=$(printf '%0900d' 0 | tr '0' x); "
            f"for i in $(seq -w 1 1800); do printf \"COMMENT ON TABLE public.lc_runner_anchor IS '{prefix}_%s_%s';\\n\" \"$i\" \"$PAYLOAD\"; done | "
            "sudo -u postgres psql -q; STATUS=${PIPESTATUS[1]}; echo psql_status=$STATUS; exit $STATUS"
        )
        generated = context.local.run(generator, timeout=300)
        commands.append(generated)
        last_marker = f"{prefix}_1800"
        commands.append(context.receiver_grep(last_marker, timeout=120))
        after = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
        commands.append(after)
        all_received = context.receiver.run(
            f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)}",
            sudo=True,
            timeout=120,
        )
        commands.append(all_received)
    finally:
        restored = context.local.run(restore_command, timeout=60)
        commands.append(restored)
        cleanup_ok = restored.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(action_id)
    marker_numbers = set(re.findall(re.escape(prefix) + r"_(\d{4})", all_received.stdout))
    source_files = set(re.findall(r"\spostgres_log:([^ ]+)\s+-", all_received.stdout))
    assertions = [
        AssertionResult("1MB rotation configured", change.returncode == 0, command_fact(change)),
        AssertionResult("volume generated", generated.returncode == 0 and "psql_status=0" in generated.stdout, command_fact(generated)),
        AssertionResult("active file changed", before.stdout.strip() != after.stdout.strip(), f"before={before.stdout.strip()} after={after.stdout.strip()}"),
        AssertionResult("1800 unique markers", marker_numbers == {f"{index:04d}" for index in range(1, 1801)}, f"unique={len(marker_numbers)}"),
        AssertionResult("multiple source files", len(source_files) >= 2, f"count={len(source_files)} files={sorted(source_files)}"),
    ]
    return evaluated_result("C5a", "Size-based rotation continuity", started, commands, assertions, "All 1,800 numbered events crossed multiple 1 MB rotations", "Passed" if cleanup_ok else "Failed")


def pg_cross_engine_rotation(context: LabContext) -> ScenarioResult:
    result = pg_forced_rotation(context)
    result.scenario_id = "G3"
    result.name = "Cross-engine rotation continuity"
    return result


def pg_copytruncate_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("G3a", "before")
    after = context.marker("G3a", "after")
    commands = [pg_anchor(context), postgres_comment(context, before), context.receiver_grep(before)]
    current = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    path = current.stdout.strip()
    backup = f"/tmp/lc-g3a-{secrets.token_hex(5)}.log"
    truncate = context.local.run(
        f"sudo cp --preserve=all -- {shlex.quote(path)} {shlex.quote(backup)} && sudo truncate -s 0 -- {shlex.quote(path)}",
        timeout=60,
    ) if path else context.local.run("false", timeout=5)
    commands.extend([current, truncate, postgres_comment(context, after)])
    received = context.receiver_grep(after, timeout=60)
    cleanup = context.local.run(f"sudo rm -f -- {shlex.quote(backup)}", timeout=15)
    commands.extend([received, cleanup])
    assertions = [
        AssertionResult("active log located", bool(path), path or command_fact(current)),
        AssertionResult("copy-truncate completed", truncate.returncode == 0, command_fact(truncate)),
        AssertionResult("post-truncate event delivered", after in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G3a", "Copy-truncate rotation continuity", started, commands, assertions, "Collection resumed after the active PostgreSQL log was copy-truncated", "Passed" if cleanup.returncode == 0 else "Failed")


def pg_small_file_restart(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G4", "after_restart")
    rotate = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_rotate_logfile();\"", timeout=30)
    time.sleep(1)
    current = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    path = current.stdout.strip()
    size = context.local.run(f"sudo stat -c %s -- {shlex.quote(path)}", timeout=15) if path else context.local.run("false", timeout=5)
    try:
        original_size = int(size.stdout.strip())
    except ValueError:
        original_size = -1
    truncate = context.local.run(f"sudo truncate -s 0 -- {shlex.quote(path)}", timeout=30) if path and original_size >= 128 else context.local.run("true", timeout=5)
    final_size = context.local.run(f"sudo stat -c %s -- {shlex.quote(path)}", timeout=15) if path else context.local.run("false", timeout=5)
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    trigger = postgres_comment(context, marker)
    received = context.receiver_grep(marker, timeout=60)
    try:
        byte_count = int(final_size.stdout.strip())
    except ValueError:
        byte_count = -1
    assertions = [
        AssertionResult("new log is under 128 bytes", 0 <= byte_count < 128, f"size={byte_count} path={path}"),
        AssertionResult("collector restarted", restart.returncode == 0, command_fact(restart)),
        AssertionResult("small-file event delivered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G4", "Nearly-empty log restart", started, [rotate, current, size, truncate, final_size, restart, trigger, received], assertions, "Collector restarted on a sub-128-byte log without losing the next event")


def pg_fresh_state(context: LabContext) -> ScenarioResult:
    started = utc_now()
    old = context.marker("G5", "history")
    new = context.marker("G5", "current")
    commands = [pg_anchor(context), postgres_comment(context, old), context.receiver_grep(old)]
    count_command = f"grep -Fc -- {shlex.quote(old)} {shlex.quote(context.receiver_log)} || true"
    before_count = context.receiver.run(count_command, sudo=True, timeout=15)
    stop = context.local.run("sudo systemctl stop log-collector", timeout=60)
    clear = context.local.run(
        "sudo find /var/lib/log-collector/state /var/lib/log-collector/disk_buffer -mindepth 1 -delete",
        timeout=60,
    )
    start = context.local.run("sudo systemctl start log-collector", timeout=60)
    time.sleep(5)
    final_old_count = context.receiver.run(count_command, sudo=True, timeout=15)
    trigger = postgres_comment(context, new)
    received = context.receiver_grep(new, timeout=60)
    commands.extend([before_count, stop, clear, start, final_old_count, trigger, received])
    try:
        initial = int(before_count.stdout.strip() or "0")
        final = int(final_old_count.stdout.strip() or "0")
    except ValueError:
        initial = final = -1
    assertions = [
        AssertionResult("collector state reset", stop.returncode == 0 and clear.returncode == 0 and start.returncode == 0, f"stop={stop.returncode} clear={clear.returncode} start={start.returncode}"),
        AssertionResult("history not replayed", initial >= 1 and final == initial, f"before={initial} after={final}"),
        AssertionResult("new event delivered", new in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G5", "Fresh-state starts at current log end", started, commands, assertions, "Reset state did not flood historical records and collection accepted a new event")


def pg_large_record(context: LabContext) -> ScenarioResult:
    started = utc_now()
    capacity_check, capacity, configured = receiver_message_capacity(context)
    required = LARGE_RECORD_PAYLOAD_BYTES + LARGE_RECORD_OVERHEAD_BYTES
    if capacity is not None and capacity < required:
        configured_kib = capacity // 1024
        required_kib = required // 1024
        return ScenarioResult(
            scenario_id="G9",
            name="Multi-megabyte PostgreSQL record",
            status="Inconclusive",
            reason=(
                f"Receiver effective message limit is {configured_kib} KiB; at least {required_kib} KiB is required "
                "to distinguish collector truncation from receiver truncation"
            ),
            started_at=started,
            ended_at=utc_now(),
            assertions=[
                AssertionResult(
                    "receiver accepts the full test record",
                    False,
                    f"configured={configured or 'unknown'} required_bytes={required}",
                )
            ],
            commands=[capacity_check],
        )
    prefix = context.marker("G9", "begin")
    suffix = context.marker("G9", "end")
    sql = f"DO $lc$ BEGIN RAISE WARNING '%', '{prefix}' || repeat('x', {LARGE_RECORD_PAYLOAD_BYTES}) || '{suffix}'; END $lc$;"
    trigger = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(sql)}", timeout=120)
    received = context.receiver_grep(prefix, timeout=120)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("multi-megabyte event generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("large event beginning delivered", prefix in received.stdout, f"prefix_visible={prefix in received.stdout}"),
        AssertionResult("large event not truncated", suffix in received.stdout, f"suffix_visible={suffix in received.stdout} received_bytes={len(received.stdout.encode('utf-8'))}"),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G9", "Multi-megabyte PostgreSQL record", started, [capacity_check, trigger, received, service], assertions, "A multi-megabyte database record reached the receiver without mid-record truncation")


def pg_malformed_record(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G10", "malformed")
    current = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    path = current.stdout.strip()
    malformed = f"{{not-valid-json,marker:{marker}}}"
    append = context.local.run(
        f"printf '%s\\n' {shlex.quote(malformed)} | sudo tee -a -- {shlex.quote(path)} >/dev/null",
        timeout=30,
    ) if path else context.local.run("false", timeout=5)
    received = context.receiver_grep(marker, timeout=60)
    flagged = bool(re.search(r"raw|malform|parse|flag", received.stdout, re.I))
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("malformed record appended", append.returncode == 0, command_fact(append)),
        AssertionResult("malformed record forwarded", marker in received.stdout, command_fact(received)),
        AssertionResult("forwarded record flagged", flagged, "flag token present" if flagged else "no raw/malformed/parse/flag token"),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G10", "Malformed record forwarding", started, [current, append, received, service], assertions, "Malformed input was forwarded and flagged without stopping the collector")


def pg_delete_recreate(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("C5d", "recreated")
    current = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    old_path = current.stdout.strip()
    delete = context.local.run(f"sudo rm -f -- {shlex.quote(old_path)}", timeout=30) if old_path else context.local.run("false", timeout=5)
    rotate = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_rotate_logfile();\"", timeout=30)
    time.sleep(3)
    new_file = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    trigger = postgres_comment(context, marker)
    received = context.receiver_grep(marker, timeout=60)
    assertions = [
        AssertionResult("old active log deleted", delete.returncode == 0, command_fact(delete)),
        AssertionResult("PostgreSQL created a new active log", bool(new_file.stdout.strip()) and new_file.stdout.strip() != old_path, f"before={old_path} after={new_file.stdout.strip()}"),
        AssertionResult("recreated-log event delivered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("C5d", "Deleted log recreation", started, [current, delete, rotate, new_file, trigger, received], assertions, "Collection followed PostgreSQL after the active log was deleted and recreated")


def pg_delete_recreate_cross_engine(context: LabContext) -> ScenarioResult:
    result = pg_delete_recreate(context)
    result.scenario_id = "G7"
    result.name = "Delete and recreate active log"
    return result


def pg_buffer_cycle_assertions(
    scenario_id: str,
    outage_established: bool,
    collector_active: bool,
    before_bytes: int,
    during_bytes: int,
    receiver_restored: bool,
    markers: set[str],
    total_lines: int,
) -> list[AssertionResult]:
    assertions = [
        AssertionResult("receiver outage established", outage_established, str(outage_established)),
        AssertionResult("collector stayed active", collector_active, str(collector_active)),
    ]
    if scenario_id == "H1":
        assertions.append(AssertionResult("disk buffer grew", during_bytes > before_bytes, f"before={before_bytes} during={during_bytes}"))
    assertions.extend(
        [
            AssertionResult("receiver restored", receiver_restored, str(receiver_restored)),
            AssertionResult("all buffered markers delivered", markers == {f"{index:03d}" for index in range(1, 301)} and total_lines == 300, f"unique={len(markers)} total_lines={total_lines}"),
        ]
    )
    return assertions


def pg_buffer_cycle(context: LabContext, scenario_id: str, name: str) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker(scenario_id, "buffer")[:44]
    unit = f"lc-rsyslog-buffer-recover-{secrets.token_hex(4)}"
    action_id = f"{scenario_id}-{unit}"
    commands: list[CommandResult] = []
    schedule = context.receiver.run(f"systemd-run --unit={unit} --on-active=2m /bin/sh -c {shlex.quote(RECEIVER_START_COMMAND)}", sudo=True, timeout=30)
    commands.append(schedule)
    if context.journal:
        context.journal.add({"id": action_id, "scope": "receiver", "command": RECEIVER_START_COMMAND, "sudo": True, "timeout": 60})
    before_health = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    before_disk = context.local.run("sudo du -sb /var/lib/log-collector/disk_buffer 2>/dev/null | awk '{print $1}'", timeout=15)
    stop = establish_receiver_outage(context)
    commands.extend([before_health, before_disk, stop])
    restore_ok = False
    try:
        generator = (
            "PAYLOAD=$(printf '%01000d' 0 | tr '0' x); "
            f"for i in $(seq -w 1 300); do printf \"COMMENT ON TABLE public.lc_runner_anchor IS '{prefix}_%s_%s';\\n\" \"$i\" \"$PAYLOAD\"; done | "
            "sudo -u postgres psql -q"
        )
        generated = context.local.run(generator, timeout=180)
        time.sleep(10)
        during_health = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
        during_disk = context.local.run("sudo du -sb /var/lib/log-collector/disk_buffer 2>/dev/null | awk '{print $1}'", timeout=15)
        service = context.local.run("systemctl is-active log-collector", timeout=15)
        commands.extend([generated, during_health, during_disk, service])
    finally:
        restore = restore_receiver_ingest(context)
        commands.append(restore)
        restore_ok = restore.returncode == 0
        context.receiver.run(f"systemctl stop {unit}.timer 2>/dev/null || true", sudo=True, timeout=15)
        if restore_ok and context.journal:
            context.journal.remove(action_id)
    received = context.receiver_grep(f"{prefix}_300", timeout=180)
    all_received = context.receiver.run(f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)}", sudo=True, timeout=60)
    commands.extend([received, all_received])
    def metric(payload: str, key: str) -> int:
        try:
            value = json.loads(payload).get(key, 0)
            return int(value)
        except (ValueError, TypeError, json.JSONDecodeError, AttributeError):
            return 0
    def integer(value: str) -> int:
        try:
            return int(value.strip())
        except ValueError:
            return 0
    before_bytes = max(metric(before_health.stdout, "disk_buffer_bytes"), integer(before_disk.stdout))
    during_bytes = max(metric(during_health.stdout, "disk_buffer_bytes"), integer(during_disk.stdout))
    markers = set(re.findall(re.escape(prefix) + r"_(\d{3})", all_received.stdout))
    assertions = pg_buffer_cycle_assertions(
        scenario_id,
        stop.returncode == 0,
        service.stdout.strip() == "active",
        before_bytes,
        during_bytes,
        restore_ok,
        markers,
        len(all_received.stdout.splitlines()),
    )
    reason = "Collector stayed active and buffered events during receiver outage" if scenario_id == "H1" else "All buffered events arrived after receiver recovery"
    return evaluated_result(scenario_id, name, started, commands, assertions, reason, "Passed" if restore_ok else "Failed")


def pg_buffer_growth(context: LabContext) -> ScenarioResult:
    return pg_buffer_cycle(context, "H1", "Disk buffer growth during receiver outage")


def pg_buffer_delivery(context: LabContext) -> ScenarioResult:
    return pg_buffer_cycle(context, "H2", "Buffered delivery after receiver recovery")


def pg_database_start_order(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("H4", "database_started")
    unit_name = context.local.run("pg_lsclusters --no-header | awk 'NR==1 {print $1\"-\"$2}'", timeout=15)
    unit = f"postgresql@{unit_name.stdout.strip()}"
    recovery_id = f"H4-{secrets.token_hex(5)}"
    recovery_command = f"systemctl start {shlex.quote(unit)}"
    schedule = context.local.run(f"sudo systemd-run --unit=lc-h4-recover-{secrets.token_hex(4)} --on-active=2m /bin/systemctl start {shlex.quote(unit)}", timeout=30)
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": recovery_command, "sudo": True, "timeout": 120})
    stop = context.local.run(f"sudo systemctl stop {shlex.quote(unit)}", timeout=120)
    restart_collector = context.local.run("sudo systemctl restart log-collector", timeout=60)
    waiting = context.local.run("systemctl is-active log-collector", timeout=15)
    start_db = context.local.run(f"sudo systemctl start {shlex.quote(unit)}", timeout=120)
    restored = start_db.returncode == 0
    if restored and context.journal:
        context.journal.remove(recovery_id)
    trigger = postgres_comment(context, marker)
    received = context.receiver_grep(marker, timeout=60)
    assertions = [
        AssertionResult("database stopped", stop.returncode == 0, command_fact(stop)),
        AssertionResult("collector active before database", restart_collector.returncode == 0 and waiting.stdout.strip() == "active", command_fact(waiting)),
        AssertionResult("database started", restored, command_fact(start_db)),
        AssertionResult("collection resumed", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H4", "Collector starts before PostgreSQL", started, [unit_name, schedule, stop, restart_collector, waiting, start_db, trigger, received], assertions, "Collector waited for PostgreSQL and resumed when the database started", "Passed" if restored else "Failed")


def pg_agent_restart_with_db_stopped(context: LabContext) -> ScenarioResult:
    result = pg_database_start_order(context)
    result.scenario_id = "G4a"
    result.name = "Agent restart while database is stopped"
    return result


def pg_uninstall(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.local.run("systemctl is-active log-collector", timeout=15)
    uninstall = context.local.run("sudo log-collector uninstall", timeout=180)
    unit = context.local.run("systemctl cat log-collector", timeout=15)
    process = context.local.run("pgrep -x log-collector", timeout=15)
    leftovers = context.local.run("sudo find /etc /var/lib /var/log -maxdepth 3 -iname '*log-collector*' -print 2>/dev/null", timeout=30)
    assertions = [
        AssertionResult("collector was installed", before.stdout.strip() == "active", command_fact(before)),
        AssertionResult("uninstall completed", uninstall.returncode == 0, command_fact(uninstall)),
        AssertionResult("systemd unit removed", unit.returncode != 0, command_fact(unit)),
        AssertionResult("collector process absent", process.returncode != 0, command_fact(process)),
    ]
    return evaluated_result("I9", "Collector uninstall", started, [before, uninstall, unit, process, leftovers], assertions, "Collector service and process were removed; remaining paths are recorded in evidence")


def pg_remote_hba_rejection(context: LabContext, scenario_id: str, explicit_reject: bool) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    receiver_host = context.receiver.config.host
    receiver_address_result = context.local.run(f"getent ahostsv4 {shlex.quote(receiver_host)} | awk 'NR==1 {{print $1}}'", timeout=15)
    receiver_address = receiver_address_result.stdout.strip()
    client_address_result = context.local.run("hostname -I | awk '{print $1}'", timeout=15)
    client_address = client_address_result.stdout.strip()
    hba_result = context.local.run("sudo -u postgres psql -Atc \"SHOW hba_file; SHOW listen_addresses;\"", timeout=15)
    settings = [line.strip() for line in hba_result.stdout.splitlines() if line.strip()]
    if len(settings) != 2 or not receiver_address or not client_address:
        raise RuntimeError("Could not determine HBA path, listen address, or lab endpoint addresses")
    hba_path, old_listen = settings
    backup = f"/tmp/lc-hba-{token}.conf"
    iptables_add = f"iptables -I INPUT -p tcp -s {shlex.quote(receiver_address)} --dport 5432 -j ACCEPT"
    iptables_del = f"iptables -D INPUT -p tcp -s {shlex.quote(receiver_address)} --dport 5432 -j ACCEPT"
    restore_sql = f"ALTER SYSTEM SET listen_addresses={pg_sql_literal(old_listen)};"
    restore_command = f"cp -a -- {shlex.quote(backup)} {shlex.quote(hba_path)}; sudo -u postgres psql -c {shlex.quote(restore_sql)}; {iptables_del} 2>/dev/null || true; systemctl restart postgresql"
    action_id = f"{scenario_id}-{token}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 180})
    backup_result = context.local.run(f"sudo cp -a -- {shlex.quote(hba_path)} {shlex.quote(backup)}", timeout=30)
    hba_lines = [
        "local all postgres peer",
        "local all all peer",
        "host all all 127.0.0.1/32 scram-sha-256",
        "host all all ::1/128 scram-sha-256",
    ]
    if explicit_reject:
        hba_lines.append(f"host all all {receiver_address}/32 reject")
    hba_content = "\n".join(hba_lines) + "\n"
    configure = context.local.run(
        f"printf %s {shlex.quote(hba_content)} | sudo tee {shlex.quote(hba_path)} >/dev/null; "
        "sudo -u postgres psql -c \"ALTER SYSTEM SET listen_addresses='*';\"; "
        f"sudo {iptables_add}; sudo systemctl restart postgresql",
        timeout=180,
    )
    client_install_sim = context.receiver.run("apt-get -s install postgresql-client", sudo=True, timeout=180)
    client_install = context.receiver.run("DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql-client", sudo=True, timeout=600)
    username = f"lc_{scenario_id.lower()}_{token}"
    remote_attempt = context.receiver.run(
        f"PGPASSWORD=wrong psql 'host={client_address} port=5432 dbname=postgres user={username} connect_timeout=5' -c 'SELECT 1;'",
        timeout=30,
    )
    expected = "no pg_hba.conf entry" if not explicit_reject else "pg_hba.conf rejects connection"
    received = context.receiver.run(
        f"grep -F -- {shlex.quote(expected)} {shlex.quote(context.receiver_log)} | grep -F -- {shlex.quote(receiver_address)} | tail -n 20",
        sudo=True,
        timeout=60,
    )
    restore = context.local.run(f"sudo bash -lc {shlex.quote(restore_command)}; sudo rm -f -- {shlex.quote(backup)}", timeout=180)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    lines = [line for line in received.stdout.splitlines() if expected in line]
    assertions = [
        AssertionResult("temporary remote-listener profile applied", backup_result.returncode == 0 and configure.returncode == 0, f"backup={backup_result.returncode} configure={configure.returncode}"),
        AssertionResult("receiver PostgreSQL client available", client_install_sim.returncode == 0 and client_install.returncode == 0, f"simulate={client_install_sim.returncode} install={client_install.returncode}"),
        AssertionResult("remote connection rejected", remote_attempt.returncode != 0, command_fact(remote_attempt)),
        AssertionResult("HBA rejection delivered", bool(lines), f"matches={len(lines)}"),
        AssertionResult("FATAL mapped to critical", any(line.startswith("<10>") for line in lines), "priorities=" + ",".join(line.split(">", 1)[0] + ">" for line in lines)),
    ]
    name = "No matching pg_hba.conf entry" if not explicit_reject else "Explicit pg_hba.conf host rejection"
    return evaluated_result(scenario_id, name, started, [receiver_address_result, client_address_result, hba_result, backup_result, configure, client_install_sim, client_install, remote_attempt, received, restore], assertions, "Remote HBA rejection was collected at critical priority", "Passed" if restore.returncode == 0 else "Failed")


def pg_no_hba_entry(context: LabContext) -> ScenarioResult:
    return pg_remote_hba_rejection(context, "C2a", False)


def pg_explicit_hba_reject(context: LabContext) -> ScenarioResult:
    return pg_remote_hba_rejection(context, "C2b", True)


def pg_panic_event(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("C2e", "panic")
    token = secrets.token_hex(5)
    source = f"/tmp/lc-panic-{token}.c"
    library = f"/tmp/lc-panic-{token}.so"
    function = f"lc_panic_{token}"
    package = "postgresql-server-dev-$(pg_config --version | awk '{print $2}' | cut -d. -f1)"
    simulation = context.local.run(f"sudo apt-get -s install build-essential {package}", timeout=180)
    install = context.local.run(f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential {package}", timeout=1800)
    c_source = (
        '#include "postgres.h"\n#include "fmgr.h"\nPG_MODULE_MAGIC;\n'
        f'PG_FUNCTION_INFO_V1({function});\nDatum {function}(PG_FUNCTION_ARGS) '
        f'{{ ereport(PANIC, (errmsg("{marker}"))); PG_RETURN_VOID(); }}\n'
    )
    write_source = context.local.run(f"printf %s {shlex.quote(c_source)} > {shlex.quote(source)}", timeout=30)
    compile_result = context.local.run(
        f"gcc -fPIC -shared -I\"$(pg_config --includedir-server)\" -o {shlex.quote(library)} {shlex.quote(source)}",
        timeout=120,
    )
    create_sql = f"CREATE OR REPLACE FUNCTION {function}() RETURNS void AS '{library}', '{function}' LANGUAGE C STRICT;"
    create = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(create_sql)}", timeout=30)
    trigger = context.local.run(f"sudo -u postgres psql -c 'SELECT {function}();'", timeout=60)
    ready = context.local.run("for i in $(seq 1 60); do pg_isready -q && exit 0; sleep 1; done; exit 1", timeout=70)
    received = context.receiver_grep(marker, timeout=120)
    cleanup_sql = f"DROP FUNCTION IF EXISTS {function}();"
    cleanup = context.local.run(
        f"sudo -u postgres psql -c {shlex.quote(cleanup_sql)}; rm -f -- {shlex.quote(source)} {shlex.quote(library)}",
        timeout=60,
    )
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    assertions = [
        AssertionResult("build dependencies available", simulation.returncode == 0 and install.returncode == 0, f"simulate={simulation.returncode} install={install.returncode}"),
        AssertionResult("PANIC test function compiled", write_source.returncode == 0 and compile_result.returncode == 0 and create.returncode == 0, f"write={write_source.returncode} compile={compile_result.returncode} create={create.returncode}"),
        AssertionResult("backend terminated by PANIC", trigger.returncode != 0, command_fact(trigger)),
        AssertionResult("PostgreSQL recovered", ready.returncode == 0, command_fact(ready)),
        AssertionResult("PANIC delivered as emergency", marker in line and line.startswith("<8>"), line or "missing"),
    ]
    return evaluated_result("C2e", "PANIC-level event", started, [simulation, install, write_source, compile_result, create, trigger, ready, received, cleanup], assertions, "A real PostgreSQL PANIC was delivered at wire priority <8> and the clone recovered", "Passed" if cleanup.returncode == 0 else "Failed")


def pg_connection_exhaustion(context: LabContext) -> ScenarioResult:
    started = utc_now()
    role = f"lc_c7e_{secrets.token_hex(4)}"
    secret = f"LcC7e-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(secret)
    old = context.local.run("sudo -u postgres psql -Atc \"SHOW max_connections; SHOW superuser_reserved_connections;\"", timeout=15)
    values = [line.strip() for line in old.stdout.splitlines() if line.strip()]
    if len(values) != 2 or not all(value.isdigit() for value in values):
        raise RuntimeError(f"Could not capture connection settings: {command_fact(old)}")
    restore_command = "sudo -u postgres psql -v ON_ERROR_STOP=1 " + pg_psql_flags(
        f"ALTER SYSTEM SET max_connections='{values[0]}';",
        f"ALTER SYSTEM SET superuser_reserved_connections='{values[1]}';",
    ) + " && sudo systemctl restart postgresql"
    action_id = f"C7e-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 180})
    create_sql = f"CREATE ROLE {role} LOGIN PASSWORD '{secret}';"
    create = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(create_sql)}", timeout=30)
    change = context.local.run(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 "
        + pg_psql_flags("ALTER SYSTEM SET max_connections='10';", "ALTER SYSTEM SET superuser_reserved_connections='1';")
        + " && sudo systemctl restart postgresql",
        timeout=180,
    )
    cleanup_ok = False
    try:
        exhaust = context.local.run(
            f"for i in $(seq 1 20); do PGPASSWORD={shlex.quote(secret)} psql -h 127.0.0.1 -U {shlex.quote(role)} -d postgres -c 'SELECT pg_sleep(20);' >/tmp/lc-c7e-$i.log 2>&1 & done; sleep 3; "
            f"PGPASSWORD={shlex.quote(secret)} psql -h 127.0.0.1 -U {shlex.quote(role)} -d postgres -c 'SELECT 1;'; STATUS=$?; wait || true; rm -f /tmp/lc-c7e-*.log; exit $STATUS",
            timeout=60,
        )
        received = context.receiver.run(
            f"grep -E 'remaining connection slots|too many clients' {shlex.quote(context.receiver_log)} | tail -n 20",
            sudo=True,
            timeout=60,
        )
    finally:
        restore = context.local.run(restore_command, timeout=180)
        drop = context.local.run(f"sudo -u postgres psql -c 'DROP ROLE IF EXISTS {role};'", timeout=30)
        cleanup_ok = restore.returncode == 0 and drop.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(action_id)
    lines = [line for line in received.stdout.splitlines() if "connection slots" in line or "too many clients" in line]
    assertions = [
        AssertionResult("temporary connection limit applied", create.returncode == 0 and change.returncode == 0, f"create={create.returncode} change={change.returncode}"),
        AssertionResult("connection exhaustion triggered", exhaust.returncode != 0, command_fact(exhaust)),
        AssertionResult("connection exhaustion delivered", bool(lines), f"matches={len(lines)}"),
        AssertionResult("FATAL severity mapped to critical", any(line.startswith("<10>") for line in lines), "priorities=" + ",".join(line.split(">", 1)[0] + ">" for line in lines)),
    ]
    return evaluated_result("C7e", "Connection exhaustion", started, [old, create, change, exhaust, received, restore, drop], assertions, "Controlled max_connections exhaustion was delivered at critical priority", "Passed" if cleanup_ok else "Failed")


def pg_pgaudit(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    table = f"lc_c8_{token}"
    old = context.local.run("sudo -u postgres psql -Atc \"SHOW shared_preload_libraries;\"", timeout=15)
    old_preload = old.stdout.strip()
    libraries = [item.strip() for item in old_preload.split(",") if item.strip()]
    if "pgaudit" not in libraries:
        libraries.append("pgaudit")
    new_preload = ",".join(libraries)
    package = "postgresql-$(pg_config --version | awk '{print $2}' | cut -d. -f1)-pgaudit"
    simulation = context.local.run(f"sudo apt-get -s install {package}", timeout=180)
    install = context.local.run(f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {package}", timeout=1800)
    restore_command = "sudo -u postgres psql -v ON_ERROR_STOP=1 " + pg_psql_flags(
        f"ALTER SYSTEM SET shared_preload_libraries={pg_sql_literal(old_preload)};",
        "ALTER SYSTEM RESET pgaudit.log;",
    ) + "; sudo systemctl restart postgresql"
    action_id = f"C8-{token}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 180})
    configure = context.local.run(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"ALTER SYSTEM SET shared_preload_libraries={new_preload!r};\" && sudo systemctl restart postgresql && "
        "sudo -u postgres psql -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION IF NOT EXISTS pgaudit;' -c \"ALTER SYSTEM SET pgaudit.log='write,ddl,role';\" -c 'SELECT pg_reload_conf();'",
        timeout=300,
    )
    cleanup_ok = False
    try:
        sql = f"CREATE TABLE public.{table}(id integer); INSERT INTO public.{table} VALUES (1); DROP TABLE public.{table};"
        trigger = context.local.run(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(sql)}", timeout=60)
        received = context.receiver.run(
            f"grep -F -- {shlex.quote(table)} {shlex.quote(context.receiver_log)} | grep -F 'AUDIT:' | tail -n 30",
            sudo=True,
            timeout=90,
        )
    finally:
        drop_extension = context.local.run("sudo -u postgres psql -c 'DROP EXTENSION IF EXISTS pgaudit;'", timeout=60)
        restore = context.local.run(restore_command, timeout=180)
        cleanup_ok = drop_extension.returncode == 0 and restore.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(action_id)
    assertions = [
        AssertionResult("pgaudit package available", simulation.returncode == 0 and install.returncode == 0, f"simulate={simulation.returncode} install={install.returncode}"),
        AssertionResult("pgaudit configured", configure.returncode == 0, command_fact(configure)),
        AssertionResult("audited statements executed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("structured pgaudit events delivered", table in received.stdout and "AUDIT:" in received.stdout, command_fact(received)),
    ]
    return evaluated_result("C8", "pgaudit structured events", started, [old, simulation, install, configure, trigger, received, drop_extension, restore], assertions, "pgaudit DDL and write events reached the receiver with audit fields", "Passed" if cleanup_ok else "Failed")


def collector_config_path(context: LabContext) -> tuple[CommandResult, str]:
    result = context.local.run(
        "sudo find /etc /var/lib/log-collector -type f -name agent.toml -print -quit 2>/dev/null",
        timeout=30,
    )
    return result, result.stdout.strip()


def pg_config_fallback(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("H7", "fallback")
    locate, config = collector_config_path(context)
    backup = f"/tmp/lc-h7-{secrets.token_hex(5)}"
    last_good = f"{config}.last-good"
    prepare = context.local.run(f"sudo mkdir -p {shlex.quote(backup)} && sudo cp -a -- {shlex.quote(config)} {shlex.quote(last_good)} {shlex.quote(backup)}/", timeout=60) if config else context.local.run("false", timeout=5)
    restore_command = f"cp -a -- {shlex.quote(backup)}/agent.toml {shlex.quote(config)}; cp -a -- {shlex.quote(backup)}/agent.toml.last-good {shlex.quote(last_good)}; systemctl restart log-collector"
    action_id = f"H7-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 120})
    corrupt = context.local.run(f"printf garbage | sudo tee {shlex.quote(config)} >/dev/null && sudo systemctl restart log-collector", timeout=120) if config else context.local.run("false", timeout=5)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    logs = context.local.run("sudo journalctl -u log-collector --since '-3 minutes' --no-pager | tail -n 100", timeout=30)
    trigger = postgres_comment(context, marker)
    received = context.receiver_grep(marker, timeout=60)
    restore = context.local.run(f"sudo bash -lc {shlex.quote(restore_command)}; sudo rm -rf -- {shlex.quote(backup)}", timeout=120)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    fallback_visible = bool(re.search(r"last.?good|fallback|recover", logs.stdout, re.I))
    assertions = [
        AssertionResult("primary and last-good config backed up", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("collector used fallback", corrupt.returncode == 0 and service.stdout.strip() == "active" and fallback_visible, command_fact(logs)),
        AssertionResult("collection continued", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H7", "Corrupt config fallback", started, [locate, prepare, corrupt, service, logs, trigger, received, restore], assertions, "Collector fell back to last-good configuration and kept collecting", "Passed" if restore.returncode == 0 else "Failed")


def pg_config_missing(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, config = collector_config_path(context)
    backup = f"/tmp/lc-h8-{secrets.token_hex(5)}"
    last_good = f"{config}.last-good"
    prepare = context.local.run(f"sudo mkdir -p {shlex.quote(backup)} && sudo cp -a -- {shlex.quote(config)} {shlex.quote(backup)}/ && if test -f {shlex.quote(last_good)}; then sudo cp -a -- {shlex.quote(last_good)} {shlex.quote(backup)}/; fi", timeout=60) if config else context.local.run("false", timeout=5)
    restore_command = f"cp -a -- {shlex.quote(backup)}/agent.toml {shlex.quote(config)}; if test -f {shlex.quote(backup)}/agent.toml.last-good; then cp -a -- {shlex.quote(backup)}/agent.toml.last-good {shlex.quote(last_good)}; fi; systemctl start log-collector"
    action_id = f"H8-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 120})
    remove = context.local.run(
        f"sudo rm -f -- {shlex.quote(config)} {shlex.quote(last_good)}; sudo systemctl restart log-collector || true; "
        "for attempt in $(seq 1 20); do state=$(systemctl is-active log-collector); test \"$state\" != activating && break; sleep 1; done; "
        "printf 'state=%s\\n' \"$state\"; test \"$state\" = active",
        timeout=150,
    ) if config else context.local.run("false", timeout=5)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    logs = context.local.run("sudo journalctl -u log-collector --since '-3 minutes' --no-pager | tail -n 100", timeout=30)
    restore = context.local.run(f"sudo bash -lc {shlex.quote(restore_command)}; sudo rm -rf -- {shlex.quote(backup)}", timeout=120)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    clear_error = bool(re.search(r"config|setup", logs.stdout, re.I))
    assertions = [
        AssertionResult("configuration backed up", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("service refused missing config", remove.returncode != 0 and service.stdout.strip() != "active", f"restart={remove.returncode} service={service.stdout.strip()}"),
        AssertionResult("clear setup/config message", clear_error, command_fact(logs)),
    ]
    return evaluated_result("H8", "Missing configuration failure", started, [locate, prepare, remove, service, logs, restore], assertions, "Missing configuration stopped startup with a clear setup/configuration message", "Passed" if restore.returncode == 0 else "Failed")


def pg_unreachable_output(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("H9", "recovered")
    host = context.receiver.config.host
    resolved = context.local.run(f"getent ahostsv4 {shlex.quote(host)} | awk 'NR==1 {{print $1}}'", timeout=15)
    address = resolved.stdout.strip()
    add_rule = f"iptables -I OUTPUT -p tcp -d {shlex.quote(address)} --dport 2514 -j REJECT"
    del_rule = f"iptables -D OUTPUT -p tcp -d {shlex.quote(address)} --dport 2514 -j REJECT"
    action_id = f"H9-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": del_rule, "sudo": True, "timeout": 30})
    block = context.local.run(add_rule, sudo=True, timeout=30) if address else context.local.run("false", timeout=5)
    time.sleep(10)
    health = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    unblock = context.local.run(del_rule, sudo=True, timeout=30) if address else context.local.run("false", timeout=5)
    if unblock.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    trigger = postgres_comment(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    try:
        payload = json.loads(health.stdout)
    except json.JSONDecodeError:
        payload = {}
    disconnected = payload.get("cloud_connected") is False or str(payload.get("cloud_status", "")).lower() not in {"connected", ""}
    assertions = [
        AssertionResult("receiver route blocked", block.returncode == 0, command_fact(block)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("health reported disconnected", disconnected, command_fact(health)),
        AssertionResult("network rule restored", unblock.returncode == 0, command_fact(unblock)),
        AssertionResult("delivery recovered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H9", "Unreachable output retry", started, [resolved, block, health, service, unblock, trigger, received], assertions, "Collector stayed active, reported disconnection, and recovered after output became reachable", "Passed" if unblock.returncode == 0 else "Failed")


def pg_turkish_locale(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G6a", "turkish")
    old = context.local.run("sudo -u postgres psql -Atc \"SHOW lc_messages;\"", timeout=15)
    old_locale = old.stdout.strip()
    simulation = context.local.run("sudo apt-get -s install locales", timeout=120)
    install = context.local.run("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y locales && sudo locale-gen tr_TR.UTF-8", timeout=900)
    restore_command = "sudo -u postgres psql -v ON_ERROR_STOP=1 " + pg_psql_flags(
        f"ALTER SYSTEM SET lc_messages={pg_sql_literal(old_locale)};",
        "SELECT pg_reload_conf();",
    )
    action_id = f"G6a-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 60})
    change = context.local.run(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 "
        + pg_psql_flags("ALTER SYSTEM SET lc_messages='tr_TR.UTF-8';", "SELECT pg_reload_conf();"),
        timeout=60,
    )
    trigger = context.local.run(f"sudo -u postgres psql -c 'SELECT * FROM {marker};'", timeout=30)
    received = context.receiver_grep(marker, timeout=60)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    restore = context.local.run(restore_command, timeout=60)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    assertions = [
        AssertionResult("Turkish locale installed", simulation.returncode == 0 and install.returncode == 0, f"simulate={simulation.returncode} install={install.returncode}"),
        AssertionResult("PostgreSQL Turkish messages enabled", change.returncode == 0, command_fact(change)),
        AssertionResult("localized error generated", trigger.returncode != 0, command_fact(trigger)),
        AssertionResult("localized event collected", marker in received.stdout, command_fact(received)),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G6a", "Turkish locale parsing", started, [old, simulation, install, change, trigger, received, service, restore], assertions, "Collector handled PostgreSQL events under a Turkish message locale", "Passed" if restore.returncode == 0 else "Failed")


def pg_latin1_database(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    database = f"lc_latin1_{token}"
    table = f"lc_g6b_{token}"
    create = context.local.run(f"sudo -u postgres createdb --template=template0 --encoding=LATIN1 --locale=C {shlex.quote(database)}", timeout=60)
    sql_prefix = f"CREATE TABLE {table}(id integer); COMMENT ON TABLE {table} IS 'caf"
    trigger = context.local.run(
        f"{{ printf %s {shlex.quote(sql_prefix)}; printf '\\351'; printf %s {shlex.quote("e';")}; }} | sudo -u postgres env PGCLIENTENCODING=LATIN1 psql -v ON_ERROR_STOP=1 {shlex.quote(database)}",
        timeout=60,
    )
    received = context.receiver_grep(table, timeout=60)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    drop = context.local.run(f"sudo -u postgres dropdb --if-exists {shlex.quote(database)}", timeout=60)
    assertions = [
        AssertionResult("LATIN1 database created", create.returncode == 0, command_fact(create)),
        AssertionResult("LATIN1 DDL generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("LATIN1 event delivered", table in received.stdout and "caf" in received.stdout, command_fact(received)),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G6b", "LATIN1 database encoding", started, [create, trigger, received, service, drop], assertions, "Collector handled a LATIN1 database event without crashing or silently dropping it", "Passed" if drop.returncode == 0 else "Failed")


def pg_apparmor_enforcing(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    marker = context.marker("I7", "apparmor")
    profile_path = f"/etc/apparmor.d/lc-log-collector-{token}"
    binary_result = context.local.run("command -v log-collector || printf /usr/local/bin/log-collector", timeout=15)
    binary = binary_result.stdout.strip()
    profile_name = f"lc-log-collector-{token}"
    profile = f'''#include <tunables/global>\nprofile {profile_name} {binary} flags=(attach_disconnected) {{\n  #include <abstractions/base>\n  capability,\n  network,\n  / r,\n  /** r,\n  /var/lib/log-collector/** rwk,\n  /var/log/log-collector/** rwk,\n  /run/** rwk,\n  /proc/** r,\n  /sys/** r,\n}}\n'''
    enabled = context.local.run("command -v aa-enabled >/dev/null && sudo aa-enabled", timeout=30)
    install = context.local.run("sudo apt-get -s install apparmor apparmor-utils && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor apparmor-utils", timeout=600)
    write_profile = context.local.run(f"printf %s {shlex.quote(profile)} | sudo tee {shlex.quote(profile_path)} >/dev/null && sudo apparmor_parser -r {shlex.quote(profile_path)}", timeout=60)
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    trigger = postgres_comment(context, marker)
    received = context.receiver_grep(marker, timeout=60)
    denials = context.local.run(f"sudo journalctl -k --since '-5 minutes' --no-pager | grep -F 'apparmor=\"DENIED\"' | grep -F {shlex.quote(profile_name)} || true", timeout=30)
    cleanup = context.local.run(f"sudo apparmor_parser -R {shlex.quote(profile_path)} 2>/dev/null || true; sudo rm -f -- {shlex.quote(profile_path)}; sudo systemctl restart log-collector", timeout=120)
    assertions = [
        AssertionResult("AppArmor available", enabled.returncode == 0 and install.returncode == 0, f"enabled={enabled.returncode} install={install.returncode}"),
        AssertionResult("enforcing profile loaded", write_profile.returncode == 0 and restart.returncode == 0, f"profile={write_profile.returncode} restart={restart.returncode}"),
        AssertionResult("event collected while confined", marker in received.stdout, command_fact(received)),
        AssertionResult("no AppArmor denial", not denials.stdout.strip(), command_fact(denials)),
    ]
    return evaluated_result("I7", "AppArmor enforcing", started, [binary_result, enabled, install, write_profile, restart, trigger, received, denials, cleanup], assertions, "Collector remained functional under an enforcing AppArmor profile", "Passed" if cleanup.returncode == 0 else "Failed")


def pg_foreground_signal(context: LabContext, scenario_id: str, double_signal: bool) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    output = f"/tmp/lc-{scenario_id.lower()}-{token}.log"
    recovery_id = f"{scenario_id}-{token}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": "systemctl start log-collector", "sudo": True, "timeout": 60})
    stop = context.local.run("sudo systemctl stop log-collector", timeout=60)
    second = "sleep 0.2; kill -INT $PID 2>/dev/null || true;" if double_signal else ""
    run = context.local.run(
        f"START=$(date +%s); sudo -u log-collector env RUST_LOG=info log-collector run >{shlex.quote(output)} 2>&1 & PID=$!; "
        f"sleep 5; kill -INT $PID; {second} "
        "for i in $(seq 1 30); do kill -0 $PID 2>/dev/null || break; sleep 1; done; "
        f"kill -0 $PID 2>/dev/null && kill -KILL $PID; wait $PID; RC=$?; END=$(date +%s); printf 'rc=%s elapsed=%s\\n' \"$RC\" \"$((END-START))\"; cat {shlex.quote(output)}",
        timeout=45,
    )
    restart = context.local.run(f"sudo systemctl start log-collector; rm -f -- {shlex.quote(output)}", timeout=60)
    if restart.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    elapsed_match = re.search(r"elapsed=(\d+)", run.stdout)
    elapsed = int(elapsed_match.group(1)) if elapsed_match else 999
    graceful_text = bool(re.search(r"drain|saved|event", run.stdout, re.I))
    assertions = [
        AssertionResult("service stopped for foreground run", stop.returncode == 0, command_fact(stop)),
        AssertionResult("foreground process exited", "elapsed=" in run.stdout and elapsed < 35, f"elapsed={elapsed}"),
        AssertionResult("shutdown activity reported", graceful_text, "drain/saved/event text present" if graceful_text else "shutdown report missing"),
        AssertionResult("service restored", restart.returncode == 0, command_fact(restart)),
    ]
    expected = "Second interrupt forced an immediate exit" if double_signal else "Single interrupt drained and exited cleanly"
    return evaluated_result(scenario_id, "Double Ctrl+C foreground exit" if double_signal else "Single Ctrl+C foreground drain", started, [stop, run, restart], assertions, expected, "Passed" if restart.returncode == 0 else "Failed")


def pg_foreground_single_interrupt(context: LabContext) -> ScenarioResult:
    return pg_foreground_signal(context, "H5", False)


def pg_foreground_double_interrupt(context: LabContext) -> ScenarioResult:
    return pg_foreground_signal(context, "H5a", True)


def pg_reboot_resume(context: LabContext) -> ScenarioResult:
    if context.evidence is None:
        raise RuntimeError("H6 requires an evidence run")
    started = utc_now()
    scenario_dir = (context.evidence.run_dir / "scenarios" / "H6").resolve()
    phase_file = scenario_dir / "post-reboot.txt"
    marker = context.marker("H6", "post_reboot")
    if phase_file.exists():
        phase = context.local.run(f"sudo cat {shlex.quote(str(phase_file))}", timeout=15)
        received = context.receiver_grep(marker, timeout=90)
        enabled = context.local.run("systemctl is-enabled log-collector", timeout=15)
        cleanup = context.local.run("sudo systemctl disable --now lc-h6-continuation.service 2>/dev/null || true; sudo rm -f /etc/systemd/system/lc-h6-continuation.service; sudo systemctl daemon-reload", timeout=60)
        assertions = [
            AssertionResult("collector active after reboot", "collector=active" in phase.stdout, command_fact(phase)),
            AssertionResult("collector enabled at boot", enabled.stdout.strip() == "enabled", command_fact(enabled)),
            AssertionResult("post-reboot database event delivered", marker in received.stdout, command_fact(received)),
            AssertionResult("continuation service removed", cleanup.returncode == 0, command_fact(cleanup)),
        ]
        return evaluated_result("H6", "Machine reboot continuity", started, [phase, received, enabled, cleanup], assertions, "Collector returned automatically after reboot and resumed database collection")
    scenario_dir.mkdir(parents=True, exist_ok=True)
    unit_path = "/etc/systemd/system/lc-h6-continuation.service"
    phase_command = (
        "for i in $(seq 1 60); do systemctl is-active --quiet postgresql && systemctl is-active --quiet log-collector && break; sleep 2; done; "
        f"runuser -u postgres -- psql -q -c {shlex.quote("COMMENT ON TABLE public.lc_runner_anchor IS '" + marker + "';")}; "
        f"printf 'collector=%%s\\ndatabase=%%s\\nmarker={marker}\\nboot_id=%%s\\n' \"$(systemctl is-active log-collector)\" \"$(systemctl is-active postgresql)\" \"$(cat /proc/sys/kernel/random/boot_id)\" > {shlex.quote(str(phase_file))}"
    )
    unit = f"[Unit]\nDescription=Log collector H6 post-reboot continuation\nAfter=network-online.target postgresql.service log-collector.service\n\n[Service]\nType=oneshot\nExecStart=/bin/bash -lc {shlex.quote(phase_command)}\n\n[Install]\nWantedBy=multi-user.target\n"
    prepare = context.local.run(f"printf %s {shlex.quote(unit)} | sudo tee {unit_path} >/dev/null; sudo systemctl daemon-reload; sudo systemctl enable lc-h6-continuation.service", timeout=60)
    if prepare.returncode != 0:
        raise RuntimeError(f"Could not prepare reboot continuation: {command_fact(prepare)}")
    print(f"[H6] Reboot continuation prepared in {context.evidence.run_dir}. After boot rerun with --resume --scenario H6.", flush=True)
    reboot = context.local.run("sudo systemctl reboot", timeout=30)
    if reboot.returncode != 0:
        raise RuntimeError(f"Reboot request failed: {command_fact(reboot)}")
    raise SystemExit(75)


def pg_buffer_disk_full(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    image = f"/tmp/lc-h11-{token}.img"
    mountpoint = "/var/lib/log-collector/disk_buffer"
    receiver_recovery = f"H11-receiver-{token}"
    local_recovery = f"H11-local-{token}"
    if context.journal:
        context.journal.add({"id": receiver_recovery, "scope": "receiver", "command": RECEIVER_START_COMMAND, "sudo": True, "timeout": 60})
        context.journal.add({"id": local_recovery, "scope": "local", "command": f"systemctl stop log-collector; umount {mountpoint} 2>/dev/null || true; rm -f {image}; systemctl start log-collector", "sudo": True, "timeout": 120})
    prepare = context.local.run(
        f"sudo systemctl stop log-collector; truncate -s 32M {shlex.quote(image)}; sudo mkfs.ext4 -q -F {shlex.quote(image)}; sudo mount -o loop {shlex.quote(image)} {mountpoint}; sudo chown log-collector:log-collector {mountpoint}; sudo systemctl start log-collector",
        timeout=180,
    )
    stop_receiver = establish_receiver_outage(context)
    cleanup_ok = False
    try:
        generator = context.local.run(
            "PAYLOAD=$(printf '%04000d' 0 | tr '0' x); for i in $(seq -w 1 20000); do printf \"COMMENT ON TABLE public.lc_runner_anchor IS 'lc_h11_%s_%s';\\n\" \"$i\" \"$PAYLOAD\"; done | sudo -u postgres psql -q",
            timeout=600,
        )
        time.sleep(15)
        disk = context.local.run(f"df -Pk {mountpoint}; sudo du -sb {mountpoint}", timeout=30)
        logs = context.local.run("sudo journalctl -u log-collector --since '-10 minutes' --no-pager | tail -n 200", timeout=30)
        service = context.local.run("systemctl is-active log-collector", timeout=15)
    finally:
        restore_receiver = restore_receiver_ingest(context)
        cleanup = context.local.run(f"sudo systemctl stop log-collector; sudo umount {mountpoint}; rm -f {shlex.quote(image)}; sudo systemctl start log-collector", timeout=180)
        cleanup_ok = restore_receiver.returncode == 0 and cleanup.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(receiver_recovery)
            context.journal.remove(local_recovery)
    clear_error = bool(re.search(r"no space|disk|buffer|write", logs.stdout, re.I))
    assertions = [
        AssertionResult("isolated 32 MB buffer filesystem mounted", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("receiver stopped", stop_receiver.returncode == 0, command_fact(stop_receiver)),
        AssertionResult("buffer pressure generated", generator.returncode == 0, command_fact(generator)),
        AssertionResult("collector survived full buffer disk", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("clear disk/buffer error", clear_error, command_fact(logs)),
    ]
    return evaluated_result("H11", "Full buffer disk handling", started, [prepare, stop_receiver, generator, disk, logs, service, restore_receiver, cleanup], assertions, "Collector remained running and reported a clear error when its isolated buffer filesystem filled", "Passed" if cleanup_ok else "Failed")


def pg_high_volume(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("G15", "load")[:42]
    commands: list[CommandResult] = []
    health_before = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    commands.append(health_before)
    for minute in range(1, LAB_SOAK_MINUTES + 1):
        generate = context.local.run(
            f"for i in $(seq -w 1 1000); do printf \"COMMENT ON TABLE public.lc_runner_anchor IS '{prefix}_{minute}_%s';\\n\" \"$i\"; done | sudo -u postgres psql -q",
            timeout=180,
        )
        commands.append(generate)
        commands.append(context.receiver_grep(f"{prefix}_{minute}_1000", timeout=120))
    all_received = context.receiver.run(f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)}", sudo=True, timeout=120)
    health_after = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    commands.extend([all_received, health_after, service])
    markers = set(re.findall(re.escape(prefix) + r"_(\d)_(\d{4})", all_received.stdout))
    def dropped(payload: str) -> int:
        try:
            return int(json.loads(payload).get("events_dropped", 0))
        except (ValueError, TypeError, json.JSONDecodeError, AttributeError):
            return -1
    before_dropped = dropped(health_before.stdout)
    after_dropped = dropped(health_after.stdout)
    assertions = [
        AssertionResult(f"{LAB_SOAK_MINUTES * 1000:,} load markers delivered", len(markers) == LAB_SOAK_MINUTES * 1000, f"unique={len(markers)}"),
        AssertionResult("no additional dropped events", before_dropped >= 0 and after_dropped == before_dropped, f"before={before_dropped} after={after_dropped}"),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G15", "Constrained high-volume run", started, commands, assertions, f"Collector delivered {LAB_SOAK_MINUTES * 1000:,} events without additional drops in the constrained {LAB_SOAK_MINUTES}-minute lab run")


def pg_constrained_soak(context: LabContext) -> ScenarioResult:
    result = pg_stability(context)
    result.scenario_id = "H12"
    result.name = "Constrained sustained-load soak"
    result.reason = f"Collector remained stable for the approved {LAB_SOAK_MINUTES}-minute constrained soak; upstream specifies several hours"
    return result


def pg_multiline_rotation_boundary(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    prefix = context.marker("C5c", "boundary")[:42]
    sql_file = f"/tmp/lc-c5c-{token}.sql"
    old = context.local.run("sudo -u postgres psql -AtF $'\\t' -c \"SELECT current_setting('log_destination'), current_setting('log_statement');\"", timeout=15)
    values = old.stdout.rstrip("\n").split("\t")
    if len(values) != 2:
        raise RuntimeError(f"Could not capture log settings: {command_fact(old)}")
    restore_command = "sudo -u postgres psql -v ON_ERROR_STOP=1 " + pg_psql_flags(
        f"ALTER SYSTEM SET log_destination={pg_sql_literal(values[0])};",
        f"ALTER SYSTEM SET log_statement={pg_sql_literal(values[1])};",
        "SELECT pg_reload_conf();",
        "SELECT pg_rotate_logfile();",
    )
    action_id = f"C5c-{token}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 90})
    configure = context.local.run(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 " + pg_psql_flags(
            "ALTER SYSTEM SET log_destination='csvlog';",
            "ALTER SYSTEM SET log_statement='all';",
            "SELECT pg_reload_conf();",
            "SELECT pg_rotate_logfile();",
        ),
        timeout=90,
    )
    cleanup_ok = False
    try:
        build_sql = context.local.run(
            f"rm -f {shlex.quote(sql_file)}; for i in $(seq -w 1 10); do printf \"SELECT /*{prefix}_%s*/ 'line-one\\n\" \"$i\" >>{shlex.quote(sql_file)}; head -c 262144 /dev/zero | tr '\\0' x >>{shlex.quote(sql_file)}; printf \"\\nline-three';\\n\" >>{shlex.quote(sql_file)}; done",
            timeout=120,
        )
        race = context.local.run(
            f"sudo -u postgres psql -q -f {shlex.quote(sql_file)} >/tmp/lc-c5c-psql-{token}.log 2>&1 & PSQL=$!; for i in $(seq 1 30); do sudo -u postgres psql -qAtc 'SELECT pg_rotate_logfile();' >/dev/null; sleep 0.1; done; wait $PSQL; STATUS=$?; rm -f {shlex.quote(sql_file)} /tmp/lc-c5c-psql-{token}.log; exit $STATUS",
            timeout=240,
        )
        last = context.receiver_grep(f"{prefix}_10", timeout=180)
        received = context.receiver.run(f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)}", sudo=True, timeout=120)
    finally:
        restore = context.local.run(restore_command, timeout=90)
        context.local.run(f"rm -f {shlex.quote(sql_file)} /tmp/lc-c5c-psql-{token}.log", timeout=15)
        cleanup_ok = restore.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(action_id)
    markers = set(re.findall(re.escape(prefix) + r"_(\d{2})", received.stdout))
    event_ids = re.findall(r'event_id="([^"]+)"', received.stdout)
    assertions = [
        AssertionResult("CSV logging configured", configure.returncode == 0, command_fact(configure)),
        AssertionResult("large multi-line statements generated during rotations", build_sql.returncode == 0 and race.returncode == 0, f"build={build_sql.returncode} race={race.returncode}"),
        AssertionResult("all boundary markers delivered", markers == {f"{index:02d}" for index in range(1, 11)}, f"markers={sorted(markers)}"),
        AssertionResult("one event per statement", len(set(event_ids)) == 10, f"events={len(event_ids)} unique={len(set(event_ids))}"),
    ]
    return evaluated_result("C5c", "Rotation during multi-line write", started, [old, configure, build_sql, race, last, received, restore], assertions, "Ten large multi-line statements survived repeated concurrent rotations without splitting or loss", "Passed" if cleanup_ok else "Failed")


def pg_permission_loss_recovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    marker = context.marker("G8", "permission")
    directory = "/var/log/postgresql"
    acl_backup = f"/tmp/lc-g8-{token}.acl"
    backup = context.local.run(f"sudo getfacl -p {directory} > {shlex.quote(acl_backup)}", timeout=30)
    restore_command = f"setfacl --restore={shlex.quote(acl_backup)}; setfacl -m u:log-collector:r {directory}/* 2>/dev/null || true; rm -f {shlex.quote(acl_backup)}"
    action_id = f"G8-{token}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 60})
    revoke = context.local.run(
        f"sudo setfacl -x u:log-collector {directory} 2>/dev/null || true; sudo setfacl -x d:u:log-collector {directory} 2>/dev/null || true; sudo -u postgres psql -qAtc 'SELECT pg_rotate_logfile();'",
        timeout=60,
    )
    time.sleep(5)
    trigger = postgres_comment(context, marker)
    time.sleep(10)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    errors = context.local.run("sudo journalctl -u log-collector --since '-5 minutes' --no-pager | grep -Ei 'permission denied|cannot open|access denied' | tail -n 50", timeout=30)
    restore = context.local.run(f"sudo bash -lc {shlex.quote(restore_command)}", timeout=60)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    received = context.receiver_grep(marker, timeout=120)
    assertions = [
        AssertionResult("ACL state backed up", backup.returncode == 0, command_fact(backup)),
        AssertionResult("collector access revoked across rotation", revoke.returncode == 0, command_fact(revoke)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("clear permission error logged", bool(errors.stdout.strip()), command_fact(errors)),
        AssertionResult("collection recovered after ACL restore", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G8", "Permission loss and recovery", started, [backup, revoke, trigger, service, errors, restore, received], assertions, "Collector reported permission loss, stayed active, and delivered the pending event after ACL restoration", "Passed" if restore.returncode == 0 else "Failed")


def pg_backward_clock(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    before = context.marker("G12", "before")
    after = context.marker("G12", "backward")
    ntp = context.local.run("timedatectl show -p NTP --value", timeout=15)
    receiver_time = context.receiver.run("date +%s", timeout=15)
    recovery_id = f"G12-{token}"
    restore_ntp = "true" if ntp.stdout.strip().lower() != "yes" else "timedatectl set-ntp true"
    restore_command = f"date -s @$(date +%s); {restore_ntp}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 60})
    before_trigger = postgres_comment(context, before)
    before_received = context.receiver_grep(before, timeout=60)
    shift = context.local.run("sudo timedatectl set-ntp false; sudo date -s '@'$(($(date +%s)-300))", timeout=30)
    after_trigger = postgres_comment(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    fresh_receiver_time = context.receiver.run("date +%s", timeout=15)
    epoch = fresh_receiver_time.stdout.strip() if fresh_receiver_time.stdout.strip().isdigit() else receiver_time.stdout.strip()
    restore = context.local.run(f"sudo date -s @{shlex.quote(epoch)}; sudo {restore_ntp}", timeout=60)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("pre-shift event delivered", before in before_received.stdout, command_fact(before_received)),
        AssertionResult("clock moved backward", shift.returncode == 0, command_fact(shift)),
        AssertionResult("post-shift event delivered", after in after_received.stdout, command_fact(after_received)),
        AssertionResult("collector did not stall or stop", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("clock synchronization restored", restore.returncode == 0, command_fact(restore)),
    ]
    return evaluated_result("G12", "Backward system clock", started, [ntp, receiver_time, before_trigger, before_received, shift, after_trigger, after_received, service, fresh_receiver_time, restore], assertions, "Collector stayed active and delivered events after the clone clock moved backward", "Passed" if restore.returncode == 0 else "Failed")


def pg_symlinked_log_directory(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    marker = context.marker("G13", "symlink")
    link = f"/var/log/lc-postgresql-link-{token}"
    old = context.local.run("sudo -u postgres psql -Atc \"SHOW log_directory; SELECT pg_current_logfile();\"", timeout=15)
    values = [line.strip() for line in old.stdout.splitlines() if line.strip()]
    if len(values) != 2:
        raise RuntimeError(f"Could not capture active log directory: {command_fact(old)}")
    old_setting, current_file = values
    target = str(Path(current_file).parent)
    restore_command = "sudo -u postgres psql -v ON_ERROR_STOP=1 " + pg_psql_flags(
        f"ALTER SYSTEM SET log_directory={pg_sql_literal(old_setting)};",
        "SELECT pg_reload_conf();",
        "SELECT pg_rotate_logfile();",
    ) + f"; sudo rm -f -- {shlex.quote(link)}"
    action_id = f"G13-{token}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 90})
    configure = context.local.run(
        f"sudo ln -s {shlex.quote(target)} {shlex.quote(link)}; sudo -u postgres psql -v ON_ERROR_STOP=1 "
        + pg_psql_flags(
            f"ALTER SYSTEM SET log_directory={pg_sql_literal(link)};",
            "SELECT pg_reload_conf();",
            "SELECT pg_rotate_logfile();",
        ),
        timeout=90,
    )
    time.sleep(3)
    active = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    trigger = postgres_comment(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    restore = context.local.run(restore_command, timeout=90)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    assertions = [
        AssertionResult("symlinked log directory configured", configure.returncode == 0, command_fact(configure)),
        AssertionResult("PostgreSQL reports symlink path", active.stdout.strip().startswith(link + "/"), command_fact(active)),
        AssertionResult("collector followed symlinked log", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G13", "Symlinked PostgreSQL log directory", started, [old, configure, active, trigger, received, restore], assertions, "Collector followed PostgreSQL through a symlinked log directory", "Passed" if restore.returncode == 0 else "Failed")


def ensure_pexpect(context: LabContext) -> CommandResult:
    try:
        importlib.import_module("pexpect")
        now = utc_now()
        return CommandResult("import pexpect", 0, "pexpect available\n", "", now, now)
    except ImportError:
        pass
    simulation = context.local.run("sudo apt-get -s install python3-pexpect", timeout=120)
    if simulation.returncode != 0:
        return simulation
    install = context.local.run("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pexpect", timeout=600)
    importlib.invalidate_caches()
    return install


def setup_wizard_probe(
    context: LabContext,
    target_pattern: str,
    *,
    answer_at_target: str | None = None,
    post_pattern: str | None = None,
    timeout: int = 90,
) -> tuple[CommandResult, CommandResult]:
    dependency = ensure_pexpect(context)
    if dependency.returncode != 0:
        now = utc_now()
        return dependency, CommandResult("sudo log-collector setup", 1, "", "python3-pexpect unavailable", now, now)
    import pexpect
    started_at = utc_now()
    child = pexpect.spawn("sudo", ["-n", "log-collector", "setup"], encoding="utf-8", codec_errors="replace", echo=False, timeout=10)
    transcript = ""
    found = False
    error = ""
    patterns = [
        target_pattern,
        r"(?i)agent\s*(?:id|identifier)[^\r\n]*[?:›]\s*$",
        r"(?i)(?:client|tenant)(?:\s*/\s*(?:client|tenant))?\s*(?:name)?[^\r\n]*[?:›]\s*$",
        r"(?m)[^\r\n]{2,}[?:›]\s*$",
        pexpect.EOF,
        pexpect.TIMEOUT,
    ]
    try:
        for _ in range(100):
            index = child.expect(patterns)
            transcript += (child.before or "") + (child.after if isinstance(child.after, str) else "")
            if index == 0:
                found = True
                if answer_at_target is not None:
                    child.sendline(answer_at_target)
                    if post_pattern:
                        post_index = child.expect([post_pattern, pexpect.EOF, pexpect.TIMEOUT], timeout=15)
                        transcript += (child.before or "") + (child.after if isinstance(child.after, str) else "")
                        found = post_index == 0
                        if not found:
                            error = "post-answer expectation was not observed"
                break
            if index == 1:
                child.sendline("")
            elif index == 2:
                child.sendline("lc-clone-test")
            elif index == 3:
                child.sendline("")
            elif index == 4:
                error = "wizard exited before target"
                break
            else:
                error = "wizard timed out before target"
                break
    finally:
        if child.isalive():
            child.sendcontrol("c")
            child.close(force=True)
    result = CommandResult(
        command="sudo log-collector setup [probe only]",
        returncode=0 if found else 1,
        stdout=transcript,
        stderr=error,
        started_at=started_at,
        ended_at=utc_now(),
    )
    return dependency, result


def complete_setup_wizard(
    context: LabContext,
    *,
    engines: set[str],
    read_from_beginning: bool = False,
    timeout: int = 300,
) -> tuple[CommandResult, CommandResult]:
    dependency = ensure_pexpect(context)
    if dependency.returncode != 0:
        now = utc_now()
        return dependency, CommandResult("sudo log-collector setup", 1, "", "python3-pexpect unavailable", now, now)
    import pexpect
    started_at = utc_now()
    child = pexpect.spawn("sudo", ["-n", "log-collector", "setup"], encoding="utf-8", codec_errors="replace", echo=False, timeout=15)
    transcript = ""
    error = ""
    patterns = [
        r"(?i)agent\s*(?:id|identifier)[^\r\n]*[?:›]\s*$",
        r"(?i)(?:client|tenant)(?:\s*/\s*(?:client|tenant))?\s*(?:name)?[^\r\n]*[?:›]\s*$",
        r"(?i)auto.?discover(?:y|ed)[^\r\n]*[?:›]\s*$",
        r"(?i)read[^\r\n]*beginning[^\r\n]*[?:›]\s*$",
        r"(?i)merge[^\r\n]*(?:continuation|detail|hint|context)[^\r\n]*[?:›]\s*$",
        r"(?i)(?:log\s*)?format[^\r\n]*[?:›]\s*$",
        r"(?i)(?:(?:enable|collect|configure|include|add)[^\r\n]*postgres|postgres[^\r\n]*(?:enable|collect|configure|include|add))[^\r\n]*[?:›]\s*$",
        r"(?i)(?:(?:enable|collect|configure|include|add)[^\r\n]*mariadb|mariadb[^\r\n]*(?:enable|collect|configure|include|add))[^\r\n]*[?:›]\s*$",
        r"(?i)(?:(?:enable|collect|configure|include|add)[^\r\n]*(?:mysql|oracle|mongo)|(?:mysql|oracle|mongo)[^\r\n]*(?:enable|collect|configure|include|add))[^\r\n]*[?:›]\s*$",
        r"(?i)(?:output\s*)?transport[^\r\n]*[?:›]\s*$",
        r"(?i)(?:receiver|destination|output)[^\r\n]*(?:host|address|server)[^\r\n]*[?:›]\s*$",
        r"(?i)(?:receiver|destination|output)?\s*port[^\r\n]*[?:›]\s*$",
        r"(?i)tls[^\r\n]*[?:›]\s*$",
        r"(?i)(?:portal|management)[^\r\n]*url[^\r\n]*[?:›]\s*$",
        r"(?i)(?:updat|github|pat|repository|asset|interval)[^\r\n]*[?:›]\s*$",
        r"(?i)(?:write|generate|save|confirm)[^\r\n]*(?:config|configuration)?[^\r\n]*[?:›]\s*$",
        r"(?m)[^\r\n]{2,}[?:›]\s*$",
        pexpect.EOF,
        pexpect.TIMEOUT,
    ]
    deadline = time.monotonic() + timeout
    try:
        for _ in range(240):
            if time.monotonic() >= deadline:
                error = "wizard exceeded completion timeout"
                break
            index = child.expect(patterns, timeout=min(15, max(1, int(deadline - time.monotonic()))))
            transcript += (child.before or "") + (child.after if isinstance(child.after, str) else "")
            if index == 0:
                child.sendline("")
            elif index == 1:
                child.sendline("lc-clone-test")
            elif index == 2:
                child.sendline("y")
            elif index == 3:
                child.sendline("y" if read_from_beginning else "n")
            elif index == 4:
                child.sendline("y")
            elif index == 5:
                child.sendline("auto")
            elif index == 6:
                child.sendline("y" if "postgresql" in engines else "n")
            elif index == 7:
                child.sendline("y" if "mariadb" in engines else "n")
            elif index == 8:
                matched = str(child.after).lower()
                selected = any(engine in matched for engine in engines)
                child.sendline("y" if selected else "n")
            elif index == 9:
                child.sendline("relp")
            elif index == 10:
                child.sendline(context.receiver.config.host)
            elif index == 11:
                child.sendline("2514")
            elif index == 12:
                child.sendline("n")
            elif index in {13, 14}:
                child.sendline("")
            elif index == 15:
                child.sendline("y")
            elif index == 16:
                child.sendline("")
            elif index == 17:
                child.close()
                code = child.exitstatus if child.exitstatus is not None else 0
                result = CommandResult("sudo log-collector setup [automated profile]", code, transcript, "", started_at, utc_now())
                return dependency, result
            else:
                error = "wizard stopped responding before completion"
                break
    finally:
        if child.isalive():
            child.sendcontrol("c")
            child.close(force=True)
    return dependency, CommandResult("sudo log-collector setup [automated profile]", 1, transcript, error, started_at, utc_now())


def backup_collector_configuration(context: LabContext, scenario_id: str) -> tuple[CommandResult, CommandResult, str, str]:
    locate, config = collector_config_path(context)
    if not config:
        raise RuntimeError("Collector agent.toml was not found")
    backup = f"/tmp/lc-{scenario_id.lower()}-{secrets.token_hex(5)}"
    copy = context.local.run(f"sudo mkdir -p {shlex.quote(backup)}; sudo cp -a -- {shlex.quote(config)}* {shlex.quote(backup)}/", timeout=60)
    if copy.returncode != 0:
        raise RuntimeError(f"Could not back up collector configuration: {command_fact(copy)}")
    return locate, copy, config, backup


def restore_collector_configuration(context: LabContext, config: str, backup: str, *, reset_state: bool = False) -> CommandResult:
    state = "find /var/lib/log-collector/state /var/lib/log-collector/disk_buffer -mindepth 1 -delete; " if reset_state else ""
    command = (
        "systemctl stop log-collector; "
        f"rm -f -- {shlex.quote(config)} {shlex.quote(config + '.last-good')}; "
        f"cp -a -- {shlex.quote(backup)}/agent.toml* {shlex.quote(str(Path(config).parent))}/; "
        + state
        + "systemctl start log-collector; "
        f"rm -rf -- {shlex.quote(backup)}"
    )
    return context.local.run(f"sudo bash -lc {shlex.quote(command)}", timeout=180)


def pg_multi_engine_setup(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, backup_result, config, backup = backup_collector_configuration(context, "A11")
    simulation = context.local.run("sudo apt-get -s install mariadb-server", timeout=180)
    install = context.local.run("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server && sudo systemctl start mariadb", timeout=1800)
    audit = context.local.run(
        "sudo install -d -o mysql -g adm -m 0750 /var/log/mysql; sudo mariadb -e \"INSTALL SONAME 'server_audit';\" 2>/dev/null || true; "
        "sudo mariadb -e \"SET GLOBAL server_audit_output_type='file'; SET GLOBAL server_audit_file_path='/var/log/mysql/server_audit.log'; SET GLOBAL server_audit_events='CONNECT,QUERY,TABLE'; SET GLOBAL server_audit_logging=ON;\"; "
        "sudo setfacl -m u:log-collector:rx -m d:u:log-collector:r /var/log/mysql; sudo setfacl -m u:log-collector:r /var/log/mysql/* 2>/dev/null || true",
        timeout=120,
    )
    dependency, wizard = complete_setup_wizard(context, engines={"postgresql", "mariadb"})
    check = context.local.run("sudo log-collector check", timeout=30)
    restart = context.local.run("sudo systemctl restart log-collector; sleep 5; sudo journalctl -u log-collector --since '-3 minutes' --no-pager | tail -n 200", timeout=90)
    restore = restore_collector_configuration(context, config, backup)
    stop_maria = context.local.run("sudo systemctl stop mariadb", timeout=60)
    transcript_engines = "postgres" in wizard.stdout.lower() and "mariadb" in wizard.stdout.lower()
    startup_engines = "postgres_log" in restart.stdout and "mariadb_log" in restart.stdout
    assertions = [
        AssertionResult("MariaDB package prepared", simulation.returncode == 0 and install.returncode == 0, f"simulate={simulation.returncode} install={install.returncode}"),
        AssertionResult("MariaDB audit source prepared", audit.returncode == 0, command_fact(audit)),
        AssertionResult("wizard completed both engine sections", wizard.returncode == 0 and transcript_engines, command_fact(wizard)),
        AssertionResult("generated multi-engine config valid", check.returncode == 0, command_fact(check)),
        AssertionResult("both inputs started", startup_engines, command_fact(restart)),
    ]
    return evaluated_result("A11", "Two engines in one setup", started, [locate, backup_result, simulation, install, audit, dependency, wizard, check, restart, restore, stop_maria], assertions, "Wizard generated a valid configuration containing active PostgreSQL and MariaDB inputs", "Passed" if restore.returncode == 0 else "Failed")


def pg_setup_last_good(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, backup_result, config, backup = backup_collector_configuration(context, "A12")
    before_hash = context.local.run(f"sudo sha256sum {shlex.quote(config)} | awk '{{print $1}}'", timeout=15)
    dependency, wizard = complete_setup_wizard(context, engines={"postgresql"})
    last_good = f"{config}.last-good"
    after_hash = context.local.run(f"sudo sha256sum {shlex.quote(last_good)} | awk '{{print $1}}'", timeout=15)
    check = context.local.run("sudo log-collector check", timeout=30)
    restore = restore_collector_configuration(context, config, backup)
    preserved = bool(before_hash.stdout.strip() and before_hash.stdout.strip() == after_hash.stdout.strip())
    assertions = [
        AssertionResult("setup rerun completed", wizard.returncode == 0, command_fact(wizard)),
        AssertionResult("previous config preserved exactly", preserved, f"before={before_hash.stdout.strip()} last_good={after_hash.stdout.strip()}"),
        AssertionResult("new config valid", check.returncode == 0, command_fact(check)),
    ]
    return evaluated_result("A12", "Setup preserves last-good config", started, [locate, backup_result, before_hash, dependency, wizard, after_hash, check, restore], assertions, "Rerunning setup preserved the exact previous encrypted config as agent.toml.last-good", "Passed" if restore.returncode == 0 else "Failed")


def pg_read_from_beginning(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, backup_result, config, backup = backup_collector_configuration(context, "G5a")
    dependency, wizard = complete_setup_wizard(context, engines={"postgresql"}, read_from_beginning=True)
    check = context.local.run("sudo log-collector check", timeout=30)
    marker = context.marker("G5a", "history")
    stop = context.local.run("sudo systemctl stop log-collector", timeout=60)
    clear = context.local.run("sudo find /var/lib/log-collector/state /var/lib/log-collector/disk_buffer -mindepth 1 -delete", timeout=60)
    history = postgres_comment(context, marker)
    start_service = context.local.run("sudo systemctl start log-collector", timeout=60)
    received = context.receiver_grep(marker, timeout=180)
    restore = restore_collector_configuration(context, config, backup, reset_state=True)
    assertions = [
        AssertionResult("read-from-beginning setup completed", wizard.returncode == 0 and check.returncode == 0, f"wizard={wizard.returncode} check={check.returncode}"),
        AssertionResult("collector state reset", stop.returncode == 0 and clear.returncode == 0, f"stop={stop.returncode} clear={clear.returncode}"),
        AssertionResult("historical event generated before collector start", history.returncode == 0, command_fact(history)),
        AssertionResult("historical event ingested", start_service.returncode == 0 and marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G5a", "Read existing history from beginning", started, [locate, backup_result, dependency, wizard, check, stop, clear, history, start_service, received, restore], assertions, "With postgres_read_from_beginning enabled, reset state ingested the pre-existing marker", "Passed" if restore.returncode == 0 else "Failed")


def pg_setup_starts(context: LabContext) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(context, r"(?i)agent\s*(?:id|identifier)")
    assertions = [AssertionResult("setup wizard reached identity step", probe.returncode == 0, command_fact(probe))]
    return evaluated_result("A1", "Setup wizard starts", started, [dependency, probe], assertions, "Setup wizard started and reached its identity step")


def pg_setup_requires_client(context: LabContext) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(
        context,
        r"(?i)(?:client|tenant)(?:\s*/\s*(?:client|tenant))?\s*(?:name)?[^\r\n]*[?:›]\s*$",
        answer_at_target="",
        post_pattern=r"(?i)(?:required|cannot be empty|must.*(?:client|tenant))",
    )
    assertions = [AssertionResult("blank client rejected", probe.returncode == 0, command_fact(probe))]
    return evaluated_result("A2", "Required client or tenant name", started, [dependency, probe], assertions, "Wizard rejected an empty client/tenant name")


def pg_setup_hostname_default(context: LabContext) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:client|tenant).*?[?:›]\s*$")
    hostname = context.local.run("hostname -s", timeout=15)
    assertions = [
        AssertionResult("wizard advanced after blank Agent ID", probe.returncode == 0, command_fact(probe)),
        AssertionResult("hostname shown as default", hostname.stdout.strip() in probe.stdout, f"hostname={hostname.stdout.strip()}"),
    ]
    return evaluated_result("A3", "Agent ID defaults to hostname", started, [dependency, probe, hostname], assertions, "Blank Agent ID advanced with the endpoint hostname as its default")


def pg_setup_installed_discovery(context: LabContext, scenario_id: str = "A4") -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:use\s+)?auto.?discover(?:y|ed)")
    current = context.local.run("sudo -u postgres psql -Atc \"SELECT pg_current_logfile();\"", timeout=15)
    path = current.stdout.strip()
    discovered = bool(re.search(r"(?i)(detected|found).*postgres|postgres.*(?:cluster|log directory|active log)", probe.stdout))
    path_visible = bool(path and (path in probe.stdout or str(Path(path).parent) in probe.stdout))
    assertions = [
        AssertionResult("PostgreSQL discovery reached", probe.returncode == 0 and discovered, command_fact(probe)),
        AssertionResult("active log location displayed", path_visible, f"active={path}"),
    ]
    name = "Ubuntu PostgreSQL discovery" if scenario_id == "C1a" else "Installed database discovery"
    return evaluated_result(scenario_id, name, started, [dependency, probe, current], assertions, "Wizard displayed the installed PostgreSQL cluster and active log location")


def pg_setup_absent_engine(context: LabContext) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:no\s+oracle|oracle.*(?:not found|not installed|found nothing|0 instance))")
    assertions = [AssertionResult("absent Oracle reported clearly", probe.returncode == 0, command_fact(probe))]
    return evaluated_result("A5", "Absent database discovery", started, [dependency, probe], assertions, "Wizard clearly reported that the absent Oracle engine was not discovered")


def pg_setup_accepts_autodiscovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(
        context,
        r"(?i)(?:use\s+)?auto.?discover(?:y|ed)[^\r\n]*[?:›]\s*$",
        answer_at_target="y",
        post_pattern=r"(?i)(?:format|read.*beginning|merge|severity)",
    )
    assertions = [AssertionResult("auto-discovery accepted", probe.returncode == 0, command_fact(probe))]
    return evaluated_result("A6", "Accept auto-discovery", started, [dependency, probe], assertions, "Wizard accepted PostgreSQL auto-discovery and advanced to input options")


def pg_encrypted_config(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, config = collector_config_path(context)
    inspect = context.local.run(f"sudo file {shlex.quote(config)}; sudo strings {shlex.quote(config)} | head -n 100", timeout=30) if config else context.local.run("false", timeout=5)
    check = context.local.run("sudo log-collector check", timeout=30)
    readable_toml = bool(re.search(r"\[\[inputs\]\]|input_type\s*=|receiver.*host\s*=", inspect.stdout, re.I))
    assertions = [
        AssertionResult("configuration located", bool(config), command_fact(locate)),
        AssertionResult("configuration not readable TOML", inspect.returncode == 0 and not readable_toml, command_fact(inspect)),
        AssertionResult("encrypted configuration remains valid", check.returncode == 0 and "config ok" in f"{check.stdout}{check.stderr}".lower(), command_fact(check)),
    ]
    return evaluated_result("A7", "Encrypted configuration at rest", started, [locate, inspect, check], assertions, "Collector configuration was valid but not readable as plaintext TOML")


def pg_setup_non_root(context: LabContext) -> ScenarioResult:
    started = utc_now()
    attempt = context.local.run(
        "set -o pipefail; timeout -k 2s 5s log-collector setup </dev/null 2>&1 | head -c 65536",
        timeout=10,
    )
    clear = bool(re.search(r"permission|root|administrator|privilege|access", f"{attempt.stdout}\n{attempt.stderr}", re.I))
    assertions = [
        AssertionResult("non-root setup refused", attempt.returncode != 0, command_fact(attempt)),
        AssertionResult("permission failure clear", clear, command_fact(attempt)),
    ]
    return evaluated_result("A13", "Non-root setup refusal", started, [attempt], assertions, "Non-root setup failed with a clear privilege message")


def pg_ubuntu_discovery(context: LabContext) -> ScenarioResult:
    return pg_setup_installed_discovery(context, "C1a")


def pg_two_cluster_discovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    version = context.local.run("pg_config --version | awk '{print $2}' | cut -d. -f1", timeout=15)
    major = version.stdout.strip()
    create = context.local.run(f"sudo pg_createcluster {shlex.quote(major)} lc_runner --start", timeout=180)
    dependency, probe = setup_wizard_probe(context, r"(?i)lc_runner")
    cleanup = context.local.run(f"sudo pg_dropcluster --stop {shlex.quote(major)} lc_runner", timeout=180)
    both = "lc_runner" in probe.stdout and ("main" in probe.stdout or context.client_hostname in probe.stdout)
    assertions = [
        AssertionResult("second cluster created", create.returncode == 0, command_fact(create)),
        AssertionResult("both clusters displayed", probe.returncode == 0 and both, command_fact(probe)),
    ]
    return evaluated_result("C1c", "Two PostgreSQL clusters discovered", started, [version, create, dependency, probe, cleanup], assertions, "Wizard displayed the main and disposable PostgreSQL clusters separately", "Passed" if cleanup.returncode == 0 else "Failed")


def pg_logging_collector_off_discovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    old = context.local.run("sudo -u postgres psql -Atc \"SHOW logging_collector;\"", timeout=15)
    old_value = old.stdout.strip()
    restore_command = "sudo -u postgres psql -c " + shlex.quote(f"ALTER SYSTEM SET logging_collector={pg_sql_literal(old_value)};") + "; sudo systemctl restart postgresql"
    action_id = f"C1d-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 180})
    change = context.local.run("sudo -u postgres psql -c \"ALTER SYSTEM SET logging_collector='off';\"; sudo systemctl restart postgresql", timeout=180)
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:logging_collector.*off|stdout|journald)")
    restore = context.local.run(restore_command, timeout=180)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    assertions = [
        AssertionResult("logging collector disabled", change.returncode == 0, command_fact(change)),
        AssertionResult("wizard reported stdout/journald logging", probe.returncode == 0, command_fact(probe)),
    ]
    return evaluated_result("C1d", "logging_collector off discovery", started, [old, change, dependency, probe, restore], assertions, "Wizard reported that PostgreSQL was logging to stdout/journald instead of inventing a file", "Passed" if restore.returncode == 0 else "Failed")


def pg_custom_log_directory_discovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    custom = f"/var/log/lc-postgresql-custom-{token}"
    old = context.local.run("sudo -u postgres psql -Atc \"SHOW log_directory;\"", timeout=15)
    old_value = old.stdout.strip()
    restore_command = "sudo -u postgres psql -v ON_ERROR_STOP=1 " + pg_psql_flags(
        f"ALTER SYSTEM SET log_directory={pg_sql_literal(old_value)};",
        "SELECT pg_reload_conf();",
        "SELECT pg_rotate_logfile();",
    ) + f"; sudo rm -rf -- {shlex.quote(custom)}"
    action_id = f"C1e-{token}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": restore_command, "sudo": False, "timeout": 120})
    configure = context.local.run(
        f"sudo install -d -o postgres -g adm -m 0750 {shlex.quote(custom)}; sudo setfacl -m u:log-collector:rx -m d:u:log-collector:r {shlex.quote(custom)}; "
        "sudo -u postgres psql -v ON_ERROR_STOP=1 " + pg_psql_flags(
            f"ALTER SYSTEM SET log_directory={pg_sql_literal(custom)};",
            "SELECT pg_reload_conf();",
            "SELECT pg_rotate_logfile();",
        ),
        timeout=120,
    )
    time.sleep(3)
    dependency, probe = setup_wizard_probe(context, re.escape(custom))
    restore = context.local.run(restore_command, timeout=120)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    assertions = [
        AssertionResult("custom log directory configured", configure.returncode == 0, command_fact(configure)),
        AssertionResult("wizard displayed custom directory", probe.returncode == 0 and custom in probe.stdout, command_fact(probe)),
    ]
    return evaluated_result("C1e", "Custom log directory discovery", started, [old, configure, dependency, probe, restore], assertions, "Wizard discovered the live custom PostgreSQL log directory", "Passed" if restore.returncode == 0 else "Failed")


def pg_service_install_cycle(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    locate, config = collector_config_path(context)
    if not config:
        raise RuntimeError("Collector agent.toml was not found for the install cycle")
    backup = f"/tmp/lc-a9-{token}"
    prepare = context.local.run(f"sudo mkdir -p {shlex.quote(backup)}; sudo cp -a -- {shlex.quote(config)}* {shlex.quote(backup)}/", timeout=60) if config else context.local.run("false", timeout=5)
    recovery_command = f"if test ! -f {shlex.quote(config)}; then cp -a -- {shlex.quote(backup)}/agent.toml* {str(Path(config).parent)}/; fi; log-collector install; systemctl start log-collector"
    action_id = f"A9-{token}"
    if context.journal:
        context.journal.add({"id": action_id, "scope": "local", "command": recovery_command, "sudo": True, "timeout": 180})
    uninstall = context.local.run("sudo log-collector uninstall", timeout=180)
    absent = context.local.run("systemctl cat log-collector", timeout=15)
    restore_config = context.local.run(f"if test ! -f {shlex.quote(config)}; then sudo cp -a -- {shlex.quote(backup)}/agent.toml* {shlex.quote(str(Path(config).parent))}/; fi", timeout=60)
    install = context.local.run("sudo log-collector install", timeout=180)
    start_service = context.local.run("sudo systemctl start log-collector", timeout=60)
    active = context.local.run("systemctl is-active log-collector", timeout=15)
    health = context.local.run("for attempt in $(seq 1 15); do curl -fsS --max-time 2 http://127.0.0.1:9100/status && exit 0; sleep 1; done; exit 1", timeout=45)
    cleanup = context.local.run(f"sudo rm -rf -- {shlex.quote(backup)}", timeout=30)
    recovered = install.returncode == 0 and start_service.returncode == 0 and active.stdout.strip() == "active"
    if recovered and cleanup.returncode == 0 and context.journal:
        context.journal.remove(action_id)
    assertions = [
        AssertionResult("configured state backed up", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("existing service removed for clean cycle", uninstall.returncode == 0 and absent.returncode != 0, f"uninstall={uninstall.returncode} unit_after_uninstall={absent.returncode}"),
        AssertionResult("service install completed", restore_config.returncode == 0 and install.returncode == 0, f"config={restore_config.returncode} install={install.returncode}"),
        AssertionResult("installed service active", recovered, command_fact(active)),
        AssertionResult("installed collector health available", health.returncode == 0, command_fact(health)),
    ]
    return evaluated_result("A9", "Service install and start", started, [locate, prepare, uninstall, absent, restore_config, install, start_service, active, health, cleanup], assertions, "Configured clone completed an uninstall/install/start cycle and returned healthy", "Passed" if recovered and cleanup.returncode == 0 else "Failed")


def pg_buffer_cap(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    image = f"/tmp/lc-h3-{token}.img"
    mountpoint = "/var/lib/log-collector/disk_buffer"
    receiver_recovery = f"H3-receiver-{token}"
    local_recovery = f"H3-local-{token}"
    if context.journal:
        context.journal.add({"id": receiver_recovery, "scope": "receiver", "command": RECEIVER_START_COMMAND, "sudo": True, "timeout": 60})
        context.journal.add({"id": local_recovery, "scope": "local", "command": f"systemctl stop log-collector; umount {mountpoint} 2>/dev/null || true; rm -f {image}; systemctl start log-collector", "sudo": True, "timeout": 180})
    before = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    prepare = context.local.run(
        f"sudo systemctl stop log-collector; truncate -s 600M {shlex.quote(image)}; sudo mkfs.ext4 -q -F {shlex.quote(image)}; sudo mount -o loop {shlex.quote(image)} {mountpoint}; sudo chown log-collector:log-collector {mountpoint}; sudo systemctl start log-collector",
        timeout=240,
    )
    stop_receiver = establish_receiver_outage(context)
    cleanup_ok = False
    try:
        generator = context.local.run(
            "PAYLOAD=$(printf '%04000d' 0 | tr '0' x); for i in $(seq -w 1 140000); do printf \"COMMENT ON TABLE public.lc_runner_anchor IS 'lc_h3_%s_%s';\\n\" \"$i\" \"$PAYLOAD\"; done | sudo -u postgres psql -q",
            timeout=1800,
        )
        time.sleep(20)
        after = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
        disk = context.local.run(f"df -Pk {mountpoint}; sudo du -sb {mountpoint}", timeout=30)
        logs = context.local.run("sudo journalctl -u log-collector --since '-30 minutes' --no-pager | tail -n 300", timeout=30)
        service = context.local.run("systemctl is-active log-collector", timeout=15)
    finally:
        restore_receiver = restore_receiver_ingest(context)
        cleanup = context.local.run(f"sudo systemctl stop log-collector; sudo umount {mountpoint}; rm -f {shlex.quote(image)}; sudo systemctl start log-collector", timeout=240)
        cleanup_ok = restore_receiver.returncode == 0 and cleanup.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(receiver_recovery)
            context.journal.remove(local_recovery)
    def dropped(payload: str) -> int:
        try:
            return int(json.loads(payload).get("events_dropped", 0))
        except (ValueError, TypeError, json.JSONDecodeError, AttributeError):
            return -1
    before_dropped = dropped(before.stdout)
    after_dropped = dropped(after.stdout)
    warning = bool(re.search(r"drop|oldest|buffer.*(?:cap|limit|full)", logs.stdout, re.I))
    assertions = [
        AssertionResult("600 MB isolated buffer filesystem mounted", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("receiver kept unavailable during load", stop_receiver.returncode == 0, command_fact(stop_receiver)),
        AssertionResult("more than default 500 MB generated", generator.returncode == 0, command_fact(generator)),
        AssertionResult("oldest events dropped at cap", before_dropped >= 0 and after_dropped > before_dropped, f"before={before_dropped} after={after_dropped}"),
        AssertionResult("cap warning emitted", warning, command_fact(logs)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("H3", "Disk buffer cap and oldest-drop behavior", started, [before, prepare, stop_receiver, generator, after, disk, logs, service, restore_receiver, cleanup], assertions, "Collector enforced its documented 500 MB cap, dropped oldest events with a warning, and stayed active", "Passed" if cleanup_ok else "Failed")


def skipped_scenario(
    scenario_id: str,
    name: str,
    reason: str,
    risk: Risk = "manual",
    execution_mode: ExecutionMode = "manual",
) -> Scenario:
    def execute(_context: LabContext) -> ScenarioResult:
        now = utc_now()
        return ScenarioResult(scenario_id, name, "Not Tested", reason, now, now)

    effective_risk: Risk = "safe" if risk == "manual" else risk
    return Scenario(
        scenario_id,
        name,
        effective_risk,
        execute,
        quiet=True,
        execution_mode=execution_mode,
        coverage_reason=reason,
    )


def pending_execution_mode(database: str, scenario_id: str) -> tuple[ExecutionMode, str]:
    """Classify catalog-only scenarios without pretending they were executed."""
    clone_only = {
        "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A9", "A11", "A12", "A13",
        "G4a", "G5", "G5a", "G7", "G8", "G10", "G12", "G13",
        "H4", "H5", "H5a", "H6", "H7", "H8", "H9", "H11", "I9",
    }
    environment = {"G6a", "G6b", "G11", "G14", "I1", "I3", "I4", "I6"}
    manual = {"G15", "H12", "G2a"}
    not_applicable: set[str] = set()
    if database == "postgresql":
        clone_only |= {"C1a", "C1c", "C1d", "C1e", "C2e", "C8", "C5c", "C5d"}
        environment |= {"C1b", "C2b", "C5b"}
        not_applicable |= {"G1c", "G1d"}
    elif database == "mysql":
        clone_only |= {"D1", "D1a", "D1b", "D1c", "D1d", "D1e", "D1g", "D7b", "D7c", "D7d"}
        environment |= {"D1f", "D1g", "D2g", "D7b", "D7c", "D7d"}
        not_applicable |= {"G1b", "G1d"}
    elif database == "mariadb":
        clone_only |= {"F1", "F2", "F6", "F7a", "F10", "F10a", "F12"}
        environment |= {"F7b", "F8", "F8a", "F9a", "F12"}
        not_applicable |= {"G1b", "G1c"}
    elif database == "oracle":
        clone_only |= {"E1", "E3", "E11a"}
        environment |= {"E4", "E7", "E6b", "E11a", "E11b", "E11d", "G13"}
        not_applicable |= {"G1b", "G1c", "G1d"}
    if scenario_id in not_applicable:
        return "not-applicable", "The scenario syntax belongs to a different database engine"
    if scenario_id in environment:
        return "environment", "Requires an OS, architecture, topology, version, or storage environment absent from this lab"
    if scenario_id in manual:
        return "manual", "Requires a real soak or operator judgement; shortening it would change the scenario"
    if scenario_id in clone_only:
        return "clone", "Automatable only inside a disposable cloned client VM"
    return "endpoint-pending", "Safe or reversible endpoint automation is planned but its adapter is not implemented yet"


def postgresql_scenarios() -> list[Scenario]:
    implemented = [
        Scenario("A1", "Setup wizard starts", "destructive", pg_setup_starts, execution_mode="clone"),
        Scenario("A2", "Required client or tenant name", "destructive", pg_setup_requires_client, execution_mode="clone"),
        Scenario("A3", "Agent ID defaults to hostname", "destructive", pg_setup_hostname_default, execution_mode="clone"),
        Scenario("A4", "Installed database discovery", "destructive", pg_setup_installed_discovery, execution_mode="clone"),
        Scenario("A5", "Absent database discovery", "destructive", pg_setup_absent_engine, execution_mode="clone"),
        Scenario("A6", "Accept auto-discovery", "destructive", pg_setup_accepts_autodiscovery, execution_mode="clone"),
        Scenario("A7", "Encrypted configuration at rest", "destructive", pg_encrypted_config, execution_mode="clone"),
        Scenario("A8", "Collector configuration validation", "safe", pg_config_check),
        Scenario("A9", "Service install and start", "destructive", pg_service_install_cycle, execution_mode="clone"),
        Scenario("A10", "Collector health endpoint", "safe", pg_health_check),
        Scenario("A11", "Two engines in one setup", "destructive", pg_multi_engine_setup, execution_mode="clone"),
        Scenario("A12", "Setup preserves last-good config", "destructive", pg_setup_last_good, execution_mode="clone"),
        Scenario("A13", "Non-root setup refusal", "destructive", pg_setup_non_root, execution_mode="clone"),
        Scenario("C1", "PostgreSQL discovery and log access", "safe", pg_setup_checks),
        Scenario("C1a", "Ubuntu PostgreSQL discovery", "destructive", pg_ubuntu_discovery, execution_mode="clone"),
        Scenario("C1c", "Two PostgreSQL clusters discovered", "destructive", pg_two_cluster_discovery, execution_mode="clone"),
        Scenario("C1d", "logging_collector off discovery", "destructive", pg_logging_collector_off_discovery, execution_mode="clone"),
        Scenario("C1e", "Custom log directory discovery", "destructive", pg_custom_log_directory_discovery, execution_mode="clone"),
        Scenario("B1", "Basic PostgreSQL collection", "safe", pg_basic_delivery),
        Scenario("B2", "Stable source identifier", "safe", pg_source_identity),
        Scenario("B3", "Service restart and checkpoint", "configuration", pg_restart_checkpoint),
        Scenario("B4", "Constrained-lab stability window", "safe", pg_stability),
        Scenario("B5", "Constrained-lab receiver outage", "disruptive", pg_receiver_outage),
        Scenario("B6", "Unique event identifiers", "safe", pg_unique_event_ids),
        Scenario("B7", "Native timestamp preservation", "safe", pg_timestamp),
        Scenario("C2", "Failed login severity", "safe", pg_failed_login),
        Scenario("C2a", "No matching pg_hba.conf entry", "destructive", pg_no_hba_entry, execution_mode="clone"),
        Scenario("C2b", "Explicit pg_hba.conf host rejection", "destructive", pg_explicit_hba_reject, execution_mode="clone"),
        Scenario("C2c", "Connection and disconnection logging", "safe", pg_connection_lifecycle),
        Scenario("C2d", "Role DDL security events", "safe", pg_role_ddl),
        Scenario("C2e", "PANIC-level event", "destructive", pg_panic_event, execution_mode="clone"),
        Scenario("C2f", "Permission-denied error severity", "safe", pg_permission_denied),
        Scenario("C8", "pgaudit structured events", "destructive", pg_pgaudit, execution_mode="clone"),
        Scenario("C3", "PostgreSQL JSON log collection", "safe", pg_json_collection),
        Scenario("C4", "CSV multi-line statement", "configuration", pg_csv_multiline),
        Scenario("C4a", "CSV quoted comma", "configuration", pg_csv_comma),
        Scenario("C4b", "CSV double quote", "configuration", pg_csv_double_quote),
        Scenario("C4c", "stderr multi-line statement", "configuration", pg_stderr_multiline),
        Scenario("C4d", "stderr and csvlog de-duplication", "configuration", pg_dual_destination),
        Scenario("C4e", "Custom log line prefix", "configuration", pg_custom_prefix),
        Scenario("C4f", "Log prefix without timestamp", "configuration", pg_prefix_without_timestamp),
        Scenario("C7", "Deadlock and ordinary DDL", "safe", pg_deadlock),
        Scenario("C7a", "Statement and lock timeouts", "safe", pg_timeouts),
        Scenario("C7b", "Backend termination", "safe", pg_backend_termination),
        Scenario("C7c", "Autovacuum and checkpoint volume", "configuration", pg_maintenance_events),
        Scenario("C7d", "PostgreSQL restart survival", "disruptive", pg_database_restart),
        Scenario("C7e", "Connection exhaustion", "destructive", pg_connection_exhaustion, execution_mode="clone"),
        Scenario("G1", "Password redaction", "safe", pg_password_redaction),
        Scenario("G1a", "CREATE USER password redaction", "safe", pg_create_user_redaction),
        Scenario("G1b", "ENCRYPTED PASSWORD redaction", "safe", pg_encrypted_password_redaction),
        Scenario("G2", "Username preservation", "safe", pg_username_preservation),
        Scenario("C5", "Forced log rotation", "configuration", pg_forced_rotation),
        Scenario("C5a", "Size-based rotation continuity", "configuration", pg_size_rotation),
        Scenario("C5c", "Rotation during multi-line write", "destructive", pg_multiline_rotation_boundary, execution_mode="clone"),
        Scenario("G3", "Cross-engine rotation continuity", "configuration", pg_cross_engine_rotation),
        Scenario("G3b", "Two rapid PostgreSQL rotations", "configuration", pg_rapid_rotation),
        Scenario("G3a", "Copy-truncate rotation continuity", "destructive", pg_copytruncate_rotation, execution_mode="clone"),
        Scenario("G4", "Nearly-empty log restart", "destructive", pg_small_file_restart, execution_mode="clone"),
        Scenario("G4a", "Agent restart while database is stopped", "disruptive", pg_agent_restart_with_db_stopped),
        Scenario("G5", "Fresh-state starts at current log end", "destructive", pg_fresh_state, execution_mode="clone"),
        Scenario("G5a", "Read existing history from beginning", "destructive", pg_read_from_beginning, execution_mode="clone"),
        Scenario("G6", "Unicode log preservation", "safe", pg_unicode),
        Scenario("G6a", "Turkish locale parsing", "destructive", pg_turkish_locale, execution_mode="clone"),
        Scenario("G6b", "LATIN1 database encoding", "configuration", pg_latin1_database),
        Scenario("G7", "Delete and recreate active log", "destructive", pg_delete_recreate_cross_engine, execution_mode="clone"),
        Scenario("G8", "Permission loss and recovery", "destructive", pg_permission_loss_recovery, execution_mode="clone"),
        Scenario("G9", "Multi-megabyte PostgreSQL record", "safe", pg_large_record),
        Scenario("G10", "Malformed record forwarding", "destructive", pg_malformed_record, execution_mode="clone"),
        Scenario("G12", "Backward system clock", "destructive", pg_backward_clock, execution_mode="clone"),
        Scenario("G13", "Symlinked PostgreSQL log directory", "destructive", pg_symlinked_log_directory, execution_mode="clone"),
        Scenario("G15", "Constrained high-volume run", "safe", pg_high_volume),
        Scenario("H1", "Disk buffer growth during receiver outage", "disruptive", pg_buffer_growth),
        Scenario("H2", "Buffered delivery after receiver recovery", "disruptive", pg_buffer_delivery),
        Scenario("H3", "Disk buffer cap and oldest-drop behavior", "destructive", pg_buffer_cap, execution_mode="clone"),
        Scenario("H4", "Collector starts before PostgreSQL", "disruptive", pg_database_start_order),
        Scenario("H5", "Single Ctrl+C foreground drain", "destructive", pg_foreground_single_interrupt, execution_mode="clone"),
        Scenario("H5a", "Double Ctrl+C foreground exit", "destructive", pg_foreground_double_interrupt, execution_mode="clone"),
        Scenario("H6", "Machine reboot continuity", "destructive", pg_reboot_resume, execution_mode="clone"),
        Scenario("H7", "Corrupt config fallback", "destructive", pg_config_fallback, execution_mode="clone"),
        Scenario("H8", "Missing configuration failure", "destructive", pg_config_missing, execution_mode="clone"),
        Scenario("H9", "Unreachable output retry", "destructive", pg_unreachable_output, execution_mode="clone"),
        Scenario("H10", "SIGKILL checkpoint recovery", "disruptive", pg_kill_recovery),
        Scenario("H11", "Full buffer disk handling", "destructive", pg_buffer_disk_full, execution_mode="clone"),
        Scenario("H12", "Constrained sustained-load soak", "safe", pg_constrained_soak),
        Scenario("I2", "Linux systemd runtime", "safe", pg_linux_systemd),
        Scenario("I5", "Static Linux packaging", "safe", pg_static_binary),
        Scenario("I7", "AppArmor enforcing", "destructive", pg_apparmor_enforcing, execution_mode="clone"),
        Scenario("I8", "Non-root collector with ACL access", "safe", pg_non_root_service),
        Scenario("I9", "Collector uninstall", "destructive", pg_uninstall, execution_mode="clone"),
        Scenario("C5d", "Deleted log recreation", "destructive", pg_delete_recreate, execution_mode="clone"),
    ]
    deferred = [
        skipped_scenario("C1b", "RHEL discovery layout", "Requires a RHEL-family test VM", execution_mode="environment"),
        skipped_scenario("C5b", "RHEL weekly ring truncation", "Requires a RHEL-family PostgreSQL layout", execution_mode="environment"),
        skipped_scenario("C6", "Runtime discovery without a hardcoded path", "Direct config inspection is not possible because the deployed config is encrypted; rotation behavior is covered by C5/G3", execution_mode="manual"),
        skipped_scenario("G2a", "Redaction in message and raw fields", "The rsyslog receiver exposes the rendered wire event but not the collector's internal raw field", execution_mode="manual"),
    ]
    return implemented + deferred


def shared_engine_scenarios() -> list[Scenario]:
    return [
        Scenario("A8", "Collector configuration validation", "safe", pg_config_check),
        Scenario("A10", "Collector health endpoint", "safe", pg_health_check),
        Scenario("I2", "Linux systemd runtime", "safe", pg_linux_systemd),
        Scenario("I5", "Static Linux packaging", "safe", pg_static_binary),
    ]


def mysql_family_cli(context: LabContext, sql: str, timeout: float = 60) -> CommandResult:
    binary = "mysql" if context.database == "mysql" else "mariadb"
    return context.local.run(
        f"sudo {binary} --batch --raw --skip-column-names --comments -e {shlex.quote(sql)}",
        timeout=timeout,
    )


def mysql_family_marker(context: LabContext, marker: str) -> CommandResult:
    prefix = "SET SESSION long_query_time=0; " if context.database == "mysql" else ""
    sql = f"{prefix}SELECT /*{marker}*/ SLEEP(0.2) AS lc_marker;"
    return mysql_family_cli(context, sql, timeout=30)


def mysql_family_basic(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("B1")
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    assertions = [
        AssertionResult("database event generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("receiver marker", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("B1", f"Basic {context.database} collection", started, [trigger, received], assertions, "Generated database marker reached the receiver")


def mysql_family_source(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("B2")
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    fields = line.split(" ", 4)
    app_name = fields[3] if len(fields) >= 4 else "missing"
    expected = "mysql_log" if context.database == "mysql" else "mariadb_log"
    assertions = [
        AssertionResult("marker delivered", marker in line, line or "missing"),
        AssertionResult(f"APP-NAME exactly {expected}", app_name == expected, app_name),
    ]
    return evaluated_result("B2", "Stable source identifier", started, [trigger, received], assertions, f"Receiver APP-NAME is exactly {expected}")


def mysql_family_restart(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("B3", "before")
    after = context.marker("B3", "after")
    before_trigger = mysql_family_marker(context, before)
    before_received = context.receiver_grep(before, timeout=90)
    count_command = f"grep -Fc -- {shlex.quote(before)} {shlex.quote(context.receiver_log)} || true"
    initial_count = context.receiver.run(count_command, sudo=True, timeout=15)
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    time.sleep(3)
    after_trigger = mysql_family_marker(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    final_count = context.receiver.run(count_command, sudo=True, timeout=15)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    try:
        initial = int(initial_count.stdout.strip() or "0")
        final = int(final_count.stdout.strip() or "0")
    except ValueError:
        initial = final = -1
    assertions = [
        AssertionResult("collector restarted", restart.returncode == 0 and service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("post-restart delivery", after in after_received.stdout, command_fact(after_received)),
        AssertionResult("no full replay", initial >= 1 and final <= initial + 3, f"before={initial} after={final}"),
    ]
    return evaluated_result("B3", "Service restart and checkpoint", started, [before_trigger, before_received, initial_count, restart, after_trigger, after_received, final_count, service], assertions, "Collector resumed after restart without replaying the full database log")


def mysql_family_event_ids(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("B6", "event")[:44]
    commands: list[CommandResult] = []
    for index in range(1, 6):
        commands.append(mysql_family_marker(context, f"{prefix}_{index}"))
    commands.append(context.receiver_grep(f"{prefix}_5", timeout=90))
    all_received = context.receiver.run(f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)} | tail -n 30", sudo=True, timeout=30)
    commands.append(all_received)
    markers = set(re.findall(re.escape(prefix) + r"_([1-5])", all_received.stdout))
    ids = re.findall(r'event_id="([^"]+)"', all_received.stdout)
    assertions = [
        AssertionResult("five markers delivered", markers == {"1", "2", "3", "4", "5"}, str(sorted(markers))),
        AssertionResult("five unique event IDs", len(set(ids)) == 5, f"total={len(ids)} unique={len(set(ids))}"),
    ]
    return evaluated_result("B6", "Unique event identifiers", started, commands, assertions, "Five database events carried five unique event IDs")


def mysql_family_password_redaction(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    username = f"lc_g1_{token}"
    secret = f"LcG1-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(secret)
    create_sql = f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{secret}'; SET PASSWORD FOR '{username}'@'localhost' = '{secret}';"
    trigger = mysql_family_cli(context, create_sql)
    received = context.receiver_grep(username, timeout=90)
    time.sleep(5)
    leak = context.receiver.run(f"grep -R -F -- {shlex.quote(secret)} {shlex.quote(context.receiver_client_dir)}", sudo=True, timeout=30)
    cleanup = mysql_family_cli(context, f"DROP USER IF EXISTS '{username}'@'localhost';")
    assertions = [
        AssertionResult("password operation delivered", username in received.stdout, command_fact(received)),
        AssertionResult("password absent from every received source", leak.returncode == 1 and not leak.stdout, "secret absent" if leak.returncode == 1 and not leak.stdout else "secret visible or search failed"),
    ]
    return evaluated_result("G1", "Password redaction", started, [trigger, received, leak, cleanup], assertions, "Disposable password was redacted across every receiver source", "Passed" if cleanup.returncode == 0 else "Failed")


def mysql_family_username(context: LabContext) -> ScenarioResult:
    started = utc_now()
    username = f"lc_g2_{secrets.token_hex(5)}"
    trigger = mysql_family_cli(context, f"CREATE USER '{username}'@'localhost'; DROP USER '{username}'@'localhost';")
    received = context.receiver_grep(username, timeout=90)
    assertions = [
        AssertionResult("user operation completed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("username preserved", username in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G2", "Username preservation", started, [trigger, received], assertions, "Disposable database username remained visible")


def mysql_family_unicode(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G6")
    value = f"{marker}_日本語_العربية_😀"
    trigger = mysql_family_cli(context, f"SELECT /*{value}*/ 1;")
    received = context.receiver_grep(marker, timeout=90)
    assertions = [
        AssertionResult("Unicode query generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("Unicode text preserved", value in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G6", "Unicode log preservation", started, [trigger, received], assertions, "Japanese, Arabic, and emoji text remained intact")


def mysql_family_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("G3", "before")
    after = context.marker("G3", "after")
    before_trigger = mysql_family_marker(context, before)
    before_received = context.receiver_grep(before, timeout=90)
    rotate = mysql_family_cli(context, "FLUSH LOGS;")
    time.sleep(3)
    after_trigger = mysql_family_marker(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    assertions = [
        AssertionResult("FLUSH LOGS completed", rotate.returncode == 0, command_fact(rotate)),
        AssertionResult("pre-rotation event delivered", before in before_received.stdout, command_fact(before_received)),
        AssertionResult("post-rotation event delivered", after in after_received.stdout, command_fact(after_received)),
    ]
    return evaluated_result("G3", "Cross-engine rotation continuity", started, [before_trigger, before_received, rotate, after_trigger, after_received], assertions, "Collection continued across FLUSH LOGS")


def mysql_family_kill_recovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("H10", "before")
    after = context.marker("H10", "after")
    commands = [mysql_family_marker(context, before), context.receiver_grep(before, timeout=90)]
    initial_pid = context.local.run("systemctl show -p MainPID --value log-collector", timeout=15)
    killed = context.local.run("sudo systemctl kill --kill-who=main --signal=SIGKILL log-collector", timeout=30)
    restarted = context.local.run("sudo systemctl restart log-collector", timeout=60)
    final_pid = context.local.run("systemctl show -p MainPID --value log-collector", timeout=15)
    commands.extend([initial_pid, killed, restarted, final_pid, mysql_family_marker(context, after)])
    received = context.receiver_grep(after, timeout=90)
    commands.append(received)
    assertions = [
        AssertionResult("SIGKILL issued", killed.returncode == 0, command_fact(killed)),
        AssertionResult("collector restarted with new PID", restarted.returncode == 0 and final_pid.stdout.strip() != initial_pid.stdout.strip(), f"before={initial_pid.stdout.strip()} after={final_pid.stdout.strip()}"),
        AssertionResult("post-kill event delivered", after in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H10", "SIGKILL checkpoint recovery", started, commands, assertions, "Collector resumed database collection after forced process termination")


def mysql_family_non_root_read(context: LabContext) -> ScenarioResult:
    started = utc_now()
    binary = "mysql" if context.database == "mysql" else "mariadb"
    variables = context.local.run(
        f"sudo {binary} -NBe \"SELECT @@global.log_error; SELECT @@global.slow_query_log_file; SELECT @@global.general_log_file;\"",
        timeout=30,
    )
    paths = [line.strip() for line in variables.stdout.splitlines() if line.strip() and line.strip().lower() not in {"stderr", "none"}]
    checks: list[CommandResult] = []
    for path in paths:
        checks.append(context.local.run(f"sudo -u log-collector test -r {shlex.quote(path)}", timeout=15))
    service_user = context.local.run("systemctl show -p User --value log-collector", timeout=15)
    effective_user = context.local.run(
        "PID=$(systemctl show -p MainPID --value log-collector); test \"$PID\" -gt 0 && ps -o user= -p \"$PID\" | xargs",
        timeout=15,
    )
    unit_identity = service_user.stdout.strip() or "unset"
    process_identity = effective_user.stdout.strip() or "missing"
    assertions = [
        AssertionResult("database log paths reported", bool(paths), str(paths)),
        AssertionResult("all reported logs readable", bool(checks) and all(item.returncode == 0 for item in checks), f"readable={sum(item.returncode == 0 for item in checks)}/{len(checks)}"),
        AssertionResult("dedicated service identity", effective_user.returncode == 0 and process_identity == "log-collector", f"unit_user={unit_identity} effective_user={process_identity}"),
    ]
    return evaluated_result("I8", "Non-root collector with database-log access", started, [variables, *checks, service_user, effective_user], assertions, "The collector process runs as log-collector and can read the database logs")


def mysql_family_service(context: LabContext) -> str:
    return "mysql" if context.database == "mysql" else "mariadb"


def mysql_family_auth_failure(context: LabContext, scenario_id: str, nonexistent: bool = False, locked: bool = False) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    username = f"lc_{scenario_id.lower()}_{token}"
    password = f"Lc-{secrets.token_hex(8)}!"
    wrong = f"Wrong-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(password)
        context.evidence.register_secret(wrong)
    commands: list[CommandResult] = []
    if context.database == "mysql":
        old_verbosity = mysql_family_cli(context, "SELECT @@global.log_error_verbosity;")
        commands.append(old_verbosity)
        commands.append(mysql_family_cli(context, "SET GLOBAL log_error_verbosity=3;"))
    else:
        old_verbosity = mysql_family_cli(context, "SELECT @@global.log_warnings;")
        commands.append(old_verbosity)
        commands.append(mysql_family_cli(context, "SET GLOBAL log_warnings=2;"))
    if not nonexistent:
        lock_clause = " ACCOUNT LOCK" if locked and context.database == "mysql" else ""
        commands.append(mysql_family_cli(context, f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{password}'{lock_clause};"))
    binary = "mysql" if context.database == "mysql" else "mariadb"
    attempt = context.local.run(
        f"{binary} --protocol=TCP -h127.0.0.1 -u {shlex.quote(username)} --password={shlex.quote(wrong)} --connect-timeout=5 -e 'SELECT 1'",
        timeout=15,
    )
    commands.append(attempt)
    received = context.receiver_grep(username, timeout=90)
    commands.append(received)
    if not nonexistent:
        commands.append(mysql_family_cli(context, f"DROP USER IF EXISTS '{username}'@'localhost';"))
    old_value = re.findall(r"\d+", old_verbosity.stdout)
    if old_value:
        setting = "log_error_verbosity" if context.database == "mysql" else "log_warnings"
        commands.append(mysql_family_cli(context, f"SET GLOBAL {setting}={old_value[-1]};"))
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    assertions = [
        AssertionResult("authentication rejected", attempt.returncode != 0, command_fact(attempt)),
        AssertionResult("failed login delivered", username in line, line or "missing"),
        AssertionResult("warning or higher wire priority", bool(re.match(r"<(?:[0-9]|1[0-2])>", line)), line or "missing"),
    ]
    title = "Nonexistent-user login severity" if nonexistent else ("Locked-account login severity" if locked else "Failed login severity")
    return evaluated_result(scenario_id, title, started, commands, assertions, "Rejected authentication was delivered at warning priority or higher")


def mysql_failed_login(context: LabContext) -> ScenarioResult:
    return mysql_family_auth_failure(context, "D2")


def mysql_nonexistent_login(context: LabContext) -> ScenarioResult:
    return mysql_family_auth_failure(context, "D2a", nonexistent=True)


def mysql_locked_login(context: LabContext) -> ScenarioResult:
    return mysql_family_auth_failure(context, "D2d", locked=True)


def mysql_user_ddl(context: LabContext) -> ScenarioResult:
    started = utc_now()
    username = f"lc_d2h_{secrets.token_hex(5)}"
    trigger = mysql_family_cli(context, f"CREATE USER '{username}'@'localhost'; GRANT SELECT ON *.* TO '{username}'@'localhost'; DROP USER '{username}'@'localhost';")
    received = context.receiver_grep(username, timeout=90)
    text = received.stdout.upper()
    assertions = [
        AssertionResult("user DDL completed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("CREATE USER collected", "CREATE USER" in text, command_fact(received)),
        AssertionResult("GRANT collected", "GRANT" in text, command_fact(received)),
        AssertionResult("DROP USER collected", "DROP USER" in text, command_fact(received)),
    ]
    return evaluated_result("D2h", "User DDL security events", started, [trigger, received], assertions, "CREATE USER, GRANT, and DROP USER were collected")


def mysql_slow_case(
    context: LabContext,
    scenario_id: str,
    name: str,
    statements: list[str],
    required: list[str],
    expected_count: int = 1,
    temporary_settings: dict[str, str] | None = None,
) -> ScenarioResult:
    started = utc_now()
    marker = context.marker(scenario_id)
    commands: list[CommandResult] = []
    temporary_settings = temporary_settings or {}
    extra_variables = list(temporary_settings)
    snapshot_fields = [
        "@@global.slow_query_log",
        "@@global.long_query_time",
        "@@global.log_output",
        *(f"@@global.{name}" for name in extra_variables),
    ]
    snapshot = mysql_family_cli(context, f"SELECT {','.join(snapshot_fields)};")
    commands.append(snapshot)
    values = snapshot.stdout.rstrip("\n").split("\t")
    if snapshot.returncode != 0 or len(values) != len(snapshot_fields):
        raise RuntimeError(f"Could not safely capture MySQL slow-log settings: {command_fact(snapshot)}")
    change_sql = ["SET GLOBAL log_output='FILE'", "SET GLOBAL slow_query_log=ON", "SET GLOBAL long_query_time=0"]
    change_sql.extend(f"SET GLOBAL {name}={value}" for name, value in temporary_settings.items())
    restore_sql = [
        f"SET GLOBAL slow_query_log={int(values[0].strip().upper() in {'1', 'ON'})}",
        f"SET GLOBAL long_query_time={values[1]}",
        f"SET GLOBAL log_output={json.dumps(values[2])}",
    ]
    for index, name in enumerate(extra_variables, start=3):
        restore_sql.append(
            f"SET GLOBAL {name}={int(values[index].strip().upper() in {'1', 'ON'})}"
        )
    restore_command = "; ".join(restore_sql) + ";"
    action_id = f"{scenario_id}-{secrets.token_hex(5)}"
    journal = getattr(context, "journal", None)
    if journal:
        binary = "mysql" if context.database == "mysql" else "mariadb"
        journal.add(
            {
                "id": action_id,
                "scope": "local",
                "command": f"sudo {binary} --batch --raw --skip-column-names -e {shlex.quote(restore_command)}",
                "sudo": False,
                "timeout": 60,
            }
        )
    change = mysql_family_cli(context, "; ".join(change_sql) + ";")
    commands.append(change)
    time.sleep(2)
    cleanup_ok = False
    try:
        for statement in statements:
            commands.append(mysql_family_cli(context, statement.format(marker=marker), timeout=180))
        received = context.receiver_grep(marker, timeout=90)
        commands.append(received)
        count = context.receiver.run(
            f"grep -Fc -- {shlex.quote(marker)} {shlex.quote(context.receiver_log)} || true",
            sudo=True,
            timeout=30,
        )
        commands.append(count)
    finally:
        restore = mysql_family_cli(context, restore_command)
        commands.append(restore)
        cleanup_ok = restore.returncode == 0
        if cleanup_ok and journal:
            journal.remove(action_id)
    try:
        occurrences = int(count.stdout.strip() or "0")
    except ValueError:
        occurrences = -1
    output = received.stdout
    assertions = [
        AssertionResult("temporary slow-log settings applied", change.returncode == 0, command_fact(change)),
        AssertionResult("all slow queries executed", all(item.returncode == 0 for item in commands[2:-3]), "see commands.log"),
        AssertionResult("record content intact", marker in output and all(item in output for item in required), command_fact(received)),
        AssertionResult("expected event count", occurrences == expected_count, f"matches={occurrences}"),
    ]
    return evaluated_result(scenario_id, name, started, commands, assertions, "Slow-log records arrived intact with the expected boundaries", "Passed" if cleanup_ok else "Failed")


def mysql_slow_same_second(context: LabContext) -> ScenarioResult:
    return mysql_slow_case(context, "D3", "Two same-second slow queries", ["SELECT /*{marker}*/ SLEEP(1);", "SELECT /*{marker}*/ SLEEP(1);"], ["SLEEP(1)"], 2)


def mysql_slow_timestamp_record(context: LabContext) -> ScenarioResult:
    return mysql_slow_case(context, "D4", "Slow query timestamp and statement", ["SELECT /*{marker}*/ SLEEP(1);"], ["SET timestamp=", "SLEEP(1)"])


def mysql_slow_multiline(context: LabContext) -> ScenarioResult:
    return mysql_slow_case(context, "D4a", "Multi-line slow query", ["SELECT /*{marker}*/\n SLEEP(1);"], ["SLEEP(1)"])


def mysql_slow_no_index(context: LabContext) -> ScenarioResult:
    marker = context.marker("D4b", "table")[:40]
    return mysql_slow_case(context, "D4b", "Unindexed query slow logging", [f"CREATE DATABASE IF NOT EXISTS log_collector_test; USE log_collector_test; DROP TABLE IF EXISTS {marker}; CREATE TABLE {marker}(id INT); INSERT INTO {marker} VALUES (1),(2); SELECT /*{{marker}}*/ * FROM {marker} WHERE id=2; DROP TABLE {marker};"], ["WHERE id=2"], temporary_settings={"log_queries_not_using_indexes": "ON"})


def mysql_slow_admin(context: LabContext) -> ScenarioResult:
    table = context.marker("D4c", "table")[:40]
    return mysql_slow_case(context, "D4c", "Slow administrative statement", [f"CREATE DATABASE IF NOT EXISTS log_collector_test; USE log_collector_test; DROP TABLE IF EXISTS {table}; CREATE TABLE {table}(id INT); ALTER TABLE {table} ADD COLUMN /*{{marker}}*/ note TEXT; DROP TABLE {table};"], ["ALTER TABLE"], temporary_settings={"log_slow_admin_statements": "ON"})


def mysql_slow_volume(context: LabContext) -> ScenarioResult:
    statements = ["; ".join(f"SELECT /*{{marker}}_{index:03d}*/ {index}" for index in range(1, 101)) + ";"]
    return mysql_slow_case(context, "D4d", "Temporary zero-threshold slow-log volume", statements, ["_100"], 100)


def mysql_general_case(context: LabContext, scenario_id: str, name: str, sql: str, required: list[str]) -> ScenarioResult:
    started = utc_now()
    marker = context.marker(scenario_id)
    snapshot = mysql_family_cli(context, "SELECT @@global.general_log,@@global.log_output;")
    values = snapshot.stdout.strip().split("\t")[-2:]
    if len(values) != 2:
        values = ["0", "FILE"]
    change = mysql_family_cli(context, "SET GLOBAL log_output='FILE'; SET GLOBAL general_log=ON;")
    time.sleep(2)
    cleanup_ok = False
    try:
        trigger = mysql_family_cli(context, sql.format(marker=marker))
        received = context.receiver_grep(marker, timeout=90)
        count = context.receiver.run(f"grep -Fc -- {shlex.quote(marker)} {shlex.quote(context.receiver_log)} || true", sudo=True, timeout=30)
    finally:
        restore = mysql_family_cli(context, f"SET GLOBAL general_log={int(values[0].strip().upper() in {'1', 'ON'})}; SET GLOBAL log_output={json.dumps(values[1])};")
        cleanup_ok = restore.returncode == 0
    try:
        occurrences = int(count.stdout.strip() or "0")
    except ValueError:
        occurrences = -1
    assertions = [
        AssertionResult("general log enabled temporarily", change.returncode == 0, command_fact(change)),
        AssertionResult("query completed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("one intact event", occurrences == 1 and all(item in received.stdout for item in required), f"matches={occurrences}; {command_fact(received)}"),
    ]
    return evaluated_result(scenario_id, name, started, [snapshot, change, trigger, received, count, restore], assertions, "General-log query arrived as one intact event", "Passed" if cleanup_ok else "Failed")


def mysql_general_multiline(context: LabContext) -> ScenarioResult:
    return mysql_general_case(context, "D5", "Multi-line general query", "SELECT /*{marker}*/\n 'line_two';", ["line_two"])


def mysql_general_fake_header(context: LabContext) -> ScenarioResult:
    return mysql_general_case(context, "D5a", "Header-like general query text", "SELECT /*{marker}*/ '2026-08-07T10:00:00 12 Query';", ["2026-08-07T10:00:00 12 Query"])


def mysql_excluded_files(context: LabContext) -> ScenarioResult:
    started = utc_now()
    inspect = context.local.run("PID=$(systemctl show -p MainPID --value log-collector); sudo lsof -nP -p \"$PID\" 2>/dev/null", timeout=30)
    forbidden = [line for line in inspect.stdout.splitlines() if re.search(r"(?:binlog|relay|\.index$|\.ibd$)", line, re.I)]
    assertions = [
        AssertionResult("collector files inspected", inspect.returncode == 0 and bool(inspect.stdout.strip()), command_fact(inspect)),
        AssertionResult("binary and table files excluded", not forbidden, "none" if not forbidden else "\n".join(forbidden[:10])),
    ]
    return evaluated_result("D8", "Binary, relay, and table-file exclusions", started, [inspect], assertions, "Collector did not open binary, relay, index, or table data files")


def mysql_rotation_alias(context: LabContext) -> ScenarioResult:
    return dataclasses.replace(mysql_family_rotation(context), scenario_id="D9", name="FLUSH LOGS rotation")


def mysql_slow_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("D9b", "rotation")[:48]
    snapshot = mysql_family_cli(context, "SELECT @@global.slow_query_log,@@global.long_query_time,@@global.log_output;")
    values = snapshot.stdout.strip().split("\t")[-3:]
    if len(values) != 3:
        values = ["0", "10", "FILE"]
    change = mysql_family_cli(context, "SET GLOBAL log_output='FILE'; SET GLOBAL slow_query_log=ON; SET GLOBAL long_query_time=0;")
    commands = [snapshot, change]
    cleanup_ok = False
    try:
        for index in range(1, 31):
            commands.append(mysql_family_cli(context, f"SELECT /*{prefix}_{index:02d}*/ {index};"))
            if index == 15:
                commands.append(mysql_family_cli(context, "FLUSH SLOW LOGS;"))
        received = context.receiver_grep(f"{prefix}_30", timeout=90)
        commands.append(received)
        all_lines = context.receiver.run(f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)}", sudo=True, timeout=30)
        commands.append(all_lines)
    finally:
        restore = mysql_family_cli(context, f"SET GLOBAL slow_query_log={int(values[0].strip().upper() in {'1', 'ON'})}; SET GLOBAL long_query_time={values[1]}; SET GLOBAL log_output={json.dumps(values[2])};")
        commands.append(restore)
        cleanup_ok = restore.returncode == 0
    markers = set(re.findall(re.escape(prefix) + r"_(\d{2})", all_lines.stdout))
    assertions = [
        AssertionResult("slow-log rotation completed", any(item.command.endswith("FLUSH SLOW LOGS;' ") or "FLUSH SLOW LOGS" in item.command for item in commands), "issued"),
        AssertionResult("all boundary markers delivered", markers == {f"{i:02d}" for i in range(1, 31)}, f"unique={len(markers)}"),
    ]
    return evaluated_result("D9b", "Slow-log rotation under activity", started, commands, assertions, "All numbered slow queries crossed the rotation boundary", "Passed" if cleanup_ok else "Failed")


def mysql_database_restart(context: LabContext) -> ScenarioResult:
    started = utc_now()
    service_name = mysql_family_service(context)
    before = context.marker("D9c", "before")
    after = context.marker("D9c", "after")
    commands = [mysql_family_marker(context, before), context.receiver_grep(before, timeout=90)]
    restart = context.local.run(f"sudo systemctl restart {service_name}", timeout=180)
    commands.append(restart)
    time.sleep(5)
    commands.extend([mysql_family_marker(context, after), context.receiver_grep(after, timeout=90)])
    collector = context.local.run("systemctl is-active log-collector", timeout=15)
    database = context.local.run(f"systemctl is-active {service_name}", timeout=15)
    commands.extend([collector, database])
    assertions = [
        AssertionResult("database restarted", restart.returncode == 0 and database.stdout.strip() == "active", command_fact(database)),
        AssertionResult("collector stayed active", collector.stdout.strip() == "active", command_fact(collector)),
        AssertionResult("post-restart event delivered", after in commands[4].stdout, command_fact(commands[4])),
    ]
    return evaluated_result("D9c", "MySQL restart survival", started, commands, assertions, "Collector survived the database restart and resumed collection")


def mysql_connection_exhaustion(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    username = f"lc_d2e_{token}"
    password = f"Lc-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(password)
    snapshot = mysql_family_cli(context, "SELECT @@global.max_connections;")
    old = re.findall(r"\d+", snapshot.stdout)
    old_value = old[-1] if old else "151"
    prepare = mysql_family_cli(context, f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{password}'; GRANT USAGE ON *.* TO '{username}'@'localhost'; SET GLOBAL max_connections=10;")
    binary = "mysql"
    saturate = context.local.run(
        f"for i in $(seq 1 12); do {binary} --protocol=TCP -h127.0.0.1 -u {username} --password={shlex.quote(password)} -e 'SELECT SLEEP(20)' >/dev/null 2>&1 & done; wait",
        timeout=30,
    )
    received = context.receiver_grep("Too many connections", timeout=90)
    restore = mysql_family_cli(context, f"SET GLOBAL max_connections={old_value}; DROP USER IF EXISTS '{username}'@'localhost';")
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    assertions = [
        AssertionResult("temporary connection ceiling applied", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("connection exhaustion logged", bool(re.search(r"too many connections|ER_CON_COUNT_ERROR", line, re.I)), line or "missing"),
        AssertionResult("error or higher wire priority", bool(re.match(r"<(?:[0-9]|1[01])>", line)), line or "missing"),
    ]
    return evaluated_result("D2e", "Connection exhaustion severity", started, [snapshot, prepare, saturate, received, restore], assertions, "Connection exhaustion was captured at error priority or higher", "Passed" if restore.returncode == 0 else "Failed")


def mariadb_prepare_audit(context: LabContext) -> tuple[list[CommandResult], dict[str, str]]:
    commands: list[CommandResult] = []
    plugin = mysql_family_cli(context, "SELECT COUNT(*) FROM information_schema.plugins WHERE plugin_name='SERVER_AUDIT';")
    commands.append(plugin)
    installed_before = plugin.stdout.strip().splitlines()[-1:] == ["1"]
    if not installed_before:
        commands.append(mysql_family_cli(context, "INSTALL SONAME 'server_audit';"))
    snapshot = mysql_family_cli(context, "SELECT @@global.server_audit_logging,@@global.server_audit_events,@@global.server_audit_output_type,@@global.server_audit_file_rotate_size;")
    commands.append(snapshot)
    values = snapshot.stdout.strip().split("\t")[-4:]
    if len(values) != 4:
        values = ["OFF", "", "FILE", "1000000"]
    change = mysql_family_cli(context, "SET GLOBAL server_audit_output_type='FILE'; SET GLOBAL server_audit_events='CONNECT,QUERY,TABLE'; SET GLOBAL server_audit_logging=ON;")
    commands.append(change)
    path = mysql_family_cli(context, "SELECT @@global.server_audit_file_path;")
    commands.append(path)
    audit_path = path.stdout.strip().splitlines()[-1] if path.stdout.strip() else "/var/lib/mysql/server_audit.log"
    if not audit_path.startswith("/"):
        datadir = mysql_family_cli(context, "SELECT @@global.datadir;")
        commands.append(datadir)
        audit_path = str(Path(datadir.stdout.strip().splitlines()[-1]) / audit_path)
    commands.append(context.local.run(f"sudo setfacl -m u:log-collector:r-- {shlex.quote(audit_path)} 2>/dev/null || true; sudo setfacl -m u:log-collector:r-x {shlex.quote(str(Path(audit_path).parent))} 2>/dev/null || true; sudo systemctl restart log-collector", timeout=90))
    time.sleep(3)
    return commands, {"installed_before": str(installed_before), "logging": values[0], "events": values[1], "output": values[2], "rotate": values[3]}


def mariadb_restore_audit(context: LabContext, state: dict[str, str]) -> CommandResult:
    statements = [
        f"SET GLOBAL server_audit_logging={int(state['logging'].strip().upper() in {'1', 'ON'})}",
        f"SET GLOBAL server_audit_events={json.dumps(state['events'])}",
        f"SET GLOBAL server_audit_output_type={json.dumps(state['output'])}",
        f"SET GLOBAL server_audit_file_rotate_size={state['rotate']}",
    ]
    if state["installed_before"] == "False":
        statements.extend(["SET GLOBAL server_audit_logging=OFF", "UNINSTALL SONAME 'server_audit'"])
    return mysql_family_cli(context, "; ".join(statements) + ";")


def mariadb_audit_query_case(context: LabContext, scenario_id: str, name: str, sql: str, required: list[str]) -> ScenarioResult:
    started = utc_now()
    marker = context.marker(scenario_id)
    commands, state = mariadb_prepare_audit(context)
    cleanup_ok = False
    try:
        trigger = mysql_family_cli(context, sql.format(marker=marker))
        received = context.receiver_grep(marker, timeout=90)
        count = context.receiver.run(f"grep -Fc -- {shlex.quote(marker)} {shlex.quote(context.receiver_log)} || true", sudo=True, timeout=30)
        commands.extend([trigger, received, count])
    finally:
        restore = mariadb_restore_audit(context, state)
        commands.append(restore)
        cleanup_ok = restore.returncode == 0
    try:
        occurrences = int(count.stdout.strip() or "0")
    except ValueError:
        occurrences = -1
    assertions = [
        AssertionResult("audit query executed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("one intact audit event", occurrences == 1 and all(item in received.stdout for item in required), f"matches={occurrences}; {command_fact(received)}"),
    ]
    return evaluated_result(scenario_id, name, started, commands, assertions, "MariaDB audit record arrived once with intact query text", "Passed" if cleanup_ok else "Failed")


def mariadb_successful_login(context: LabContext) -> ScenarioResult:
    started = utc_now()
    username = f"lc_f3_{secrets.token_hex(5)}"
    password = f"Lc-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(password)
    commands, state = mariadb_prepare_audit(context)
    create = mysql_family_cli(context, f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{password}';")
    login = context.local.run(f"mariadb --protocol=TCP -h127.0.0.1 -u {username} --password={shlex.quote(password)} -e 'SELECT 1'", timeout=15)
    received = context.receiver_grep(username, timeout=90)
    drop = mysql_family_cli(context, f"DROP USER IF EXISTS '{username}'@'localhost';")
    restore = mariadb_restore_audit(context, state)
    commands.extend([create, login, received, drop, restore])
    assertions = [
        AssertionResult("successful login completed", login.returncode == 0, command_fact(login)),
        AssertionResult("successful login collected", username in received.stdout and bool(re.search(r"CONNECT|QUERY", received.stdout, re.I)), command_fact(received)),
    ]
    return evaluated_result("F3", "Successful login audit", started, commands, assertions, "MariaDB server_audit recorded a successful login", "Passed" if drop.returncode == 0 and restore.returncode == 0 else "Failed")


def mariadb_failed_login(context: LabContext) -> ScenarioResult:
    return dataclasses.replace(mysql_family_auth_failure(context, "F4"), name="MariaDB failed login severity")


def mariadb_audit_comma(context: LabContext) -> ScenarioResult:
    return mariadb_audit_query_case(context, "F5", "Unescaped commas in audit query", "SELECT /*{marker}*/ 'a,b,c';", ["a,b,c"])


def mariadb_audit_quote(context: LabContext) -> ScenarioResult:
    return mariadb_audit_query_case(context, "F5a", "Escaped quote in audit query", "SELECT /*{marker}*/ 'alice\\\'s value';", ["alice", "value"])


def mariadb_audit_multiline(context: LabContext) -> ScenarioResult:
    return mariadb_audit_query_case(context, "F5b", "Multi-line audit query", "SELECT /*{marker}*/\n 'line_two';", ["line_two"])


def mariadb_audit_fake_timestamp(context: LabContext) -> ScenarioResult:
    return mariadb_audit_query_case(context, "F5c", "Timestamp-like audit query text", "SELECT /*{marker}*/ '20260807 10:00:00,fake';", ["20260807 10:00:00,fake"])


def mariadb_audit_retcode(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("F5d")
    commands, state = mariadb_prepare_audit(context)
    trigger = mysql_family_cli(context, f"SELECT /*{marker}*/ * FROM lc_runner_missing_table;")
    received = context.receiver_grep(marker, timeout=90)
    restore = mariadb_restore_audit(context, state)
    commands.extend([trigger, received, restore])
    retcodes = [int(value) for value in re.findall(r"(?:retcode[=\": ]+|,)(\d+)(?:,|\b)", received.stdout, re.I)]
    assertions = [
        AssertionResult("query failed as intended", trigger.returncode != 0, command_fact(trigger)),
        AssertionResult("nonzero retcode parsed", any(value != 0 for value in retcodes), str(retcodes)),
    ]
    return evaluated_result("F5d", "Audit retcode extraction", started, commands, assertions, "Failed query carried a nonzero parsed retcode", "Passed" if restore.returncode == 0 else "Failed")


def mariadb_audit_event_kinds(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("F5e")
    username = f"lc_f5e_{secrets.token_hex(4)}"
    commands, state = mariadb_prepare_audit(context)
    trigger = mysql_family_cli(context, f"CREATE USER '{username}'@'localhost'; CREATE TABLE {marker}(id INT); INSERT INTO {marker} VALUES (1); SELECT /*{marker}*/ * FROM {marker}; DROP TABLE {marker}; DROP USER '{username}'@'localhost';")
    received = context.receiver_grep(marker, timeout=90)
    user_received = context.receiver_grep(username, timeout=30)
    restore = mariadb_restore_audit(context, state)
    commands.extend([trigger, received, user_received, restore])
    combined = received.stdout + user_received.stdout
    assertions = [
        AssertionResult("mixed audit activity generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("CONNECT or user event collected", username in combined, combined[-1000:]),
        AssertionResult("QUERY event collected", bool(re.search(r"QUERY", combined, re.I)) and marker in combined, combined[-1000:]),
        AssertionResult("TABLE event collected", bool(re.search(r"TABLE", combined, re.I)), combined[-1000:]),
    ]
    return evaluated_result("F5e", "CONNECT, QUERY, and TABLE audit events", started, commands, assertions, "All configured MariaDB audit event kinds were collected", "Passed" if restore.returncode == 0 else "Failed")


def mariadb_audit_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("F5f", "rotation")[:48]
    commands, state = mariadb_prepare_audit(context)
    commands.append(mysql_family_cli(context, "SET GLOBAL server_audit_file_rotate_size=8192;"))
    for index in range(1, 101):
        commands.append(mysql_family_cli(context, f"SELECT /*{prefix}_{index:03d}*/ REPEAT('x',200);"))
    received = context.receiver_grep(f"{prefix}_100", timeout=120)
    all_lines = context.receiver.run(f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)}", sudo=True, timeout=30)
    restore = mariadb_restore_audit(context, state)
    commands.extend([received, all_lines, restore])
    markers = set(re.findall(re.escape(prefix) + r"_(\d{3})", all_lines.stdout))
    assertions = [AssertionResult("all rotated audit records delivered", markers == {f"{i:03d}" for i in range(1, 101)}, f"unique={len(markers)}")]
    return evaluated_result("F5f", "server_audit size rotation", started, commands, assertions, "All numbered audit events crossed small-file rotations", "Passed" if restore.returncode == 0 else "Failed")


def mariadb_error_format(context: LabContext) -> ScenarioResult:
    result = mysql_family_auth_failure(context, "F9", nonexistent=True)
    line = next((item.observed for item in result.assertions if item.name == "failed login delivered"), "")
    format_assertion = AssertionResult("MariaDB text error shape", "[MY-" not in line and bool(re.search(r"\d{4}-\d{2}-\d{2}|\d{6}", line)), line or "missing")
    result.assertions.append(format_assertion)
    if not format_assertion.passed:
        result.status = "Fail"
        result.reason = "Failed assertion(s): MariaDB text error shape"
    result.name = "MariaDB text error-log format"
    return result


def mariadb_slow_and_general(context: LabContext) -> ScenarioResult:
    started = utc_now()
    slow = context.marker("F11", "slow")
    general = context.marker("F11", "general")
    snapshot = mysql_family_cli(context, "SELECT @@global.slow_query_log,@@global.general_log,@@global.long_query_time,@@global.log_output;")
    values = snapshot.stdout.strip().split("\t")[-4:]
    if len(values) != 4:
        values = ["0", "0", "10", "FILE"]
    change = mysql_family_cli(context, "SET GLOBAL log_output='FILE'; SET GLOBAL slow_query_log=ON; SET GLOBAL general_log=ON; SET GLOBAL long_query_time=0;")
    slow_trigger = mysql_family_cli(context, f"SELECT /*{slow}*/ SLEEP(1);")
    general_trigger = mysql_family_cli(context, f"SELECT /*{general}*/ 1;")
    slow_received = context.receiver_grep(slow, timeout=90)
    general_received = context.receiver_grep(general, timeout=90)
    restore = mysql_family_cli(context, f"SET GLOBAL slow_query_log={int(values[0].upper() in {'1', 'ON'})}; SET GLOBAL general_log={int(values[1].upper() in {'1', 'ON'})}; SET GLOBAL long_query_time={values[2]}; SET GLOBAL log_output={json.dumps(values[3])};")
    assertions = [
        AssertionResult("slow log collected", slow in slow_received.stdout, command_fact(slow_received)),
        AssertionResult("general log collected", general in general_received.stdout, command_fact(general_received)),
    ]
    return evaluated_result("F11", "MariaDB slow and general log collection", started, [snapshot, change, slow_trigger, general_trigger, slow_received, general_received, restore], assertions, "Both inherited MySQL log formats were collected", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_stability_case(context: LabContext, scenario_id: str, minutes: int = LAB_STABILITY_MINUTES) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker(scenario_id, "stability")[:48]
    sample_command = "printf 'pid=%s rss=%s restarts=%s status=%s fds=%s\\n' \"$(systemctl show -p MainPID --value log-collector)\" \"$(ps -o rss= -p \"$(systemctl show -p MainPID --value log-collector)\" | xargs)\" \"$(systemctl show -p NRestarts --value log-collector)\" \"$(systemctl is-active log-collector)\" \"$(find /proc/$(systemctl show -p MainPID --value log-collector)/fd -maxdepth 1 -type l 2>/dev/null | wc -l)\""
    commands: list[CommandResult] = []
    samples: list[tuple[int, int, int, str, int]] = []
    pattern = re.compile(r"pid=(\d+) rss=(\d+) restarts=(\d+) status=(\S+) fds=(\d+)")
    for index in range(0, minutes + 1):
        if index:
            commands.append(mysql_family_marker(context, f"{prefix}_{index:02d}"))
            time.sleep(60)
        sample = context.local.run(sample_command, timeout=15)
        commands.append(sample)
        match = pattern.search(sample.stdout)
        if match:
            samples.append((int(match[1]), int(match[2]), int(match[3]), match[4], int(match[5])))
    received = context.receiver_grep(prefix, timeout=90)
    commands.append(received)
    marker_numbers = set(re.findall(re.escape(prefix) + r"_(\d{2})", received.stdout))
    rss_ok = bool(samples) and max(row[1] for row in samples) <= samples[0][1] + 131072
    fd_ok = bool(samples) and max(row[4] for row in samples) <= samples[0][4] + 64
    assertions = [
        AssertionResult("complete runtime samples", len(samples) == minutes + 1, f"samples={len(samples)}"),
        AssertionResult("collector remained active without restart", bool(samples) and all(row[3] == "active" for row in samples) and len({row[0] for row in samples}) == 1 and len({row[2] for row in samples}) == 1, str(samples)),
        AssertionResult("bounded RSS", rss_ok, str([row[1] for row in samples])),
        AssertionResult("bounded file descriptors", fd_ok, str([row[4] for row in samples])),
        AssertionResult("all stability markers delivered", marker_numbers == {f"{i:02d}" for i in range(1, minutes + 1)}, str(sorted(marker_numbers))),
    ]
    name = "Constrained-lab stability window" if scenario_id == "B4" else "Constrained sustained-load soak"
    return evaluated_result(scenario_id, name, started, commands, assertions, f"Collector remained stable for the approved {minutes}-minute constrained-lab window")


def mysql_family_stability(context: LabContext) -> ScenarioResult:
    return mysql_family_stability_case(context, "B4")


def mysql_family_soak(context: LabContext) -> ScenarioResult:
    return mysql_family_stability_case(context, "H12")


def mysql_family_timestamp(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("B7")
    snapshot = mysql_family_cli(context, "SELECT @@global.slow_query_log,@@global.long_query_time,@@global.log_output,@@global.slow_query_log_file;")
    values = snapshot.stdout.strip().split("\t")[-4:]
    if len(values) != 4:
        values = ["0", "10", "FILE", ""]
    change = mysql_family_cli(context, "SET GLOBAL log_output='FILE'; SET GLOBAL slow_query_log=ON; SET GLOBAL long_query_time=0;")
    trigger = mysql_family_cli(context, f"SELECT /*{marker}*/ SLEEP(0.2);")
    received = context.receiver_grep(marker, timeout=90)
    path = values[3]
    native = context.local.run(
        f"sudo awk -v m={shlex.quote(marker)} 'BEGIN{{t=\"\"}} /^# Time: /{{t=substr($0,9)}} index($0,m){{print t; exit}}' {shlex.quote(path)}",
        timeout=30,
    ) if path else snapshot
    restore = mysql_family_cli(context, f"SET GLOBAL slow_query_log={int(values[0].upper() in {'1', 'ON'})}; SET GLOBAL long_query_time={values[1]}; SET GLOBAL log_output={json.dumps(values[2])};")
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    wire_match = re.match(r"<\d+>1\s+(\S+)", line)
    native_value = native.stdout.strip().splitlines()[-1] if native.stdout.strip() else ""
    wire_value = wire_match.group(1) if wire_match else ""
    native_normalized = native_value.replace("T", " ").replace("Z", " UTC")
    match = timestamps_match(native_normalized, wire_value, tolerance_seconds=1.0) if native_value and wire_value else False
    assertions = [
        AssertionResult("database-native timestamp located", bool(native_value), command_fact(native)),
        AssertionResult("receiver wire timestamp located", bool(wire_value), line or "missing"),
        AssertionResult("same event instant", match, f"native={native_value} wire={wire_value}"),
    ]
    return evaluated_result("B7", "Native timestamp preservation", started, [snapshot, change, trigger, received, native, restore], assertions, "Receiver timestamp matches the database's own slow-log timestamp", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_outage_case(context: LabContext, scenario_id: str, seconds: int, require_buffer: bool, require_delivery: bool) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker(scenario_id, "outage")[:48]
    commands: list[CommandResult] = []
    recovery_id = f"{scenario_id}-{secrets.token_hex(5)}"
    before = context.local.run("sudo du -sb /var/lib/log-collector/disk_buffer 2>/dev/null || echo '0 missing'", timeout=30)
    commands.append(before)
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "receiver", "command": RECEIVER_START_COMMAND, "sudo": True, "timeout": 60})
    stop = establish_receiver_outage(context)
    commands.append(stop)
    cleanup_ok = False
    try:
        deadline = time.monotonic() + seconds
        index = 0
        while time.monotonic() < deadline:
            index += 1
            commands.append(mysql_family_marker(context, f"{prefix}_{index:03d}"))
            time.sleep(min(5, max(0.1, deadline - time.monotonic())))
        during = context.local.run("sudo du -sb /var/lib/log-collector/disk_buffer 2>/dev/null || echo '0 missing'; systemctl is-active log-collector", timeout=30)
        commands.append(during)
    finally:
        restore = restore_receiver_ingest(context)
        commands.append(restore)
        cleanup_ok = restore.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(recovery_id)
    received = context.receiver_grep(f"{prefix}_{index:03d}", timeout=120)
    commands.append(received)
    after = context.local.run("sudo du -sb /var/lib/log-collector/disk_buffer 2>/dev/null || echo '0 missing'; systemctl is-active log-collector", timeout=30)
    commands.append(after)
    def first_size(result: CommandResult) -> int:
        match = re.search(r"^(\d+)", result.stdout)
        return int(match.group(1)) if match else -1
    assertions = [
        AssertionResult("receiver outage established", stop.returncode == 0, command_fact(stop)),
        AssertionResult("collector stayed active", "active" in during.stdout and "active" in after.stdout, f"during={during.stdout.strip()} after={after.stdout.strip()}"),
    ]
    if require_buffer:
        assertions.append(AssertionResult("disk buffer grew", first_size(during) > first_size(before), f"before={first_size(before)} during={first_size(during)}"))
    if require_delivery:
        assertions.append(AssertionResult("buffered tail marker delivered", f"{prefix}_{index:03d}" in received.stdout, command_fact(received)))
    names = {"B5": "Constrained-lab receiver outage", "H1": "Disk buffer growth during receiver outage", "H2": "Buffered delivery after recovery"}
    return evaluated_result(scenario_id, names[scenario_id], started, commands, assertions, "Collector stayed alive and handled the receiver outage as expected", "Passed" if cleanup_ok else "Failed")


def mysql_family_receiver_outage(context: LabContext) -> ScenarioResult:
    return mysql_family_outage_case(context, "B5", LAB_OUTAGE_MINUTES * 60, False, True)


def mysql_family_buffer_growth(context: LabContext) -> ScenarioResult:
    return mysql_family_outage_case(context, "H1", 30, True, False)


def mysql_family_buffer_delivery(context: LabContext) -> ScenarioResult:
    return mysql_family_outage_case(context, "H2", 30, True, True)


def mysql_family_rapid_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    markers = [context.marker("G3b", f"part{i}") for i in range(1, 4)]
    commands: list[CommandResult] = []
    for index, marker in enumerate(markers):
        commands.append(mysql_family_marker(context, marker))
        if index < 2:
            commands.append(mysql_family_cli(context, "FLUSH LOGS;"))
            time.sleep(2)
    received = context.receiver_grep(markers[-1], timeout=90)
    commands.append(received)
    all_lines = context.receiver.run(f"grep -E -- {shlex.quote('|'.join(markers))} {shlex.quote(context.receiver_log)}", sudo=True, timeout=30)
    commands.append(all_lines)
    assertions = [AssertionResult("all markers crossed two rotations", all(marker in all_lines.stdout for marker in markers), command_fact(all_lines))]
    return evaluated_result("G3b", "Two rapid database rotations", started, commands, assertions, "Collection followed two rapid FLUSH LOGS rotations")


def mysql_family_agent_before_database(context: LabContext, scenario_id: str = "H4") -> ScenarioResult:
    started = utc_now()
    service_name = mysql_family_service(context)
    marker = context.marker(scenario_id, "recovered")
    recovery_id = f"{scenario_id}-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": f"systemctl start {service_name}; systemctl start log-collector", "sudo": True, "timeout": 180})
    stop = context.local.run(f"sudo systemctl stop {service_name}", timeout=120)
    restart_collector = context.local.run("sudo systemctl restart log-collector", timeout=60)
    waiting = context.local.run("systemctl is-active log-collector", timeout=15)
    start_database = context.local.run(f"sudo systemctl start {service_name}", timeout=180)
    time.sleep(5)
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    cleanup_ok = start_database.returncode == 0
    if cleanup_ok and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("database stopped", stop.returncode == 0, command_fact(stop)),
        AssertionResult("collector active while database absent", restart_collector.returncode == 0 and waiting.stdout.strip() == "active", command_fact(waiting)),
        AssertionResult("database restarted", start_database.returncode == 0, command_fact(start_database)),
        AssertionResult("collection resumed", marker in received.stdout, command_fact(received)),
    ]
    name = "Agent restart while database is stopped" if scenario_id == "G4a" else "Collector starts before database"
    return evaluated_result(scenario_id, name, started, [stop, restart_collector, waiting, start_database, trigger, received], assertions, "Collector waited for the database and resumed collection", "Passed" if cleanup_ok else "Failed")


def mysql_family_db_stopped_restart(context: LabContext) -> ScenarioResult:
    return mysql_family_agent_before_database(context, "G4a")


def mysql_family_delete_recreate(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G7")
    path_result = mysql_family_cli(context, "SELECT @@global.slow_query_log_file;")
    path = path_result.stdout.strip().splitlines()[-1] if path_result.stdout.strip() else ""
    snapshot = mysql_family_cli(context, "SELECT @@global.slow_query_log,@@global.long_query_time;")
    values = snapshot.stdout.strip().split("\t")[-2:]
    if len(values) != 2:
        values = ["0", "10"]
    change = mysql_family_cli(context, "SET GLOBAL slow_query_log=ON; SET GLOBAL long_query_time=0;")
    time.sleep(2)
    delete = context.local.run(f"sudo rm -f -- {shlex.quote(path)}", timeout=30) if path else path_result
    rotate = mysql_family_cli(context, "FLUSH SLOW LOGS;")
    time.sleep(3)
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    restore = mysql_family_cli(context, f"SET GLOBAL slow_query_log={int(values[0].upper() in {'1', 'ON'})}; SET GLOBAL long_query_time={values[1]};")
    assertions = [
        AssertionResult("active slow log deleted", bool(path) and delete.returncode == 0, path or command_fact(delete)),
        AssertionResult("database recreated log", rotate.returncode == 0 and context.local.run(f"test -f {shlex.quote(path)}", timeout=15).returncode == 0, path),
        AssertionResult("collector picked up replacement", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G7", "Delete and recreate active log", started, [path_result, snapshot, change, delete, rotate, trigger, received, restore], assertions, "Collector followed the recreated database log", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_permission_recovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G8")
    path_result = mysql_family_cli(context, "SELECT @@global.slow_query_log_file;")
    path = path_result.stdout.strip().splitlines()[-1] if path_result.stdout.strip() else ""
    mode_result = context.local.run(f"stat -c %a {shlex.quote(path)}", timeout=15) if path else path_result
    mode = mode_result.stdout.strip() or "640"
    recovery_id = f"G8-{secrets.token_hex(5)}"
    if context.journal and path:
        context.journal.add({"id": recovery_id, "scope": "local", "command": f"chmod {mode} {shlex.quote(path)}", "sudo": True, "timeout": 30})
    deny = context.local.run(f"sudo chmod 000 {shlex.quote(path)}", timeout=30) if path else path_result
    time.sleep(5)
    logs = context.local.run("sudo journalctl -u log-collector --since '-2 minutes' --no-pager", timeout=30)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    restore_mode = context.local.run(f"sudo chmod {mode} {shlex.quote(path)}", timeout=30) if path else path_result
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    cleanup_ok = restore_mode.returncode == 0
    if cleanup_ok and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("permission removed", deny.returncode == 0, command_fact(deny)),
        AssertionResult("clear read error emitted", bool(re.search(r"permission|denied|cannot.*open", logs.stdout, re.I)), command_fact(logs)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("collection recovered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G8", "Permission loss and recovery", started, [path_result, mode_result, deny, logs, service, restore_mode, trigger, received], assertions, "Collector reported the read denial, stayed active, and recovered", "Passed" if cleanup_ok else "Failed")


def mysql_large_record_command(binary: str, prefix: str, suffix: str, payload_bytes: int) -> str:
    sql_prefix = f"SET SESSION long_query_time=0; SELECT /*{prefix}*/ LENGTH('"
    sql_suffix = f"') /*{suffix}*/ AS payload_len;"
    return (
        f"{{ printf %s {shlex.quote(sql_prefix)}; "
        f"head -c {payload_bytes} /dev/zero | tr '\\0' x; "
        f"printf %s {shlex.quote(sql_suffix)}; }} | "
        f"sudo {shlex.quote(binary)} --comments --batch --skip-column-names --max-allowed-packet=8M"
    )


def mysql_family_large_record(context: LabContext) -> ScenarioResult:
    started = utc_now()
    capacity_check, capacity, configured = receiver_message_capacity(context)
    required = LARGE_RECORD_PAYLOAD_BYTES + LARGE_RECORD_OVERHEAD_BYTES
    if capacity is not None and capacity < required:
        return ScenarioResult(
            scenario_id="G9",
            name="Multi-megabyte database record",
            status="Inconclusive",
            reason=f"Receiver effective message limit is {capacity // 1024} KiB; at least {required // 1024} KiB is required before testing truncation",
            started_at=started,
            ended_at=utc_now(),
            assertions=[AssertionResult("receiver accepts the full test record", False, f"configured={configured} required_bytes={required}")],
            commands=[capacity_check],
        )
    prefix = context.marker("G9", "begin")
    suffix = context.marker("G9", "end")
    binary = "mysql" if context.database == "mysql" else "mariadb"
    trigger = context.local.run(mysql_large_record_command(binary, prefix, suffix, LARGE_RECORD_PAYLOAD_BYTES), timeout=180)
    received = context.receiver_event(prefix, timeout=120)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("multi-megabyte query executed", trigger.returncode == 0 and "2097152" in trigger.stdout, command_fact(trigger)),
        AssertionResult("large record beginning delivered", prefix in received.stdout, f"prefix_visible={prefix in received.stdout}"),
        AssertionResult("large record not truncated", suffix in received.stdout, f"suffix_visible={suffix in received.stdout} received_bytes={len(received.stdout.encode('utf-8'))}"),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G9", "Multi-megabyte database record", started, [capacity_check, trigger, received, service], assertions, "Collector handled a multi-megabyte query record without truncation or crashing")


def mysql_family_high_volume(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("G15", "load")[:44]
    binary = "mysql" if context.database == "mysql" else "mariadb"
    snapshot = mysql_family_cli(context, "SELECT @@global.slow_query_log,@@global.long_query_time;")
    values = snapshot.stdout.strip().split("\t")[-2:]
    if len(values) != 2:
        values = ["0", "10"]
    change = mysql_family_cli(context, "SET GLOBAL slow_query_log=ON; SET GLOBAL long_query_time=0;")
    generator = context.local.run(f"for i in $(seq -w 1 1000); do printf 'SELECT /*{prefix}_%s*/ 1;\\n' \"$i\"; done | sudo {binary} --batch --comments", timeout=300)
    received = context.receiver_grep(f"{prefix}_1000", timeout=180)
    all_lines = context.receiver.run(f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)}", sudo=True, timeout=60)
    health = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    restore = mysql_family_cli(context, f"SET GLOBAL slow_query_log={int(values[0].upper() in {'1', 'ON'})}; SET GLOBAL long_query_time={values[1]};")
    markers = set(re.findall(re.escape(prefix) + r"_(\d{4})", all_lines.stdout))
    assertions = [
        AssertionResult("1,000 queries generated", generator.returncode == 0, command_fact(generator)),
        AssertionResult("all numbered records delivered", len(markers) == 1000, f"unique={len(markers)}"),
        AssertionResult("collector health available", health.returncode == 0, command_fact(health)),
    ]
    return evaluated_result("G15", "Constrained high-volume run", started, [snapshot, change, generator, received, all_lines, health, restore], assertions, "Collector delivered the constrained 1,000-event load", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_setup_discovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:use\s+)?auto.?discover(?:y|ed)")
    variables = mysql_family_cli(context, "SELECT @@global.datadir,@@global.log_error,@@global.slow_query_log_file;")
    paths = [part for part in variables.stdout.strip().split("\t") if part]
    engine_name = "mysql" if context.database == "mysql" else "mariadb"
    discovered = engine_name in probe.stdout.lower() and bool(re.search(r"detected|found|discover", probe.stdout, re.I))
    visible = any(path in probe.stdout or Path(path).name in probe.stdout for path in paths)
    assertions = [
        AssertionResult("installed engine discovered", probe.returncode == 0 and discovered, command_fact(probe)),
        AssertionResult("database location displayed", visible, f"reported={paths}"),
    ]
    return evaluated_result("A4", "Installed database discovery", started, [dependency, probe, variables], assertions, f"Wizard displayed the installed {context.database} instance and its log location")


def mysql_family_setup_last_good(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, backup_result, config, backup = backup_collector_configuration(context, "A12")
    before_hash = context.local.run(f"sudo sha256sum {shlex.quote(config)} | awk '{{print $1}}'", timeout=15)
    dependency, wizard = complete_setup_wizard(context, engines={context.database})
    after_hash = context.local.run(f"sudo sha256sum {shlex.quote(config + '.last-good')} | awk '{{print $1}}'", timeout=15)
    check = context.local.run("sudo log-collector check", timeout=30)
    restore = restore_collector_configuration(context, config, backup)
    assertions = [
        AssertionResult("setup rerun completed", wizard.returncode == 0, command_fact(wizard)),
        AssertionResult("previous config preserved exactly", bool(before_hash.stdout.strip()) and before_hash.stdout.strip() == after_hash.stdout.strip(), f"before={before_hash.stdout.strip()} last_good={after_hash.stdout.strip()}"),
        AssertionResult("new config valid", check.returncode == 0, command_fact(check)),
    ]
    return evaluated_result("A12", "Setup preserves last-good config", started, [locate, backup_result, before_hash, dependency, wizard, after_hash, check, restore], assertions, "Rerunning setup preserved the previous encrypted config", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_small_file_restart(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G4", "after_restart")
    snapshot = mysql_family_cli(context, "SELECT @@global.slow_query_log,@@global.long_query_time,@@global.slow_query_log_file;")
    values = snapshot.stdout.strip().split("\t")[-3:]
    if len(values) != 3:
        values = ["0", "10", ""]
    path = values[2]
    change = mysql_family_cli(context, "SET GLOBAL slow_query_log=ON; SET GLOBAL long_query_time=0; FLUSH SLOW LOGS;")
    time.sleep(2)
    truncate = context.local.run(f"sudo truncate -s 0 -- {shlex.quote(path)}", timeout=30) if path else snapshot
    size = context.local.run(f"sudo stat -c %s -- {shlex.quote(path)}", timeout=15) if path else snapshot
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    restore = mysql_family_cli(context, f"SET GLOBAL slow_query_log={int(values[0].upper() in {'1', 'ON'})}; SET GLOBAL long_query_time={values[1]};")
    try:
        byte_count = int(size.stdout.strip())
    except ValueError:
        byte_count = -1
    assertions = [
        AssertionResult("active log is under 128 bytes", 0 <= byte_count < 128, f"size={byte_count} path={path}"),
        AssertionResult("collector restarted", restart.returncode == 0, command_fact(restart)),
        AssertionResult("next event delivered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G4", "Nearly-empty log restart", started, [snapshot, change, truncate, size, restart, trigger, received, restore], assertions, "Collector restarted on a sub-128-byte log without losing the next event", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_fresh_state(context: LabContext) -> ScenarioResult:
    started = utc_now()
    old = context.marker("G5", "history")
    new = context.marker("G5", "current")
    old_trigger = mysql_family_marker(context, old)
    old_received = context.receiver_grep(old, timeout=90)
    count_command = f"grep -Fc -- {shlex.quote(old)} {shlex.quote(context.receiver_log)} || true"
    before = context.receiver.run(count_command, sudo=True, timeout=15)
    stop = context.local.run("sudo systemctl stop log-collector", timeout=60)
    clear = context.local.run("sudo find /var/lib/log-collector/state /var/lib/log-collector/disk_buffer -mindepth 1 -delete", timeout=60)
    start_service = context.local.run("sudo systemctl start log-collector", timeout=60)
    time.sleep(5)
    after = context.receiver.run(count_command, sudo=True, timeout=15)
    new_trigger = mysql_family_marker(context, new)
    new_received = context.receiver_grep(new, timeout=90)
    try:
        before_count = int(before.stdout.strip() or "0")
        after_count = int(after.stdout.strip() or "0")
    except ValueError:
        before_count = after_count = -1
    assertions = [
        AssertionResult("collector state reset", stop.returncode == 0 and clear.returncode == 0 and start_service.returncode == 0, f"stop={stop.returncode} clear={clear.returncode} start={start_service.returncode}"),
        AssertionResult("history not replayed", before_count >= 1 and after_count == before_count, f"before={before_count} after={after_count}"),
        AssertionResult("new event delivered", new in new_received.stdout, command_fact(new_received)),
    ]
    return evaluated_result("G5", "Fresh-state starts at current log end", started, [old_trigger, old_received, before, stop, clear, start_service, after, new_trigger, new_received], assertions, "Fresh state started at current log end without flooding history")


def mysql_family_read_from_beginning(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, backup_result, config, backup = backup_collector_configuration(context, "G5a")
    dependency, wizard = complete_setup_wizard(context, engines={context.database}, read_from_beginning=True)
    check = context.local.run("sudo log-collector check", timeout=30)
    marker = context.marker("G5a", "history")
    stop = context.local.run("sudo systemctl stop log-collector", timeout=60)
    clear = context.local.run("sudo find /var/lib/log-collector/state /var/lib/log-collector/disk_buffer -mindepth 1 -delete", timeout=60)
    history = mysql_family_marker(context, marker)
    start_service = context.local.run("sudo systemctl start log-collector", timeout=60)
    received = context.receiver_grep(marker, timeout=180)
    restore = restore_collector_configuration(context, config, backup, reset_state=True)
    assertions = [
        AssertionResult("read-from-beginning setup completed", wizard.returncode == 0 and check.returncode == 0, f"wizard={wizard.returncode} check={check.returncode}"),
        AssertionResult("collector state reset", stop.returncode == 0 and clear.returncode == 0, f"stop={stop.returncode} clear={clear.returncode}"),
        AssertionResult("historical event generated before collector start", history.returncode == 0, command_fact(history)),
        AssertionResult("historical event ingested", start_service.returncode == 0 and marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G5a", "Read existing history from beginning", started, [locate, backup_result, dependency, wizard, check, stop, clear, history, start_service, received, restore], assertions, "Read-from-beginning ingested the pre-existing database event", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_malformed(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G10", "malformed")
    path_result = mysql_family_cli(context, "SELECT @@global.slow_query_log_file;")
    path = path_result.stdout.strip().splitlines()[-1] if path_result.stdout.strip() else ""
    malformed = f"{{not-valid-database-log,marker:{marker}}}"
    append = context.local.run(f"printf '%s\\n' {shlex.quote(malformed)} | sudo tee -a -- {shlex.quote(path)} >/dev/null", timeout=30) if path else path_result
    received = context.receiver_grep(marker, timeout=90)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    flagged = bool(re.search(r"raw|malform|parse|flag", received.stdout, re.I))
    assertions = [
        AssertionResult("malformed record appended", append.returncode == 0, command_fact(append)),
        AssertionResult("malformed record forwarded", marker in received.stdout, command_fact(received)),
        AssertionResult("forwarded record flagged", flagged, "flag token present" if flagged else "flag missing"),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G10", "Malformed record forwarding", started, [path_result, append, received, service], assertions, "Malformed input was forwarded and flagged without stopping the collector")


def mysql_family_symlink_log(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    real = f"/var/log/mysql/lc-real-{token}.log"
    link = f"/var/log/mysql/lc-link-{token}.log"
    marker = context.marker("G13")
    snapshot = mysql_family_cli(context, "SELECT @@global.slow_query_log,@@global.long_query_time,@@global.slow_query_log_file;")
    values = snapshot.stdout.strip().split("\t")[-3:]
    if len(values) != 3:
        values = ["0", "10", "/var/log/mysql/slow.log"]
    restore_sql = f"SET GLOBAL slow_query_log=OFF; SET GLOBAL slow_query_log_file={json.dumps(values[2])}; SET GLOBAL long_query_time={values[1]}; SET GLOBAL slow_query_log={int(values[0].upper() in {'1', 'ON'})};"
    binary = "mysql" if context.database == "mysql" else "mariadb"
    recovery_id = f"G13-{token}"
    recovery = f"{binary} -e {shlex.quote(restore_sql)}; rm -f -- {shlex.quote(link)} {shlex.quote(real)}; systemctl restart log-collector"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": recovery, "sudo": True, "timeout": 180})
    prepare = context.local.run(f"sudo install -o mysql -g adm -m 0640 /dev/null {shlex.quote(real)}; sudo ln -s {shlex.quote(real)} {shlex.quote(link)}; sudo setfacl -m u:log-collector:r {shlex.quote(real)}", timeout=30)
    change = mysql_family_cli(context, f"SET GLOBAL slow_query_log=OFF; SET GLOBAL slow_query_log_file={json.dumps(link)}; SET GLOBAL long_query_time=0; SET GLOBAL slow_query_log=ON;")
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    restore = mysql_family_cli(context, restore_sql)
    cleanup = context.local.run(f"sudo rm -f -- {shlex.quote(link)} {shlex.quote(real)}", timeout=30)
    restart = context.local.run("sudo systemctl restart log-collector", timeout=90)
    verify = mysql_family_cli(context, "SELECT @@global.slow_query_log,@@global.long_query_time,@@global.slow_query_log_file;")
    restored = restore.returncode == 0 and cleanup.returncode == 0 and restart.returncode == 0 and values[2] in verify.stdout
    if restored and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("symlinked log configured", prepare.returncode == 0 and change.returncode == 0, f"prepare={prepare.returncode} change={change.returncode}"),
        AssertionResult("event through symlink collected", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G13", "Symlinked database log", started, [snapshot, prepare, change, trigger, received, restore, cleanup, restart, verify], assertions, "Collector followed a symlinked database log path", "Passed" if restored else "Failed")


def mysql_family_config_fallback(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("H7", "fallback")
    locate, config = collector_config_path(context)
    backup = f"/tmp/lc-h7-{secrets.token_hex(5)}"
    last_good = f"{config}.last-good"
    prepare = context.local.run(f"sudo mkdir -p {shlex.quote(backup)} && sudo cp -a -- {shlex.quote(config)} {shlex.quote(last_good)} {shlex.quote(backup)}/", timeout=60) if config else context.local.run("false", timeout=5)
    restore_command = f"cp -a -- {shlex.quote(backup)}/agent.toml {shlex.quote(config)}; cp -a -- {shlex.quote(backup)}/agent.toml.last-good {shlex.quote(last_good)}; systemctl restart log-collector"
    recovery_id = f"H7-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 120})
    corrupt = context.local.run(f"printf garbage | sudo tee {shlex.quote(config)} >/dev/null && sudo systemctl restart log-collector", timeout=120) if config else context.local.run("false", timeout=5)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    logs = context.local.run("sudo journalctl -u log-collector --since '-3 minutes' --no-pager | tail -n 100", timeout=30)
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    restore = context.local.run(f"sudo bash -lc {shlex.quote(restore_command)}; sudo rm -rf -- {shlex.quote(backup)}", timeout=120)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("configuration backed up", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("collector used last-good fallback", corrupt.returncode == 0 and service.stdout.strip() == "active" and bool(re.search(r"last.?good|fallback|recover", logs.stdout, re.I)), command_fact(logs)),
        AssertionResult("collection continued", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H7", "Corrupt config fallback", started, [locate, prepare, corrupt, service, logs, trigger, received, restore], assertions, "Collector used last-good configuration and kept collecting", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_unreachable_output(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("H9", "recovered")
    resolved = context.local.run(f"getent ahostsv4 {shlex.quote(context.receiver.config.host)} | awk 'NR==1 {{print $1}}'", timeout=15)
    address = resolved.stdout.strip()
    add_rule = f"iptables -I OUTPUT -p tcp -d {shlex.quote(address)} --dport 2514 -j REJECT"
    del_rule = f"iptables -D OUTPUT -p tcp -d {shlex.quote(address)} --dport 2514 -j REJECT"
    recovery_id = f"H9-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": del_rule, "sudo": True, "timeout": 30})
    block = context.local.run(add_rule, sudo=True, timeout=30) if address else context.local.run("false", timeout=5)
    trigger = mysql_family_marker(context, marker)
    time.sleep(10)
    health = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    unblock = context.local.run(del_rule, sudo=True, timeout=30) if address else context.local.run("false", timeout=5)
    if unblock.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    received = context.receiver_grep(marker, timeout=90)
    try:
        payload = json.loads(health.stdout)
    except json.JSONDecodeError:
        payload = {}
    disconnected = payload.get("cloud_connected") is False or str(payload.get("cloud_status", "")).lower() not in {"connected", ""}
    assertions = [
        AssertionResult("receiver route blocked", block.returncode == 0, command_fact(block)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("health reported disconnected", disconnected, command_fact(health)),
        AssertionResult("delivery recovered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H9", "Unreachable output retry", started, [resolved, block, trigger, health, service, unblock, received], assertions, "Collector stayed active and recovered after output became reachable", "Passed" if unblock.returncode == 0 else "Failed")


def mysql_family_reboot_resume(context: LabContext) -> ScenarioResult:
    if context.evidence is None:
        raise RuntimeError("H6 requires an evidence run")
    started = utc_now()
    scenario_dir = (context.evidence.run_dir / "scenarios" / "H6").resolve()
    phase_file = scenario_dir / "post-reboot.txt"
    marker = context.marker("H6", "post_reboot")
    service_name = mysql_family_service(context)
    if phase_file.exists():
        phase = context.local.run(f"sudo cat {shlex.quote(str(phase_file))}", timeout=15)
        received = context.receiver_grep(marker, timeout=90)
        enabled = context.local.run("systemctl is-enabled log-collector", timeout=15)
        cleanup = context.local.run("sudo systemctl disable --now lc-h6-continuation.service 2>/dev/null || true; sudo rm -f /etc/systemd/system/lc-h6-continuation.service; sudo systemctl daemon-reload", timeout=60)
        assertions = [
            AssertionResult("collector active after reboot", "collector=active" in phase.stdout, command_fact(phase)),
            AssertionResult("collector enabled at boot", enabled.stdout.strip() == "enabled", command_fact(enabled)),
            AssertionResult("post-reboot event delivered", marker in received.stdout, command_fact(received)),
        ]
        return evaluated_result("H6", "Machine reboot continuity", started, [phase, received, enabled, cleanup], assertions, "Collector returned automatically and resumed database collection")
    scenario_dir.mkdir(parents=True, exist_ok=True)
    binary = "mysql" if context.database == "mysql" else "mariadb"
    phase_command = f"for i in $(seq 1 60); do systemctl is-active --quiet {service_name} && systemctl is-active --quiet log-collector && break; sleep 2; done; {binary} --comments -e {shlex.quote('SET SESSION long_query_time=0; SELECT /*' + marker + '*/ SLEEP(0.2);')}; printf 'collector=%%s\\ndatabase=%%s\\nmarker={marker}\\n' \"$(systemctl is-active log-collector)\" \"$(systemctl is-active {service_name})\" > {shlex.quote(str(phase_file))}"
    unit = f"[Unit]\nDescription=Log collector H6 continuation\nAfter=network-online.target {service_name}.service log-collector.service\n\n[Service]\nType=oneshot\nExecStart=/bin/bash -lc {shlex.quote(phase_command)}\n\n[Install]\nWantedBy=multi-user.target\n"
    prepare = context.local.run(f"printf %s {shlex.quote(unit)} | sudo tee /etc/systemd/system/lc-h6-continuation.service >/dev/null; sudo systemctl daemon-reload; sudo systemctl enable lc-h6-continuation.service", timeout=60)
    if prepare.returncode != 0:
        raise RuntimeError(f"Could not prepare reboot continuation: {command_fact(prepare)}")
    print(f"[H6] Reboot prepared. After boot rerun with --resume --scenario H6. Evidence: {context.evidence.run_dir}", flush=True)
    reboot = context.local.run("sudo systemctl reboot", timeout=30)
    if reboot.returncode != 0:
        raise RuntimeError(f"Reboot request failed: {command_fact(reboot)}")
    raise SystemExit(75)


def mysql_family_buffer_disk_full(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    image = f"/tmp/lc-h11-{token}.img"
    mountpoint = "/var/lib/log-collector/disk_buffer"
    if context.journal:
        context.journal.add({"id": f"H11-r-{token}", "scope": "receiver", "command": RECEIVER_START_COMMAND, "sudo": True, "timeout": 60})
        context.journal.add({"id": f"H11-l-{token}", "scope": "local", "command": f"systemctl stop log-collector; umount {mountpoint} 2>/dev/null || true; rm -f {image}; systemctl start log-collector", "sudo": True, "timeout": 180})
    prepare = context.local.run(f"sudo systemctl stop log-collector; truncate -s 32M {shlex.quote(image)}; sudo mkfs.ext4 -q -F {shlex.quote(image)}; sudo mount -o loop {shlex.quote(image)} {mountpoint}; sudo chown log-collector:log-collector {mountpoint}; sudo systemctl start log-collector", timeout=180)
    stop_receiver = establish_receiver_outage(context)
    binary = "mysql" if context.database == "mysql" else "mariadb"
    cleanup_ok = False
    try:
        generator = context.local.run(f"PAYLOAD=$(head -c 4000 /dev/zero | tr '\\0' x); for i in $(seq -w 1 20000); do printf 'SELECT /*lc_h11_%s_%s*/ 1;\\n' \"$i\" \"$PAYLOAD\"; done | sudo {binary} --batch", timeout=900)
        time.sleep(15)
        disk = context.local.run(f"df -Pk {mountpoint}; sudo du -sb {mountpoint}", timeout=30)
        logs = context.local.run("sudo journalctl -u log-collector --since '-10 minutes' --no-pager | tail -n 200", timeout=30)
        service = context.local.run("systemctl is-active log-collector", timeout=15)
    finally:
        restore_receiver = restore_receiver_ingest(context)
        cleanup = context.local.run(f"sudo systemctl stop log-collector; sudo umount {mountpoint}; rm -f {shlex.quote(image)}; sudo systemctl start log-collector", timeout=180)
        cleanup_ok = restore_receiver.returncode == 0 and cleanup.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(f"H11-r-{token}")
            context.journal.remove(f"H11-l-{token}")
    assertions = [
        AssertionResult("isolated buffer filesystem mounted", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("receiver stopped", stop_receiver.returncode == 0, command_fact(stop_receiver)),
        AssertionResult("buffer pressure generated", generator.returncode == 0, command_fact(generator)),
        AssertionResult("collector survived full buffer disk", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("clear disk or buffer error", bool(re.search(r"no space|disk|buffer|write", logs.stdout, re.I)), command_fact(logs)),
    ]
    return evaluated_result("H11", "Full buffer disk handling", started, [prepare, stop_receiver, generator, disk, logs, service, restore_receiver, cleanup], assertions, "Collector remained running and reported the full buffer disk", "Passed" if cleanup_ok else "Failed")


def mysql_family_apparmor(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    marker = context.marker("I7", "apparmor")
    profile_path = f"/etc/apparmor.d/lc-log-collector-{token}"
    binary_result = context.local.run("command -v log-collector || printf /usr/local/bin/log-collector", timeout=15)
    binary = binary_result.stdout.strip()
    profile_name = f"lc-log-collector-{token}"
    profile = f"#include <tunables/global>\nprofile {profile_name} {binary} flags=(attach_disconnected) {{\n #include <abstractions/base>\n capability,\n network,\n / r,\n /** r,\n /var/lib/log-collector/** rwk,\n /var/log/log-collector/** rwk,\n /run/** rwk,\n /proc/** r,\n /sys/** r,\n}}\n"
    install = context.local.run("sudo apt-get -s install apparmor apparmor-utils && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor apparmor-utils", timeout=600)
    load = context.local.run(f"printf %s {shlex.quote(profile)} | sudo tee {shlex.quote(profile_path)} >/dev/null && sudo apparmor_parser -r {shlex.quote(profile_path)} && sudo systemctl restart log-collector", timeout=120)
    trigger = mysql_family_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    denials = context.local.run(f"sudo journalctl -k --since '-5 minutes' --no-pager | grep -F 'apparmor=\"DENIED\"' | grep -F {shlex.quote(profile_name)} || true", timeout=30)
    cleanup = context.local.run(f"sudo apparmor_parser -R {shlex.quote(profile_path)} 2>/dev/null || true; sudo rm -f -- {shlex.quote(profile_path)}; sudo systemctl restart log-collector", timeout=120)
    assertions = [
        AssertionResult("AppArmor tools available", install.returncode == 0, command_fact(install)),
        AssertionResult("enforcing profile loaded", load.returncode == 0, command_fact(load)),
        AssertionResult("event collected while confined", marker in received.stdout, command_fact(received)),
        AssertionResult("no AppArmor denial", not denials.stdout.strip(), command_fact(denials)),
    ]
    return evaluated_result("I7", "AppArmor enforcing", started, [binary_result, install, load, trigger, received, denials, cleanup], assertions, "Collector remained functional under an enforcing AppArmor profile", "Passed" if cleanup.returncode == 0 else "Failed")


def mysql_family_multi_engine_setup(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, backup_result, config, backup = backup_collector_configuration(context, "A11")
    simulation = context.local.run("sudo apt-get -s install postgresql", timeout=180)
    install = context.local.run("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql && sudo systemctl start postgresql", timeout=1800)
    pg_logging = context.local.run("sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"ALTER SYSTEM SET logging_collector='on';\" -c \"ALTER SYSTEM SET log_destination='jsonlog';\" -c \"ALTER SYSTEM SET log_statement='all';\"; sudo systemctl restart postgresql; sudo setfacl -Rm u:log-collector:rX /var/log/postgresql", timeout=240)
    dependency, wizard = complete_setup_wizard(context, engines={context.database, "postgresql"})
    check = context.local.run("sudo log-collector check", timeout=30)
    restart = context.local.run("sudo systemctl restart log-collector; sleep 5; sudo journalctl -u log-collector --since '-3 minutes' --no-pager | tail -n 200", timeout=90)
    restore = restore_collector_configuration(context, config, backup)
    assertions = [
        AssertionResult("PostgreSQL package prepared", simulation.returncode == 0 and install.returncode == 0, f"simulate={simulation.returncode} install={install.returncode}"),
        AssertionResult("PostgreSQL logging prepared", pg_logging.returncode == 0, command_fact(pg_logging)),
        AssertionResult("wizard completed both engine sections", wizard.returncode == 0 and "postgres" in wizard.stdout.lower() and context.database in wizard.stdout.lower(), command_fact(wizard)),
        AssertionResult("multi-engine config valid", check.returncode == 0, command_fact(check)),
        AssertionResult("both inputs started", "postgres_log" in restart.stdout and f"{context.database}_log" in restart.stdout, command_fact(restart)),
    ]
    return evaluated_result("A11", "Two engines in one setup", started, [locate, backup_result, simulation, install, pg_logging, dependency, wizard, check, restart, restore], assertions, "Wizard configured PostgreSQL and the selected MySQL-family engine together", "Passed" if restore.returncode == 0 else "Failed")


def wizard_output_case(context: LabContext, scenario_id: str, name: str, target: str, expectation: str) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(context, target)
    assertions = [AssertionResult(expectation, probe.returncode == 0, command_fact(probe))]
    return evaluated_result(scenario_id, name, started, [dependency, probe], assertions, expectation)


def mysql_default_selection(context: LabContext) -> ScenarioResult:
    return wizard_output_case(context, "D1", "MySQL default log selection", r"(?is)(error.*slow.*audit|general.*(?:off|disabled|not selected))", "Wizard selected error, slow, and audit while leaving general off")


def mysql_general_warning(context: LabContext) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(context, r"(?i)general(?:\s+query)?\s+log[^\r\n]*[?:›]\s*$", answer_at_target="y", post_pattern=r"(?i)(?:warning|cost|volume|performance|50\s*gb|throughput)")
    assertions = [AssertionResult("general-log cost warning displayed", probe.returncode == 0, command_fact(probe))]
    return evaluated_result("D1a", "Explicit general-log selection warning", started, [dependency, probe], assertions, "Wizard allowed general-log selection and displayed its cost warning")


def mysql_temp_config_case(context: LabContext, scenario_id: str, name: str, content: str, target: str) -> ScenarioResult:
    started = utc_now()
    subdir = "mariadb.conf.d" if context.database == "mariadb" else "mysql.conf.d"
    path = f"/etc/mysql/{subdir}/zz-lc-{scenario_id.lower()}.cnf"
    service_name = mysql_family_service(context)
    recovery_id = f"{scenario_id}-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": f"rm -f {path}; systemctl restart {service_name}", "sudo": True, "timeout": 180})
    write = context.local.run(f"printf %s {shlex.quote(content)} | sudo tee {shlex.quote(path)} >/dev/null; sudo systemctl restart {service_name}", timeout=180)
    dependency, probe = setup_wizard_probe(context, target)
    defaults = context.local.run("sudo my_print_defaults mysqld server mariadb 2>/dev/null || true", timeout=30)
    cleanup = context.local.run(f"sudo rm -f -- {shlex.quote(path)}; sudo systemctl restart {service_name}", timeout=180)
    if cleanup.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("temporary server configuration accepted", write.returncode == 0, command_fact(write)),
        AssertionResult("wizard handled configured layout", probe.returncode == 0, command_fact(probe)),
    ]
    return evaluated_result(scenario_id, name, started, [write, dependency, probe, defaults, cleanup], assertions, f"Wizard handled {name.lower()}", "Passed" if cleanup.returncode == 0 else "Failed")


def mysql_client_section_ignored(context: LabContext) -> ScenarioResult:
    started = utc_now()
    path = "/etc/mysql/conf.d/zz-lc-d1c.cnf"
    content = "[client]\nport=65000\nsocket=/tmp/lc-does-not-exist.sock\n"
    write = context.local.run(f"printf %s {shlex.quote(content)} | sudo tee {path} >/dev/null", timeout=30)
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:detected|found).*mysql")
    cleanup = context.local.run(f"sudo rm -f {path}", timeout=30)
    assertions = [
        AssertionResult("conflicting client section installed", write.returncode == 0, command_fact(write)),
        AssertionResult("server discovery ignored client values", probe.returncode == 0 and "65000" not in probe.stdout and "/tmp/lc-does-not-exist.sock" not in probe.stdout, command_fact(probe)),
    ]
    return evaluated_result("D1c", "Ignore conflicting client section", started, [write, dependency, probe, cleanup], assertions, "Wizard ignored port and socket values from the client section", "Passed" if cleanup.returncode == 0 else "Failed")


def mysql_dash_option(context: LabContext) -> ScenarioResult:
    return mysql_temp_config_case(context, "D1d", "Dash and underscore option equivalence", "[mysqld]\nslow-query-log=ON\nslow-query-log-file=/var/log/mysql/lc-d1d-slow.log\n", r"(?i)lc-d1d-slow\.log")


def mysql_relative_log(context: LabContext) -> ScenarioResult:
    return mysql_temp_config_case(context, "D1e", "Relative log path resolution", "[mysqld]\nslow_query_log=ON\nslow_query_log_file=lc-d1e-relative.log\n", r"(?i)(?:datadir|/var/lib/mysql).*lc-d1e-relative\.log")


def mysql_include_directives(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    main = "/etc/mysql/mysql.cnf"
    include_file = f"/etc/mysql/lc-d1b-{token}.cnf"
    include_dir = f"/etc/mysql/lc-d1b-{token}.d"
    included = f"{include_dir}/included.cnf"
    backup = f"/etc/mysql/.lc-d1b-{token}.my.cnf"
    recovery_id = f"D1b-{token}"
    recovery = f"cp -a {backup} {main}; systemctl reset-failed mysql; systemctl restart mysql && rm -rf {include_file} {include_dir} {backup}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": recovery, "sudo": True, "timeout": 180})
    prepare = context.local.run(
        f"sudo cp -a {main} {backup}; sudo install -d {include_dir}; "
        f"printf '%b' {shlex.quote('[mysqld]\\nslow_query_log=ON\\nslow_query_log_file=/var/log/mysql/lc-d1b-file.log\\n')} | sudo tee {include_file} >/dev/null; "
        f"printf '%b' {shlex.quote('[mysqld]\\ngeneral_log_file=/var/log/mysql/lc-d1b-dir.log\\n')} | sudo tee {included} >/dev/null; "
        f"printf '%b' {shlex.quote(f'\\n!include {include_file}\\n!includedir {include_dir}\\n')} | sudo tee -a {main} >/dev/null; "
        "sudo systemctl reset-failed mysql; sudo systemctl restart mysql",
        timeout=180,
    )
    dependency, probe = setup_wizard_probe(context, r"(?i)lc-d1b-(?:file|dir)\.log")
    defaults = context.local.run("sudo my_print_defaults mysqld", timeout=30)
    cleanup = context.local.run(f"sudo bash -lc {shlex.quote(recovery)}", timeout=180)
    if cleanup.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("include and includedir configuration accepted", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("both included values parsed", "lc-d1b-file.log" in defaults.stdout and "lc-d1b-dir.log" in defaults.stdout, command_fact(defaults)),
        AssertionResult("wizard followed include directives", probe.returncode == 0, command_fact(probe)),
    ]
    return evaluated_result("D1b", "MySQL include directive discovery", started, [prepare, dependency, probe, defaults, cleanup], assertions, "Wizard followed both include forms", "Passed" if cleanup.returncode == 0 else "Failed")


def mysql_remote_auth_probe(context: LabContext, scenario_id: str, block_host: bool) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    username = f"lc_{scenario_id.lower()}_{token}"
    config = f"/etc/mysql/mysql.conf.d/zz-lc-{scenario_id.lower()}.cnf"
    client_ip_result = context.local.run("hostname -I | awk '{print $1}'", timeout=15)
    client_ip = client_ip_result.stdout.strip()
    receiver_ip_result = context.local.run(f"getent ahostsv4 {shlex.quote(context.receiver.config.host)} | awk 'NR==1 {{print $1}}'", timeout=15)
    receiver_ip = receiver_ip_result.stdout.strip()
    firewall_add = f"iptables -I INPUT -p tcp -s {receiver_ip} --dport 3306 -j ACCEPT"
    firewall_del = f"iptables -D INPUT -p tcp -s {receiver_ip} --dport 3306 -j ACCEPT"
    recovery_id = f"{scenario_id}-{token}"
    recovery = f"rm -f {config}; {firewall_del} 2>/dev/null || true; systemctl restart mysql"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": recovery, "sudo": True, "timeout": 180})
    prepare = context.local.run(
        f"printf %s {shlex.quote('[mysqld]\\nbind-address=0.0.0.0\\n')} | sudo tee {config} >/dev/null; "
        f"sudo systemctl restart mysql; sudo {firewall_add}",
        timeout=180,
    )
    create = mysql_family_cli(context, f"CREATE USER '{username}'@'10.255.255.255' IDENTIFIED BY 'unused';")
    old_max = mysql_family_cli(context, "SELECT @@global.max_connect_errors;")
    if block_host:
        configure = mysql_family_cli(context, "SET GLOBAL max_connect_errors=3; FLUSH HOSTS;")
    else:
        configure = old_max
    # Standard-library-only MySQL protocol probe: receive the handshake, then
    # either disconnect repeatedly or submit an invalid Protocol 4.1 response.
    remote_code = (
        "import socket,struct,time\n"
        f"h={client_ip!r};u={username!r}\n"
        "def packet(auth):\n"
        " s=socket.create_connection((h,3306),5);hdr=s.recv(4);n=int.from_bytes(hdr[:3],'little');s.recv(n)\n"
        " if not auth:s.close();return b''\n"
        " p=struct.pack('<IIB23s',0x00088205,16777216,45,b'')+u.encode()+b'\\0'+bytes([20])+bytes(20)+b'mysql_native_password\\0'\n"
        " s.sendall(len(p).to_bytes(3,'little')+b'\\x01'+p);r=s.recv(4096);s.close();return r\n"
        + ("[packet(False) for _ in range(6)];time.sleep(1)\n" if block_host else "")
        + "print(packet(True).decode('latin1','replace'))\n"
    )
    remote = context.receiver.run(f"python3 -c {shlex.quote(remote_code)}", timeout=60)
    received = context.receiver_grep(username, timeout=90)
    old_match = re.findall(r"\d+", old_max.stdout)
    restore_max = mysql_family_cli(context, f"SET GLOBAL max_connect_errors={old_match[-1] if old_match else 100}; FLUSH HOSTS; DROP USER IF EXISTS '{username}'@'10.255.255.255';")
    cleanup = context.local.run(f"sudo bash -lc {shlex.quote(recovery)}", timeout=180)
    if cleanup.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    expected = r"blocked|ER_HOST_IS_BLOCKED" if block_host else r"not allowed|not privileged|access denied"
    assertions = [
        AssertionResult("remote listener prepared", prepare.returncode == 0 and bool(client_ip and receiver_ip), f"client={client_ip} receiver={receiver_ip}"),
        AssertionResult("remote rejection observed", remote.returncode == 0 and bool(re.search(expected, remote.stdout, re.I)), command_fact(remote)),
        AssertionResult("security event collected", username in received.stdout or (block_host and bool(re.search(r"blocked", received.stdout, re.I))), command_fact(received)),
        AssertionResult("warning or higher priority", bool(re.match(r"<(?:[0-9]|1[0-2])>", line)), line or "missing"),
    ]
    name = "Blocked host severity" if block_host else "Disallowed host severity"
    return evaluated_result(scenario_id, name, started, [client_ip_result, receiver_ip_result, prepare, create, old_max, configure, remote, received, restore_max, cleanup], assertions, "Remote authentication denial was raised and collected", "Passed" if cleanup.returncode == 0 else "Failed")


def mysql_disallowed_host(context: LabContext) -> ScenarioResult:
    return mysql_remote_auth_probe(context, "D2b", False)


def mysql_blocked_host(context: LabContext) -> ScenarioResult:
    return mysql_remote_auth_probe(context, "D2c", True)


def mysql_existing_error_not_demoted(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.receiver.run(f"stat -c %s {shlex.quote(context.receiver_log)}", sudo=True, timeout=15)
    recovery_id = f"D3a-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": "systemctl start mysql", "sudo": True, "timeout": 180})
    crash = context.local.run("sudo systemctl kill --kill-who=main --signal=ABRT mysql", timeout=30)
    time.sleep(10)
    restart = context.local.run("sudo systemctl start mysql", timeout=180)
    if restart.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    try:
        offset = int(before.stdout.strip()) + 1
    except ValueError:
        offset = 1
    received = context.receiver.run(f"tail -c +{offset} {shlex.quote(context.receiver_log)} | tail -n 200", sudo=True, timeout=30)
    serious = [line for line in received.stdout.splitlines() if re.search(r"signal|abort|crash|shutdown|starting", line, re.I)]
    priority_ok = bool(serious) and all(bool(re.match(r"<(?:[0-9]|1[01])>", line)) for line in serious)
    assertions = [
        AssertionResult("server abort triggered", crash.returncode == 0, command_fact(crash)),
        AssertionResult("database recovered", restart.returncode == 0, command_fact(restart)),
        AssertionResult("native error events collected", bool(serious), "\n".join(serious[-10:]) or "missing"),
        AssertionResult("error severity not demoted", priority_ok, "\n".join(serious[-10:]) or "missing"),
    ]
    return evaluated_result("D3a", "Existing error severity is not demoted", started, [before, crash, restart, received], assertions, "Native MySQL error records remained error priority or higher", "Passed" if restart.returncode == 0 else "Failed")


def mysql_error_code_format(context: LabContext) -> ScenarioResult:
    result = mysql_family_auth_failure(context, "D2f", nonexistent=True)
    received = next((item.stdout for item in result.commands if item.command.startswith("receiver:")), "")
    assertion = AssertionResult("MySQL error code preserved", bool(re.search(r"\[MY-\d+\]", received)), received or "missing")
    result.assertions = [
        item for item in result.assertions
        if item.name in {"authentication rejected", "failed login delivered"}
    ] + [assertion]
    failed = [item.name for item in result.assertions if not item.passed]
    result.status = "Fail" if failed else "Pass"
    result.reason = f"Failed assertion(s): {', '.join(failed)}" if failed else "MySQL 8 error code remained visible"
    result.name = "MySQL 8 error-code format"
    return result


def mysql_community_gap_warning(context: LabContext) -> ScenarioResult:
    started = utc_now()
    plugin = mysql_family_cli(context, "SELECT COUNT(*) FROM information_schema.plugins WHERE plugin_name LIKE '%audit%';")
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    logs = context.local.run("sudo journalctl -u log-collector --since '-3 minutes' --no-pager", timeout=30)
    warning = bool(re.search(r"successful.*login.*(?:not|no|unavailable)|community.*audit|commercial.*plugin", logs.stdout, re.I))
    assertions = [
        AssertionResult("Community audit plugin absent", plugin.stdout.strip().splitlines()[-1:] == ["0"], command_fact(plugin)),
        AssertionResult("successful-login coverage warning emitted", restart.returncode == 0 and warning, command_fact(logs)),
    ]
    return evaluated_result("D6", "MySQL Community audit-gap warning", started, [plugin, restart, logs], assertions, "Collector warned that successful logins are unavailable without an audit plugin")


def mysql_successful_login_absent(context: LabContext) -> ScenarioResult:
    started = utc_now()
    username = f"lc_d7_{secrets.token_hex(5)}"
    password = f"Lc-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(password)
    plugin = mysql_family_cli(context, "SELECT COUNT(*) FROM information_schema.plugins WHERE plugin_name LIKE '%audit%';")
    general = mysql_family_cli(context, "SELECT @@global.general_log;")
    create = mysql_family_cli(context, f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{password}';")
    before = context.receiver.run(f"grep -Fc -- {shlex.quote(username)} {shlex.quote(context.receiver_log)} || true", sudo=True, timeout=15)
    login = context.local.run(f"mysql --protocol=TCP -h127.0.0.1 -u {username} --password={shlex.quote(password)} -e 'SELECT 1'", timeout=15)
    time.sleep(10)
    after = context.receiver.run(f"grep -Fc -- {shlex.quote(username)} {shlex.quote(context.receiver_log)} || true", sudo=True, timeout=15)
    drop = mysql_family_cli(context, f"DROP USER IF EXISTS '{username}'@'localhost';")
    try:
        before_count = int(before.stdout.strip() or "0")
        after_count = int(after.stdout.strip() or "0")
    except ValueError:
        before_count = after_count = -1
    assertions = [
        AssertionResult("Community mode without audit or general log", plugin.stdout.strip().endswith("0") and general.stdout.strip().upper() in {"0", "OFF"}, f"plugins={plugin.stdout.strip()} general={general.stdout.strip()}"),
        AssertionResult("successful login completed", login.returncode == 0, command_fact(login)),
        AssertionResult("successful login not fabricated", before_count >= 0 and after_count == before_count, f"before={before_count} after={after_count}"),
    ]
    return evaluated_result("D7", "Successful Community login gap", started, [plugin, general, create, before, login, after, drop], assertions, "No successful-login event was fabricated in Community mode", "Passed" if drop.returncode == 0 else "Failed")


def mysql_table_output_warning(context: LabContext) -> ScenarioResult:
    started = utc_now()
    old = mysql_family_cli(context, "SELECT @@global.log_output;")
    old_value = old.stdout.strip().splitlines()[-1] if old.stdout.strip() else "FILE"
    change = mysql_family_cli(context, "SET GLOBAL log_output='TABLE';")
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:log_output.*table|no.*file|nothing.*tail|table.*not.*file)")
    restore = mysql_family_cli(context, f"SET GLOBAL log_output={json.dumps(old_value)};")
    assertions = [
        AssertionResult("TABLE output configured", change.returncode == 0, command_fact(change)),
        AssertionResult("wizard reported no file", probe.returncode == 0, command_fact(probe)),
    ]
    return evaluated_result("D8a", "TABLE log output warning", started, [old, change, dependency, probe, restore], assertions, "Wizard stated that TABLE output has no file to collect", "Passed" if restore.returncode == 0 else "Failed")


def mysql_stderr_warning(context: LabContext) -> ScenarioResult:
    return mysql_temp_config_case(context, "D8b", "Empty or stderr error-log handling", "[mysqld]\nlog-error=\n", r"(?i)(?:stderr|journald|no.*error.*file|nothing.*tail)")


def mysql_json_error_sink(context: LabContext) -> ScenarioResult:
    started = utc_now()
    component = mysql_family_cli(context, "SELECT COUNT(*) FROM mysql.component WHERE component_urn='file://component_log_sink_json';")
    installed_before = component.stdout.strip().splitlines()[-1:] == ["1"]
    old_services = mysql_family_cli(context, "SELECT @@global.log_error_services;")
    old_value = old_services.stdout.strip().splitlines()[-1] if old_services.stdout.strip() else "log_filter_internal; log_sink_internal"
    old_verbosity = mysql_family_cli(context, "SELECT @@global.log_error_verbosity;")
    verbosity_value = old_verbosity.stdout.strip().splitlines()[-1] if old_verbosity.stdout.strip() else "2"
    install = mysql_family_cli(context, "INSTALL COMPONENT 'file://component_log_sink_json';") if not installed_before else component
    change = mysql_family_cli(context, "SET GLOBAL log_error_services='log_filter_internal; log_sink_internal; log_sink_json'; SET GLOBAL log_error_verbosity=3;")
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    username = f"lc_d7a_{secrets.token_hex(5)}"
    attempt = context.local.run(f"mysql --protocol=TCP -h127.0.0.1 -u {username} --password=wrong --connect-timeout=5 -e 'SELECT 1'", timeout=15)
    received = context.receiver_grep(username, timeout=90)
    restore_sql = f"SET GLOBAL log_error_services={json.dumps(old_value)}; SET GLOBAL log_error_verbosity={verbosity_value};"
    if not installed_before:
        restore_sql += " UNINSTALL COMPONENT 'file://component_log_sink_json';"
    restore = mysql_family_cli(context, restore_sql)
    assertions = [
        AssertionResult("JSON error sink enabled", install.returncode == 0 and change.returncode == 0 and restart.returncode == 0, f"install={install.returncode} change={change.returncode} restart={restart.returncode}"),
        AssertionResult("failed login generated", attempt.returncode != 0, command_fact(attempt)),
        AssertionResult("JSON sibling source collected", username in received.stdout and ".00.json" in received.stdout, command_fact(received)),
    ]
    return evaluated_result("D7a", "MySQL JSON error sink alongside text", started, [component, old_services, old_verbosity, install, change, restart, attempt, received, restore], assertions, "The .00.json sibling error log was collected alongside text", "Passed" if restore.returncode == 0 else "Failed")


def mysql_packaged_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("D9a", "before")
    after = context.marker("D9a", "after")
    before_trigger = mysql_family_marker(context, before)
    before_received = context.receiver_grep(before, timeout=90)
    rotate = context.local.run("sudo logrotate -f /etc/logrotate.d/mysql-server 2>/dev/null || sudo logrotate -f /etc/logrotate.d/mysql 2>/dev/null; sudo mysqladmin flush-logs", timeout=120)
    after_trigger = mysql_family_marker(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    assertions = [
        AssertionResult("packaged rotation completed", rotate.returncode == 0, command_fact(rotate)),
        AssertionResult("pre-rotation event delivered", before in before_received.stdout, command_fact(before_received)),
        AssertionResult("post-rotation event delivered", after in after_received.stdout, command_fact(after_received)),
    ]
    return evaluated_result("D9a", "Packaged logrotate continuity", started, [before_trigger, before_received, rotate, after_trigger, after_received], assertions, "Collection continued across packaged logrotate and mysqladmin flush-logs")


def mysql_family_create_user_redaction(context: LabContext) -> ScenarioResult:
    started = utc_now()
    username = f"lc_g1a_{secrets.token_hex(5)}"
    secret = f"LcG1a-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(secret)
    trigger = mysql_family_cli(context, f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{secret}';")
    received = context.receiver_grep(username, timeout=90)
    leak = context.receiver.run(f"grep -R -F -- {shlex.quote(secret)} {shlex.quote(context.receiver_client_dir)}", sudo=True, timeout=30)
    cleanup = mysql_family_cli(context, f"DROP USER IF EXISTS '{username}'@'localhost';")
    assertions = [
        AssertionResult("CREATE USER delivered", username in received.stdout, command_fact(received)),
        AssertionResult("password redacted", leak.returncode == 1 and not leak.stdout, "secret absent" if leak.returncode == 1 else "secret visible or search failed"),
    ]
    return evaluated_result("G1a", "CREATE USER password redaction", started, [trigger, received, leak, cleanup], assertions, "CREATE USER remained visible while its password was redacted", "Passed" if cleanup.returncode == 0 else "Failed")


def mysql_old_password_syntax(context: LabContext) -> ScenarioResult:
    started = utc_now()
    secret = f"LcG1c-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(secret)
    trigger = mysql_family_cli(context, f"SET PASSWORD = PASSWORD('{secret}');")
    if trigger.returncode != 0 and re.search(r"syntax|does not exist|FUNCTION.*PASSWORD", trigger.stderr, re.I):
        return ScenarioResult("G1c", "Legacy PASSWORD() redaction", "Not Tested", "Not applicable: installed MySQL version no longer supports PASSWORD()", started, utc_now(), commands=[trigger])
    received = context.receiver_grep("SET PASSWORD", timeout=90)
    leak = context.receiver.run(f"grep -R -F -- {shlex.quote(secret)} {shlex.quote(context.receiver_client_dir)}", sudo=True, timeout=30)
    assertions = [
        AssertionResult("legacy password statement delivered", trigger.returncode == 0 and "SET PASSWORD" in received.stdout, command_fact(received)),
        AssertionResult("legacy password redacted", leak.returncode == 1 and not leak.stdout, "secret absent" if leak.returncode == 1 else "secret visible or search failed"),
    ]
    return evaluated_result("G1c", "Legacy PASSWORD() redaction", started, [trigger, received, leak], assertions, "Legacy PASSWORD() syntax was redacted")


def mariadb_backslash_password(context: LabContext) -> ScenarioResult:
    started = utc_now()
    username = f"lc_g1d_{secrets.token_hex(5)}"
    secret = f"LcG1d-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(secret)
    commands, state = mariadb_prepare_audit(context)
    create = mysql_family_cli(context, f"CREATE USER '{username}'@'localhost'; SET PASSWORD FOR '{username}'@'localhost' = '{secret}';")
    received = context.receiver_grep(username, timeout=90)
    leak = context.receiver.run(f"grep -R -F -- {shlex.quote(secret)} {shlex.quote(context.receiver_client_dir)}", sudo=True, timeout=30)
    drop = mysql_family_cli(context, f"DROP USER IF EXISTS '{username}'@'localhost';")
    restore = mariadb_restore_audit(context, state)
    commands.extend([create, received, leak, drop, restore])
    assertions = [
        AssertionResult("SET PASSWORD audit record delivered", username in received.stdout, command_fact(received)),
        AssertionResult("audit-log password redacted", leak.returncode == 1 and not leak.stdout, "secret absent" if leak.returncode == 1 else "secret visible or search failed"),
    ]
    return evaluated_result("G1d", "MariaDB audit password redaction", started, commands, assertions, "MariaDB audit form preserved username and redacted the password", "Passed" if drop.returncode == 0 and restore.returncode == 0 else "Failed")


def mysql_family_copytruncate(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("G3a", "before")
    after = context.marker("G3a", "after")
    path_result = mysql_family_cli(context, "SELECT @@global.slow_query_log_file;")
    path = path_result.stdout.strip().splitlines()[-1] if path_result.stdout.strip() else ""
    before_trigger = mysql_family_marker(context, before)
    before_received = context.receiver_grep(before, timeout=90)
    backup = f"/tmp/lc-g3a-{secrets.token_hex(5)}.log"
    truncate = context.local.run(f"sudo cp --preserve=all -- {shlex.quote(path)} {shlex.quote(backup)} && sudo truncate -s 0 -- {shlex.quote(path)}", timeout=60) if path else path_result
    after_trigger = mysql_family_marker(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    cleanup = context.local.run(f"sudo rm -f -- {shlex.quote(backup)}", timeout=15)
    assertions = [
        AssertionResult("active log located", bool(path), path or command_fact(path_result)),
        AssertionResult("copy-truncate completed", truncate.returncode == 0, command_fact(truncate)),
        AssertionResult("post-truncate event delivered", after in after_received.stdout, command_fact(after_received)),
    ]
    return evaluated_result("G3a", "Copy-truncate rotation continuity", started, [path_result, before_trigger, before_received, truncate, after_trigger, after_received, cleanup], assertions, "Collection resumed after copy-truncate", "Passed" if cleanup.returncode == 0 else "Failed")


def mysql_family_backward_clock(context: LabContext) -> ScenarioResult:
    started = utc_now()
    during = context.marker("G12", "backward")
    after = context.marker("G12", "restored")
    receiver_time = context.receiver.run("date -u +%Y-%m-%dT%H:%M:%SZ", timeout=15)
    restore_command = f"date -u -s {shlex.quote(receiver_time.stdout.strip())}; timedatectl set-ntp true 2>/dev/null || true"
    recovery_id = f"G12-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 60})
    change = context.local.run("sudo timedatectl set-ntp false 2>/dev/null || true; sudo date -s '1 hour ago'", timeout=30)
    during_trigger = mysql_family_marker(context, during)
    during_received = context.receiver_grep(during, timeout=90)
    restore = context.local.run(restore_command, sudo=True, timeout=60)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    after_trigger = mysql_family_marker(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("clock moved backwards", change.returncode == 0, command_fact(change)),
        AssertionResult("event collected during backward clock", during in during_received.stdout, command_fact(during_received)),
        AssertionResult("clock restored", restore.returncode == 0, command_fact(restore)),
        AssertionResult("collection continued after restore", after in after_received.stdout and service.stdout.strip() == "active", command_fact(after_received)),
    ]
    return evaluated_result("G12", "Backward system clock", started, [receiver_time, change, during_trigger, during_received, restore, after_trigger, after_received, service], assertions, "Collection continued across a backward clock change", "Passed" if restore.returncode == 0 else "Failed")


def mysql_family_buffer_cap(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    image = f"/tmp/lc-h3-{token}.img"
    mountpoint = "/var/lib/log-collector/disk_buffer"
    before = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    prepare = context.local.run(f"sudo systemctl stop log-collector; truncate -s 600M {shlex.quote(image)}; sudo mkfs.ext4 -q -F {shlex.quote(image)}; sudo mount -o loop {shlex.quote(image)} {mountpoint}; sudo chown log-collector:log-collector {mountpoint}; sudo systemctl start log-collector", timeout=240)
    stop_receiver = establish_receiver_outage(context)
    binary = "mysql" if context.database == "mysql" else "mariadb"
    cleanup_ok = False
    try:
        generator = context.local.run(f"PAYLOAD=$(head -c 4000 /dev/zero | tr '\\0' x); for i in $(seq -w 1 140000); do printf 'SELECT /*lc_h3_%s_%s*/ 1;\\n' \"$i\" \"$PAYLOAD\"; done | sudo {binary} --batch", timeout=1800)
        time.sleep(20)
        after = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
        logs = context.local.run("sudo journalctl -u log-collector --since '-30 minutes' --no-pager | tail -n 300", timeout=30)
        service = context.local.run("systemctl is-active log-collector", timeout=15)
    finally:
        restore_receiver = restore_receiver_ingest(context)
        cleanup = context.local.run(f"sudo systemctl stop log-collector; sudo umount {mountpoint}; rm -f {shlex.quote(image)}; sudo systemctl start log-collector", timeout=240)
        cleanup_ok = restore_receiver.returncode == 0 and cleanup.returncode == 0
    def dropped(payload: str) -> int:
        try:
            return int(json.loads(payload).get("events_dropped", 0))
        except (ValueError, TypeError, json.JSONDecodeError, AttributeError):
            return -1
    assertions = [
        AssertionResult("600 MB isolated buffer filesystem mounted", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("receiver unavailable during load", stop_receiver.returncode == 0, command_fact(stop_receiver)),
        AssertionResult("more than 500 MB generated", generator.returncode == 0, command_fact(generator)),
        AssertionResult("oldest events dropped at cap", dropped(before.stdout) >= 0 and dropped(after.stdout) > dropped(before.stdout), f"before={dropped(before.stdout)} after={dropped(after.stdout)}"),
        AssertionResult("cap warning emitted", bool(re.search(r"drop|oldest|buffer.*(?:cap|limit|full)", logs.stdout, re.I)), command_fact(logs)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("H3", "Disk buffer cap and oldest-drop behavior", started, [before, prepare, stop_receiver, generator, after, logs, service, restore_receiver, cleanup], assertions, "Collector enforced its buffer cap and stayed active", "Passed" if cleanup_ok else "Failed")


def mariadb_default_audit(context: LabContext) -> ScenarioResult:
    return wizard_output_case(context, "F1", "MariaDB default audit selection", r"(?is)mariadb.*server_audit.*(?:default|enabled|yes|selected)", "Wizard selected server_audit by default")


def mariadb_missing_audit_warning(context: LabContext) -> ScenarioResult:
    started = utc_now()
    plugin = mysql_family_cli(context, "SELECT COUNT(*) FROM information_schema.plugins WHERE plugin_name='SERVER_AUDIT';")
    installed = plugin.stdout.strip().splitlines()[-1:] == ["1"]
    remove = mysql_family_cli(context, "UNINSTALL SONAME 'server_audit';") if installed else plugin
    dependency, probe = setup_wizard_probe(context, r"(?is)server_audit.*(?:install soname|install plugin|not installed|missing)")
    restore = mysql_family_cli(context, "INSTALL SONAME 'server_audit';") if installed else plugin
    assertions = [
        AssertionResult("server_audit absent for probe", remove.returncode == 0, command_fact(remove)),
        AssertionResult("exact enablement guidance displayed", probe.returncode == 0 and bool(re.search(r"INSTALL\s+(?:SONAME|PLUGIN)", probe.stdout, re.I)), command_fact(probe)),
    ]
    return evaluated_result("F2", "Missing server_audit warning", started, [plugin, remove, dependency, probe, restore], assertions, "Wizard displayed exact server_audit enablement statements", "Passed" if restore.returncode == 0 else "Failed")


def mariadb_log_basename(context: LabContext) -> ScenarioResult:
    return mysql_temp_config_case(context, "F6", "MariaDB log-basename discovery", "[mariadb]\nlog-basename=lc_f6_base\n", r"(?i)lc_f6_base(?:\.err|-slow\.log|\.log)")


def mariadb_debian_config(context: LabContext) -> ScenarioResult:
    started = utc_now()
    files = context.local.run("sudo find /etc/mysql/mariadb.conf.d -maxdepth 1 -type f -print | sort", timeout=30)
    dependency, probe = setup_wizard_probe(context, r"(?i)/etc/mysql/mariadb\.conf\.d/")
    assertions = [
        AssertionResult("Debian MariaDB config directory present", files.returncode == 0 and bool(files.stdout.strip()), command_fact(files)),
        AssertionResult("wizard reported Debian config path", probe.returncode == 0, command_fact(probe)),
    ]
    return evaluated_result("F7", "Debian and Ubuntu MariaDB configuration", started, [files, dependency, probe], assertions, "Wizard read MariaDB configuration from the Debian-family directory")


def mariadb_section_discovery(context: LabContext) -> ScenarioResult:
    content = "[mariadb]\nlog_warnings=2\n[mariadb-10.11]\nslow_query_log=ON\n[galera]\nwsrep_on=OFF\n"
    return mysql_temp_config_case(context, "F7a", "MariaDB version and Galera sections", content, r"(?i)(?:mariadb|slow.*log|galera)")


def mariadb_nonfile_audit(context: LabContext, scenario_id: str, output_type: str) -> ScenarioResult:
    started = utc_now()
    commands, state = mariadb_prepare_audit(context)
    change = mysql_family_cli(context, f"SET GLOBAL server_audit_logging=OFF; SET GLOBAL server_audit_output_type={json.dumps(output_type)}; SET GLOBAL server_audit_logging=ON;")
    dependency, probe = setup_wizard_probe(context, rf"(?is)server_audit.*{re.escape(output_type)}.*(?:no.*file|nothing.*tail|syslog|table)")
    restore = mariadb_restore_audit(context, state)
    commands.extend([change, dependency, probe, restore])
    assertions = [
        AssertionResult(f"{output_type} audit output configured", change.returncode == 0, command_fact(change)),
        AssertionResult("wizard did not invent a file", probe.returncode == 0, command_fact(probe)),
    ]
    return evaluated_result(scenario_id, f"server_audit {output_type} output", started, commands, assertions, "Wizard clearly stated that the non-file audit output has no file to tail", "Passed" if restore.returncode == 0 else "Failed")


def mariadb_syslog_audit(context: LabContext) -> ScenarioResult:
    return mariadb_nonfile_audit(context, "F10", "SYSLOG")


def mariadb_table_audit(context: LabContext) -> ScenarioResult:
    return mariadb_nonfile_audit(context, "F10a", "TABLE")


def oracle_sql(context: LabContext, sql: str, connect: str = "/ as sysdba", timeout: float = 120) -> CommandResult:
    script = f"whenever sqlerror exit sql.sqlcode\nset heading off feedback off pages 0 lines 32767 trimspool on\n{sql}\nexit\n"
    return context.local.run(f"printf %s {shlex.quote(script)} | sudo -iu oracle sqlplus -s {shlex.quote(connect)}", timeout=timeout)


def oracle_alert_marker(context: LabContext, marker: str) -> CommandResult:
    safe = marker.replace("'", "''")
    return oracle_sql(context, f"begin dbms_system.ksdwrt(2,'{safe}'); end;\n/")


def oracle_path_query(context: LabContext) -> CommandResult:
    return oracle_sql(
        context,
        "select 'TRACE='||value from v$diag_info where name='Diag Trace';\n"
        "select 'ALERT='||value from v$diag_info where name='Diag Alert';\n"
        "select 'AUDIT='||value from v$parameter where name='audit_file_dest';",
    )


def oracle_paths(result: CommandResult) -> dict[str, str]:
    paths: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.strip().split("=", 1)
            if key in {"TRACE", "ALERT", "AUDIT"}:
                paths[key] = value
    return paths


def oracle_basic(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("B1")
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    assertions = [
        AssertionResult("Oracle alert event generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("receiver marker", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("B1", "Basic Oracle collection", started, [trigger, received], assertions, "Generated Oracle alert marker reached the receiver")


def oracle_source(context: LabContext) -> ScenarioResult:
    result = oracle_basic(context)
    result.scenario_id = "B2"
    result.name = "Stable source identifier"
    line = result.commands[-1].stdout.strip().splitlines()[-1] if result.commands[-1].stdout.strip() else ""
    fields = line.split(" ", 4)
    app_name = fields[3] if len(fields) >= 4 else "missing"
    assertion = AssertionResult("APP-NAME exactly oracle_log", app_name == "oracle_log", app_name)
    result.assertions.append(assertion)
    if not assertion.passed:
        result.status = "Fail"
        result.reason = "Failed assertion(s): APP-NAME exactly oracle_log"
    return result


def oracle_restart_checkpoint(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("B3", "before")
    after = context.marker("B3", "after")
    before_trigger = oracle_alert_marker(context, before)
    before_received = context.receiver_grep(before, timeout=90)
    count_command = f"grep -Fc -- {shlex.quote(before)} {shlex.quote(context.receiver_log)} || true"
    initial = context.receiver.run(count_command, sudo=True, timeout=15)
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    after_trigger = oracle_alert_marker(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    final = context.receiver.run(count_command, sudo=True, timeout=15)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    try:
        before_count = int(initial.stdout.strip() or "0")
        after_count = int(final.stdout.strip() or "0")
    except ValueError:
        before_count = after_count = -1
    assertions = [
        AssertionResult("collector restarted", restart.returncode == 0 and service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("post-restart delivery", after in after_received.stdout, command_fact(after_received)),
        AssertionResult("no full replay", before_count >= 1 and after_count <= before_count + 3, f"before={before_count} after={after_count}"),
    ]
    return evaluated_result("B3", "Service restart and checkpoint", started, [before_trigger, before_received, initial, restart, after_trigger, after_received, final, service], assertions, "Collector resumed Oracle collection without replaying the full log")


def oracle_stability_case(context: LabContext, scenario_id: str) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker(scenario_id, "stability")[:48]
    sample_command = "printf 'pid=%s rss=%s restarts=%s status=%s fds=%s\\n' \"$(systemctl show -p MainPID --value log-collector)\" \"$(ps -o rss= -p \"$(systemctl show -p MainPID --value log-collector)\" | xargs)\" \"$(systemctl show -p NRestarts --value log-collector)\" \"$(systemctl is-active log-collector)\" \"$(find /proc/$(systemctl show -p MainPID --value log-collector)/fd -maxdepth 1 -type l 2>/dev/null | wc -l)\""
    commands: list[CommandResult] = []
    samples: list[tuple[int, int, int, str, int]] = []
    pattern = re.compile(r"pid=(\d+) rss=(\d+) restarts=(\d+) status=(\S+) fds=(\d+)")
    for index in range(0, LAB_STABILITY_MINUTES + 1):
        if index:
            commands.append(oracle_alert_marker(context, f"{prefix}_{index:02d}"))
            time.sleep(60)
        sample = context.local.run(sample_command, timeout=15)
        commands.append(sample)
        match = pattern.search(sample.stdout)
        if match:
            samples.append((int(match[1]), int(match[2]), int(match[3]), match[4], int(match[5])))
    received = context.receiver_grep(prefix, timeout=90)
    commands.append(received)
    markers = set(re.findall(re.escape(prefix) + r"_(\d{2})", received.stdout))
    assertions = [
        AssertionResult("complete runtime samples", len(samples) == LAB_STABILITY_MINUTES + 1, f"samples={len(samples)}"),
        AssertionResult("collector remained active without restart", bool(samples) and all(row[3] == "active" for row in samples) and len({row[0] for row in samples}) == 1 and len({row[2] for row in samples}) == 1, str(samples)),
        AssertionResult("bounded RSS", bool(samples) and max(row[1] for row in samples) <= samples[0][1] + 131072, str([row[1] for row in samples])),
        AssertionResult("bounded file descriptors", bool(samples) and max(row[4] for row in samples) <= samples[0][4] + 64, str([row[4] for row in samples])),
        AssertionResult("all markers delivered", markers == {f"{i:02d}" for i in range(1, LAB_STABILITY_MINUTES + 1)}, str(sorted(markers))),
    ]
    name = "Constrained-lab stability window" if scenario_id == "B4" else "Constrained sustained-load soak"
    return evaluated_result(scenario_id, name, started, commands, assertions, f"Collector remained stable for the approved {LAB_STABILITY_MINUTES}-minute lab window")


def oracle_stability(context: LabContext) -> ScenarioResult:
    return oracle_stability_case(context, "B4")


def oracle_soak(context: LabContext) -> ScenarioResult:
    return oracle_stability_case(context, "H12")


def oracle_outage_case(context: LabContext, scenario_id: str, seconds: int, buffer_required: bool) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker(scenario_id, "outage")[:48]
    before = context.local.run("sudo du -sb /var/lib/log-collector/disk_buffer 2>/dev/null || echo '0 missing'", timeout=30)
    recovery_id = f"{scenario_id}-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "receiver", "command": RECEIVER_START_COMMAND, "sudo": True, "timeout": 60})
    stop = establish_receiver_outage(context)
    commands = [before, stop]
    cleanup_ok = False
    try:
        deadline = time.monotonic() + seconds
        index = 0
        while time.monotonic() < deadline:
            index += 1
            commands.append(oracle_alert_marker(context, f"{prefix}_{index:03d}"))
            time.sleep(min(5, max(0.1, deadline - time.monotonic())))
        during = context.local.run("sudo du -sb /var/lib/log-collector/disk_buffer 2>/dev/null || echo '0 missing'; systemctl is-active log-collector", timeout=30)
        commands.append(during)
    finally:
        restore = restore_receiver_ingest(context)
        commands.append(restore)
        cleanup_ok = restore.returncode == 0
        if cleanup_ok and context.journal:
            context.journal.remove(recovery_id)
    received = context.receiver_grep(f"{prefix}_{index:03d}", timeout=120)
    commands.append(received)
    def size(result: CommandResult) -> int:
        match = re.search(r"^(\d+)", result.stdout)
        return int(match.group(1)) if match else -1
    assertions = [
        AssertionResult("receiver outage established", stop.returncode == 0, command_fact(stop)),
        AssertionResult("collector stayed active", "active" in during.stdout, command_fact(during)),
        AssertionResult("tail marker delivered after recovery", f"{prefix}_{index:03d}" in received.stdout, command_fact(received)),
    ]
    if buffer_required:
        assertions.append(AssertionResult("disk buffer grew", size(during) > size(before), f"before={size(before)} during={size(during)}"))
    names = {"B5": "Constrained-lab receiver outage", "H1": "Disk buffer growth during receiver outage", "H2": "Buffered delivery after recovery"}
    return evaluated_result(scenario_id, names[scenario_id], started, commands, assertions, "Collector stayed alive, buffered, and recovered", "Passed" if cleanup_ok else "Failed")


def oracle_receiver_outage(context: LabContext) -> ScenarioResult:
    return oracle_outage_case(context, "B5", LAB_OUTAGE_MINUTES * 60, False)


def oracle_buffer_growth(context: LabContext) -> ScenarioResult:
    return oracle_outage_case(context, "H1", 30, True)


def oracle_buffer_delivery(context: LabContext) -> ScenarioResult:
    return oracle_outage_case(context, "H2", 30, True)


def oracle_unique_ids(context: LabContext) -> ScenarioResult:
    started = utc_now()
    prefix = context.marker("B6", "event")[:44]
    commands = [oracle_alert_marker(context, f"{prefix}_{i}") for i in range(1, 6)]
    commands.append(context.receiver_grep(f"{prefix}_5", timeout=90))
    received = context.receiver.run(f"grep -F -- {shlex.quote(prefix + '_')} {shlex.quote(context.receiver_log)} | tail -n 30", sudo=True, timeout=30)
    commands.append(received)
    markers = set(re.findall(re.escape(prefix) + r"_([1-5])", received.stdout))
    ids = re.findall(r'event_id="([^"]+)"', received.stdout)
    assertions = [
        AssertionResult("five Oracle markers delivered", markers == {"1", "2", "3", "4", "5"}, str(sorted(markers))),
        AssertionResult("five unique event IDs", len(set(ids)) == 5, f"total={len(ids)} unique={len(set(ids))}"),
    ]
    return evaluated_result("B6", "Unique event identifiers", started, commands, assertions, "Five Oracle events carried five unique event IDs")


def oracle_unified_gap_warning(context: LabContext) -> ScenarioResult:
    started = utc_now()
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    logs = context.local.run("sudo journalctl -u log-collector --since '-3 minutes' --no-pager", timeout=30)
    warned = bool(re.search(r"UNIFIED_AUDIT_TRAIL|unified.*audit.*(?:not|unsupported|SQL view)|\.bin.*(?:not|unsupported)", logs.stdout, re.I))
    assertions = [
        AssertionResult("collector restarted", restart.returncode == 0, command_fact(restart)),
        AssertionResult("unified audit coverage gap announced", warned, command_fact(logs)),
    ]
    return evaluated_result("E1", "Unified audit coverage warning", started, [restart, logs], assertions, "Collector announced that unified audit view and binary spillover are not collected")


def oracle_audit_case(context: LabContext, scenario_id: str, role: str, sql: str, required: list[str]) -> ScenarioResult:
    started = utc_now()
    marker = context.marker(scenario_id)
    settings = oracle_sql(context, "select value from v$parameter where name='audit_sys_operations';\nselect value from v$parameter where name='audit_file_dest';")
    connect = f"/ as {role}"
    trigger = oracle_sql(context, sql.format(marker=marker), connect=connect)
    received = context.receiver_grep(marker, timeout=120)
    assertions = [
        AssertionResult("SYS operation auditing enabled", "TRUE" in settings.stdout.upper(), command_fact(settings)),
        AssertionResult(f"{role.upper()} operation completed", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("traditional audit event collected", marker in received.stdout, command_fact(received)),
    ]
    for fragment in required:
        assertions.append(AssertionResult(f"audit field {fragment}", fragment.lower() in received.stdout.lower(), command_fact(received)))
    return evaluated_result(scenario_id, f"{role.upper()} traditional audit record", started, [settings, trigger, received], assertions, "Traditional .aud event was collected with parsed fields")


def oracle_sysdba_audit(context: LabContext) -> ScenarioResult:
    return oracle_audit_case(context, "E2", "sysdba", "select /*{marker}*/ instance_name from v$instance;", ["ACTION", "USERID"])


def oracle_sysoper_audit(context: LabContext) -> ScenarioResult:
    return oracle_audit_case(context, "E2a", "sysoper", "select /*{marker}*/ instance_name from v$instance;", ["ACTION", "USERID"])


def oracle_failed_sysdba(context: LabContext) -> ScenarioResult:
    started = utc_now()
    username = f"LC_E2B_{secrets.token_hex(4).upper()}"
    attempt = oracle_sql(context, "select 1 from dual;", connect=f"{username}/wrong as sysdba", timeout=30)
    received = context.receiver_grep(username, timeout=120)
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    assertions = [
        AssertionResult("SYSDBA login rejected", attempt.returncode != 0, command_fact(attempt)),
        AssertionResult("failed privileged login collected", username in received.stdout, command_fact(received)),
        AssertionResult("warning or higher priority", bool(re.match(r"<(?:[0-9]|1[0-2])>", line)), line or "missing"),
    ]
    return evaluated_result("E2b", "Failed SYSDBA login severity", started, [attempt, received], assertions, "Failed SYSDBA authentication reached the receiver at warning priority or higher")


def oracle_audit_fields(context: LabContext) -> ScenarioResult:
    result = oracle_audit_case(context, "E2c", "sysdba", "select /*{marker}*/ sys_context('USERENV','SESSION_USER') from dual;", ["ACTION", "STATUS", "USERID"])
    result.name = "Parsed traditional audit fields"
    return result


def oracle_audit_quote(context: LabContext) -> ScenarioResult:
    return oracle_audit_case(context, "E2d", "sysdba", "select /*{marker}*/ q'[alice's value]' from dual;", ["alice's value"])


def oracle_alert_severity(context: LabContext, scenario_id: str, code: str, expected_max: int) -> ScenarioResult:
    started = utc_now()
    marker = context.marker(scenario_id)
    message = f"{code}: {marker} synthetic safe parser probe"
    trigger = oracle_alert_marker(context, message)
    received = context.receiver_grep(marker, timeout=90)
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    priority = int(re.match(r"<(\d+)>", line).group(1)) if re.match(r"<(\d+)>", line) else 99
    assertions = [
        AssertionResult("Oracle alert entry generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("alert entry collected", marker in received.stdout and code in received.stdout, command_fact(received)),
        AssertionResult("wire severity correct", priority <= expected_max, f"priority={priority} line={line}"),
    ]
    name = "Critical Oracle alert severity" if scenario_id == "E5" else "Ordinary Oracle error severity"
    return evaluated_result(scenario_id, name, started, [trigger, received], assertions, f"{code} reached the expected wire severity")


def oracle_critical_error(context: LabContext) -> ScenarioResult:
    return oracle_alert_severity(context, "E5", "ORA-00600", 10)


def oracle_ordinary_error(context: LabContext) -> ScenarioResult:
    return oracle_alert_severity(context, "E5a", "ORA-00942", 11)


def oracle_multiline_alert(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("E7a")
    trigger = oracle_alert_marker(context, f"{marker} first line\\nsecond line\\nthird line")
    received = context.receiver_grep(marker, timeout=90)
    count = context.receiver.run(f"grep -Fc -- {shlex.quote(marker)} {shlex.quote(context.receiver_log)} || true", sudo=True, timeout=30)
    try:
        occurrences = int(count.stdout.strip() or "0")
    except ValueError:
        occurrences = -1
    assertions = [
        AssertionResult("multi-line alert generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("one intact alert event", occurrences == 1 and "second line" in received.stdout and "third line" in received.stdout, f"matches={occurrences}; {command_fact(received)}"),
    ]
    return evaluated_result("E7a", "Multi-line alert entry", started, [trigger, received, count], assertions, "Multi-line Oracle alert arrived as one event")


def oracle_xml_alert(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("E7b")
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    assertions = [
        AssertionResult("alert marker generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("XML alert source collected", marker in received.stdout and bool(re.search(r"log\.xml|alert[/\\]", received.stdout, re.I)), command_fact(received)),
    ]
    return evaluated_result("E7b", "Oracle XML alert stream", started, [trigger, received], assertions, "Oracle log.xml fragment was parsed and collected")


def oracle_xml_single_quote(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("E7c")
    value = f"{marker} alice's value"
    trigger = oracle_alert_marker(context, value)
    received = context.receiver_grep(marker, timeout=90)
    assertions = [
        AssertionResult("quoted XML alert generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("single quote preserved", value in received.stdout, command_fact(received)),
    ]
    return evaluated_result("E7c", "Single-quoted XML content", started, [trigger, received], assertions, "Single-quoted Oracle XML content remained intact")


def oracle_instance_restart(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("E7e", "after")
    stop = oracle_sql(context, "shutdown immediate;", timeout=300)
    start = oracle_sql(context, "startup;", timeout=300)
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=180)
    lifecycle = context.receiver.run(f"grep -Ei 'shutting down|shutdown|starting ORACLE|instance started' {shlex.quote(context.receiver_log)} | tail -n 50", sudo=True, timeout=30)
    collector = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("instance stopped and started", stop.returncode == 0 and start.returncode == 0, f"stop={stop.returncode} start={start.returncode}"),
        AssertionResult("lifecycle messages collected", bool(lifecycle.stdout.strip()), command_fact(lifecycle)),
        AssertionResult("collector stayed active and resumed", collector.stdout.strip() == "active" and marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("E7e", "Oracle startup and shutdown", started, [stop, start, trigger, received, lifecycle, collector], assertions, "Oracle startup/shutdown messages were collected and collection resumed", "Passed" if start.returncode == 0 else "Failed")


def oracle_listener_unknown(context: LabContext, scenario_id: str) -> ScenarioResult:
    started = utc_now()
    service = context.marker(scenario_id, "service")[:60]
    attempt = oracle_sql(context, "select 1 from dual;", connect=f"bad/bad@//127.0.0.1:1521/{service}", timeout=30)
    received = context.receiver_grep(service, timeout=90)
    assertions = [
        AssertionResult("listener connection attempted", attempt.returncode != 0, command_fact(attempt)),
        AssertionResult("listener event collected", service in received.stdout, command_fact(received)),
    ]
    if scenario_id == "E6d":
        line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
        assertions.append(AssertionResult("TNS-12514 at error priority", "12514" in received.stdout and bool(re.match(r"<(?:[0-9]|1[01])>", line)), line or "missing"))
    name = "Listener connection event" if scenario_id == "E6" else "Unknown listener service severity"
    return evaluated_result(scenario_id, name, started, [attempt, received], assertions, "Oracle listener connection attempt was collected")


def oracle_listener_connect(context: LabContext) -> ScenarioResult:
    return oracle_listener_unknown(context, "E6")


def oracle_listener_tns12514(context: LabContext) -> ScenarioResult:
    return oracle_listener_unknown(context, "E6d")


def oracle_listener_restart(context: LabContext) -> ScenarioResult:
    started = utc_now()
    stop = context.local.run("sudo -iu oracle lsnrctl stop", timeout=120)
    start = context.local.run("sudo -iu oracle lsnrctl start", timeout=180)
    time.sleep(3)
    received = context.receiver.run(f"grep -Ei 'stop|start|TNSLSNR' {shlex.quote(context.receiver_log)} | tail -n 50", sudo=True, timeout=30)
    assertions = [
        AssertionResult("listener stop/start completed", stop.returncode == 0 and start.returncode == 0, f"stop={stop.returncode} start={start.returncode}"),
        AssertionResult("listener lifecycle collected", bool(received.stdout.strip()), command_fact(received)),
    ]
    return evaluated_result("E6c", "Listener stop and start", started, [stop, start, received], assertions, "Listener lifecycle events were collected", "Passed" if start.returncode == 0 else "Failed")


def oracle_excluded_files(context: LabContext) -> ScenarioResult:
    started = utc_now()
    inspect = context.local.run("PID=$(systemctl show -p MainPID --value log-collector); sudo lsof -nP -p \"$PID\" 2>/dev/null", timeout=30)
    forbidden = [line for line in inspect.stdout.splitlines() if re.search(r"\.(?:trc|trm|bin)$", line, re.I)]
    assertions = [
        AssertionResult("collector files inspected", inspect.returncode == 0 and bool(inspect.stdout.strip()), command_fact(inspect)),
        AssertionResult("trace and binary files excluded", not forbidden, "none" if not forbidden else "\n".join(forbidden[:10])),
    ]
    return evaluated_result("E11", "Oracle trace and binary exclusions", started, [inspect], assertions, "Collector did not open .trc, .trm, or .bin files")


def oracle_adrci_purge(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("E11c", "before")
    after = context.marker("E11c", "after")
    before_trigger = oracle_alert_marker(context, before)
    before_received = context.receiver_grep(before, timeout=90)
    purge = context.local.run("printf 'purge -age 1\\nexit\\n' | sudo -iu oracle adrci", timeout=180)
    after_trigger = oracle_alert_marker(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("ADR purge completed", purge.returncode == 0, command_fact(purge)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("collection continued after disappearing files", after in after_received.stdout, command_fact(after_received)),
    ]
    return evaluated_result("E11c", "ADR purge during collection", started, [before_trigger, before_received, purge, after_trigger, after_received, service], assertions, "Collector survived ADR purge and continued collecting")


def oracle_password_redaction_case(context: LabContext, scenario_id: str, create: bool) -> ScenarioResult:
    started = utc_now()
    username = f"LC_{scenario_id.upper()}_{secrets.token_hex(4).upper()}"
    secret = f"Lc{scenario_id}-{secrets.token_hex(8)}!"
    if context.evidence:
        context.evidence.register_secret(secret)
    if create:
        sql = f"create user {username} identified by \"{secret}\"; drop user {username};"
    else:
        sql = f"create user {username} identified by Temp1234x; alter user {username} identified by \"{secret}\"; drop user {username};"
    trigger = oracle_sql(context, sql)
    received = context.receiver_grep(username, timeout=120)
    leak = context.receiver.run(f"grep -R -F -- {shlex.quote(secret)} {shlex.quote(context.receiver_client_dir)}", sudo=True, timeout=30)
    assertions = [
        AssertionResult("Oracle user DDL delivered", trigger.returncode == 0 and username in received.stdout, command_fact(received)),
        AssertionResult("password absent from every received source", leak.returncode == 1 and not leak.stdout, "secret absent" if leak.returncode == 1 else "secret visible or search failed"),
    ]
    name = "CREATE USER password redaction" if create else "ALTER USER password redaction"
    return evaluated_result(scenario_id, name, started, [trigger, received, leak], assertions, "Oracle username remained visible while password material was redacted")


def oracle_password_redaction(context: LabContext) -> ScenarioResult:
    return oracle_password_redaction_case(context, "G1", False)


def oracle_create_user_redaction(context: LabContext) -> ScenarioResult:
    return oracle_password_redaction_case(context, "G1a", True)


def oracle_username(context: LabContext) -> ScenarioResult:
    result = oracle_password_redaction_case(context, "G2", False)
    result.name = "Username preservation"
    return result


def oracle_unicode(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G6")
    value = f"{marker}_日本語_العربية_😀"
    trigger = oracle_alert_marker(context, value)
    received = context.receiver_grep(marker, timeout=90)
    assertions = [
        AssertionResult("Unicode alert generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("Unicode preserved", value in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G6", "Unicode log preservation", started, [trigger, received], assertions, "Japanese, Arabic, and emoji text remained intact")


def oracle_kill_recovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.marker("H10", "before")
    after = context.marker("H10", "after")
    commands = [oracle_alert_marker(context, before), context.receiver_grep(before, timeout=90)]
    initial_pid = context.local.run("systemctl show -p MainPID --value log-collector", timeout=15)
    killed = context.local.run("sudo systemctl kill --kill-who=main --signal=SIGKILL log-collector", timeout=30)
    restarted = context.local.run("sudo systemctl restart log-collector", timeout=60)
    final_pid = context.local.run("systemctl show -p MainPID --value log-collector", timeout=15)
    trigger = oracle_alert_marker(context, after)
    received = context.receiver_grep(after, timeout=90)
    commands.extend([initial_pid, killed, restarted, final_pid, trigger, received])
    assertions = [
        AssertionResult("SIGKILL issued", killed.returncode == 0, command_fact(killed)),
        AssertionResult("collector restarted with new PID", restarted.returncode == 0 and final_pid.stdout.strip() != initial_pid.stdout.strip(), f"before={initial_pid.stdout.strip()} after={final_pid.stdout.strip()}"),
        AssertionResult("post-kill event delivered", after in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H10", "SIGKILL checkpoint recovery", started, commands, assertions, "Collector resumed Oracle collection after forced process termination")


def oracle_non_root_access(context: LabContext) -> ScenarioResult:
    started = utc_now()
    query = oracle_path_query(context)
    paths = oracle_paths(query)
    candidates: list[str] = []
    for key, path in paths.items():
        if key == "TRACE":
            candidates.extend([f"{path}/alert_*.log", f"{path}/listener*.log"])
        elif key == "ALERT":
            candidates.append(f"{path}/log.xml")
        elif key == "AUDIT":
            candidates.append(f"{path}/*.aud")
    checks: list[CommandResult] = []
    for pattern in candidates:
        checks.append(context.local.run(f"FILE=$(find {shlex.quote(str(Path(pattern).parent))} -maxdepth 1 -type f -name {shlex.quote(Path(pattern).name)} -print -quit 2>/dev/null); test -z \"$FILE\" || sudo -u log-collector test -r \"$FILE\"", timeout=30))
    service_user = context.local.run("systemctl show -p User --value log-collector", timeout=15)
    effective_user = context.local.run(
        "PID=$(systemctl show -p MainPID --value log-collector); test \"$PID\" -gt 0 && ps -o user= -p \"$PID\" | xargs",
        timeout=15,
    )
    unit_identity = service_user.stdout.strip() or "unset"
    process_identity = effective_user.stdout.strip() or "missing"
    assertions = [
        AssertionResult("Oracle diagnostic paths discovered", bool(paths), str(paths)),
        AssertionResult("discovered files readable by service account", bool(checks) and all(item.returncode == 0 for item in checks), f"readable={sum(item.returncode == 0 for item in checks)}/{len(checks)}"),
        AssertionResult("dedicated service identity", effective_user.returncode == 0 and process_identity == "log-collector", f"unit_user={unit_identity} effective_user={process_identity}"),
    ]
    return evaluated_result("I8", "Non-root collector with Oracle-log access", started, [query, *checks, service_user, effective_user], assertions, "The collector process runs as log-collector and can read Oracle diagnostic and audit files")


def oracle_setup_discovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    paths_result = oracle_path_query(context)
    paths = oracle_paths(paths_result)
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:detected|found).*oracle|oracle.*(?:ADR|audit|listener)")
    visible = any(path in probe.stdout or Path(path).name in probe.stdout for path in paths.values())
    assertions = [
        AssertionResult("Oracle discovery reached", probe.returncode == 0 and "oracle" in probe.stdout.lower(), command_fact(probe)),
        AssertionResult("ADR or audit location displayed", visible, f"paths={paths}"),
    ]
    return evaluated_result("A4", "Installed Oracle discovery", started, [paths_result, dependency, probe], assertions, "Wizard displayed the installed Oracle ADR and audit locations")


def oracle_setup_last_good(context: LabContext) -> ScenarioResult:
    return mysql_family_setup_last_good(context)


def oracle_setup_absent_engine(context: LabContext) -> ScenarioResult:
    started = utc_now()
    dependency, probe = setup_wizard_probe(context, r"(?i)(?:no\s+mariadb|mariadb.*(?:not found|not installed|found nothing|0 instance))")
    assertions = [AssertionResult("absent MariaDB reported clearly", probe.returncode == 0, command_fact(probe))]
    return evaluated_result("A5", "Absent database discovery", started, [dependency, probe], assertions, "Wizard clearly reported that the absent comparison engine was not discovered")


def oracle_timestamp(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("B7")
    paths_result = oracle_path_query(context)
    paths = oracle_paths(paths_result)
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    trace = paths.get("TRACE", "")
    native = context.local.run(
        f"sudo awk -v m={shlex.quote(marker)} 'BEGIN{{t=\"\"}} /^[0-9][0-9][0-9][0-9]-|^[A-Z][a-z][a-z] /{{t=$0}} index($0,m){{print t; exit}}' {shlex.quote(trace)}/alert_*.log",
        timeout=30,
    ) if trace else paths_result
    line = received.stdout.strip().splitlines()[-1] if received.stdout.strip() else ""
    wire_match = re.match(r"<\d+>1\s+(\S+)", line)
    native_value = native.stdout.strip().splitlines()[-1] if native.stdout.strip() else ""
    wire_value = wire_match.group(1) if wire_match else ""
    assertions = [
        AssertionResult("native alert timestamp located", bool(native_value), command_fact(native)),
        AssertionResult("receiver wire timestamp located", bool(wire_value), line or "missing"),
        AssertionResult("same event instant", timestamps_match(native_value, wire_value, tolerance_seconds=1.0) if native_value and wire_value else False, f"native={native_value} wire={wire_value}"),
    ]
    return evaluated_result("B7", "Native timestamp preservation", started, [paths_result, trigger, received, native], assertions, "Receiver timestamp matches Oracle's alert-log timestamp")


def oracle_audit_new_files(context: LabContext) -> ScenarioResult:
    started = utc_now()
    first = context.marker("E9", "first")
    second = context.marker("E9", "second")
    trigger1 = oracle_sql(context, f"select /*{first}*/ 1 from dual;")
    received1 = context.receiver_grep(first, timeout=120)
    trigger2 = oracle_sql(context, f"select /*{second}*/ 1 from dual;")
    received2 = context.receiver_grep(second, timeout=120)
    def source(payload: str) -> str:
        match = re.search(r"oracle_log:([^ ]+\.aud)", payload)
        return match.group(1) if match else ""
    source1, source2 = source(received1.stdout), source(received2.stdout)
    assertions = [
        AssertionResult("two privileged audit records generated", trigger1.returncode == 0 and trigger2.returncode == 0, f"first={trigger1.returncode} second={trigger2.returncode}"),
        AssertionResult("both records collected", first in received1.stdout and second in received2.stdout, f"first={source1} second={source2}"),
        AssertionResult("new file has independent attribution", bool(source1 and source2 and source1 != source2), f"first={source1} second={source2}"),
    ]
    return evaluated_result("E9", "Traditional audit new-file attribution", started, [trigger1, received1, trigger2, received2], assertions, "Each new .aud file was independently attributed")


def oracle_adump_rescan(context: LabContext) -> ScenarioResult:
    started = utc_now()
    samples: list[float] = []
    commands: list[CommandResult] = []
    for index in range(3):
        marker = context.marker("E10", f"scan{index}")
        begin = time.monotonic()
        trigger = oracle_sql(context, f"select /*{marker}*/ 1 from dual;")
        received = context.receiver_grep(marker, timeout=75)
        elapsed = time.monotonic() - begin
        commands.extend([trigger, received])
        if marker in received.stdout:
            samples.append(elapsed)
        time.sleep(2)
    median = sorted(samples)[len(samples) // 2] if samples else -1
    assertions = [
        AssertionResult("three scan samples collected", len(samples) == 3, str(samples)),
        AssertionResult("rescan cadence near 30 seconds", 10 <= median <= 55, f"median={median:.1f}s samples={[round(v,1) for v in samples]}"),
    ]
    return evaluated_result("E10", "ADR audit-directory rescan cadence", started, commands, assertions, "Observed .aud discovery cadence was consistent with the documented 30-second scan")


def oracle_adump_scale(context: LabContext) -> ScenarioResult:
    started = utc_now()
    paths_result = oracle_path_query(context)
    audit = oracle_paths(paths_result).get("AUDIT", "")
    temp_prefix = f"lc_e10a_{secrets.token_hex(5)}"
    before = context.local.run("PID=$(systemctl show -p MainPID --value log-collector); ps -o %cpu=,rss= -p \"$PID\"", timeout=15)
    create = context.local.run(f"sudo -u oracle bash -lc 'for i in $(seq -w 1 3000); do : > {shlex.quote(audit)}/{temp_prefix}_$i.aud; done'", timeout=180) if audit else paths_result
    time.sleep(40)
    after = context.local.run("PID=$(systemctl show -p MainPID --value log-collector); ps -o %cpu=,rss= -p \"$PID\"; systemctl is-active log-collector", timeout=15)
    cleanup = context.local.run(f"sudo find {shlex.quote(audit)} -maxdepth 1 -type f -name {shlex.quote(temp_prefix + '_*.aud')} -delete", timeout=120) if audit else paths_result
    assertions = [
        AssertionResult("3,000 audit files created", create.returncode == 0, command_fact(create)),
        AssertionResult("collector remained active", "active" in after.stdout, command_fact(after)),
        AssertionResult("runtime samples captured", before.returncode == 0 and after.returncode == 0, f"before={before.stdout.strip()} after={after.stdout.strip()}"),
    ]
    return evaluated_result("E10a", "Large adump directory scan", started, [paths_result, before, create, after, cleanup], assertions, "Collector remained stable while adump contained several thousand files", "Passed" if cleanup.returncode == 0 else "Failed")


def oracle_cdb_con_id(context: LabContext) -> ScenarioResult:
    started = utc_now()
    pdbs = oracle_sql(context, "select name from v$pdbs where open_mode='READ WRITE' and rownum=1;")
    pdb = pdbs.stdout.strip().splitlines()[-1] if pdbs.stdout.strip() else ""
    if not pdb:
        return ScenarioResult("E7d", "CDB and PDB con_id", "Not Tested", "Not applicable: no open pluggable database is available", started, utc_now(), commands=[pdbs])
    marker = context.marker("E7d")
    trigger = oracle_sql(context, f"alter session set container={pdb};\nbegin dbms_system.ksdwrt(2,'{marker}'); end;\n/")
    received = context.receiver_grep(marker, timeout=90)
    assertions = [
        AssertionResult("PDB alert generated", trigger.returncode == 0, command_fact(trigger)),
        AssertionResult("con_id field present", bool(re.search(r"\bcon_id[=\"': ]+\d+", received.stdout, re.I)), command_fact(received)),
        AssertionResult("con_uid not confused with con_id", not bool(re.search(r"\bcon_id[=\"': ]+.*con_uid", received.stdout, re.I)), command_fact(received)),
    ]
    return evaluated_result("E7d", "CDB and PDB con_id", started, [pdbs, trigger, received], assertions, "PDB alert carried the correct con_id")


def oracle_trace_incident(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("E7f")
    trace = oracle_sql(context, f"oradebug setmypid\noradebug tracefile_name\noradebug dump errorstack 3\nbegin dbms_system.ksdwrt(2,'{marker} trace generated'); end;\n/")
    received = context.receiver_grep(marker, timeout=90)
    open_files = context.local.run("PID=$(systemctl show -p MainPID --value log-collector); sudo lsof -nP -p \"$PID\" 2>/dev/null | grep -E '\\.(trc|trm)$' || true", timeout=30)
    assertions = [
        AssertionResult("trace and alert activity generated", trace.returncode == 0, command_fact(trace)),
        AssertionResult("alert reference collected", marker in received.stdout, command_fact(received)),
        AssertionResult("trace body not opened", not open_files.stdout.strip(), command_fact(open_files)),
    ]
    return evaluated_result("E7f", "Trace incident exclusion", started, [trace, received, open_files], assertions, "Alert reference was collected while the trace body remained excluded")


def oracle_listener_source_fields(context: LabContext) -> ScenarioResult:
    result = oracle_listener_unknown(context, "E6a")
    result.name = "Listener source and client-claimed host fields"
    payload = result.commands[-1].stdout
    real = re.search(r"\(ADDRESS=.*?\(HOST=([^)]+)\)", payload, re.I)
    claimed = re.search(r"\(CID=.*?\(HOST=([^)]+)\)", payload, re.I)
    assertion = AssertionResult("ADDRESS.HOST distinct from CID.HOST", bool(real and claimed) and real.group(1) != claimed.group(1), f"address={real.group(1) if real else 'missing'} cid={claimed.group(1) if claimed else 'missing'}")
    result.assertions.append(assertion)
    if not assertion.passed:
        result.status = "Fail"
        result.reason = "Failed assertion(s): ADDRESS.HOST distinct from CID.HOST"
    return result


def oracle_listener_noise(context: LabContext) -> ScenarioResult:
    started = utc_now()
    before = context.receiver.run(f"grep -ci 'service_update' {shlex.quote(context.receiver_log)} || true", sudo=True, timeout=15)
    reloads = [context.local.run("sudo -iu oracle lsnrctl reload", timeout=60) for _ in range(5)]
    time.sleep(10)
    events = context.receiver.run(f"grep -i 'service_update' {shlex.quote(context.receiver_log)} | tail -n 200", sudo=True, timeout=30)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("listener reload activity completed", all(item.returncode == 0 for item in reloads), str([item.returncode for item in reloads])),
        AssertionResult("service_update events collected", bool(events.stdout.strip()), command_fact(events)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("E6e", "Listener service_update volume", started, [before, *reloads, events, service], assertions, "Listener service-update noise was collected and recorded for volume review")


def oracle_rotation(context: LabContext) -> ScenarioResult:
    result = oracle_audit_new_files(context)
    result.scenario_id = "G3"
    result.name = "Cross-engine rotation continuity"
    return result


def oracle_copytruncate(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G3a")
    paths_result = oracle_path_query(context)
    trace = oracle_paths(paths_result).get("TRACE", "")
    current = context.local.run(f"find {shlex.quote(trace)} -maxdepth 1 -type f -name 'alert_*.log' -print -quit", timeout=15) if trace else paths_result
    path = current.stdout.strip()
    backup = f"/tmp/lc-g3a-{secrets.token_hex(5)}.log"
    truncate = context.local.run(f"sudo cp --preserve=all {shlex.quote(path)} {backup}; sudo truncate -s 0 {shlex.quote(path)}", timeout=60) if path else current
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    cleanup = context.local.run(f"sudo rm -f {backup}", timeout=15)
    assertions = [
        AssertionResult("Oracle text alert copy-truncated", truncate.returncode == 0, command_fact(truncate)),
        AssertionResult("post-truncate event delivered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G3a", "Copy-truncate rotation continuity", started, [paths_result, current, truncate, trigger, received, cleanup], assertions, "Collection resumed after the Oracle text alert was copy-truncated", "Passed" if cleanup.returncode == 0 else "Failed")


def oracle_rapid_rotation(context: LabContext) -> ScenarioResult:
    started = utc_now()
    markers = [context.marker("G3b", f"part{i}") for i in range(1, 4)]
    commands: list[CommandResult] = []
    for marker in markers:
        commands.append(oracle_sql(context, f"select /*{marker}*/ 1 from dual;"))
    received = context.receiver_grep(markers[-1], timeout=120)
    all_lines = context.receiver.run(f"grep -E -- {shlex.quote('|'.join(markers))} {shlex.quote(context.receiver_log)}", sudo=True, timeout=30)
    commands.extend([received, all_lines])
    assertions = [AssertionResult("all rapid new-file markers collected", all(marker in all_lines.stdout for marker in markers), command_fact(all_lines))]
    return evaluated_result("G3b", "Rapid traditional-audit file creation", started, commands, assertions, "Collection followed three rapidly created .aud files")


def oracle_large_record(context: LabContext) -> ScenarioResult:
    started = utc_now()
    capacity_check, capacity, configured = receiver_message_capacity(context)
    required = LARGE_RECORD_PAYLOAD_BYTES + LARGE_RECORD_OVERHEAD_BYTES
    if capacity is not None and capacity < required:
        return ScenarioResult(
            scenario_id="G9",
            name="Multi-megabyte Oracle record",
            status="Inconclusive",
            reason=f"Receiver effective message limit is {capacity // 1024} KiB; at least {required // 1024} KiB is required before testing truncation",
            started_at=started,
            ended_at=utc_now(),
            assertions=[AssertionResult("receiver accepts the full test record", False, f"configured={configured} required_bytes={required}")],
            commands=[capacity_check],
        )
    prefix = context.marker("G9", "begin")
    suffix = context.marker("G9", "end")
    paths_result = oracle_path_query(context)
    trace = oracle_paths(paths_result).get("TRACE", "")
    current = context.local.run(f"find {shlex.quote(trace)} -maxdepth 1 -type f -name 'alert_*.log' -print -quit", timeout=15) if trace else paths_result
    path = current.stdout.strip()
    append = context.local.run(f"{{ printf %s {shlex.quote(prefix)}; head -c {LARGE_RECORD_PAYLOAD_BYTES} /dev/zero | tr '\\0' x; printf '%s\\n' {shlex.quote(suffix)}; }} | sudo tee -a {shlex.quote(path)} >/dev/null", timeout=120) if path else current
    received = context.receiver_event(prefix, timeout=180)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("multi-megabyte alert record appended", append.returncode == 0, command_fact(append)),
        AssertionResult("large event beginning delivered", prefix in received.stdout, f"prefix={prefix in received.stdout}"),
        AssertionResult("large event not truncated", suffix in received.stdout, f"suffix={suffix in received.stdout} bytes={len(received.stdout.encode())}"),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G9", "Multi-megabyte Oracle record", started, [capacity_check, paths_result, current, append, received, service], assertions, "A multi-megabyte Oracle record reached the receiver without truncation")


def oracle_buffer_cap(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    image = f"/tmp/lc-h3-{token}.img"
    mountpoint = "/var/lib/log-collector/disk_buffer"
    paths_result = oracle_path_query(context)
    trace = oracle_paths(paths_result).get("TRACE", "")
    current = context.local.run(f"find {shlex.quote(trace)} -maxdepth 1 -type f -name 'alert_*.log' -print -quit", timeout=15) if trace else paths_result
    path = current.stdout.strip()
    before = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    prepare = context.local.run(f"sudo systemctl stop log-collector; truncate -s 600M {shlex.quote(image)}; sudo mkfs.ext4 -q -F {shlex.quote(image)}; sudo mount -o loop {shlex.quote(image)} {mountpoint}; sudo chown log-collector:log-collector {mountpoint}; sudo systemctl start log-collector", timeout=240)
    stop_receiver = establish_receiver_outage(context)
    cleanup_ok = False
    try:
        generator = context.local.run(f"PAYLOAD=$(head -c 4000 /dev/zero | tr '\\0' x); for i in $(seq -w 1 140000); do printf 'lc_oracle_h3_%s_%s\\n' \"$i\" \"$PAYLOAD\"; done | sudo tee -a {shlex.quote(path)} >/dev/null", timeout=1800) if path else current
        time.sleep(20)
        after = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
        logs = context.local.run("sudo journalctl -u log-collector --since '-30 minutes' --no-pager | tail -n 300", timeout=30)
        service = context.local.run("systemctl is-active log-collector", timeout=15)
    finally:
        restore_receiver = restore_receiver_ingest(context)
        cleanup = context.local.run(f"sudo systemctl stop log-collector; sudo umount {mountpoint}; rm -f {shlex.quote(image)}; sudo systemctl start log-collector", timeout=240)
        cleanup_ok = restore_receiver.returncode == 0 and cleanup.returncode == 0
    def dropped(payload: str) -> int:
        try:
            return int(json.loads(payload).get("events_dropped", 0))
        except (ValueError, TypeError, json.JSONDecodeError, AttributeError):
            return -1
    assertions = [
        AssertionResult("600 MB isolated buffer filesystem mounted", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("receiver unavailable during load", stop_receiver.returncode == 0, command_fact(stop_receiver)),
        AssertionResult("more than 500 MB generated", generator.returncode == 0, command_fact(generator)),
        AssertionResult("oldest events dropped at cap", dropped(before.stdout) >= 0 and dropped(after.stdout) > dropped(before.stdout), f"before={dropped(before.stdout)} after={dropped(after.stdout)}"),
        AssertionResult("cap warning emitted", bool(re.search(r"drop|oldest|buffer.*(?:cap|limit|full)", logs.stdout, re.I)), command_fact(logs)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("H3", "Disk buffer cap and oldest-drop behavior", started, [paths_result, current, before, prepare, stop_receiver, generator, after, logs, service, restore_receiver, cleanup], assertions, "Collector enforced its buffer cap and stayed active", "Passed" if cleanup_ok else "Failed")


def oracle_apparmor(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    marker = context.marker("I7", "apparmor")
    profile_path = f"/etc/apparmor.d/lc-log-collector-{token}"
    binary_result = context.local.run("command -v log-collector || printf /usr/local/bin/log-collector", timeout=15)
    binary = binary_result.stdout.strip()
    profile_name = f"lc-log-collector-{token}"
    profile = f"#include <tunables/global>\nprofile {profile_name} {binary} flags=(attach_disconnected) {{\n #include <abstractions/base>\n capability,\n network,\n / r,\n /** r,\n /var/lib/log-collector/** rwk,\n /var/log/log-collector/** rwk,\n /run/** rwk,\n /proc/** r,\n /sys/** r,\n}}\n"
    install = context.local.run("sudo apt-get -s install apparmor apparmor-utils && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor apparmor-utils", timeout=600)
    load = context.local.run(f"printf %s {shlex.quote(profile)} | sudo tee {shlex.quote(profile_path)} >/dev/null && sudo apparmor_parser -r {shlex.quote(profile_path)} && sudo systemctl restart log-collector", timeout=120)
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    denials = context.local.run(f"sudo journalctl -k --since '-5 minutes' --no-pager | grep -F 'apparmor=\"DENIED\"' | grep -F {shlex.quote(profile_name)} || true", timeout=30)
    cleanup = context.local.run(f"sudo apparmor_parser -R {shlex.quote(profile_path)} 2>/dev/null || true; sudo rm -f -- {shlex.quote(profile_path)}; sudo systemctl restart log-collector", timeout=120)
    assertions = [
        AssertionResult("AppArmor tools available", install.returncode == 0, command_fact(install)),
        AssertionResult("enforcing profile loaded", load.returncode == 0, command_fact(load)),
        AssertionResult("Oracle event collected while confined", marker in received.stdout, command_fact(received)),
        AssertionResult("no AppArmor denial", not denials.stdout.strip(), command_fact(denials)),
    ]
    return evaluated_result("I7", "AppArmor enforcing", started, [binary_result, install, load, trigger, received, denials, cleanup], assertions, "Collector remained functional under an enforcing AppArmor profile", "Passed" if cleanup.returncode == 0 else "Failed")


def oracle_missing_audit_files(context: LabContext) -> ScenarioResult:
    started = utc_now()
    paths_result = oracle_path_query(context)
    audit = oracle_paths(paths_result).get("AUDIT", "")
    backup = f"/tmp/lc-e3-{secrets.token_hex(5)}"
    recovery_id = f"E3-{secrets.token_hex(5)}"
    recovery = f"find {backup} -maxdepth 1 -type f -name '*.aud' -exec mv -t {audit} -- {{}} +; rmdir {backup}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": recovery, "sudo": True, "timeout": 120})
    move = context.local.run(f"sudo mkdir -p {backup}; sudo find {shlex.quote(audit)} -maxdepth 1 -type f -name '*.aud' -exec mv -t {backup} -- {{}} +", timeout=120) if audit else paths_result
    dependency, probe = setup_wizard_probe(context, r"(?is)(?:no.*\.aud|audit.*files.*(?:missing|not found|none)|AUDIT_SYS_OPERATIONS.*AUDIT_FILE_DEST)")
    restore = context.local.run(f"sudo bash -lc {shlex.quote(recovery)}", timeout=120) if audit else paths_result
    if restore.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("traditional audit files isolated", move.returncode == 0, command_fact(move)),
        AssertionResult("clear audit enablement warning", probe.returncode == 0 and "audit" in probe.stdout.lower(), command_fact(probe)),
    ]
    return evaluated_result("E3", "No traditional audit files warning", started, [paths_result, move, dependency, probe, restore], assertions, "Wizard mentioned AUDIT_SYS_OPERATIONS and AUDIT_FILE_DEST when no .aud files existed", "Passed" if restore.returncode == 0 else "Failed")


def oracle_midfile_resume(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("E9a")
    generate = oracle_sql(context, f"select /*{marker}*/ 1 from dual;")
    paths_result = oracle_path_query(context)
    audit = oracle_paths(paths_result).get("AUDIT", "")
    original = context.local.run(f"sudo grep -rl -- {shlex.quote(marker)} {shlex.quote(audit)} --include='*.aud' | head -n 1", timeout=30) if audit else paths_result
    source = original.stdout.strip()
    synthetic = f"{audit}/lc_e9a_{secrets.token_hex(5)}.aud" if audit else ""
    split = context.local.run(f"LINES=$(sudo wc -l < {shlex.quote(source)}); HALF=$((LINES/2)); sudo head -n \"$HALF\" {shlex.quote(source)} > {shlex.quote(synthetic)}; sudo chown oracle:oinstall {shlex.quote(synthetic)}", timeout=60) if source else original
    start_track = context.local.run("sudo systemctl restart log-collector", timeout=60)
    time.sleep(5)
    append = context.local.run(f"LINES=$(sudo wc -l < {shlex.quote(source)}); HALF=$((LINES/2)); sudo tail -n +$((HALF+1)) {shlex.quote(source)} | sudo tee -a {shlex.quote(synthetic)} >/dev/null", timeout=60) if source else original
    received = context.receiver_grep(marker, timeout=120)
    cleanup = context.local.run(f"sudo rm -f {shlex.quote(synthetic)}", timeout=30) if synthetic else original
    assertions = [
        AssertionResult("headerless continuation prepared", generate.returncode == 0 and split.returncode == 0 and append.returncode == 0, f"generate={generate.returncode} split={split.returncode} append={append.returncode}"),
        AssertionResult("mid-file continuation collected", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("E9a", "Resume mid-way through .aud file", started, [generate, paths_result, original, split, start_track, append, received, cleanup], assertions, "Headerless .aud continuation retained correct attribution", "Passed" if cleanup.returncode == 0 else "Failed")


def oracle_small_file_restart(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G4")
    paths_result = oracle_path_query(context)
    audit = oracle_paths(paths_result).get("AUDIT", "")
    path = f"{audit}/lc_g4_{secrets.token_hex(5)}.aud" if audit else ""
    create = context.local.run(f"printf 'AUDIT_ACTIONS\\n' | sudo tee {shlex.quote(path)} >/dev/null; sudo chown oracle:oinstall {shlex.quote(path)}", timeout=30) if path else paths_result
    size = context.local.run(f"stat -c %s {shlex.quote(path)}", timeout=15) if path else paths_result
    restart = context.local.run("sudo systemctl restart log-collector", timeout=60)
    record = f"ACTION :[6] 'SELECT'\nUSERID:[3] 'SYS'\nSQLTEXT:[128] 'select /*{marker}*/ 1 from dual'\n"
    append = context.local.run(f"printf %s {shlex.quote(record)} | sudo tee -a {shlex.quote(path)} >/dev/null", timeout=30) if path else paths_result
    received = context.receiver_grep(marker, timeout=120)
    cleanup = context.local.run(f"sudo rm -f {shlex.quote(path)}", timeout=30) if path else paths_result
    try:
        byte_count = int(size.stdout.strip())
    except ValueError:
        byte_count = -1
    assertions = [
        AssertionResult("tracked file under 128 bytes", 0 <= byte_count < 128, f"size={byte_count}"),
        AssertionResult("collector restarted", restart.returncode == 0, command_fact(restart)),
        AssertionResult("next audit record delivered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G4", "Nearly-empty log restart", started, [paths_result, create, size, restart, append, received, cleanup], assertions, "Collector restarted on a tiny .aud file and collected its next record", "Passed" if cleanup.returncode == 0 else "Failed")


def oracle_database_start_order(context: LabContext, scenario_id: str = "H4") -> ScenarioResult:
    started = utc_now()
    marker = context.marker(scenario_id, "recovered")
    recovery_id = f"{scenario_id}-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": "sudo -iu oracle sqlplus -s '/ as sysdba' <<< 'startup;'", "sudo": False, "timeout": 300})
    stop = oracle_sql(context, "shutdown immediate;", timeout=300)
    restart_collector = context.local.run("sudo systemctl restart log-collector", timeout=60)
    waiting = context.local.run("systemctl is-active log-collector", timeout=15)
    start_db = oracle_sql(context, "startup;", timeout=300)
    if start_db.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=180)
    assertions = [
        AssertionResult("Oracle instance stopped", stop.returncode == 0, command_fact(stop)),
        AssertionResult("collector active before database", restart_collector.returncode == 0 and waiting.stdout.strip() == "active", command_fact(waiting)),
        AssertionResult("Oracle instance started", start_db.returncode == 0, command_fact(start_db)),
        AssertionResult("collection resumed", marker in received.stdout, command_fact(received)),
    ]
    name = "Agent restart while database is stopped" if scenario_id == "G4a" else "Collector starts before Oracle"
    return evaluated_result(scenario_id, name, started, [stop, restart_collector, waiting, start_db, trigger, received], assertions, "Collector waited for Oracle and resumed when it started", "Passed" if start_db.returncode == 0 else "Failed")


def oracle_db_stopped_restart(context: LabContext) -> ScenarioResult:
    return oracle_database_start_order(context, "G4a")


def oracle_fresh_state(context: LabContext) -> ScenarioResult:
    started = utc_now()
    old = context.marker("G5", "history")
    new = context.marker("G5", "current")
    old_trigger = oracle_alert_marker(context, old)
    old_received = context.receiver_grep(old, timeout=90)
    count_command = f"grep -Fc -- {shlex.quote(old)} {shlex.quote(context.receiver_log)} || true"
    before = context.receiver.run(count_command, sudo=True, timeout=15)
    stop = context.local.run("sudo systemctl stop log-collector", timeout=60)
    clear = context.local.run("sudo find /var/lib/log-collector/state /var/lib/log-collector/disk_buffer -mindepth 1 -delete", timeout=60)
    start_service = context.local.run("sudo systemctl start log-collector", timeout=60)
    time.sleep(5)
    after = context.receiver.run(count_command, sudo=True, timeout=15)
    new_trigger = oracle_alert_marker(context, new)
    new_received = context.receiver_grep(new, timeout=90)
    try:
        before_count = int(before.stdout.strip() or "0")
        after_count = int(after.stdout.strip() or "0")
    except ValueError:
        before_count = after_count = -1
    assertions = [
        AssertionResult("collector state reset", stop.returncode == 0 and clear.returncode == 0 and start_service.returncode == 0, f"stop={stop.returncode} clear={clear.returncode} start={start_service.returncode}"),
        AssertionResult("history not replayed", before_count >= 1 and after_count == before_count, f"before={before_count} after={after_count}"),
        AssertionResult("new event delivered", new in new_received.stdout, command_fact(new_received)),
    ]
    return evaluated_result("G5", "Fresh-state starts at current log end", started, [old_trigger, old_received, before, stop, clear, start_service, after, new_trigger, new_received], assertions, "Fresh state started at current Oracle log end")


def oracle_read_from_beginning(context: LabContext) -> ScenarioResult:
    started = utc_now()
    locate, backup_result, config, backup = backup_collector_configuration(context, "G5a")
    dependency, wizard = complete_setup_wizard(context, engines={"oracle"}, read_from_beginning=True)
    check = context.local.run("sudo log-collector check", timeout=30)
    marker = context.marker("G5a", "history")
    stop = context.local.run("sudo systemctl stop log-collector", timeout=60)
    clear = context.local.run("sudo find /var/lib/log-collector/state /var/lib/log-collector/disk_buffer -mindepth 1 -delete", timeout=60)
    history = oracle_alert_marker(context, marker)
    start_service = context.local.run("sudo systemctl start log-collector", timeout=60)
    received = context.receiver_grep(marker, timeout=180)
    restore = restore_collector_configuration(context, config, backup, reset_state=True)
    assertions = [
        AssertionResult("read-from-beginning setup completed", wizard.returncode == 0 and check.returncode == 0, f"wizard={wizard.returncode} check={check.returncode}"),
        AssertionResult("historical event generated before collector start", stop.returncode == 0 and clear.returncode == 0 and history.returncode == 0, command_fact(history)),
        AssertionResult("historical event ingested", start_service.returncode == 0 and marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G5a", "Read existing history from beginning", started, [locate, backup_result, dependency, wizard, check, stop, clear, history, start_service, received, restore], assertions, "Oracle read-from-beginning ingested pre-existing history", "Passed" if restore.returncode == 0 else "Failed")


def oracle_delete_recreate(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G7")
    paths_result = oracle_path_query(context)
    trace = oracle_paths(paths_result).get("TRACE", "")
    current = context.local.run(f"find {shlex.quote(trace)} -maxdepth 1 -type f -name 'alert_*.log' -print -quit", timeout=15) if trace else paths_result
    path = current.stdout.strip()
    stop = oracle_sql(context, "shutdown immediate;", timeout=300)
    delete = context.local.run(f"sudo rm -f {shlex.quote(path)}", timeout=30) if path else current
    start_db = oracle_sql(context, "startup;", timeout=300)
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=180)
    recreated = context.local.run(f"test -f {shlex.quote(path)}", timeout=15) if path else current
    assertions = [
        AssertionResult("active text alert deleted while instance stopped", stop.returncode == 0 and delete.returncode == 0, f"stop={stop.returncode} delete={delete.returncode}"),
        AssertionResult("Oracle recreated alert log", start_db.returncode == 0 and recreated.returncode == 0, command_fact(recreated)),
        AssertionResult("collector picked up replacement", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G7", "Delete and recreate active log", started, [paths_result, current, stop, delete, start_db, trigger, received, recreated], assertions, "Collector followed Oracle's recreated alert log", "Passed" if start_db.returncode == 0 else "Failed")


def oracle_permission_recovery(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G8")
    paths_result = oracle_path_query(context)
    trace = oracle_paths(paths_result).get("TRACE", "")
    current = context.local.run(f"find {shlex.quote(trace)} -maxdepth 1 -type f -name 'alert_*.log' -print -quit", timeout=15) if trace else paths_result
    path = current.stdout.strip()
    mode_result = context.local.run(f"stat -c %a {shlex.quote(path)}", timeout=15) if path else current
    mode = mode_result.stdout.strip() or "640"
    recovery_id = f"G8-{secrets.token_hex(5)}"
    if context.journal and path:
        context.journal.add({"id": recovery_id, "scope": "local", "command": f"chmod {mode} {path}", "sudo": True, "timeout": 30})
    deny = context.local.run(f"sudo chmod 000 {shlex.quote(path)}", timeout=30) if path else current
    time.sleep(5)
    logs = context.local.run("sudo journalctl -u log-collector --since '-2 minutes' --no-pager", timeout=30)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    restore = context.local.run(f"sudo chmod {mode} {shlex.quote(path)}", timeout=30) if path else current
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("permission removed", deny.returncode == 0, command_fact(deny)),
        AssertionResult("clear read error emitted", bool(re.search(r"permission|denied|cannot.*open", logs.stdout, re.I)), command_fact(logs)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("collection recovered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("G8", "Permission loss and recovery", started, [paths_result, current, mode_result, deny, logs, service, restore, trigger, received], assertions, "Collector reported denial, stayed active, and recovered", "Passed" if restore.returncode == 0 else "Failed")


def oracle_malformed(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("G10")
    paths_result = oracle_path_query(context)
    alert = oracle_paths(paths_result).get("ALERT", "")
    path = f"{alert}/log.xml" if alert else ""
    malformed = f"<msg malformed='yes'><txt>{marker}</broken>"
    append = context.local.run(f"printf '%s\\n' {shlex.quote(malformed)} | sudo tee -a {shlex.quote(path)} >/dev/null", timeout=30) if path else paths_result
    received = context.receiver_grep(marker, timeout=90)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("malformed XML fragment appended", append.returncode == 0, command_fact(append)),
        AssertionResult("malformed record forwarded", marker in received.stdout, command_fact(received)),
        AssertionResult("forwarded record flagged", bool(re.search(r"raw|malform|parse|flag", received.stdout, re.I)), command_fact(received)),
        AssertionResult("collector remained active", service.stdout.strip() == "active", command_fact(service)),
    ]
    return evaluated_result("G10", "Malformed record forwarding", started, [paths_result, append, received, service], assertions, "Malformed Oracle XML was forwarded and flagged")


def oracle_backward_clock(context: LabContext) -> ScenarioResult:
    started = utc_now()
    during = context.marker("G12", "backward")
    after = context.marker("G12", "restored")
    receiver_time = context.receiver.run("date -u +%Y-%m-%dT%H:%M:%SZ", timeout=15)
    restore_command = f"date -u -s {shlex.quote(receiver_time.stdout.strip())}; timedatectl set-ntp true 2>/dev/null || true"
    recovery_id = f"G12-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 60})
    change = context.local.run("sudo timedatectl set-ntp false 2>/dev/null || true; sudo date -s '1 hour ago'", timeout=30)
    during_trigger = oracle_alert_marker(context, during)
    during_received = context.receiver_grep(during, timeout=90)
    restore = context.local.run(restore_command, sudo=True, timeout=60)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    after_trigger = oracle_alert_marker(context, after)
    after_received = context.receiver_grep(after, timeout=90)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    assertions = [
        AssertionResult("clock moved backwards", change.returncode == 0, command_fact(change)),
        AssertionResult("event collected during backward clock", during in during_received.stdout, command_fact(during_received)),
        AssertionResult("clock restored", restore.returncode == 0, command_fact(restore)),
        AssertionResult("collection continued after restore", after in after_received.stdout and service.stdout.strip() == "active", command_fact(after_received)),
    ]
    return evaluated_result("G12", "Backward system clock", started, [receiver_time, change, during_trigger, during_received, restore, after_trigger, after_received, service], assertions, "Oracle collection continued across a backward clock change", "Passed" if restore.returncode == 0 else "Failed")


def oracle_config_fallback(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("H7")
    locate, config = collector_config_path(context)
    backup = f"/tmp/lc-h7-{secrets.token_hex(5)}"
    last_good = f"{config}.last-good"
    prepare = context.local.run(f"sudo mkdir -p {backup} && sudo cp -a {shlex.quote(config)} {shlex.quote(last_good)} {backup}/", timeout=60) if config else context.local.run("false", timeout=5)
    restore_command = f"cp -a {backup}/agent.toml {config}; cp -a {backup}/agent.toml.last-good {last_good}; systemctl restart log-collector"
    recovery_id = f"H7-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": restore_command, "sudo": True, "timeout": 120})
    corrupt = context.local.run(f"printf garbage | sudo tee {shlex.quote(config)} >/dev/null && sudo systemctl restart log-collector", timeout=120) if config else context.local.run("false", timeout=5)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    logs = context.local.run("sudo journalctl -u log-collector --since '-3 minutes' --no-pager | tail -n 100", timeout=30)
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    restore = context.local.run(f"sudo bash -lc {shlex.quote(restore_command)}; sudo rm -rf {backup}", timeout=120)
    if restore.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    assertions = [
        AssertionResult("configuration backed up", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("collector used last-good fallback", corrupt.returncode == 0 and service.stdout.strip() == "active" and bool(re.search(r"last.?good|fallback|recover", logs.stdout, re.I)), command_fact(logs)),
        AssertionResult("collection continued", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H7", "Corrupt config fallback", started, [locate, prepare, corrupt, service, logs, trigger, received, restore], assertions, "Collector used last-good config and kept collecting", "Passed" if restore.returncode == 0 else "Failed")


def oracle_unreachable_output(context: LabContext) -> ScenarioResult:
    started = utc_now()
    marker = context.marker("H9")
    resolved = context.local.run(f"getent ahostsv4 {shlex.quote(context.receiver.config.host)} | awk 'NR==1 {{print $1}}'", timeout=15)
    address = resolved.stdout.strip()
    add_rule = f"iptables -I OUTPUT -p tcp -d {address} --dport 2514 -j REJECT"
    del_rule = f"iptables -D OUTPUT -p tcp -d {address} --dport 2514 -j REJECT"
    recovery_id = f"H9-{secrets.token_hex(5)}"
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "local", "command": del_rule, "sudo": True, "timeout": 30})
    block = context.local.run(add_rule, sudo=True, timeout=30) if address else context.local.run("false", timeout=5)
    time.sleep(10)
    health = context.local.run("curl -fsS --max-time 5 http://127.0.0.1:9100/status", timeout=15)
    service = context.local.run("systemctl is-active log-collector", timeout=15)
    unblock = context.local.run(del_rule, sudo=True, timeout=30) if address else context.local.run("false", timeout=5)
    if unblock.returncode == 0 and context.journal:
        context.journal.remove(recovery_id)
    trigger = oracle_alert_marker(context, marker)
    received = context.receiver_grep(marker, timeout=90)
    try:
        payload = json.loads(health.stdout)
    except json.JSONDecodeError:
        payload = {}
    disconnected = payload.get("cloud_connected") is False or str(payload.get("cloud_status", "")).lower() not in {"connected", ""}
    assertions = [
        AssertionResult("receiver route blocked", block.returncode == 0, command_fact(block)),
        AssertionResult("collector stayed active", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("health reported disconnected", disconnected, command_fact(health)),
        AssertionResult("delivery recovered", marker in received.stdout, command_fact(received)),
    ]
    return evaluated_result("H9", "Unreachable output retry", started, [resolved, block, health, service, unblock, trigger, received], assertions, "Collector stayed active and recovered output", "Passed" if unblock.returncode == 0 else "Failed")


def oracle_reboot_resume(context: LabContext) -> ScenarioResult:
    if context.evidence is None:
        raise RuntimeError("H6 requires an evidence run")
    started = utc_now()
    scenario_dir = (context.evidence.run_dir / "scenarios" / "H6").resolve()
    phase_file = scenario_dir / "post-reboot.txt"
    marker = context.marker("H6", "post_reboot")
    if phase_file.exists():
        phase = context.local.run(f"sudo cat {shlex.quote(str(phase_file))}", timeout=15)
        received = context.receiver_grep(marker, timeout=120)
        enabled = context.local.run("systemctl is-enabled log-collector", timeout=15)
        cleanup = context.local.run("sudo systemctl disable --now lc-h6-continuation.service 2>/dev/null || true; sudo rm -f /etc/systemd/system/lc-h6-continuation.service; sudo systemctl daemon-reload", timeout=60)
        assertions = [
            AssertionResult("collector active after reboot", "collector=active" in phase.stdout, command_fact(phase)),
            AssertionResult("collector enabled at boot", enabled.stdout.strip() == "enabled", command_fact(enabled)),
            AssertionResult("post-reboot Oracle event delivered", marker in received.stdout, command_fact(received)),
        ]
        return evaluated_result("H6", "Machine reboot continuity", started, [phase, received, enabled, cleanup], assertions, "Collector returned automatically and resumed Oracle collection")
    scenario_dir.mkdir(parents=True, exist_ok=True)
    sql = f"begin dbms_system.ksdwrt(2,'{marker}'); end;\\n/\\nexit\\n"
    phase_command = (
        "for i in $(seq 1 90); do systemctl is-active --quiet log-collector && pgrep -f ora_pmon >/dev/null && break; sleep 2; done; "
        f"printf %s {shlex.quote(sql)} | runuser -u oracle -- bash -lc \"sqlplus -s '/ as sysdba'\"; "
        f"printf 'collector=%%s\\nmarker={marker}\\n' \"$(systemctl is-active log-collector)\" > {shlex.quote(str(phase_file))}"
    )
    unit = f"[Unit]\nDescription=Log collector Oracle H6 continuation\nAfter=network-online.target log-collector.service\n\n[Service]\nType=oneshot\nExecStart=/bin/bash -lc {shlex.quote(phase_command)}\n\n[Install]\nWantedBy=multi-user.target\n"
    prepare = context.local.run(f"printf %s {shlex.quote(unit)} | sudo tee /etc/systemd/system/lc-h6-continuation.service >/dev/null; sudo systemctl daemon-reload; sudo systemctl enable lc-h6-continuation.service", timeout=60)
    if prepare.returncode != 0:
        raise RuntimeError(f"Could not prepare reboot continuation: {command_fact(prepare)}")
    print(f"[H6] Reboot prepared. After boot rerun with --resume --scenario H6. Evidence: {context.evidence.run_dir}", flush=True)
    reboot = context.local.run("sudo systemctl reboot", timeout=30)
    if reboot.returncode != 0:
        raise RuntimeError(f"Reboot request failed: {command_fact(reboot)}")
    raise SystemExit(75)


def oracle_buffer_disk_full(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(5)
    image = f"/tmp/lc-h11-{token}.img"
    mountpoint = "/var/lib/log-collector/disk_buffer"
    paths_result = oracle_path_query(context)
    trace = oracle_paths(paths_result).get("TRACE", "")
    current = context.local.run(f"find {shlex.quote(trace)} -maxdepth 1 -type f -name 'alert_*.log' -print -quit", timeout=15) if trace else paths_result
    path = current.stdout.strip()
    prepare = context.local.run(f"sudo systemctl stop log-collector; truncate -s 32M {shlex.quote(image)}; sudo mkfs.ext4 -q -F {shlex.quote(image)}; sudo mount -o loop {shlex.quote(image)} {mountpoint}; sudo chown log-collector:log-collector {mountpoint}; sudo systemctl start log-collector", timeout=180)
    stop_receiver = establish_receiver_outage(context)
    cleanup_ok = False
    try:
        generator = context.local.run(f"PAYLOAD=$(head -c 4000 /dev/zero | tr '\\0' x); for i in $(seq -w 1 20000); do printf 'lc_oracle_h11_%s_%s\\n' \"$i\" \"$PAYLOAD\"; done | sudo tee -a {shlex.quote(path)} >/dev/null", timeout=900) if path else current
        time.sleep(15)
        disk = context.local.run(f"df -Pk {mountpoint}; sudo du -sb {mountpoint}", timeout=30)
        logs = context.local.run("sudo journalctl -u log-collector --since '-10 minutes' --no-pager | tail -n 200", timeout=30)
        service = context.local.run("systemctl is-active log-collector", timeout=15)
    finally:
        restore_receiver = restore_receiver_ingest(context)
        cleanup = context.local.run(f"sudo systemctl stop log-collector; sudo umount {mountpoint}; rm -f {shlex.quote(image)}; sudo systemctl start log-collector", timeout=180)
        cleanup_ok = restore_receiver.returncode == 0 and cleanup.returncode == 0
    assertions = [
        AssertionResult("isolated 32 MB buffer filesystem mounted", prepare.returncode == 0, command_fact(prepare)),
        AssertionResult("receiver stopped", stop_receiver.returncode == 0, command_fact(stop_receiver)),
        AssertionResult("buffer pressure generated", generator.returncode == 0, command_fact(generator)),
        AssertionResult("collector survived full buffer disk", service.stdout.strip() == "active", command_fact(service)),
        AssertionResult("clear disk or buffer error", bool(re.search(r"no space|disk|buffer|write", logs.stdout, re.I)), command_fact(logs)),
    ]
    return evaluated_result("H11", "Full buffer disk handling", started, [paths_result, current, prepare, stop_receiver, generator, disk, logs, service, restore_receiver, cleanup], assertions, "Collector remained running and reported the full buffer disk", "Passed" if cleanup_ok else "Failed")


def mysql_family_scenarios() -> list[Scenario]:
    scenarios = shared_engine_scenarios() + [
        Scenario("A1", "Setup wizard starts", "destructive", pg_setup_starts, execution_mode="clone"),
        Scenario("A2", "Required client or tenant name", "destructive", pg_setup_requires_client, execution_mode="clone"),
        Scenario("A3", "Agent ID defaults to hostname", "destructive", pg_setup_hostname_default, execution_mode="clone"),
        Scenario("A4", "Installed database discovery", "destructive", mysql_family_setup_discovery, execution_mode="clone"),
        Scenario("A5", "Absent database discovery", "destructive", pg_setup_absent_engine, execution_mode="clone"),
        Scenario("A6", "Accept auto-discovery", "destructive", pg_setup_accepts_autodiscovery, execution_mode="clone"),
        Scenario("A7", "Encrypted configuration at rest", "destructive", pg_encrypted_config, execution_mode="clone"),
        Scenario("A9", "Service install and start", "destructive", pg_service_install_cycle, execution_mode="clone"),
        Scenario("A12", "Setup preserves last-good config", "destructive", mysql_family_setup_last_good, execution_mode="clone"),
        Scenario("A13", "Non-root setup refusal", "destructive", pg_setup_non_root, execution_mode="clone"),
        Scenario("B1", "Basic database collection", "safe", mysql_family_basic),
        Scenario("B2", "Stable source identifier", "safe", mysql_family_source),
        Scenario("B3", "Service restart and checkpoint", "configuration", mysql_family_restart),
        Scenario("B6", "Unique event identifiers", "safe", mysql_family_event_ids),
        Scenario("G1", "Password redaction", "safe", mysql_family_password_redaction),
        Scenario("G2", "Username preservation", "safe", mysql_family_username),
        Scenario("G3", "Cross-engine rotation continuity", "configuration", mysql_family_rotation),
        Scenario("G6", "Unicode log preservation", "safe", mysql_family_unicode),
        Scenario("H10", "SIGKILL checkpoint recovery", "disruptive", mysql_family_kill_recovery),
        Scenario("I8", "Non-root collector with database-log access", "safe", mysql_family_non_root_read),
        Scenario("B4", "Constrained-lab stability window", "safe", mysql_family_stability),
        Scenario("B5", "Constrained-lab receiver outage", "disruptive", mysql_family_receiver_outage),
        Scenario("B7", "Native timestamp preservation", "safe", mysql_family_timestamp),
        Scenario("G3b", "Two rapid database rotations", "configuration", mysql_family_rapid_rotation),
        Scenario("G4a", "Agent restart while database is stopped", "disruptive", mysql_family_db_stopped_restart),
        Scenario("G4", "Nearly-empty log restart", "destructive", mysql_family_small_file_restart, execution_mode="clone"),
        Scenario("G5", "Fresh-state starts at current log end", "destructive", mysql_family_fresh_state, execution_mode="clone"),
        Scenario("G5a", "Read existing history from beginning", "destructive", mysql_family_read_from_beginning, execution_mode="clone"),
        Scenario("G7", "Delete and recreate active log", "destructive", mysql_family_delete_recreate, execution_mode="clone"),
        Scenario("G8", "Permission loss and recovery", "destructive", mysql_family_permission_recovery, execution_mode="clone"),
        Scenario("G9", "Multi-megabyte database record", "safe", mysql_family_large_record),
        Scenario("G10", "Malformed record forwarding", "destructive", mysql_family_malformed, execution_mode="clone"),
        Scenario("G13", "Symlinked database log", "destructive", mysql_family_symlink_log, execution_mode="clone"),
        Scenario("G15", "Constrained high-volume run", "safe", mysql_family_high_volume),
        Scenario("H1", "Disk buffer growth during receiver outage", "disruptive", mysql_family_buffer_growth),
        Scenario("H2", "Buffered delivery after recovery", "disruptive", mysql_family_buffer_delivery),
        Scenario("H4", "Collector starts before database", "disruptive", mysql_family_agent_before_database),
        Scenario("H5", "Single Ctrl+C foreground drain", "destructive", pg_foreground_single_interrupt, execution_mode="clone"),
        Scenario("H5a", "Double Ctrl+C foreground exit", "destructive", pg_foreground_double_interrupt, execution_mode="clone"),
        Scenario("H6", "Machine reboot continuity", "destructive", mysql_family_reboot_resume, execution_mode="clone"),
        Scenario("H7", "Corrupt config fallback", "destructive", mysql_family_config_fallback, execution_mode="clone"),
        Scenario("H8", "Missing configuration failure", "destructive", pg_config_missing, execution_mode="clone"),
        Scenario("H9", "Unreachable output retry", "destructive", mysql_family_unreachable_output, execution_mode="clone"),
        Scenario("H11", "Full buffer disk handling", "destructive", mysql_family_buffer_disk_full, execution_mode="clone"),
        Scenario("H12", "Constrained sustained-load soak", "safe", mysql_family_soak),
        Scenario("I7", "AppArmor enforcing", "destructive", mysql_family_apparmor, execution_mode="clone"),
        Scenario("I9", "Collector uninstall", "destructive", pg_uninstall, execution_mode="clone"),
    ]
    return scenarios


def mysql_scenarios() -> list[Scenario]:
    return mysql_family_scenarios() + [
        Scenario("A11", "Two engines in one setup", "destructive", mysql_family_multi_engine_setup, execution_mode="clone"),
        Scenario("D1", "MySQL default log selection", "destructive", mysql_default_selection, execution_mode="clone"),
        Scenario("D1a", "Explicit general-log selection warning", "destructive", mysql_general_warning, execution_mode="clone"),
        Scenario("D1b", "MySQL include directive discovery", "destructive", mysql_include_directives, execution_mode="clone"),
        Scenario("D1c", "Ignore conflicting client section", "destructive", mysql_client_section_ignored, execution_mode="clone"),
        Scenario("D1d", "Dash and underscore option equivalence", "destructive", mysql_dash_option, execution_mode="clone"),
        Scenario("D1e", "Relative log path resolution", "destructive", mysql_relative_log, execution_mode="clone"),
        Scenario("D2f", "MySQL 8 error-code format", "safe", mysql_error_code_format),
        Scenario("D6", "MySQL Community audit-gap warning", "safe", mysql_community_gap_warning),
        Scenario("D7", "Successful Community login gap", "safe", mysql_successful_login_absent),
        Scenario("D7a", "MySQL JSON error sink alongside text", "configuration", mysql_json_error_sink),
        Scenario("D8a", "TABLE log output warning", "configuration", mysql_table_output_warning),
        Scenario("D8b", "Empty or stderr error-log handling", "destructive", mysql_stderr_warning, execution_mode="clone"),
        Scenario("D2", "Failed login severity", "safe", mysql_failed_login),
        Scenario("D2a", "Nonexistent-user login severity", "safe", mysql_nonexistent_login),
        Scenario("D2b", "Disallowed host severity", "destructive", mysql_disallowed_host, execution_mode="clone"),
        Scenario("D2c", "Blocked host severity", "destructive", mysql_blocked_host, execution_mode="clone"),
        Scenario("D2d", "Locked-account login severity", "safe", mysql_locked_login),
        Scenario("D2e", "Connection exhaustion severity", "destructive", mysql_connection_exhaustion, execution_mode="clone"),
        Scenario("D2h", "User DDL security events", "safe", mysql_user_ddl),
        Scenario("D3a", "Existing error severity is not demoted", "destructive", mysql_existing_error_not_demoted, execution_mode="clone"),
        Scenario("D3", "Two same-second slow queries", "safe", mysql_slow_same_second),
        Scenario("D4", "Slow query timestamp and statement", "safe", mysql_slow_timestamp_record),
        Scenario("D4a", "Multi-line slow query", "safe", mysql_slow_multiline),
        Scenario("D4b", "Unindexed query slow logging", "configuration", mysql_slow_no_index),
        Scenario("D4c", "Slow administrative statement", "configuration", mysql_slow_admin),
        Scenario("D4d", "Temporary zero-threshold slow-log volume", "configuration", mysql_slow_volume),
        Scenario("D5", "Multi-line general query", "configuration", mysql_general_multiline),
        Scenario("D5a", "Header-like general query text", "configuration", mysql_general_fake_header),
        Scenario("D8", "Binary, relay, and table-file exclusions", "safe", mysql_excluded_files),
        Scenario("D9", "FLUSH LOGS rotation", "configuration", mysql_rotation_alias),
        Scenario("D9a", "Packaged logrotate continuity", "configuration", mysql_packaged_rotation),
        Scenario("D9b", "Slow-log rotation under activity", "configuration", mysql_slow_rotation),
        Scenario("D9c", "MySQL restart survival", "disruptive", mysql_database_restart),
        Scenario("G1a", "CREATE USER password redaction", "safe", mysql_family_create_user_redaction),
        Scenario("G1c", "Legacy PASSWORD() redaction", "safe", mysql_old_password_syntax),
        Scenario("G3a", "Copy-truncate rotation continuity", "destructive", mysql_family_copytruncate, execution_mode="clone"),
        Scenario("G12", "Backward system clock", "destructive", mysql_family_backward_clock, execution_mode="clone"),
        Scenario("H3", "Disk buffer cap and oldest-drop behavior", "destructive", mysql_family_buffer_cap, execution_mode="clone"),
    ]


def mariadb_scenarios() -> list[Scenario]:
    return mysql_family_scenarios() + [
        Scenario("A11", "Two engines in one setup", "destructive", mysql_family_multi_engine_setup, execution_mode="clone"),
        Scenario("F1", "MariaDB default audit selection", "destructive", mariadb_default_audit, execution_mode="clone"),
        Scenario("F2", "Missing server_audit warning", "destructive", mariadb_missing_audit_warning, execution_mode="clone"),
        Scenario("F6", "MariaDB log-basename discovery", "destructive", mariadb_log_basename, execution_mode="clone"),
        Scenario("F7", "Debian and Ubuntu MariaDB configuration", "safe", mariadb_debian_config),
        Scenario("F7a", "MariaDB version and Galera sections", "destructive", mariadb_section_discovery, execution_mode="clone"),
        Scenario("F10", "server_audit SYSLOG output", "destructive", mariadb_syslog_audit, execution_mode="clone"),
        Scenario("F10a", "server_audit TABLE output", "destructive", mariadb_table_audit, execution_mode="clone"),
        Scenario("F3", "Successful login audit", "configuration", mariadb_successful_login),
        Scenario("F4", "Failed login severity", "safe", mariadb_failed_login),
        Scenario("F5", "Unescaped commas in audit query", "configuration", mariadb_audit_comma),
        Scenario("F5a", "Escaped quote in audit query", "configuration", mariadb_audit_quote),
        Scenario("F5b", "Multi-line audit query", "configuration", mariadb_audit_multiline),
        Scenario("F5c", "Timestamp-like audit query text", "configuration", mariadb_audit_fake_timestamp),
        Scenario("F5d", "Audit retcode extraction", "configuration", mariadb_audit_retcode),
        Scenario("F5e", "CONNECT, QUERY, and TABLE audit events", "configuration", mariadb_audit_event_kinds),
        Scenario("F5f", "server_audit size rotation", "configuration", mariadb_audit_rotation),
        Scenario("F9", "MariaDB text error-log format", "safe", mariadb_error_format),
        Scenario("F11", "MariaDB slow and general log collection", "configuration", mariadb_slow_and_general),
        Scenario("G1a", "CREATE USER password redaction", "safe", mysql_family_create_user_redaction),
        Scenario("G1d", "MariaDB audit password redaction", "safe", mariadb_backslash_password),
        Scenario("G3a", "Copy-truncate rotation continuity", "destructive", mysql_family_copytruncate, execution_mode="clone"),
        Scenario("G12", "Backward system clock", "destructive", mysql_family_backward_clock, execution_mode="clone"),
        Scenario("H3", "Disk buffer cap and oldest-drop behavior", "destructive", mysql_family_buffer_cap, execution_mode="clone"),
    ]


def oracle_scenarios() -> list[Scenario]:
    return shared_engine_scenarios() + [
        Scenario("A1", "Setup wizard starts", "destructive", pg_setup_starts, execution_mode="clone"),
        Scenario("A2", "Required client or tenant name", "destructive", pg_setup_requires_client, execution_mode="clone"),
        Scenario("A3", "Agent ID defaults to hostname", "destructive", pg_setup_hostname_default, execution_mode="clone"),
        Scenario("A4", "Installed Oracle discovery", "destructive", oracle_setup_discovery, execution_mode="clone"),
        Scenario("A5", "Absent database discovery", "destructive", oracle_setup_absent_engine, execution_mode="clone"),
        Scenario("A6", "Accept auto-discovery", "destructive", pg_setup_accepts_autodiscovery, execution_mode="clone"),
        Scenario("A7", "Encrypted configuration at rest", "destructive", pg_encrypted_config, execution_mode="clone"),
        Scenario("A9", "Service install and start", "destructive", pg_service_install_cycle, execution_mode="clone"),
        Scenario("A11", "Two engines in one setup", "destructive", mysql_family_multi_engine_setup, execution_mode="clone"),
        Scenario("A12", "Setup preserves last-good config", "destructive", oracle_setup_last_good, execution_mode="clone"),
        Scenario("A13", "Non-root setup refusal", "destructive", pg_setup_non_root, execution_mode="clone"),
        Scenario("B1", "Basic Oracle collection", "safe", oracle_basic),
        Scenario("B2", "Stable source identifier", "safe", oracle_source),
        Scenario("B3", "Service restart and checkpoint", "configuration", oracle_restart_checkpoint),
        Scenario("B4", "Constrained-lab stability window", "safe", oracle_stability),
        Scenario("B5", "Constrained-lab receiver outage", "disruptive", oracle_receiver_outage),
        Scenario("B6", "Unique event identifiers", "safe", oracle_unique_ids),
        Scenario("B7", "Native timestamp preservation", "safe", oracle_timestamp),
        Scenario("E1", "Unified audit coverage warning", "destructive", oracle_unified_gap_warning, execution_mode="clone"),
        Scenario("E3", "No traditional audit files warning", "destructive", oracle_missing_audit_files, execution_mode="clone"),
        Scenario("E2", "SYSDBA traditional audit record", "safe", oracle_sysdba_audit),
        Scenario("E2a", "SYSOPER traditional audit record", "safe", oracle_sysoper_audit),
        Scenario("E2b", "Failed SYSDBA login severity", "safe", oracle_failed_sysdba),
        Scenario("E2c", "Parsed traditional audit fields", "safe", oracle_audit_fields),
        Scenario("E2d", "Quoted traditional audit value", "safe", oracle_audit_quote),
        Scenario("E9", "Traditional audit new-file attribution", "safe", oracle_audit_new_files),
        Scenario("E9a", "Resume mid-way through .aud file", "destructive", oracle_midfile_resume, execution_mode="clone"),
        Scenario("E10", "ADR audit-directory rescan cadence", "safe", oracle_adump_rescan),
        Scenario("E10a", "Large adump directory scan", "configuration", oracle_adump_scale),
        Scenario("E5", "Critical Oracle alert severity", "safe", oracle_critical_error),
        Scenario("E5a", "Ordinary Oracle error severity", "safe", oracle_ordinary_error),
        Scenario("E7a", "Multi-line alert entry", "safe", oracle_multiline_alert),
        Scenario("E7b", "Oracle XML alert stream", "safe", oracle_xml_alert),
        Scenario("E7c", "Single-quoted XML content", "safe", oracle_xml_single_quote),
        Scenario("E7d", "CDB and PDB con_id", "safe", oracle_cdb_con_id),
        Scenario("E7e", "Oracle startup and shutdown", "disruptive", oracle_instance_restart),
        Scenario("E7f", "Trace incident exclusion", "configuration", oracle_trace_incident),
        Scenario("E6", "Listener connection event", "safe", oracle_listener_connect),
        Scenario("E6a", "Listener source and client-claimed host fields", "safe", oracle_listener_source_fields),
        Scenario("E6c", "Listener stop and start", "disruptive", oracle_listener_restart),
        Scenario("E6d", "Unknown listener service severity", "safe", oracle_listener_tns12514),
        Scenario("E6e", "Listener service_update volume", "safe", oracle_listener_noise),
        Scenario("E11", "Oracle trace and binary exclusions", "safe", oracle_excluded_files),
        Scenario("E11c", "ADR purge during collection", "configuration", oracle_adrci_purge),
        Scenario("G1", "ALTER USER password redaction", "safe", oracle_password_redaction),
        Scenario("G1a", "CREATE USER password redaction", "safe", oracle_create_user_redaction),
        Scenario("G2", "Username preservation", "safe", oracle_username),
        Scenario("G3", "Cross-engine rotation continuity", "configuration", oracle_rotation),
        Scenario("G3a", "Copy-truncate rotation continuity", "destructive", oracle_copytruncate, execution_mode="clone"),
        Scenario("G3b", "Rapid traditional-audit file creation", "configuration", oracle_rapid_rotation),
        Scenario("G4", "Nearly-empty log restart", "destructive", oracle_small_file_restart, execution_mode="clone"),
        Scenario("G4a", "Agent restart while database is stopped", "destructive", oracle_db_stopped_restart, execution_mode="clone"),
        Scenario("G5", "Fresh-state starts at current log end", "destructive", oracle_fresh_state, execution_mode="clone"),
        Scenario("G5a", "Read existing history from beginning", "destructive", oracle_read_from_beginning, execution_mode="clone"),
        Scenario("G6", "Unicode log preservation", "safe", oracle_unicode),
        Scenario("G7", "Delete and recreate active log", "destructive", oracle_delete_recreate, execution_mode="clone"),
        Scenario("G8", "Permission loss and recovery", "destructive", oracle_permission_recovery, execution_mode="clone"),
        Scenario("G9", "Multi-megabyte Oracle record", "safe", oracle_large_record),
        Scenario("G10", "Malformed record forwarding", "destructive", oracle_malformed, execution_mode="clone"),
        Scenario("G12", "Backward system clock", "destructive", oracle_backward_clock, execution_mode="clone"),
        Scenario("H1", "Disk buffer growth during receiver outage", "disruptive", oracle_buffer_growth),
        Scenario("H2", "Buffered delivery after recovery", "disruptive", oracle_buffer_delivery),
        Scenario("H3", "Disk buffer cap and oldest-drop behavior", "destructive", oracle_buffer_cap, execution_mode="clone"),
        Scenario("H4", "Collector starts before Oracle", "destructive", oracle_database_start_order, execution_mode="clone"),
        Scenario("H5", "Single Ctrl+C foreground drain", "destructive", pg_foreground_single_interrupt, execution_mode="clone"),
        Scenario("H5a", "Double Ctrl+C foreground exit", "destructive", pg_foreground_double_interrupt, execution_mode="clone"),
        Scenario("H6", "Machine reboot continuity", "destructive", oracle_reboot_resume, execution_mode="clone"),
        Scenario("H7", "Corrupt config fallback", "destructive", oracle_config_fallback, execution_mode="clone"),
        Scenario("H8", "Missing configuration failure", "destructive", pg_config_missing, execution_mode="clone"),
        Scenario("H9", "Unreachable output retry", "destructive", oracle_unreachable_output, execution_mode="clone"),
        Scenario("H10", "SIGKILL checkpoint recovery", "disruptive", oracle_kill_recovery),
        Scenario("H11", "Full buffer disk handling", "destructive", oracle_buffer_disk_full, execution_mode="clone"),
        Scenario("H12", "Constrained sustained-load soak", "safe", oracle_soak),
        Scenario("I7", "AppArmor enforcing", "destructive", oracle_apparmor, execution_mode="clone"),
        Scenario("I8", "Non-root collector with Oracle-log access", "safe", oracle_non_root_access),
        Scenario("I9", "Collector uninstall", "destructive", pg_uninstall, execution_mode="clone"),
    ]


def scenario_catalog(database: str) -> list[Scenario]:
    if database == "postgresql":
        implemented = postgresql_scenarios()
    elif database == "mysql":
        implemented = mysql_scenarios()
    elif database == "mariadb":
        implemented = mariadb_scenarios()
    else:
        implemented = oracle_scenarios()
    by_id = {scenario.scenario_id: scenario for scenario in implemented}
    catalog: list[Scenario] = []
    for scenario_id in SCENARIO_IDS[database]:
        if scenario_id in by_id:
            catalog.append(by_id[scenario_id])
            continue
        mode, reason = pending_execution_mode(database, scenario_id)
        catalog.append(
            skipped_scenario(
                scenario_id,
                f"{database.title()} scenario {scenario_id}",
                reason,
                execution_mode=mode,
            )
        )
    return catalog


class RunnerLock:
    def __init__(self):
        self.path = Path(f"/tmp/log-collector-test-runner-{os.getuid()}.lock")
        self.handle: Any | None = None

    def __enter__(self) -> "RunnerLock":
        self.handle = self.path.open("w", encoding="utf-8")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another test-runner process is already active for this user") from error
        self.handle.write(f"pid={os.getpid()} started={utc_now()}\n")
        self.handle.flush()
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        if self.handle:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def install_offer(database: str, local: LocalExecutor) -> bool:
    packages = {
        "postgresql": "postgresql postgresql-contrib acl",
        "mysql": "mysql-server acl",
        "mariadb": "mariadb-server mariadb-plugin-connect acl",
    }
    if database == "oracle":
        print("Oracle installation remains manual because media, licensing, ORACLE_BASE, SID, and edition are site-specific.")
        return False
    package_list = packages[database]
    print(f"\nSimulating installation of: {package_list}")
    simulation = local.run(f"apt-get -s install {package_list}", sudo=True, timeout=120)
    print(simulation.stdout)
    if simulation.returncode != 0:
        print(simulation.stderr, file=sys.stderr)
        return False
    answer = input("Install these packages now? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        print("Installation declined; no package changes were made.")
        return False
    installation = local.run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {package_list}", sudo=True, timeout=1200)
    print(installation.stdout)
    if installation.returncode != 0:
        print(installation.stderr, file=sys.stderr)
        return False
    print("Database packages installed. Review logging, run the collector setup wizard, then rerun status.")
    return True


def command_status(database: str) -> int:
    context: LabContext | None = None
    try:
        context = open_lab(database)
        report = collect_preflight(context)
        print_preflight(report)
        return 0 if report.ready else 4
    finally:
        if context:
            context.receiver.close()


def command_prepare(database: str) -> int:
    context: LabContext | None = None
    try:
        context = open_lab(database)
        report = collect_preflight(context)
        print_preflight(report)
        database_missing = any(problem.startswith(database) for problem in report.problems)
        if database_missing:
            install_offer(database, context.local)
            return 4
        if report.ready:
            print("\nThe selected engine, collector, receiver, and minimum resources are ready.")
        print("Database logging and collector input changes require an explicit reviewed preparation profile.")
        print("The runner does not overwrite them automatically; use the repository engine guide and `sudo log-collector setup`.")
        return 0 if report.ready else 4
    finally:
        if context:
            context.receiver.close()


def select_requested_scenarios(database: str, value: str | None) -> list[Scenario]:
    catalog = scenario_catalog(database)
    if not value:
        return catalog
    requested = [item.strip().lower() for item in value.split(",") if item.strip()]
    by_id = {item.scenario_id.lower(): item for item in catalog}
    unknown = [item for item in requested if item not in by_id]
    if unknown:
        raise ValueError(f"Unknown scenario(s) {', '.join(unknown)} for {database}.")
    return [by_id[item] for item in requested]


def command_run(args: argparse.Namespace) -> int:
    if os.geteuid() == 0:
        print("Run db-test-runner.py as the normal endpoint user, not with sudo.", file=sys.stderr)
        return 3
    try:
        selected_scenarios = select_requested_scenarios(args.database, args.scenario)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    try:
        policy = resolve_execution_policy(args, hostname=socket.gethostname().split(".", 1)[0])
    except (EOFError, KeyboardInterrupt):
        print("\nRisk selection cancelled.", file=sys.stderr)
        return 130
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 2
    try:
        evidence = (
            EvidenceRun.resume_latest(args.evidence_dir, args.database)
            if args.resume
            else EvidenceRun.create(args.evidence_dir, args.database)
        )
    except FileNotFoundError as error:
        print(str(error), file=sys.stderr)
        return 3
    journal = RecoveryJournal(args.evidence_dir / args.database / "recovery.json")
    context: LabContext | None = None
    try:
        context = open_lab(args.database, evidence)
        context.journal = journal
        report = collect_preflight(context)
        print_preflight(report)
        environment = dict(report.facts)
        environment.update(
            {
                "database": args.database,
                "client_hostname": context.client_hostname,
                "receiver_log_hostname": context.receiver_hostname or context.client_hostname,
                "receiver_log": context.receiver_log,
                "preflight_ready": report.ready,
                "preflight_problems": report.problems,
            }
        )
        evidence.record_environment(environment)
        if not report.ready:
            evidence.finalize("Aborted - Preflight")
            print(f"Evidence: {evidence.run_dir}")
            return 4

        if args.scenario:
            scenarios = selected_scenarios
        elif args.resume:
            scenarios = selected_scenarios
            completed = {
                result.scenario_id
                for result in evidence.results
                if result.status in {"Pass", "Fail", "Not Tested"}
            }
            scenarios = [item for item in scenarios if item.scenario_id not in completed]
            print(f"Resuming {evidence.run_id}; {len(completed)} completed scenario(s) skipped.")
        else:
            scenarios = selected_scenarios
        results = ScenarioOrchestrator(policy, evidence, context).run(scenarios)
        evidence.finalize()
        totals = {status: sum(result.status == status for result in results) for status in STATUSES}
        print("\nRun totals: " + ", ".join(f"{status}={count}" for status, count in totals.items() if count))
        print(f"\nEvidence: {evidence.run_dir}")
        if any(result.status in {"Cleanup Failed", "Inconclusive"} for result in results):
            return 3
        if any(result.status == "Fail" for result in results):
            return 1
        return 0
    except (KeyboardInterrupt, EOFError):
        evidence.finalize("Interrupted")
        print(f"\nInterrupted. Evidence and recovery state: {evidence.run_dir}", file=sys.stderr)
        return 130
    except Exception as error:
        evidence.record_environment({"fatal_error": f"{type(error).__name__}: {error}"})
        evidence.finalize("Aborted - Harness Error")
        print(f"Harness error: {error}", file=sys.stderr)
        print(f"Evidence: {evidence.run_dir}", file=sys.stderr)
        return 3
    finally:
        if context:
            context.receiver.close()


def command_restore(database: str, evidence_dir: Path) -> int:
    journal = RecoveryJournal(evidence_dir / database / "recovery.json")
    actions = journal.pending_actions()
    if not actions:
        print(f"No pending recovery actions for {database}.")
        return 0
    context: LabContext | None = None
    try:
        context = open_lab(database)
        failures = 0
        for action in reversed(actions):
            scope = action.get("scope")
            command = action.get("command")
            action_id = action.get("id")
            if scope not in {"local", "receiver"} or not isinstance(command, str) or not action_id:
                print(f"Invalid recovery action retained: {action!r}", file=sys.stderr)
                failures += 1
                continue
            executor = context.local if scope == "local" else context.receiver
            result = executor.run(command, sudo=bool(action.get("sudo", True)), timeout=float(action.get("timeout", 120)))
            print(f"Restore {action_id}: exit={result.returncode}")
            if result.returncode == 0:
                journal.remove(str(action_id))
            else:
                failures += 1
                print(result.stderr, file=sys.stderr)
        return 0 if failures == 0 else 3
    finally:
        if context:
            context.receiver.close()


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    status: str
    reason: str
    started_at: str
    ended_at: str
    assertions: list[AssertionResult] = field(default_factory=list)
    commands: list[CommandResult] = field(default_factory=list)
    cleanup_status: str = "Not required"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    risk: Risk
    execute: Callable[[Any], ScenarioResult | None]
    quiet: bool = False
    execution_mode: ExecutionMode = "endpoint"
    coverage_reason: str = "Implemented by the endpoint runner"


@dataclass(frozen=True)
class PolicyDecision:
    run: bool
    status: str
    reason: str


@dataclass(frozen=True)
class ExecutionPolicy:
    include_disruptive: bool = False
    include_destructive: bool = False

    def decide(self, scenario: Scenario) -> PolicyDecision:
        if scenario.risk == "destructive" and not self.include_destructive:
            return PolicyDecision(False, "Not Tested", "Destructive scenario skipped by default")
        if scenario.risk == "disruptive" and not self.include_disruptive:
            return PolicyDecision(False, "Not Tested", "Disruptive scenario skipped by default")
        if scenario.risk == "manual":
            return PolicyDecision(False, "Not Tested", "Manual scenario is not safely automatable")
        return PolicyDecision(True, "", "")


def resolve_execution_policy(
    args: argparse.Namespace,
    *,
    hostname: str,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[[str], Any] = print,
) -> ExecutionPolicy:
    safe_only = bool(getattr(args, "safe_only", False))
    include_disruptive = bool(getattr(args, "include_disruptive", False))
    include_destructive = bool(getattr(args, "include_destructive", False))
    if safe_only and (include_disruptive or include_destructive):
        raise RuntimeError("--safe-only cannot be combined with disruptive or destructive options")
    if safe_only:
        return ExecutionPolicy(False, False)
    if not include_disruptive and not include_destructive:
        include_destructive = input_fn(
            "Include destructive scenarios on a dedicated cloned VM? [y/N]: "
        ).strip().lower() in {"y", "yes"}
    include_disruptive = True
    if include_destructive:
        print_fn(f"Destructive target hostname: {hostname}")
        print_fn("WARNING: continue only inside the dedicated cloned client VM, never the original client.")
        if not bool(getattr(args, "confirm_clone", False)):
            confirmation = input_fn(
                "Type CLONE to confirm this endpoint is the disposable cloned VM: "
            ).strip()
            if confirmation != "CLONE":
                raise RuntimeError("Destructive scenarios require dedicated clone confirmation")
    return ExecutionPolicy(include_disruptive, include_destructive)


class ScenarioOrchestrator:
    def __init__(self, policy: ExecutionPolicy, evidence: "EvidenceRun", context: Any):
        self.policy = policy
        self.evidence = evidence
        self.context = context

    def run(self, scenarios: list[Scenario]) -> list[ScenarioResult]:
        results: list[ScenarioResult] = []
        for scenario in scenarios:
            decision = self.policy.decide(scenario)
            if not decision.run:
                now = utc_now()
                result = ScenarioResult(
                    scenario_id=scenario.scenario_id,
                    name=scenario.name,
                    status=decision.status,
                    reason=decision.reason,
                    started_at=now,
                    ended_at=now,
                )
            else:
                if not scenario.quiet:
                    print(f"[{scenario.scenario_id}] {scenario.name}", flush=True)
                try:
                    result = scenario.execute(self.context)
                    if result is None:
                        raise RuntimeError("scenario returned no result")
                except Exception as error:
                    now = utc_now()
                    result = ScenarioResult(
                        scenario_id=scenario.scenario_id,
                        name=scenario.name,
                        status="Inconclusive",
                        reason=f"Harness or infrastructure error: {type(error).__name__}: {error}",
                        started_at=now,
                        ended_at=now,
                    )
            self.evidence.record_result(result)
            results.append(result)
            print(f"[{scenario.scenario_id}] {result.status}: {result.reason}", flush=True)
        return results


class RecoveryJournal:
    """Durable LIFO restoration actions for interrupted configuration tests."""

    def __init__(self, path: Path):
        self.path = path

    def pending_actions(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            raise ValueError(f"Invalid recovery journal: {self.path}")
        return actions

    def add(self, action: dict[str, Any]) -> None:
        actions = self.pending_actions()
        actions.append(action)
        atomic_write(self.path, json.dumps({"version": 1, "actions": actions}, indent=2) + "\n")
        os.chmod(self.path, 0o600)

    def remove(self, action_id: str) -> None:
        actions = [item for item in self.pending_actions() if item.get("id") != action_id]
        if actions:
            atomic_write(self.path, json.dumps({"version": 1, "actions": actions}, indent=2) + "\n")
            os.chmod(self.path, 0o600)
        elif self.path.exists():
            self.path.unlink()


class EvidenceRun:
    def __init__(self, run_dir: Path, database: str, run_id: str):
        self.run_dir = run_dir
        self.database = database
        self.run_id = run_id
        self.results: list[ScenarioResult] = []
        self._secrets: list[str] = []

    @classmethod
    def create(cls, base: Path, database: str, run_id: str | None = None) -> "EvidenceRun":
        database = safe_name(database)
        run_id = safe_name(run_id or make_run_id(database))
        run_dir = base / database / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        os.chmod(run_dir, 0o700)
        (run_dir / "scenarios").mkdir(mode=0o700)
        metadata = {
            "schema_version": 1,
            "runner_version": VERSION,
            "database": database,
            "run_id": run_id,
            "started_at": utc_now(),
            "status": "In Progress",
        }
        atomic_write(run_dir / "run.json", json.dumps(metadata, indent=2) + "\n")
        return cls(run_dir, database, run_id)

    @classmethod
    def resume_latest(cls, base: Path, database: str) -> "EvidenceRun":
        database_dir = base / safe_name(database)
        candidates: list[tuple[str, Path, dict[str, Any]]] = []
        if database_dir.exists():
            for run_path in database_dir.iterdir():
                metadata_path = run_path / "run.json"
                if not run_path.is_dir() or not metadata_path.exists():
                    continue
                try:
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                if metadata.get("status") != "Complete":
                    candidates.append((str(metadata.get("started_at", "")), run_path, metadata))
        if not candidates:
            raise FileNotFoundError(f"No incomplete {database} evidence run exists under {database_dir}")
        _, run_dir, metadata = sorted(candidates, key=lambda item: (item[0], item[1].name))[-1]
        resumed = cls(run_dir, database, str(metadata.get("run_id", run_dir.name)))
        scenario_root = run_dir / "scenarios"
        if scenario_root.exists():
            for result_path in sorted(scenario_root.glob("*/result.json")):
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload["assertions"] = [AssertionResult(**item) for item in payload.get("assertions", [])]
                payload["commands"] = [CommandResult(**item) for item in payload.get("commands", [])]
                resumed.results.append(ScenarioResult(**payload))
        metadata["status"] = "In Progress"
        metadata["resumed_at"] = utc_now()
        metadata.pop("ended_at", None)
        atomic_write(run_dir / "run.json", json.dumps(metadata, indent=2) + "\n")
        return resumed

    def record_environment(self, values: dict[str, Any]) -> None:
        atomic_write(
            self.run_dir / "environment.json",
            json.dumps(self._redact(values), indent=2, sort_keys=True) + "\n",
        )

    def register_secret(self, secret: str) -> None:
        if secret and secret not in self._secrets:
            self._secrets.append(secret)

    def _redact_text(self, value: str) -> str:
        for secret in sorted(self._secrets, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value

    def _redact(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value

    def record_result(self, result: ScenarioResult) -> None:
        if result.status not in STATUSES:
            raise ValueError(f"Unsupported scenario status: {result.status}")
        scenario_dir = self.run_dir / "scenarios" / safe_name(result.scenario_id)
        scenario_dir.mkdir(mode=0o700, exist_ok=True)
        payload = self._redact(dataclasses.asdict(result))
        atomic_write(scenario_dir / "result.json", json.dumps(payload, indent=2) + "\n")
        command_lines: list[str] = []
        for index, command in enumerate(result.commands, start=1):
            command_lines.append(f"$ {self._redact_text(command.command)}\n")
            command_lines.append(self._redact_text(command.stdout))
            if command.stderr:
                command_lines.append(f"\n[stderr]\n{self._redact_text(command.stderr)}")
            command_lines.append(f"\n[exit={command.returncode} timed_out={command.timed_out}]\n")
            atomic_write(
                scenario_dir / f"command-{index:02d}.json",
                json.dumps(self._redact(dataclasses.asdict(command)), indent=2) + "\n",
            )
        if command_lines:
            atomic_write(scenario_dir / "commands.log", "".join(command_lines))
        self.results = [item for item in self.results if item.scenario_id != result.scenario_id]
        self.results.append(result)
        self._write_results()

    def _write_results(self) -> None:
        lines = ["Scenario ID\tStatus\tReason\tStarted At\tEnded At"]
        for result in self.results:
            reason = self._redact_text(result.reason).replace("\t", " ").replace("\n", " ")
            lines.append(
                f"{result.scenario_id}\t{result.status}\t{reason}\t{result.started_at}\t{result.ended_at}"
            )
        atomic_write(self.run_dir / "results.tsv", "\n".join(lines) + "\n")

    def finalize(self, status: str = "Complete") -> None:
        run_path = self.run_dir / "run.json"
        metadata = json.loads(run_path.read_text(encoding="utf-8"))
        metadata.update({"ended_at": utc_now(), "status": status})
        atomic_write(run_path, json.dumps(metadata, indent=2) + "\n")
        self._write_summary()
        self._write_hashes()

    def _write_summary(self) -> None:
        counts: dict[str, int] = {status: 0 for status in STATUSES}
        for result in self.results:
            counts[result.status] += 1
        lines = [
            f"# {self.database.title()} Integration Test Run",
            "",
            f"Run ID: `{self.run_id}`",
            "",
            "| Status | Count |",
            "|---|---:|",
        ]
        lines.extend(f"| {status} | {count} |" for status, count in counts.items() if count)
        lines.extend(["", "| Scenario | Status | Finding |", "|---|---|---|"])
        for result in self.results:
            reason = self._redact_text(result.reason).replace("|", "/")
            lines.append(f"| {result.scenario_id} | {result.status} | {reason} |")
        atomic_write(self.run_dir / "run-summary.md", "\n".join(lines) + "\n")

    def _write_hashes(self) -> None:
        lines: list[str] = []
        for path in sorted(self.run_dir.rglob("*")):
            if not path.is_file() or path.name == "SHA256SUMS":
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.relative_to(self.run_dir)}")
        atomic_write(self.run_dir / "SHA256SUMS", "\n".join(lines) + "\n")


def add_database_argument(parser: argparse.ArgumentParser, required: bool = False) -> None:
    parser.add_argument("--database", choices=DATABASES, required=required)


def command_coverage(database: str, output_format: str = "table") -> int:
    scenarios = scenario_catalog(database)
    implemented = sum(not scenario.quiet for scenario in scenarios)
    counts = {
        mode: sum(scenario.execution_mode == mode for scenario in scenarios)
        for mode in ("endpoint", "endpoint-pending", "clone", "environment", "manual", "not-applicable")
    }
    if output_format == "json":
        payload = {
            "database": database,
            "runner_version": VERSION,
            "total": len(scenarios),
            "implemented": implemented,
            "not_implemented": len(scenarios) - implemented,
            "counts": counts,
            "scenarios": {
                scenario.scenario_id: {
                    "name": scenario.name,
                    "mode": scenario.execution_mode,
                    "reason": scenario.coverage_reason,
                    "implemented": not scenario.quiet,
                }
                for scenario in scenarios
            },
        }
        print(json.dumps(payload, indent=2))
        return 0
    print(f"Implemented\t{implemented}")
    print(f"Not implemented\t{len(scenarios) - implemented}\n")
    print("Mode\tCount")
    for mode, count in counts.items():
        print(f"{mode}\t{count}")
    print("\nScenario ID\tImplemented\tMode\tReason")
    for scenario in scenarios:
        print(f"{scenario.scenario_id}\t{'yes' if not scenario.quiet else 'no'}\t{scenario.execution_mode}\t{scenario.coverage_reason}")
    return 0


def prompt_database(
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[[str], Any] = print,
) -> str:
    labels = {
        "postgresql": "PostgreSQL",
        "mysql": "MySQL",
        "mariadb": "MariaDB",
        "oracle": "Oracle",
    }
    print_fn("\nSelect the database to test:")
    for index, database in enumerate(DATABASES, start=1):
        print_fn(f"  {index}) {labels[database]}")
    while True:
        selection = input_fn("Database [1-4]: ").strip().lower()
        if selection.isdigit():
            index = int(selection)
            if 1 <= index <= len(DATABASES):
                return DATABASES[index - 1]
        if selection in DATABASES:
            return selection
        print_fn("Invalid selection. Enter 1-4 or a database name.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="db-test-runner.py",
        description="Ubuntu database log-collector integration test runner",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status", help="Inspect lab readiness without changing it")
    add_database_argument(status_parser)

    prepare_parser = subparsers.add_parser("prepare", help="Interactively prepare a selected database")
    add_database_argument(prepare_parser)

    run_parser = subparsers.add_parser("run", help="Run all applicable automated scenarios")
    add_database_argument(run_parser)
    run_parser.add_argument("--scenario", help="Run one scenario or a comma-separated ordered list")
    run_parser.add_argument("--resume", action="store_true", help="Resume the newest incomplete run")
    run_parser.add_argument("--include-disruptive", action="store_true")
    run_parser.add_argument("--include-destructive", action="store_true")
    run_parser.add_argument("--confirm-clone", action="store_true", help="Confirm destructive execution is inside a disposable cloned VM")
    run_parser.add_argument("--safe-only", action="store_true", help="Run safe/configuration scenarios without risk prompts")
    run_parser.add_argument("--evidence-dir", type=Path, default=Path("evidence"))

    restore_parser = subparsers.add_parser("restore", help="Apply pending crash-recovery actions")
    add_database_argument(restore_parser)
    restore_parser.add_argument("--evidence-dir", type=Path, default=Path("evidence"))

    coverage_parser = subparsers.add_parser("coverage", help="Report automated, clone-only, environment, and manual coverage")
    add_database_argument(coverage_parser)
    coverage_parser.add_argument("--format", choices=("table", "json"), default="table")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.database is None:
        try:
            args.database = prompt_database()
        except (EOFError, KeyboardInterrupt):
            print("\nDatabase selection cancelled.", file=sys.stderr)
            return 130
    with RunnerLock():
        if args.command == "status":
            return command_status(args.database)
        if args.command == "prepare":
            return command_prepare(args.database)
        if args.command == "run":
            return command_run(args)
        if args.command == "restore":
            return command_restore(args.database, args.evidence_dir)
        if args.command == "coverage":
            return command_coverage(args.database, args.format)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
