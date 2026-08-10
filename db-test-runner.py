#!/usr/bin/env python3
"""Interactive Ubuntu database log-collector integration test runner.

Run this program as the normal endpoint user. It elevates individual local
commands with sudo and connects to the receiver using password-authenticated
SSH. Credentials are held in memory and are never written to evidence.
"""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import getpass
import hashlib
import importlib
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


VERSION = "0.1.2-draft"
DATABASES = ("postgresql", "mysql", "mariadb", "oracle")
STATUSES = ("Pass", "Fail", "Not Tested", "Inconclusive", "Cleanup Failed")
Risk = Literal["safe", "configuration", "disruptive", "destructive", "manual"]
LAB_STABILITY_MINUTES = 5
LAB_OUTAGE_MINUTES = 5
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
    evidence: "EvidenceRun | None" = None
    journal: "RecoveryJournal | None" = None

    @property
    def receiver_log(self) -> str:
        source = RECEIVER_SOURCES[self.database]
        return f"/var/log/clients/{self.client_hostname}/{source}"

    @property
    def receiver_client_dir(self) -> str:
        return f"/var/log/clients/{self.client_hostname}"

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
    if evidence:
        evidence.register_secret(config.password)
        evidence.register_secret(config.sudo_password or "")
    return LabContext(database, local, receiver, hostname.stdout.strip(), evidence=evidence)


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
        f"systemd-run --unit={unit} --on-active={LAB_OUTAGE_MINUTES + 1}m /bin/systemctl start rsyslog", sudo=True, timeout=30
    )
    commands.append(schedule)
    if context.journal:
        context.journal.add({"id": recovery_id, "scope": "receiver", "command": "systemctl start rsyslog", "sudo": True, "timeout": 60})
    initial = context.local.run(
        "printf 'pid=%s restarts=%s\\n' \"$(systemctl show -p MainPID --value log-collector)\" \"$(systemctl show -p NRestarts --value log-collector)\"",
        timeout=15,
    )
    commands.append(initial)
    stop = context.receiver.run("systemctl stop rsyslog", sudo=True, timeout=30)
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
        restore = context.receiver.run("systemctl start rsyslog", sudo=True, timeout=60)
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


def pg_password_redaction(context: LabContext) -> ScenarioResult:
    started = utc_now()
    token = secrets.token_hex(6)
    role = f"lc_g1_{secrets.token_hex(4)}"
    secret = f"LcTest-{token}!"
    if context.evidence:
        context.evidence.register_secret(secret)
    create_sql = f"CREATE ROLE {role} LOGIN PASSWORD '{secret}';"
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
    return evaluated_result("G1", "Password redaction", started, commands, assertions, "Disposable password was redacted while the role DDL remained visible", "Passed" if cleanup.returncode == 0 else "Failed")


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


def skipped_scenario(scenario_id: str, name: str, reason: str, risk: Risk = "manual") -> Scenario:
    def execute(_context: LabContext) -> ScenarioResult:
        now = utc_now()
        return ScenarioResult(scenario_id, name, "Not Tested", reason, now, now)

    effective_risk: Risk = "safe" if risk == "manual" else risk
    return Scenario(scenario_id, name, effective_risk, execute, quiet=True)


def postgresql_scenarios() -> list[Scenario]:
    implemented = [
        Scenario("C1", "PostgreSQL discovery and log access", "safe", pg_setup_checks),
        Scenario("B1", "Basic PostgreSQL collection", "safe", pg_basic_delivery),
        Scenario("B2", "Stable source identifier", "safe", pg_source_identity),
        Scenario("B3", "Service restart and checkpoint", "configuration", pg_restart_checkpoint),
        Scenario("B4", "Constrained-lab stability window", "safe", pg_stability),
        Scenario("B5", "Constrained-lab receiver outage", "disruptive", pg_receiver_outage),
        Scenario("B6", "Unique event identifiers", "safe", pg_unique_event_ids),
        Scenario("B7", "Native timestamp preservation", "safe", pg_timestamp),
        Scenario("C2", "Failed login severity", "safe", pg_failed_login),
        Scenario("C2c", "Connection and disconnection logging", "safe", pg_connection_lifecycle),
        Scenario("C2d", "Role DDL security events", "safe", pg_role_ddl),
        Scenario("C2f", "Permission-denied error severity", "safe", pg_permission_denied),
        Scenario("C7", "Deadlock and ordinary DDL", "safe", pg_deadlock),
        Scenario("C7a", "Statement and lock timeouts", "safe", pg_timeouts),
        Scenario("C7b", "Backend termination", "safe", pg_backend_termination),
        Scenario("C7c", "Autovacuum and checkpoint volume", "configuration", pg_maintenance_events),
        Scenario("C7d", "PostgreSQL restart survival", "disruptive", pg_database_restart),
        Scenario("G1", "Password redaction", "safe", pg_password_redaction),
        Scenario("G2", "Username preservation", "safe", pg_username_preservation),
        Scenario("C5", "Forced log rotation", "configuration", pg_forced_rotation),
        Scenario("C5a", "Size-based rotation continuity", "configuration", pg_size_rotation),
        Scenario("G3", "Cross-engine rotation continuity", "configuration", pg_cross_engine_rotation),
    ]
    deferred = [
        skipped_scenario("C2e", "PANIC-level event", "Requires a disposable corruptible cluster", "destructive"),
        skipped_scenario("C7e", "Disk or global connection exhaustion", "Unsafe on the constrained shared endpoint", "destructive"),
        skipped_scenario("C1b", "RHEL discovery layout", "Not applicable to Ubuntu"),
        skipped_scenario("C5b", "RHEL weekly ring truncation", "Not applicable to the active Ubuntu layout"),
        skipped_scenario("C8", "pgaudit structured events", "Requires optional pgaudit installation and explicit approval"),
    ]
    return implemented + deferred


def scenario_catalog(database: str) -> list[Scenario]:
    implemented = postgresql_scenarios() if database == "postgresql" else []
    by_id = {scenario.scenario_id: scenario for scenario in implemented}
    return [
        by_id.get(
            scenario_id,
            skipped_scenario(
                scenario_id,
                f"{database.title()} scenario {scenario_id}",
                f"Scenario is catalogued but not safely automated in draft {VERSION}",
            ),
        )
        for scenario_id in SCENARIO_IDS[database]
    ]


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
        print("This draft does not overwrite them automatically; use the repository engine guide and `sudo log-collector setup`.")
        return 0 if report.ready else 4
    finally:
        if context:
            context.receiver.close()


def command_run(args: argparse.Namespace) -> int:
    if os.geteuid() == 0:
        print("Run db-test-runner.py as the normal endpoint user, not with sudo.", file=sys.stderr)
        return 3
    if args.scenario and args.scenario.lower() not in {
        item.scenario_id.lower() for item in scenario_catalog(args.database)
    }:
        print(f"Unknown scenario {args.scenario!r} for {args.database}.", file=sys.stderr)
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

        scenarios = scenario_catalog(args.database)
        if args.scenario:
            scenarios = [item for item in scenarios if item.scenario_id.lower() == args.scenario.lower()]
            if not scenarios:
                evidence.finalize("Aborted - Unknown Scenario")
                print(f"Unknown scenario {args.scenario!r} for {args.database}.", file=sys.stderr)
                return 2
        elif args.resume:
            completed = {
                result.scenario_id
                for result in evidence.results
                if result.status in {"Pass", "Fail", "Not Tested"}
            }
            scenarios = [item for item in scenarios if item.scenario_id not in completed]
            print(f"Resuming {evidence.run_id}; {len(completed)} completed scenario(s) skipped.")
        policy = ExecutionPolicy(args.include_disruptive, args.include_destructive)
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
            if not scenario.quiet:
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
    run_parser.add_argument("--scenario", help="Run one scenario for reproduction")
    run_parser.add_argument("--resume", action="store_true", help="Resume the newest incomplete run")
    run_parser.add_argument("--include-disruptive", action="store_true")
    run_parser.add_argument("--include-destructive", action="store_true")
    run_parser.add_argument("--evidence-dir", type=Path, default=Path("evidence"))

    restore_parser = subparsers.add_parser("restore", help="Apply pending crash-recovery actions")
    add_database_argument(restore_parser)
    restore_parser.add_argument("--evidence-dir", type=Path, default=Path("evidence"))
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
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
