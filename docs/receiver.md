# Log Collector Receiver

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/retyingfct/setup/main/receiver.sh | sudo bash
```

The installer supports Ubuntu and Debian receivers. It installs the required packages and prompts for the bind address, RELP port, log directory, retention, queue limits, and UFW rule.

## Persistence

The receiver configuration persists across restarts:

- `rsyslog` is enabled to start automatically.
- The RELP listener configuration is stored in `/etc/rsyslog.d/10-log-collector-relp.conf`.
- Log rotation is stored in `/etc/logrotate.d/log-collector-clients`.
- UFW rules persist when UFW is enabled.
- The disk-assisted queue is saved under `/var/spool/rsyslog` and retained during a clean shutdown.
- Received logs remain under `/var/log/clients` by default.

An abrupt power loss can still lose events that have not reached disk. Clients reconnect and replay unacknowledged RELP events after the receiver returns.

## Default settings

| Setting | Default |
|---|---|
| Bind address | All interfaces (`0.0.0.0`) |
| RELP port | `2514/tcp` |
| Log directory | `/var/log/clients` |
| Retention | 14 daily rotations |
| Queue | 50,000 events |
| Queue disk limit | 256 MB |

Received events are stored as:

```text
/var/log/clients/<hostname>/<source>.log
```

## Verify

```bash
sudo rsyslogd -N1
sudo systemctl is-active rsyslog
sudo ss -lntp | grep ':2514'
```

From a Linux client:

```bash
nc -zv <receiver-ip> 2514
```

From Windows PowerShell:

```powershell
Test-NetConnection <receiver-ip> -Port 2514
```

Copyright © Forensic CyberTech Pvt. Ltd.
