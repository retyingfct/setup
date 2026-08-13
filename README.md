# Setup Scripts

## Log Collector Receiver

```bash
curl -fsSL https://raw.githubusercontent.com/retyingfct/setup/main/receiver.sh | sudo bash
```

## Database Test Runner

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/retyingfct/setup/main/db-test-runner.py) run
```

## Windows Database Test Runner

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/retyingfct/setup/main/windows-db-test-runner.py) run --database postgresql
```

Copyright © Forensic CyberTech Pvt. Ltd.
