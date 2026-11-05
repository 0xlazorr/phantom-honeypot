# Phantom Honeypot 🕸️🐍

A high-performance, asynchronous **Multi-Protocol Threat Deception & Intelligence Sensor** built in **Python** with **Asyncio**.

Simulates vulnerable services (SSH, Redis, HTTP web apps) across non-privileged ports to lure, capture, log, and analyze attacker reconnaissance, automated brute-force attacks, and remote exploit payloads in real time.

---

## 🏛️ Architecture & Traps

```text
Attacker / Automated Scanner (Internet or Internal Subnet)
                │
                ├──► [ Port 2222: SSH Trap ] ── (Captures SSH client banner & credential pairs)
                │
                ├──► [ Port 6379: Redis Trap ] ── (Intercepts CONFIG, SLAVEOF, RCE attempts)
                │
                └──► [ Port 8080: Web Trap ] ── (Lures scanners probing /.env, .git, Log4j, SQLi)
                            │
                            ▼
                [ Threat Intelligence Engine ] (IOC Extraction, JSON telemetry & terminal alerts)
```

---

## 🌟 Key Features

- **Asynchronous Concurrent Traps**: Emulates multiple network service state machines simultaneously with low memory consumption.
- **SSH Credential Harvester**: Records client software versions (`OpenSSH`, `Paramiko`, etc.) and credentials used during brute-force campaigns.
- **In-Memory Redis Deception**: Responds with valid Redis protocol tokens (`+OK`, `+PONG`) to lure attackers into revealing their full post-exploitation command chains.
- **Web Exploit & Recon Hunter**: Flags directory traversal, secret hunting (`.env`, `.aws/credentials`), Spring4Shell, and Log4j injection strings (`${jndi:ldap:...}`).
- **Real-Time Threat Telemetry**: Emits structured JSON events and terminal rich tables suitable for SIEM forwarding.

---

## 📂 Project Structure

```text
phantom-honeypot/
├── pyproject.toml         # Packaging
├── requirements.txt       # Dependencies
├── phantom/
│   ├── __init__.py        # Public API
│   ├── ssh_trap.py        # Asynchronous fake SSH service
│   ├── redis_trap.py      # Fake Redis server & command logger
│   ├── http_trap.py       # Vulnerable HTTP honeytrap
│   ├── logger.py          # Threat event serializer & JSON exporter
│   └── cli.py             # Multi-trap server runner
├── examples/
│   └── run_all_traps.py   # Standalone launcher
└── README.md
```

---

## 🚀 Quickstart

### Start All Honeypot Traps:
```bash
python3 -m phantom.cli start --traps ssh,redis,http
```

### Test Interaction:
```bash
# In another terminal:
curl http://localhost:8080/.env
redis-cli -p 6380 PING
```

---

## 📜 License
MIT License • Engineered by [Lazarus Ebi](https://github.com/0xlazorr)
