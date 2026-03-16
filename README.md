# SOC Project

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)

A Security Operations Center project built as part of a master's in cybersecurity. It covers log parsing, alert detection, threat intelligence lookups and incident response.

---

## What this project does

```mermaid
flowchart LR
    A[Log files] --> B[Log Parser]
    B --> C[Parsed JSON]
    C --> D[Alert Engine]
    D --> E{Match?}
    E -- Yes --> F[Alert + MITRE tag]
    E -- No --> G[Skip]
    F --> H[Dashboard]
    F --> I[Threat Intel Check]
    I --> J[AbuseIPDB]
```

---

## Project structure

```
soc-project/
├── soc/
│   ├── log-parser/
│   │   ├── parser.py        # Parses syslog, apache and auth logs
│   │   └── sample.log       # Sample log file for testing
│   ├── alert-rules/
│   │   ├── rules.yaml       # Detection rules with MITRE ATT&CK mapping
│   │   ├── alert_engine.py  # Runs logs against the rules
│   │   └── threat_intel.py  # Checks IPs against AbuseIPDB
│   ├── dashboard/
│   │   └── dashboard.py     # Terminal dashboard
│   └── incident-response/
│       └── playbook.md      # IR playbook per incident type
├── tests/
│   ├── test_parser.py
│   └── test_alert_engine.py
├── requirements.txt
├── CONTRIBUTING.md
└── CHANGELOG.md
```

---

## How it works

### 1. Parse logs

```bash
python soc/log-parser/parser.py --file soc/log-parser/sample.log --output parsed.json
```

The parser reads the log file line by line and figures out what type each line is — SSH auth, Apache access log, or general syslog. It flags anything suspicious.

### 2. Run alerts

```bash
python soc/alert-rules/alert_engine.py --logs parsed.json --rules soc/alert-rules/rules.yaml
```

The alert engine checks each parsed log entry against the rules in `rules.yaml`. When a rule matches it prints an alert with the severity level and MITRE ATT&CK technique ID.

### 3. Check threat intel

```bash
python soc/alert-rules/threat_intel.py --logs parsed.json
```

This pulls unique IPs from the parsed logs and checks each one against AbuseIPDB. It shows a confidence score and abuse category for any known bad IPs.

> You need a free AbuseIPDB API key. Get one at https://www.abuseipdb.com/register and set it as an environment variable: `export ABUSEIPDB_KEY=your_key_here`

### 4. View dashboard

```bash
python soc/dashboard/dashboard.py --logs parsed.json
```

---

## Alert example

```
[HIGH] Brute Force SSH (RULE-001)
  MITRE ATT&CK : T1110 – Brute Force
  Action       : alert
  Log entry    : Failed password for root from 192.168.1.100 port 22

[MEDIUM] Invalid User Login (RULE-002)
  MITRE ATT&CK : T1078 – Valid Accounts
  Action       : alert
  Log entry    : Invalid user admin from 192.168.1.100
```

---

## MITRE ATT&CK coverage

```mermaid
mindmap
  root((MITRE ATT&CK))
    Credential Access
      T1110 Brute Force
      T1078 Valid Accounts
    Initial Access
      T1190 Exploit Public App
    Execution
      T1059 Command and Scripting
    Discovery
      T1046 Network Service Scan
    Impact
      T1498 Network DoS
```

---

## Alert severity breakdown (sample run)

```mermaid
pie title Alert Severity Distribution
    "High" : 35
    "Medium" : 45
    "Low" : 20
```

---

## How the detection pipeline runs

```mermaid
sequenceDiagram
    participant Logs
    participant Parser
    participant Engine
    participant ThreatIntel
    participant Analyst

    Logs->>Parser: Raw log lines
    Parser->>Engine: Parsed JSON entries
    Engine->>Engine: Match against rules
    Engine->>ThreatIntel: Source IP lookup
    ThreatIntel->>Engine: Abuse score + category
    Engine->>Analyst: Alert with severity + MITRE tag
```

---

## Setup

```bash
git clone https://github.com/Speed-boo3/soc-project.git
cd soc-project
pip install -r requirements.txt
export ABUSEIPDB_KEY=your_key_here
```

---

## Running the tests

```bash
pytest tests/
```

---

## Related project

The GRC side of this work lives in a separate repo: [grc-project](https://github.com/Speed-boo3/grc-project)

SOC detects threats. GRC makes sure the controls are in place to prevent them. The two feed each other.
