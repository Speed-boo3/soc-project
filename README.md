<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a0000,100:ff0000&height=180&section=header&text=SOC%20Project&fontSize=55&fontColor=ff4444&animation=fadeIn&fontAlignY=45&desc=Log%20Analysis%20%7C%20Alert%20Detection%20%7C%20MITRE%20ATT%26CK%20%7C%20Threat%20Intelligence&descAlignY=68&descColor=ffffff&descSize=14"/>

</div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-0d1117?style=for-the-badge&logo=python&logoColor=00ff41)
![License](https://img.shields.io/badge/License-MIT-0d1117?style=for-the-badge&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-11%20passing-0d1117?style=for-the-badge&logo=pytest&logoColor=00ff41)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-0d1117?style=for-the-badge&logoColor=ff4444)
![AbuseIPDB](https://img.shields.io/badge/Threat%20Intel-AbuseIPDB-0d1117?style=for-the-badge&logoColor=ff9900)

</div>

---

Raw logs go in. Structured alerts with MITRE ATT&CK tags and live threat intelligence scores come out.

Built to understand how a real alert pipeline works from the ground up — not just point a SIEM at logs and hope for the best.

---

## Pipeline overview

```mermaid
flowchart TD
    A[Raw Log File] --> B[Log Parser]
    B --> C{Log type?}
    C -->|SSH and Auth| D[Auth Entry]
    C -->|Apache| E[Web Entry]
    C -->|Syslog| F[System Entry]
    D & E & F --> G[Parsed JSON]
    G --> H[Alert Engine]
    H --> I{Rule match?}
    I -->|Yes| J[Alert fired]
    I -->|No| K[Skipped]
    J --> L[MITRE ATT&CK tag]
    J --> M[Threat Intel lookup]
    M --> N[AbuseIPDB score]
    L & N --> O[Terminal Dashboard]

    style A fill:#1a0a0a,color:#ff6666,stroke:#ff4444
    style J fill:#1a0000,color:#ff4444,stroke:#ff0000
    style G fill:#0a1a0a,color:#00ff41,stroke:#00cc33
    style O fill:#0a0a1a,color:#4499ff,stroke:#2277dd
```

---

## Components

| Component | File | What it does |
|---|---|---|
| Log Parser | `soc/log-parser/parser.py` | Reads logs line by line, detects type, flags suspicious entries |
| Alert Engine | `soc/alert-rules/alert_engine.py` | Matches parsed entries against detection rules |
| Detection Rules | `soc/alert-rules/rules.yaml` | YAML rules with MITRE ATT&CK technique mapping |
| Threat Intel | `soc/alert-rules/threat_intel.py` | Checks source IPs against AbuseIPDB in real time |
| Dashboard | `soc/dashboard/dashboard.py` | Terminal overview of log stats and recent alerts |
| IR Playbook | `soc/incident-response/playbook.md` | Step-by-step response per incident type |

---

## MITRE ATT&CK coverage

Each rule is mapped to a technique so every alert tells you not just what happened but how it fits into a real attack pattern.

| Rule | Name | Severity | Technique | Tactic |
|---|---|---|---|---|
| RULE-001 | Brute Force SSH | High | T1110 | Credential Access |
| RULE-002 | Invalid User Login | Medium | T1078 | Initial Access |
| RULE-003 | Sudo Auth Failure | Medium | T1078 | Privilege Escalation |
| RULE-004 | HTTP Credential Stuffing | High | T1110.004 | Credential Access |
| RULE-005 | Admin Path Access | Low | T1190 | Initial Access |
| RULE-006 | Segfault Detected | Medium | T1203 | Execution |

```mermaid
flowchart LR
    subgraph CA[Credential Access]
        T1110[T1110 Brute Force]
        T1110b[T1110.004 Credential Stuffing]
    end
    subgraph IA[Initial Access]
        T1078[T1078 Valid Accounts]
        T1190[T1190 Exploit Public App]
    end
    subgraph PE[Privilege Escalation]
        T1078b[T1078 Valid Accounts]
    end
    subgraph EX[Execution]
        T1203[T1203 Client Exploitation]
    end

    R1[RULE-001] --> T1110
    R4[RULE-004] --> T1110b
    R2[RULE-002] --> T1078
    R5[RULE-005] --> T1190
    R3[RULE-003] --> T1078b
    R6[RULE-006] --> T1203

    style CA fill:#1a0000,stroke:#ff4444,color:#ff8888
    style IA fill:#1a1000,stroke:#ffaa00,color:#ffcc66
    style PE fill:#001a00,stroke:#00ff41,color:#66ff88
    style EX fill:#00001a,stroke:#4488ff,color:#88aaff
```

---

## Alert severity distribution

```mermaid
pie title Alert Severity Distribution
    "High"   : 35
    "Medium" : 45
    "Low"    : 20
```

---

## Full detection sequence

```mermaid
sequenceDiagram
    participant Log as Log File
    participant Parser as Log Parser
    participant Engine as Alert Engine
    participant Intel as Threat Intel
    participant Analyst as Analyst

    Log->>Parser: Raw log lines
    Parser->>Parser: Detect type and flag suspicious
    Parser->>Engine: Parsed JSON entries
    Engine->>Engine: Match against rules.yaml
    Engine->>Intel: Source IP address
    Intel->>Intel: AbuseIPDB lookup
    Intel->>Engine: Abuse confidence score
    Engine->>Analyst: Alert with severity, MITRE tag and IP score
```

---

## Alert output example

```
3 alert(s) triggered:

[HIGH] Brute Force SSH (RULE-001)
  MITRE ATT&CK : T1110 - Brute Force (Credential Access)
  Action       : alert
  Log entry    : Failed password for root from 192.168.1.100 port 22

[HIGH] HTTP Credential Stuffing (RULE-004)
  MITRE ATT&CK : T1110.004 - Credential Stuffing (Credential Access)
  Action       : alert
  Log entry    : POST /login HTTP/1.1

[MEDIUM] Invalid User Login (RULE-002)
  MITRE ATT&CK : T1078 - Valid Accounts (Initial Access)
  Action       : alert
  Log entry    : Invalid user admin from 192.168.1.100
```

---

## Project structure

```
soc-project/
├── soc/
│   ├── log-parser/
│   │   ├── parser.py           <- parses syslog, apache, auth logs
│   │   └── sample.log          <- sample log file for testing
│   ├── alert-rules/
│   │   ├── rules.yaml          <- detection rules with MITRE mapping
│   │   ├── alert_engine.py     <- runs logs against the rules
│   │   └── threat_intel.py     <- AbuseIPDB IP reputation lookup
│   ├── dashboard/
│   │   └── dashboard.py        <- terminal dashboard
│   └── incident-response/
│       └── playbook.md         <- response steps per incident type
├── tests/
│   ├── test_parser.py          <- 6 parser tests
│   └── test_alert_engine.py    <- 5 engine tests
├── .github/workflows/
│   └── tests.yml               <- runs on every push
├── requirements.txt
├── CONTRIBUTING.md
└── CHANGELOG.md
```

---

## Quickstart

```bash
git clone https://github.com/Speed-boo3/soc-project.git
cd soc-project
pip install -r requirements.txt
```

**Step 1 — Parse a log file**
```bash
python soc/log-parser/parser.py --file soc/log-parser/sample.log --output parsed.json
```

**Step 2 — Run detection rules**
```bash
python soc/alert-rules/alert_engine.py --logs parsed.json --rules soc/alert-rules/rules.yaml
```

**Step 3 — Check threat intel**
```bash
export ABUSEIPDB_KEY=your_key_here
python soc/alert-rules/threat_intel.py --logs parsed.json
```

**Step 4 — View dashboard**
```bash
python soc/dashboard/dashboard.py --logs parsed.json
```

---

## Tests

11 tests covering the parser and alert engine. Runs automatically on every push.

```bash
pytest tests/ -v
```

---

## Related

The GRC side of this work is in [grc-project](https://github.com/Speed-boo3/grc-project). SOC detects what is happening. GRC tracks whether the controls that should prevent it are actually in place.

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:ff0000,50:1a0000,100:0d1117&height=100&section=footer"/>
</div>
