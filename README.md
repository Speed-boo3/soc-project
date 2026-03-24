<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,40:0a0a2e,100:ff0000&height=220&section=header&text=SOC%20Project&fontSize=65&fontColor=ff4444&animation=fadeIn&fontAlignY=42&desc=Security%20Operations%20Center%20%7C%20Built%20from%20scratch%20in%20Python&descAlignY=66&descColor=aaaaaa&descSize=15"/>

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=17&duration=2500&pause=800&color=FF4444&center=true&vCenter=true&width=650&lines=What+is+a+SOC+and+how+does+it+work%3F;Log+Analysis+%26+Threat+Detection;MITRE+ATT%26CK+Detection+Engineering;Threat+Intelligence+%26+IP+Reputation;Brute+Force+Detection+%26+IR+Playbooks;Built+for+students+learning+blue+team+security"/>

<br/>

![Python](https://img.shields.io/badge/Python-3.8+-0d1117?style=for-the-badge&logo=python&logoColor=00ff41)
![Tests](https://img.shields.io/badge/Tests-11%20passing-0d1117?style=for-the-badge&logo=pytest&logoColor=00ff41)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-0d1117?style=for-the-badge&logoColor=ff4444)
![License](https://img.shields.io/badge/License-MIT-0d1117?style=for-the-badge&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/Threat%20Intel-AbuseIPDB-0d1117?style=for-the-badge&logoColor=ff9900)

</div>

---

## What is this project?

This is a hands-on SOC project built from scratch in Python. It is designed for students and anyone curious about how security operations actually work — not just in theory, but in practice.

Every tool in this project solves a real problem that a SOC analyst faces daily. You can run it yourself, break it, modify it and learn from it.

---

## What is a SOC?

A **Security Operations Center** is a team of security analysts who monitor, detect and respond to threats against an organisation 24/7. Think of it as the defensive nerve center of a company's security.

```mermaid
flowchart LR
    subgraph OUTSIDE[Outside threats]
        ATK[Attackers]
        MAL[Malware]
        PHI[Phishing]
    end

    subgraph SOC[Security Operations Center]
        MON[Monitor]
        DET[Detect]
        RES[Respond]
        REP[Report]
        MON --> DET --> RES --> REP
    end

    subgraph ASSETS[Organisation]
        SRV[Servers]
        USR[Users]
        NET[Network]
    end

    OUTSIDE --> ASSETS
    ASSETS -->|Logs and alerts| SOC
    SOC -->|Contain and fix| ASSETS

    style SOC fill:#0a0a1a,stroke:#4488ff,color:#88aaff
    style OUTSIDE fill:#1a0000,stroke:#ff4444,color:#ff8888
    style ASSETS fill:#0a1a0a,stroke:#00ff41,color:#66ff88
```

A SOC analyst's job is to:
- Collect logs from servers, firewalls, endpoints and applications
- Detect suspicious patterns using rules and threat intelligence
- Investigate alerts to determine if they are real threats or false positives
- Respond to confirmed incidents following structured playbooks
- Document findings and improve detection over time

---

## SOC categories — what a SOC covers

A real SOC is split into several focus areas. This project covers all of them:

```mermaid
mindmap
  root((SOC))
    Log Analysis
      Parse raw log files
      Detect log types
      Flag suspicious lines
    Detection Engineering
      Write detection rules
      Map rules to MITRE ATT&CK
      Tune alert thresholds
    Threat Intelligence
      Check IP reputation
      Identify known bad actors
      Enrich alerts with context
    Incident Response
      Triage alerts
      Contain the threat
      Eradicate and recover
    Network Security
      Scan for open ports
      Identify exposure
      Feed findings into risk register
    Forensics
      Identify file hashes
      Check for known malware
      Analyse artifacts
```

---

## The detection pipeline

This is how raw logs become actionable alerts:

```mermaid
flowchart TD
    A[Raw Log File] --> B[Log Parser]
    B --> C{Log type?}
    C -->|SSH and Auth| D[Auth Entry]
    C -->|Apache| E[Web Entry]
    C -->|Syslog| F[System Entry]
    D & E & F --> G[Parsed JSON]
    G --> H[Alert Engine]
    G --> P[Brute Force Detector]
    H --> I{Rule match?}
    I -->|Yes| J[Alert fired]
    I -->|No| K[Skipped]
    P --> J
    J --> L[MITRE ATT&CK tag]
    J --> M[Threat Intel lookup]
    M --> N[AbuseIPDB score]
    L & N --> O[Terminal Dashboard]
    J --> Q[IR Playbook triggered]

    style A fill:#1a0a0a,color:#ff6666,stroke:#ff4444
    style J fill:#1a0000,color:#ff4444,stroke:#ff0000
    style G fill:#0a1a0a,color:#66ff88,stroke:#00ff41
    style O fill:#0a0a1a,color:#88aaff,stroke:#4488ff
    style Q fill:#1a1000,color:#ffcc66,stroke:#ffaa00
```

---

## Tools

| Tool | File | Category | What it does |
|---|---|---|---|
| Log Parser | `soc/log-parser/parser.py` | Log Analysis | Reads log files, detects type, flags suspicious entries |
| Alert Engine | `soc/alert-rules/alert_engine.py` | Detection Engineering | Runs parsed logs through MITRE ATT&CK-mapped rules |
| Detection Rules | `soc/alert-rules/rules.yaml` | Detection Engineering | YAML rules — one per threat scenario |
| Threat Intel | `soc/alert-rules/threat_intel.py` | Threat Intelligence | Checks source IPs against AbuseIPDB in real time |
| Dashboard | `soc/dashboard/dashboard.py` | Monitoring | Terminal overview of log stats and live alerts |
| IR Playbook | `soc/incident-response/playbook.md` | Incident Response | Step-by-step response per MITRE technique |
| Hash Checker | `soc/hash-checker/hash_checker.py` | Forensics | Identifies hash type and checks against malware database |
| Brute Force Detector | `soc/brute-force-detector/detector.py` | Detection | Flags IPs with too many failed login attempts |

---

## MITRE ATT&CK

MITRE ATT&CK is a globally recognised framework that maps attacker behaviour to specific techniques. Every detection rule in this project is tagged with a technique ID so you always know what attack you are looking at.

> For example: when a rule fires for repeated failed SSH logins, it is tagged as **T1110 — Brute Force** under the **Credential Access** tactic. This tells you immediately what the attacker is trying to do.

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

## Alert severity levels

Not every alert is equally urgent. This project uses three severity levels:

```mermaid
flowchart LR
    H[High] -->|Respond in 30 min| HA[Brute force, credential stuffing]
    M[Medium] -->|Respond in 4 hours| MA[Sudo failures, segfaults, invalid users]
    L[Low] -->|Log and review| LA[Admin path access, informational]

    style H fill:#1a0000,stroke:#ff0000,color:#ff6666
    style M fill:#1a1000,stroke:#ffaa00,color:#ffcc66
    style L fill:#001a00,stroke:#00ff41,color:#66ff88
```

```mermaid
pie title Alert Severity Distribution
    "High"   : 35
    "Medium" : 45
    "Low"    : 20
```

---

## Incident response

When an alert fires, the SOC follows a structured response process. This is based on NIST SP 800-61 — the industry standard for incident response.

```mermaid
flowchart TD
    A[Alert fires] --> B[Triage]
    B --> C{Real threat?}
    C -->|No| D[Close as false positive]
    C -->|Yes| E[Contain]
    E --> F[Eradicate]
    F --> G[Recover]
    G --> H[Post-incident report]
    H --> I[Improve detection rules]

    style A fill:#1a0000,color:#ff4444,stroke:#ff0000
    style D fill:#0a1a0a,color:#66ff88,stroke:#00ff41
    style H fill:#0a0a1a,color:#88aaff,stroke:#4488ff
    style I fill:#0a1a0a,color:#66ff88,stroke:#00ff41
```

Full playbooks for each scenario are in `soc/incident-response/playbook.md`.

---

## What alerts look like

This is what the alert engine outputs when it detects something:

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

## Full detection sequence

This diagram shows every step from raw log to analyst — including the threat intelligence lookup:

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

## Project structure

```
soc-project/
├── soc/
│   ├── log-parser/
│   │   ├── parser.py               <- reads and classifies log lines
│   │   └── sample.log              <- sample log for testing
│   ├── alert-rules/
│   │   ├── rules.yaml              <- detection rules with MITRE mapping
│   │   ├── alert_engine.py         <- runs logs against the rules
│   │   └── threat_intel.py         <- AbuseIPDB IP reputation lookup
│   ├── dashboard/
│   │   └── dashboard.py            <- terminal dashboard
│   ├── incident-response/
│   │   └── playbook.md             <- IR playbook per incident type
│   ├── hash-checker/
│   │   └── hash_checker.py         <- identifies hash type, checks malware db
│   └── brute-force-detector/
│       └── detector.py             <- flags IPs with too many failed logins
├── tests/
│   ├── test_parser.py              <- 6 parser tests
│   └── test_alert_engine.py        <- 5 engine tests
├── .github/workflows/
│   └── tests.yml                   <- runs on every push
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

**Step 5 — Check a file hash**
```bash
python soc/hash-checker/hash_checker.py --hash d41d8cd98f00b204e9800998ecf8427e
```

**Step 6 — Detect brute force attempts**
```bash
python soc/brute-force-detector/detector.py --file soc/log-parser/sample.log --threshold 3
```

---

## Tests

```bash
pytest tests/ -v
```

11 tests covering the log parser and alert engine. Runs automatically on every push via GitHub Actions.

---

## Want to learn more about SOC?

If this project got you interested in blue team security, here are some good starting points:

- [MITRE ATT&CK Framework](https://attack.mitre.org) — the full technique library
- [NIST SP 800-61](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) — incident response guide
- [AbuseIPDB](https://www.abuseipdb.com) — free threat intelligence API
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — web security testing guide

---

## Related

The GRC side of this work is in [grc-project](https://github.com/Speed-boo3/grc-project). SOC detects what is happening. GRC tracks whether the controls that should prevent it are actually in place.

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:ff0000,50:0a0a2e,100:0d1117&height=120&section=footer&text=Detect.%20Respond.%20Improve.&fontSize=20&fontColor=ff4444&animation=twinkling"/>
</div>
