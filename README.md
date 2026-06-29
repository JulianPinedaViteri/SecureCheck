# SecureCheck

A Python Flask REST API that performs automated cybersecurity compliance checks on system configurations, identifying misconfigurations like insecure protocols, open vulnerable ports, and weak password policies.

## What It Does

SecureCheck is a two-part automated security compliance pipeline:

1. `scanner.py` — runs on any target machine, automatically collects real system data (open ports, SSH/Telnet/FTP status, password policy), and sends it to the API with no manual input
2. `app.py` — a Flask REST API that receives the system data, runs it through six security compliance rules, and returns a structured JSON report with findings, severities, and a score out of 100

## Pipeline Flow

\```
scanner.py collects real system data
    ↓
POST request to SecureCheck API
    ↓
app.py runs compliance rules
    ↓
Returns findings + compliance score
    ↓
scanner.py prints formatted report
\```

## Compliance Rules

| Rule | Severity | Points Deducted |
|---|---|---|
| No Telnet enabled | HIGH | 25 |
| No FTP enabled | MEDIUM | 15 |
| Password length >= 12 | HIGH | 25 |
| SSH must be enabled | HIGH | 20 |
| Port 23 (Telnet) must be closed | HIGH | 20 |
| Port 21 (FTP) must be closed | MEDIUM | 15 |

## Endpoints

**GET /health** — confirms the API is running

**POST /scan** — accepts system config JSON, returns compliance report

## Example Request

```json
{
    "open_ports": [21, 22, 23, 80, 443],
    "telnet_enabled": true,
    "ftp_enabled": true,
    "password_length": 8,
    "ssh_enabled": false
}
```

## Example Response

```json
{
    "overall_status": "FAIL",
    "score": "0/100",
    "findings": [
        {
            "rule": "No Telnet",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "Telnet transmits data in cleartext. Use SSH instead."
        }
    ]
}
```

## Tech Stack

- Python 3
- Flask
- Tested with Postman and scanner.py

## Background

## Background

## Background

This project came out of a home lab I built to get more hands on experience with real security tooling. While working on a separate Suricata IDS project I kept seeing the same misconfigurations show up as alerts: Telnet on port 23, FTP brute force on port 21, weak credentials. That got me thinking about catching those issues before deployment rather than detecting them after the fact.

SecureCheck is the result of that. The compliance rules it checks against are directly based on the same vulnerabilities I was detecting with Suricata, just shifted left in the pipeline. Adding scanner.py took it further by removing the manual step entirely. Now it runs on a target machine, collects the real system data automatically, and sends it to the API without any human input needed. The goal was to build something that reflects how security automation actually works, not just a standalone script or API sitting in isolation.