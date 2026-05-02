# 🛡️ Splunk SOC Home Lab

> A hands-on SIEM lab built with Splunk Enterprise on Windows — designed to simulate real SOC Analyst L1 workflows including log ingestion, SPL querying, and threat detection.

---

## 📌 Project Overview

This project demonstrates how to build a functional Security Operations Center (SOC) environment from scratch using Splunk Enterprise. It covers the full pipeline from raw Windows Event Logs to actionable detection rules mapped to the **MITRE ATT&CK framework**.

**Skills demonstrated:**
- SIEM deployment and configuration (Splunk Enterprise)
- Windows Event Log analysis (Security, System, Application)
- Splunk Search Processing Language (SPL)
- Threat detection rule development
- MITRE ATT&CK framework mapping

---

## 🏗️ Lab Architecture

```
Windows Machine
      │
      │  Windows Event Logs
      │  (Security / System / Application)
      ▼
Splunk Enterprise (localhost:8000)
      │
      │  Indexing & Search
      ▼
SPL Detection Rules
      │
      ▼
Alerts & Investigation
```

---

## ⚙️ Setup

See the full setup guide here → [docs/setup_guide.md](docs/setup_guide.md)

**Quick summary:**
1. Install Splunk Enterprise (free tier, 500MB/day)
2. Connect Windows Event Logs via Settings → Data Inputs
3. Verify ingestion: `index=* | stats count by sourcetype`
4. Run detection rules from the `detection-rules/` folder

---

## 🔍 Key Windows Event IDs

| Event ID | Description | SOC Relevance |
|----------|-------------|---------------|
| 4624 | Successful logon | Baseline activity |
| 4625 | Failed logon | Brute force indicator |
| 4648 | Logon with explicit credentials | Pass-the-Hash |
| 4672 | Admin privileges assigned | Privilege escalation |
| 4720 | New user account created | Persistence technique |
| 4732 | User added to Admins group | Escalation |
| 4688 | New process created | Malware execution |

---

## 🚨 Detection Rules

All rules are in the [`detection-rules/`](detection-rules/) folder.

---

### Rule 1 — Brute Force Attack
**File:** `detection-rules/brute_force.spl`
**MITRE:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
**Severity:** 🔴 HIGH

Detects when a single IP generates more than 10 failed login attempts (EventCode 4625) within a 5-minute window.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count by _time, IpAddress, Account_Name
| where count > 10
| sort -count
```

**Why it matters:** RDP and VPN brute force is one of the most common initial access techniques. Early detection prevents account compromise.

**Improvements:** Add IP whitelist for service accounts; correlate with geolocation to flag foreign IPs.

---

### Rule 2 — Login Outside Business Hours
**File:** `detection-rules/after_hours_login.spl`
**MITRE:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Severity:** 🟡 MEDIUM

Detects successful logins (EventCode 4624) outside of 07:00–20:00 or on weekends.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4624
| eval hour=tonumber(strftime(_time, "%H"))
| eval day=strftime(_time, "%A")
| where (hour < 7 OR hour > 20) OR (day="Saturday" OR day="Sunday")
| table _time, Account_Name, IpAddress, ComputerName, hour, day
| sort -_time
```

**Why it matters:** Attackers prefer off-hours when SOC monitoring is reduced. Legitimate users rarely log in at 3AM.

**Improvements:** Add Logon_Type=10 filter for RDP-only; exclude on-call admin accounts via lookup table.

---

### Rule 3 — Privilege Escalation
**File:** `detection-rules/privilege_escalation.spl`
**MITRE:** [TA0004 - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
**Severity:** 🔴 CRITICAL

Detects admin privilege assignment (EventCode 4672) or a user being added to the Administrators group (EventCode 4732).

```spl
index=* sourcetype="WinEventLog:Security" (EventCode=4672 OR EventCode=4732)
| eval action=case(
    EventCode=4672, "Admin privileges used at login",
    EventCode=4732, "User added to Administrators group")
| table _time, Account_Name, ComputerName, action
| sort -_time
```

**Why it matters:** Privilege escalation is a critical step in most attack chains. Detecting it early can stop an attacker before they establish persistence.

**Improvements:** Correlate with prior brute force events on the same account — 4625 → 4624 → 4672 chain is a strong compromise indicator.

---

### Rule 4 — Persistence via New Account
**File:** `detection-rules/new_account_created.spl`
**MITRE:** [T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
**Severity:** 🟡 MEDIUM / 🔴 CRITICAL

Detects new account creation (EventCode 4720). Escalates to CRITICAL if the account is immediately added to Administrators (4732).

```spl
index=* sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| stats values(EventCode) as events, count by Account_Name
| where count >= 2
```

**Why it matters:** Attackers create backdoor accounts to maintain access even after the initial vector is patched.

**Improvements:** Integrate with HR system — if no onboarding ticket exists for the new account, auto-escalate to P1.

---

### Rule 5 — Lateral Movement
**File:** `detection-rules/lateral_movement.spl`
**MITRE:** [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
**Severity:** 🔴 CRITICAL

Detects a single account authenticating to 3 or more unique machines via network logon (Logon_Type=3) — a strong indicator of lateral movement.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4624
| where Logon_Type=3 AND Account_Name!="ANONYMOUS LOGON"
| stats count dc(ComputerName) as unique_machines by Account_Name, IpAddress
| where unique_machines > 3
| sort -unique_machines
```

**Why it matters:** Normal users work on 1–2 machines. An account hitting 10+ machines in an hour likely indicates Pass-the-Hash or credential reuse across the network.

**Improvements:** Add time window (e.g., within 1 hour); integrate with SOAR for automatic account isolation.

---

## 📚 Key SPL Concepts Learned

| Command | What it does |
|---------|-------------|
| `index=*` | Search all indexes |
| `sourcetype=` | Filter by log source |
| `stats count by` | Count events grouped by field |
| `eval` | Create new calculated fields |
| `where` | Filter rows by condition |
| `bucket _time span=5m` | Group events into time windows |
| `dc()` | Count distinct values |
| `sort -count` | Sort descending by count |
| `table` | Display specific fields only |

---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Technique | Rule |
|--------|-----------|------|
| Initial Access | T1110 Brute Force | Rule 1 |
| Defense Evasion | T1078 Valid Accounts | Rule 2 |
| Privilege Escalation | TA0004 | Rule 3 |
| Persistence | T1136 Create Account | Rule 4 |
| Lateral Movement | T1550 Alt Auth Material | Rule 5 |

---

## 🛠️ Tools & Technologies

- **Splunk Enterprise** — SIEM platform
- **Windows Event Logs** — Security, System, Application
- **SPL** — Splunk Search Processing Language
- **MITRE ATT&CK** — Threat framework for rule mapping

---

## 👤 Author

**Islam Jumakulov**
Aspiring SOC Analyst | Cybersecurity Enthusiast

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](www.linkedin.com/in/islam-jumakulov-8a28b73a7)

---

## 📄 License

This project is open source and available under the [MIT License](LICE  NSE).
