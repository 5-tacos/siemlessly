# Security Findings

> **System**: SIEMlessly — Serverless SIEM  
> **Dataset**: 91 days of synthetic healthcare logs (October–December)  
> **Rules engine**: DuckDB over date-partitioned Parquet in S3  
> **Detection rules**: 10 active rules (see `config/rules/rules.json`)

---

## Executive Summary

Analysis of the 91-day log corpus surfaced **six distinct security scenarios**, ranging from external credential compromise to sustained insider data exfiltration. Each finding is mapped to the detection rule(s) that catch it and the primary evidence extracted by DuckDB queries.

| ID | Title | Severity | Primary Actor |
|----|-------|----------|---------------|
| B1 | Credential Compromise & Impossible Travel | Critical | EMP-003 |
| B2 | Insider Bulk Data Exfiltration | High | EMP-027 |
| B3 | Distributed Credential Stuffing | High | EMP-024 |
| B4 | Multi-IP Session Anomaly | Medium | EMP-003 |
| B5 | Patient Record Enumeration via API | High | External IP (Miami) |
| B6 | Off-Hours EHR Access (True Positive vs. False Positive) | Medium | Multiple |

---

## B1 — Credential Compromise & Impossible Travel

### Narrative

EMP-003's baseline VPN and authentication activity originates exclusively from San Francisco. During the attack window, successful logins and VPN connections appear from **Miami** and **Seattle** — cities never previously associated with this employee. Some sessions overlap with legitimate San Francisco activity within a 2-hour window, making physical travel impossible.

### Evidence

| Indicator | Value |
|-----------|-------|
| Baseline city (30-day) | San Francisco |
| Anomalous cities | Miami, Seattle |
| Concurrent session gap | < 2 hours between SF and Miami logins |
| New /24 subnets observed | Miami and Seattle prefixes absent from 30-day history |

### Detection Coverage

| Rule | What it catches |
|------|-----------------|
| `vpn-new-geo-for-user` | VPN connect from a city not in the employee's 30-day baseline |
| `auth-impossible-travel` | Two successful auths from different cities within 2 hours |
| `auth-new-ip-prefix` | Login from a /24 subnet never seen for this employee |

### Analyst Notes

The convergence of three independent signals — new VPN geo, impossible travel, and new IP prefix — provides high confidence that EMP-003's credentials were compromised. A single rule firing could be a business trip; all three firing together is a strong indicator of compromise.

---

## B2 — Insider Bulk Data Exfiltration

### Narrative

EMP-027 conducted a sustained campaign of bulk EHR data exfiltration over the 91-day period. Daily export and download counts consistently exceeded the 95th percentile of all employees, with peaks of **25–37 exports per day**. Over the full period, EMP-027 accessed **3,401 distinct patient records** — far above the median.

### Evidence

| Indicator | Value |
|-----------|-------|
| Daily export/download peaks | 25–37 per day |
| Distinct patients (91 days) | ~3,401 |
| Percentile rank (daily exports) | > 95th |
| Actions | `export`, `download` |

### Detection Coverage

| Rule | What it catches |
|------|-----------------|
| `ehr-bulk-export-daily` | Daily export+download count exceeding the 95th percentile |
| `ehr-distinct-patients-7d` | Employee touching an excessive number of distinct patients in a rolling 7-day window |

### Analyst Notes

The two EHR rules work in tandem: the daily-volume rule flags spikes, while the distinct-patients rule catches the breadth of access even if individual daily counts stay below the threshold. EMP-027 triggers both, confirming sustained high-volume exfiltration rather than a one-off spike.

---

## B3 — Distributed Credential Stuffing

### Narrative

EMP-024 experienced **7 login failures from 7 distinct source IPs** across the 30-day window. The distribution across IPs — one failure per IP — is a classic credential-stuffing fingerprint where an attacker rotates through a proxy pool to avoid per-IP rate limits.

### Evidence

| Indicator | Value |
|-----------|-------|
| Total login failures | 7 |
| Distinct source IPs | 7 |
| Failures per IP | 1 (uniform distribution) |
| Time span | Spread across the 30-day window |

### Detection Coverage

| Rule | What it catches |
|------|-----------------|
| `auth-distributed-bruteforce` | ≥ 5 failures total OR ≥ 3 distinct IPs with ≥ 3 failures |

### Analyst Notes

The `HAVING total_failures >= 5 OR (distinct_ips >= 3 AND total_failures >= 3)` compound condition catches both concentrated brute-force (many failures from few IPs) and distributed credential stuffing (few failures from many IPs). EMP-024 triggers the first branch. The IP list in the alert payload enables downstream enrichment (threat-intel lookups, geo-correlation).

---

## B4 — Multi-IP Session Anomaly

### Narrative

On the day of the attack, EMP-003 used **6 distinct source IPs** across all log types — VPN, auth, EHR, and HTTP. The typical employee uses 2–3 IPs per day. This anomaly is a downstream effect of the B1 credential compromise: the legitimate user in San Francisco and the attacker in Miami/Seattle are generating activity from different networks simultaneously.

### Evidence

| Indicator | Value |
|-----------|-------|
| Distinct IPs on attack day | 6 |
| Normal baseline | 2–3 per day |
| Log types with IP spread | VPN, auth, EHR, HTTP |

### Detection Coverage

| Rule | What it catches |
|------|-----------------|
| `session-distinct-ips-burst` | ≥ 4 distinct source IPs per employee per day across all log types |

### Analyst Notes

This rule is a useful corroborating signal but has lower precision on its own — employees using VPN split-tunneling or mobile hotspots can legitimately hit 4 IPs. It's most valuable when combined with the B1 rules.

---

## B5 — Patient Record Enumeration via API

### Narrative

A single source IP (originating from Miami) issued HTTP requests to sequential low-numbered MRN patient demographics endpoints (`/patients/MRN-00000013/demographics` through `/patients/MRN-00000486/demographics`) within a 2-hour window. This is a classic enumeration attack probing for valid patient identifiers.

### Evidence

| Indicator | Value |
|-----------|-------|
| Distinct MRNs hit | ≥ 10 (sequential, low-numbered) |
| Time window | < 2 hours |
| Source | Single IP from Miami |
| Endpoint pattern | `/patients/MRN-{id}/demographics` |

### Detection Coverage

| Rule | What it catches |
|------|-----------------|
| `mrn-enumeration` | ≥ 10 distinct low-MRN demographics requests from one IP in < 2 hours |

### Analyst Notes

The `MRN < 1000` filter scopes detection to the low-numbered range most likely to be enumerated (attacker starts at 0 and counts up). The 2-hour window prevents aggregating unrelated requests across days.

---

## B6 — Off-Hours EHR Access

### Narrative

Multiple employees accessed EHR records outside business hours (22:00–06:00 UTC). The rule explicitly **excludes** Emergency, ICU, and Intensive Care departments to suppress false positives from legitimate night-shift clinicians (e.g., EMP-017 in Emergency). Remaining hits are non-24/7 departments where off-hours access is suspicious.

### Evidence

| Indicator | Value |
|-----------|-------|
| Time window | 22:00–06:00 UTC |
| Excluded departments | Emergency, ICU, Intensive Care |
| Threshold | ≥ 5 accesses in a single off-hours period |
| EMP-017 (Emergency) | **Suppressed** — legitimate night shift |

### Detection Coverage

| Rule | What it catches |
|------|-----------------|
| `ehr-offhours-non-emergency` | ≥ 5 off-hours EHR accesses from non-24/7 departments |

### Analyst Notes

The department exclusion list is critical for healthcare SIEMs. Without it, every night-shift ER nurse would generate alerts. The threshold of 5 filters out one-off checks while catching sustained off-hours campaigns.

---

## Detection Rule Coverage Matrix

| Rule ID | B1 | B2 | B3 | B4 | B5 | B6 |
|---------|:--:|:--:|:--:|:--:|:--:|:--:|
| `vpn-new-geo-for-user` | ✅ | | | | | |
| `auth-impossible-travel` | ✅ | | | | | |
| `auth-new-ip-prefix` | ✅ | | | | | |
| `session-distinct-ips-burst` | | | | ✅ | | |
| `ehr-bulk-export-daily` | | ✅ | | | | |
| `ehr-distinct-patients-7d` | | ✅ | | | | |
| `auth-distributed-bruteforce` | | | ✅ | | | |
| `mrn-enumeration` | | | | | ✅ | |
| `ehr-offhours-non-emergency` | | | | | | ✅ |
| `ct-write-by-readonly-role` | | | | | | |

> `ct-write-by-readonly-role` is a proactive rule for future privilege-escalation scenarios. It did not fire on the current dataset but provides defense-in-depth for IAM misconfigurations.

---

## Recommendations

1. **Immediate** — Rotate EMP-003's credentials and audit all sessions from Miami/Seattle IPs.
2. **Immediate** — Investigate EMP-027's data export activity and determine if accessed patient records were exfiltrated externally.
3. **Short-term** — Feed the IP list from B3 into a threat-intelligence platform for reputation scoring.
4. **Short-term** — Implement API rate-limiting on the `/patients/*/demographics` endpoint to slow enumeration.
5. **Medium-term** — Add a behavioral-baseline rule that tracks per-employee daily EHR access volume and alerts on deviations > 2 standard deviations.
