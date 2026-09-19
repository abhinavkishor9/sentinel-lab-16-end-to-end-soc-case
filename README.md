# Sentinel Lab 16 — End-to-End SOC Case

An end-to-end Microsoft Sentinel SOC investigation that correlates authentication, endpoint, network, threat intelligence, incident context, and MITRE ATT&CK data to investigate a simulated suspicious account activity case.

## Overview

This capstone lab simulates a SOC investigation where an alert involving `user1@contoso.com` requires analysis across multiple telemetry sources.

The investigation follows a practical analyst workflow rather than treating a single indicator as proof of compromise. Authentication activity is correlated with endpoint process execution, network connections, threat intelligence, and MITRE ATT&CK techniques to determine what the available evidence supports.

The lab uses self-contained KQL `datatable()` datasets so that the investigation remains reproducible even when persistent Sentinel tables or connectors are unavailable.

## Investigation Scenario

A High-severity Sentinel incident is generated for suspicious account activity involving `user1@contoso.com` and `DESKTOP-LAB01`.

The initial authentication telemetry shows failed sign-ins from `198.51.100.25`, followed by successful authentication from `203.0.113.50`. Shortly afterward, endpoint telemetry shows `winword.exe` launching PowerShell with an encoded command.

Additional PowerShell activity includes user, network, and account discovery commands. Network telemetry then shows connections from the workstation to `203.0.113.50` and `login-example.com`.

Threat intelligence classifies `203.0.113.50` and `login-example.com` as suspicious within the simulated feed, while `198.51.100.25` is classified as benign corporate infrastructure.

The investigation focuses on correlating these events into a single timeline while distinguishing observed facts from contextual indicators and unresolved uncertainty.

## Lab Objectives

- Investigate a simulated SOC case from alert triage through final assessment.
- Analyze authentication activity and identify suspicious sign-in patterns.
- Correlate identity activity with endpoint process execution.
- Investigate suspicious PowerShell and discovery activity.
- Correlate endpoint activity with network connections.
- Apply simulated threat intelligence to observed indicators.
- Map observed behavior to relevant MITRE ATT&CK techniques.
- Build a chronological sequence of related events.
- Determine affected entities and investigative scope.
- Produce an evidence-based assessment and response recommendations.
- Practice repeatable KQL investigation using self-contained datasets.

## Investigation Flow

### 1. Alert & Triage

Review the Sentinel incident and establish the initial case context.

Identify:

- Incident ID
- Alert name
- Severity
- User
- Device
- Source IP
- Initial investigation window

### 2. KQL Investigation

Use KQL to examine the individual telemetry sources and identify relevant events.

The investigation covers:

- Authentication events
- Endpoint process activity
- Network connections
- Threat intelligence indicators
- Incident metadata

### 3. Incident, Entities & Timeline

Correlate the observed user, device, IP addresses, domain, and process activity.

The events are then organized chronologically to identify relationships between authentication, endpoint execution, and network activity.

### 4. Threat Intelligence & MITRE ATT&CK

Correlate observed indicators with the simulated threat intelligence dataset and map relevant endpoint behaviors to MITRE ATT&CK techniques.

MITRE mappings are treated as behavioral classifications supported by telemetry rather than confirmation of adversary intent.

### 5. Scope & Verdict

Assess the available evidence and determine:

- Affected user
- Affected endpoint
- Relevant source infrastructure
- Related network indicators
- Observed post-authentication activity
- Remaining uncertainty

### 6. Response Recommendation

Develop practical SOC response recommendations based on the observed evidence, case scope, and telemetry limitations.

## Simulated Data Sources

| Dataset | Purpose |
|---|---|
| `AuthData` | Authentication attempts, users, source IPs, locations, and results |
| `EndpointData` | Process creation and command-line activity |
| `NetworkData` | Outbound connections from the affected endpoint |
| `TIData` | Simulated IP and domain threat intelligence |
| `IncidentData` | Incident and alert metadata |

## Key Entities

| Entity | Value |
|---|---|
| User | `user1@contoso.com` |
| Device | `DESKTOP-LAB01` |
| Suspicious IP | `203.0.113.50` |
| Benign IP | `198.51.100.25` |
| Suspicious Domain | `login-example.com` |
| Incident | `INC-2026-016` |
| Alert | `Suspicious Account Activity` |
| Severity | `High` |

## Key Findings

The investigation identified a sequence in which authentication activity from the suspicious external IP was followed by endpoint activity on the associated workstation.

Observed endpoint behavior included:

- `winword.exe` launching PowerShell
- Encoded PowerShell command execution
- `whoami.exe`
- `ipconfig.exe`
- `net.exe user`

Network telemetry also showed connections to the suspicious IP address and domain identified in the simulated threat intelligence feed.

The evidence supports correlation between the authentication, endpoint, and network events. However, individual artifacts are not treated as standalone proof of account compromise or attacker intent.

## MITRE ATT&CK Mapping

| Technique | ID | Observed Behavior |
|---|---|---|
| Valid Accounts | T1078 | Successful authentication using `user1` |
| PowerShell | T1059.001 | PowerShell launched from `winword.exe` |
| System Owner/User Discovery | T1033 | `whoami.exe` execution |
| System Network Configuration Discovery | T1016 | `ipconfig /all` execution |
| Account Discovery | T1087 | `net user` execution |

These mappings describe behaviors observed in the simulated telemetry and should not be interpreted as proof that a specific adversary performed them.

## Evidence Model

The investigation follows an evidence-driven model:

```text
Indicator
    ↓
Observed Event
    ↓
Correlated Activity
    ↓
Behavioral Context
    ↓
Assessment
    ↓
Verdict
```

Examples:

- Failed login ≠ confirmed compromise
- Successful login ≠ automatically legitimate or malicious
- Suspicious PowerShell ≠ confirmed malicious execution
- Threat intelligence match ≠ confirmed intrusion

The goal is to establish what the telemetry demonstrates and clearly document what remains uncertain.

## Investigation Limitations

This lab uses simulated telemetry generated with KQL `datatable()` statements.

The data does not represent production Microsoft Sentinel telemetry and does not provide complete visibility into real identity, endpoint, network, or cloud environments.

Threat intelligence classifications are also simulated and should be treated as investigative context rather than authoritative external intelligence.

Because the dataset is intentionally limited, conclusions are restricted to the events represented within the investigation window.

## Skills Demonstrated

- Microsoft Sentinel investigation
- KQL query development
- Authentication analysis
- Endpoint investigation
- PowerShell analysis
- Network activity correlation
- Threat intelligence correlation
- Entity investigation
- Timeline construction
- MITRE ATT&CK mapping
- Evidence-based SOC assessment
- Incident response planning
- Detection and investigation documentation


## Conclusion

This lab demonstrates an end-to-end SOC investigation process using correlated authentication, endpoint, network, threat intelligence, incident, and ATT&CK context.

The investigation emphasizes evidence validation, event correlation, timeline reconstruction, and explicit handling of uncertainty rather than relying on isolated indicators to determine the outcome of a case.
````
