# sentinel-lab-16-end-to-end-soc-case
## Overview
A Microsoft Sentinel alert is generated for suspicious activity involving a user account. The analyst must investigate the alert using available authentication, endpoint, and network telemetry to determine whether the activity represents a genuine security incident.

This capstone lab simulates a SOC investigation where an alert involving `user1@contoso.com` requires analysis across multiple telemetry sources.

The investigation follows a practical analyst workflow rather than treating a single indicator as proof of compromise. Authentication activity is correlated with endpoint process execution, network connections, threat intelligence, and MITRE ATT&CK techniques to determine what the available evidence supports.

The lab uses self-contained KQL `datatable()` datasets so that the investigation remains reproducible even when persistent Sentinel tables or connectors are unavailable.

## Investigation Scenario

```

A security monitoring team receives a **High-severity Sentinel incident** involving `user1@contoso.com` on `DESKTOP-LAB01`. The initial alert identifies suspicious authentication activity associated with the external IP address `203.0.113.50`. The analyst must determine whether the authentication activity is isolated or connected to additional activity on the endpoint.

The investigation begins with authentication telemetry showing multiple failed attempts from `198.51.100.25`, followed by successful sign-ins from `203.0.113.50`. The analyst is required to examine the timing, source addresses, authentication results, and locations before making any assessment about the account.

Further investigation reveals endpoint activity shortly after the successful authentication events. `winword.exe` launches PowerShell with an encoded command, followed by commands associated with user, network, and account discovery. Network telemetry also shows connections from the workstation to `203.0.113.50` and `login-example.com`.

The analyst must correlate the available evidence across:

- Authentication activity
- Endpoint process execution
- Network connections
- Threat intelligence
- Incident metadata
- MITRE ATT&CK techniques
- Chronological event relationships

Threat intelligence identifies `203.0.113.50` and `login-example.com` as suspicious within the simulated feed, while `198.51.100.25` is classified as benign corporate infrastructure. These classifications provide investigative context but are not treated as standalone proof of compromise.

The objective of the scenario is to determine what can be established from the available telemetry, identify the affected entities and sequence of activity, document remaining uncertainty, and develop appropriate SOC response recommendations. The investigation should follow the evidence rather than assuming that any individual indicator or event represents confirmed malicious activity.
```

## Lab Objectives

```
- Investigate a simulated SOC case from the initial alert through final assessment and response recommendations.
- Validate suspicious authentication activity by examining failed and successful sign-ins, source IPs, locations, users, and authentication outcomes.
- Correlate identity activity with endpoint process execution to determine whether the authentication events are followed by relevant host activity.
- Analyze a simulated process chain involving Microsoft Word, PowerShell, and discovery utilities, including an encoded PowerShell command.
- Examine network activity from the affected endpoint and correlate external connections with observed authentication and endpoint events.
- Apply simulated threat intelligence to IP addresses and domains while distinguishing indicator matches from confirmed malicious activity.
- Build a chronological sequence of related events across authentication, endpoint, and network telemetry.
- Map observed behaviors to relevant MITRE ATT&CK techniques without treating technique mappings as proof of adversary activity.
- Determine the scope of the case by identifying the affected account, endpoint, source infrastructure, and related indicators.
- Produce an evidence-based assessment that separates confirmed observations, contextual indicators, and unresolved uncertainty.
- Develop practical SOC response recommendations based on the available evidence and the limitations of the simulated telemetry.
- Practice using self-contained KQL queries to perform repeatable investigation and correlation when persistent Sentinel tables are unavailable or unreliable.
```

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

