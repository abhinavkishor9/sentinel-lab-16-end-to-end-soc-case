# Investigation Notes

## Case Information

| Field | Value |
|---|---|
| Incident ID | `INC-2026-016` |
| Alert | `Suspicious Account Activity` |
| Severity | `High` |
| Status | `New` |
| User | `user1@contoso.com` |
| Device | `DESKTOP-LAB01` |
| Suspicious IP | `203.0.113.50` |
| Investigation Start | `2026-09-19 09:02 UTC` |
| Investigation End | `2026-09-19 09:20:30 UTC` |

---

## Initial Triage

The investigation began with a simulated Sentinel incident for suspicious account activity involving `user1@contoso.com`.

The incident identifies `DESKTOP-LAB01` as the associated endpoint and `203.0.113.50` as the suspicious source IP.

The initial authentication data shows two failed authentication attempts from `198.51.100.25`, followed by three successful authentication events from `203.0.113.50`.

The source IP and simulated location change provided the initial reason to continue the investigation.

---

## Authentication Investigation

The authentication events observed for `user1@contoso.com` were:

| Time | IP Address | Location | Result |
|---|---|---|---|
| `09:02` | `198.51.100.25` | Hyderabad, IN | `50126` |
| `09:04` | `198.51.100.25` | Hyderabad, IN | `50126` |
| `09:07` | `203.0.113.50` | New York, US | `0` |
| `09:09` | `203.0.113.50` | New York, US | `0` |
| `09:14` | `203.0.113.50` | New York, US | `0` |

The first two events represent failed authentication attempts.

The next three events are successful authentication events from a different source IP.

The successful authentication events establish that authentication succeeded from the suspicious source in the simulated dataset. They do not independently establish whether the activity was performed by an attacker or by the legitimate user.

---

## Endpoint Investigation

Endpoint telemetry from `DESKTOP-LAB01` begins at `09:16 UTC`.

The first process relationship is:

```text
winword.exe
    ↓
powershell.exe
```

The PowerShell command line contains:

```text
powershell.exe -EncodedCommand SQBF...
```

The subsequent process activity is:

```text
powershell.exe
    ├── whoami.exe
    ├── ipconfig.exe
    └── net.exe
```

Observed commands include:

```text
whoami
ipconfig /all
net user
```

These commands are consistent with user, network configuration, and account discovery behavior.

The available telemetry does not expose the decoded contents of the PowerShell command. The encoded command is therefore treated as suspicious execution evidence rather than proof of a malicious payload.

---

## Network Investigation

The network telemetry shows:

| Time | Destination IP | Domain | Port | Action |
|---|---|---|---:|---|
| `09:16:30` | `203.0.113.50` | `login-example.com` | `443` | Allowed |
| `09:17:30` | `203.0.113.50` | `login-example.com` | `443` | Allowed |
| `09:20:30` | `198.51.100.25` | `office-example.com` | `443` | Allowed |

The first two connections originate from `DESKTOP-LAB01` and connect to the same suspicious IP observed in the authentication telemetry.

The destination domain is also present in the simulated TI dataset.

The later connection to `198.51.100.25` is associated with the simulated benign corporate infrastructure record.

---

## Threat Intelligence Correlation

The simulated TI feed contains:

| Indicator | Type | Threat Category | Confidence | Status |
|---|---|---|---:|---|
| `login-example.com` | Domain | Credential Harvesting Infrastructure | `90` | Suspicious |
| `203.0.113.50` | IPv4 | Suspicious Authentication Infrastructure | `85` | Suspicious |
| `198.51.100.25` | IPv4 | Corporate NAT | `5` | Benign |

The authentication events from `203.0.113.50` therefore correlate with a suspicious TI record.

The network activity involving `login-example.com` provides an additional TI correlation.

The TI classification increases the investigative significance of the indicators but is not treated as standalone evidence of compromise.

---

## Entity Correlation

The investigation identifies the following entities:

### User

```text
user1@contoso.com
```

### Device

```text
DESKTOP-LAB01
```

### Suspicious IP

```text
203.0.113.50
```

### Suspicious Domain

```text
login-example.com
```

### Benign Reference IP

```text
198.51.100.25
```

### Processes

```text
winword.exe
powershell.exe
whoami.exe
ipconfig.exe
net.exe
```

The same user and device appear across authentication, endpoint, and network telemetry, allowing the datasets to be correlated into a single investigative sequence.

---

## Timeline Correlation

The activity can be reconstructed as:

```text
09:02
Failed authentication from 198.51.100.25

09:04
Failed authentication from 198.51.100.25

09:07
Successful authentication from 203.0.113.50

09:09
Successful authentication from 203.0.113.50

09:14
Successful authentication from 203.0.113.50

09:16
winword.exe launches powershell.exe with an encoded command

09:16:30
DESKTOP-LAB01 connects to 203.0.113.50:443

09:17
PowerShell launches whoami.exe

09:17:30
DESKTOP-LAB01 connects to login-example.com:443

09:18
PowerShell launches ipconfig.exe

09:19
PowerShell launches net.exe

09:20:30
DESKTOP-LAB01 connects to 198.51.100.25:443
```

The temporal relationship between the authentication, endpoint, and network events is the primary basis for the investigation.

---

## MITRE ATT&CK Mapping

### T1078 — Valid Accounts

Successful authentication events were observed for `user1@contoso.com`.

The telemetry demonstrates successful use of the account but does not establish whether the credentials were obtained or used by an attacker.

### T1059.001 — PowerShell

`winword.exe` launched `powershell.exe` with an encoded command.

This provides direct endpoint evidence of PowerShell execution.

### T1033 — System Owner/User Discovery

`whoami.exe` was launched by PowerShell.

The command is consistent with identifying the current user context.

### T1016 — System Network Configuration Discovery

`ipconfig.exe /all` was launched by PowerShell.

The command is consistent with collecting network configuration information.

### T1087 — Account Discovery

`net user` was launched by PowerShell.

The command is consistent with account discovery activity.

MITRE ATT&CK mappings are based on observed behaviors and are not treated as independent confirmation of malicious intent.

---

## Scope Assessment

The available simulated telemetry identifies:

- One user: `user1@contoso.com`
- One endpoint: `DESKTOP-LAB01`
- One suspicious IP: `203.0.113.50`
- One suspicious domain: `login-example.com`
- One benign reference IP: `198.51.100.25`

No additional users or endpoints appear in the simulated datasets.

The observed scope is therefore limited to the user and endpoint represented in the available telemetry.

This does not prove that no additional systems or accounts were affected because the dataset is intentionally limited.

---

## Assessment

The investigation identified a connected sequence involving:

1. Failed authentication from the normal simulated source.
2. Successful authentication from a different external source.
3. Suspicious TI associated with that external source.
4. Word spawning PowerShell.
5. Encoded PowerShell execution.
6. Subsequent discovery activity.
7. Network communication with the suspicious IP.
8. Network communication with a suspicious domain.

Taken together, the activity warrants continued incident response and validation.

The available evidence does not independently establish:

- The identity of the person performing the activity.
- The contents of the encoded PowerShell command.
- Credential theft.
- Persistence.
- Data access or exfiltration.
- Additional affected systems.

The assessment should therefore remain tied to the evidence available in the simulated dataset.

---

## Response Recommendations

The following actions would be appropriate for continued SOC investigation:

- Validate the successful authentication events with the user or identity team.
- Review active sessions and authentication tokens.
- Protect the affected account according to organizational procedures.
- Investigate `DESKTOP-LAB01` for additional endpoint activity.
- Decode and safely analyze the PowerShell command.
- Review process creation and file activity surrounding the Word and PowerShell execution.
- Search for `203.0.113.50` across available telemetry.
- Search for `login-example.com` across available telemetry.
- Identify any additional users or devices communicating with the indicators.
- Preserve relevant authentication, endpoint, and network evidence.
- Reassess the incident after additional evidence is collected.
````
