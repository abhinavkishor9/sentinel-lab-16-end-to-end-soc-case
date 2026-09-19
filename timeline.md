# Investigation Timeline

## Case Information

| Field | Value |
|---|---|
| Incident ID | `INC-2026-016` |
| User | `user1@contoso.com` |
| Device | `DESKTOP-LAB01` |
| Start | `2026-09-19 09:02 UTC` |
| End | `2026-09-19 09:20:30 UTC` |

---

## Timeline

| Time UTC | Source | Activity | Entity |
|---|---|---|---|
| 09:02 | Authentication | Failed authentication | `198.51.100.25` |
| 09:04 | Authentication | Failed authentication | `198.51.100.25` |
| 09:07 | Authentication | Successful authentication | `203.0.113.50` |
| 09:09 | Authentication | Successful authentication | `203.0.113.50` |
| 09:14 | Authentication | Successful authentication | `203.0.113.50` |
| 09:16 | Endpoint | `winword.exe` launches PowerShell with encoded command | `DESKTOP-LAB01` |
| 09:16:30 | Network | HTTPS connection to `203.0.113.50` | `DESKTOP-LAB01` |
| 09:17 | Endpoint | PowerShell launches `whoami.exe` | `DESKTOP-LAB01` |
| 09:17:30 | Network | HTTPS connection to `login-example.com` | `DESKTOP-LAB01` |
| 09:18 | Endpoint | PowerShell launches `ipconfig.exe /all` | `DESKTOP-LAB01` |
| 09:19 | Endpoint | PowerShell launches `net user` | `DESKTOP-LAB01` |
| 09:20:30 | Network | HTTPS connection to `198.51.100.25` | `DESKTOP-LAB01` |

---

## Authentication Phase

### 09:02 UTC

`user1@contoso.com` generates a failed authentication attempt from:

```text
198.51.100.25
```

Location:

```text
Hyderabad, IN
```

Result:

```text
50126
```

### 09:04 UTC

A second failed authentication attempt occurs from the same IP address.

```text
user1@contoso.com
198.51.100.25
Hyderabad, IN
Result=50126
```

### 09:07 UTC

A successful authentication occurs from:

```text
203.0.113.50
```

Location:

```text
New York, US
```

Result:

```text
0
```

### 09:09 UTC

A second successful authentication occurs from the same suspicious source.

### 09:14 UTC

A third successful authentication occurs from the same source.

---

## Endpoint Phase

### 09:16 UTC

`DESKTOP-LAB01` records:

```text
winword.exe
    ↓
powershell.exe
```

The PowerShell command line contains:

```text
powershell.exe -EncodedCommand SQBF...
```

This establishes PowerShell execution from a Microsoft Word parent process.

### 09:17 UTC

PowerShell launches:

```text
whoami.exe
```

Command:

```text
whoami
```

This is consistent with user discovery.

### 09:18 UTC

PowerShell launches:

```text
ipconfig.exe
```

Command:

```text
ipconfig /all
```

This is consistent with network configuration discovery.

### 09:19 UTC

PowerShell launches:

```text
net.exe
```

Command:

```text
net user
```

This is consistent with account discovery.

---

## Network Phase

### 09:16:30 UTC

`DESKTOP-LAB01` communicates with:

```text
203.0.113.50:443
```

Destination domain:

```text
login-example.com
```

Action:

```text
Allowed
```

### 09:17:30 UTC

A second HTTPS connection occurs to:

```text
203.0.113.50:443
```

with:

```text
login-example.com
```

as the destination domain.

### 09:20:30 UTC

The workstation communicates with:

```text
198.51.100.25:443
```

Destination domain:

```text
office-example.com
```

This IP is classified as benign corporate infrastructure in the simulated TI feed.

---

## Correlated Sequence

The overall sequence is:

```text
Failed authentication
        ↓
Second failed authentication
        ↓
Successful authentication from new source
        ↓
Repeated successful authentication
        ↓
Word launches encoded PowerShell
        ↓
Connection to suspicious IP
        ↓
User discovery
        ↓
Connection to suspicious domain
        ↓
Network configuration discovery
        ↓
Account discovery
```

---

## Key Entities

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

### Benign IP

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

---

## Investigation Window

The first observed event occurs at:

```text
09:02 UTC
```

The last observed event occurs at:

```text
09:20:30 UTC
```

The available simulated investigation window is approximately:

```text
18 minutes 30 seconds
```

This represents only the period covered by the simulated telemetry.

---

## Timeline Assessment

The strongest correlation occurs between the successful authentication from `203.0.113.50`, subsequent PowerShell activity on `DESKTOP-LAB01`, and network communication with `203.0.113.50` and `login-example.com`.

The sequence provides sufficient investigative context to continue response and validation.

The timeline does not independently establish the complete attack path, the contents of the encoded command, credential theft, persistence, or the identity of the person responsible for the activity.
````
