# Investigation Timeline

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

