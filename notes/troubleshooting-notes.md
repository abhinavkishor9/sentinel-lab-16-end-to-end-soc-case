# Troubleshooting Notes

## Overview

This lab was built using self-contained KQL `datatable()` datasets.

The approach was selected because the Sentinel workspace did not consistently provide the required persistent tables and telemetry for this simulated investigation.

Using `datatable()` allowed each investigation stage to be executed independently while keeping the dataset reproducible.

---

## Persistent Table and Schema Issues

Earlier Sentinel labs showed that expected tables and fields were not always available in the workspace.

Examples included:

- Expected tables returning no useful records.
- `TimeGenerated` not being available in some datasets.
- `Timestamp` not being available in some datasets.
- Custom tables not consistently returning the expected data.
- Connector-dependent queries requiring schemas that were not present.

For this reason, Lab 16 uses explicit simulated datasets instead of assuming production telemetry is available.

---

## Explicit Datatype Definitions

Each `datatable()` defines its column types explicitly.

Example:

```kusto
let AuthData = datatable(
    TimeGenerated:datetime,
    User:string,
    IPAddress:string,
    Location:string,
    Application:string,
    ResultType:string,
    AuthenticationMethod:string
)
[
    ...
];
```

Explicit types prevent ambiguity when sorting timestamps, filtering strings, and correlating fields.

---

## Timeline Union

Authentication, endpoint, and network datasets have different schemas.

The raw datasets should not be unioned without first normalizing their columns.

The working approach is to project each dataset into:

```text
TimeGenerated
EventType
Details
```

For example:

```kusto
AuthData
| project
    TimeGenerated,
    EventType = "Authentication",
    Details = strcat(
        User,
        " | ",
        IPAddress,
        " | ",
        Location,
        " | Result=",
        ResultType
    )
```

Endpoint data can be normalized into the same structure:

```kusto
EndpointData
| project
    TimeGenerated,
    EventType = "Endpoint",
    Details = strcat(
        ParentProcess,
        " -> ",
        Process,
        " | ",
        CommandLine
    )
```

The normalized datasets can then be combined with `union`.

This keeps the final timeline consistent even though the original datasets contain different fields.

---

## Threat Intelligence Join Issue

The TI correlation query produced an error during development.

The authentication dataset used:

```text
IPAddress
```

while the TI dataset used:

```text
Indicator
```

The initial approach attempted to correlate the two different field names directly.

To simplify the correlation, the authentication data was extended with an `Indicator` field:

```kusto
AuthData
| extend Indicator = IPAddress
```

The TI dataset also uses:

```text
Indicator
```

The join can therefore use the common field:

```kusto
| join kind=leftouter TIData on Indicator
```

This produced the expected TI enrichment.

---

## Working TI Correlation

The simplified structure is:

```kusto
let AuthData = datatable(
    TimeGenerated:datetime,
    User:string,
    IPAddress:string,
    Location:string,
    ResultType:string
)
[
    datetime(2026-09-19 09:02:00), "user1@contoso.com", "198.51.100.25", "Hyderabad, IN", "50126",
    datetime(2026-09-19 09:04:00), "user1@contoso.com", "198.51.100.25", "Hyderabad, IN", "50126",
    datetime(2026-09-19 09:07:00), "user1@contoso.com", "203.0.113.50", "New York, US", "0",
    datetime(2026-09-19 09:09:00), "user1@contoso.com", "203.0.113.50", "New York, US", "0",
    datetime(2026-09-19 09:14:00), "user1@contoso.com", "203.0.113.50", "New York, US", "0"
];

let TIData = datatable(
    Indicator:string,
    ThreatCategory:string,
    Confidence:int,
    TIStatus:string
)
[
    "203.0.113.50", "Suspicious Authentication Infrastructure", 85, "Suspicious",
    "198.51.100.25", "Corporate NAT", 5, "Benign"
];

AuthData
| extend Indicator = IPAddress
| join kind=leftouter TIData on Indicator
| project
    TimeGenerated,
    User,
    IPAddress,
    Location,
    ResultType,
    ThreatCategory,
    Confidence,
    TIStatus
| order by TimeGenerated asc
```

The resulting correlation showed:

```text
203.0.113.50 → Suspicious Authentication Infrastructure
198.51.100.25 → Corporate NAT
```

---

## TI Domain Correlation

The authentication TI join only correlates IP addresses.

The domain indicator:

```text
login-example.com
```

is maintained separately because it does not exist in the authentication `IPAddress` field.

The network dataset provides the appropriate location for correlating the domain indicator.

This avoids forcing unrelated indicator types into the same join.

---

## KQL Validation Approach

Queries were tested incrementally rather than building the entire investigation in one query.

The validation sequence was:

```text
IncidentData
      ↓
AuthData
      ↓
EndpointData
      ↓
NetworkData
      ↓
Timeline
      ↓
TI Correlation
      ↓
Scope
```

This made it easier to identify whether an issue came from:

- Dataset creation
- Column naming
- Datatype definitions
- Filtering
- Projection
- Union
- Join logic

---

## Evidence Validation

The investigation intentionally avoids treating a single event as a confirmed conclusion.

Examples:

```text
Failed authentication
≠
Account compromise
```

```text
Successful authentication
≠
Confirmed attacker access
```

```text
Encoded PowerShell
≠
Confirmed malicious payload
```

```text
Suspicious TI
≠
Confirmed intrusion
```

The assessment is based on correlation between multiple telemetry sources.

---

## Simulated Telemetry Limitation

The `datatable()` approach makes the investigation reproducible but also limits what can be concluded.

The lab does not contain real:

- Entra ID logs
- Defender telemetry
- Proxy logs
- Firewall logs
- Process hashes
- File hashes
- File creation events
- Persistence events
- User confirmation
- Threat intelligence provider data

Therefore, query output should be described as simulated investigation evidence.

---

## Troubleshooting Principle

When a Sentinel query fails, the investigation should be simplified before adding additional logic.

The troubleshooting sequence used in this lab was:

```text
Validate dataset
      ↓
Validate schema
      ↓
Validate filter
      ↓
Validate projection
      ↓
Validate union
      ↓
Validate correlation
      ↓
Validate final output
```

This approach prevents a complex query from hiding the actual source of a parser or schema error.
````
