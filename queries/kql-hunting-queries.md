# KQL Threat Hunting Queries

## Failed Login Attempts

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName
| order by FailedAttempts desc
```

## Successful Logins

```kql
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress
```

## Multiple Failed Logins From Same IP

```kql
SigninLogs
| where ResultType != 0
| summarize Attempts=count() by IPAddress
| where Attempts > 5
```

## Administrative Activity

```kql
AuditLogs
| where OperationName contains "Add"
| project TimeGenerated, OperationName, InitiatedBy
```

## Suspicious Process Execution

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "powershell"
```

## Security Events in Last 24 Hours

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
```

## User Activity Timeline

```kql
SigninLogs
| project TimeGenerated, UserPrincipalName, IPAddress
| order by TimeGenerated asc
```

## Threat Hunting for External IP Activity

```kql
SigninLogs
| where IPAddress !startswith "10."
| project TimeGenerated, UserPrincipalName, IPAddress
```
