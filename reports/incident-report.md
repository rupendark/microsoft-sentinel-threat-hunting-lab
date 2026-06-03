# Security Investigation Report

## Executive Summary

A security investigation was conducted using Microsoft Sentinel to analyze alerts, review security events, and identify potential indicators of compromise. The investigation followed a structured SOC workflow including alert validation, event correlation, and threat hunting.

## Scope

* Alert Investigation
* Log Analysis
* Threat Hunting
* IOC Identification
* Incident Documentation

## Investigation Process

### 1. Alert Review

Security alerts generated within Microsoft Sentinel were reviewed and prioritized according to severity and potential business impact.

### 2. Event Analysis

Relevant log events were analyzed using Kusto Query Language (KQL). Authentication activities, user actions, and system events were examined to identify suspicious behavior.

### 3. Threat Hunting

Proactive hunting activities were performed to detect anomalous activity, unauthorized access attempts, and indicators associated with potential threats.

### 4. Event Correlation

Multiple log sources and security events were correlated to reconstruct timelines and understand the context surrounding detected alerts.

## Findings

* Suspicious activities were identified through log analysis.
* Security alerts were validated and categorized.
* Indicators of compromise were reviewed and documented.
* Relevant attack patterns were mapped to MITRE ATT&CK techniques.

## Recommendations

* Continue proactive threat hunting activities.
* Improve detection coverage through custom analytics rules.
* Reduce false positives through alert tuning.
* Maintain continuous monitoring of critical assets.

## Skills Applied

* Microsoft Sentinel Investigation
* Alert Triage
* Threat Hunting
* KQL Querying
* Log Correlation
* Incident Analysis
* IOC Identification
