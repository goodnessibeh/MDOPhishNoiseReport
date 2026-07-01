# MDO Phishing Noise Report - Design

**Date:** 2026-07-01
**Status:** Approved design (brainstorming complete)
**Author:** Goodness Caleb Ibeh

---

## 1. Purpose

A single, read-only PowerShell 7 **monolith script** that analyzes the current Microsoft
Defender for Office 365 (MDO) phishing alert/incident load and categorizes it by **how
Defender processes each item** - automatically resolved vs escalated for manual review -
then writes an Excel workbook with one sheet per analysis. It answers "where is the
manual-review noise coming from" and doubles as the baseline business case for the
Phishing Triage Agent.

Authentication mirrors the other tools: interactive delegated OAuth via `Connect-MgGraph`.
The script has an editable `$Upn` variable near the top; if it is blank the script prompts,
then sign-in follows. Nothing is written to the tenant - reads only.

## 2. Data sources (from research)

| Need | Endpoint | Scope |
|---|---|---|
| MDO alerts + AIR state | `GET /security/alerts_v2` (`$filter=serviceSource eq 'microsoftDefenderForOffice365'`) | `SecurityAlert.Read.All` |
| Correlated incidents | `GET /security/incidents?$expand=alerts` | `SecurityIncident.Read.All` |
| Email volume / senders / delivery / policy | `POST /security/runHuntingQuery` (KQL over `EmailEvents`, `EmailPostDeliveryEvents`) | `ThreatHunting.Read.All` |
| User-reported submissions | `GET /beta/security/threatSubmission/emailThreats` | `ThreatSubmission.Read.All` |

All four are read-only, admin-consent scopes. The signed-in admin needs **Security Reader**
(or higher). Advanced hunting is capped at **30 days / 100k rows** - queries pre-aggregate
with `summarize`, never pull raw rows.

## 3. Processing-path bucketing (the core logic)

Primary signal is `alerts_v2.investigationState`; proxies are labelled honestly.

- **Auto-resolved:** `investigationState in (successfullyRemediated, benign, suppressedAlert)`;
  proxy `status=resolved AND assignedTo is null`.
- **Escalated (manual review):** `investigationState in (pendingApproval, partiallyRemediated,
  partiallyInvestigated, pendingResource, queued, running)`; or `status in (new, inProgress)`;
  or `assignedTo` is a user.
- **Auto-blocked at delivery:** `EmailEvents.DeliveryAction in (Blocked, Junked, Replaced)` for
  phish `ThreatTypes`.
- **Post-delivery Auto vs Manual:** `EmailPostDeliveryEvents.ActionTrigger == 'Automation'`
  (or ZAP `ActionType`) vs `ActionType == 'Manual remediation'`.

Honest gaps (called out in the workbook): no `resolvedBy` actor on alerts/incidents; no API to
enumerate alert-tuning rules; no Graph `automatedInvestigations` object (state read off the
alert); `EmailPostDeliveryEvents.ActionResult` enum not publicly documented.

## 4. Workbook sheets

1. **Processing overview** - total MDO phishing load in the window, split Auto-resolved /
   Escalated / Auto-blocked, open vs resolved, FP/TP classification split, trend by day.
2. **Manual-review drivers** - for the escalated bucket only: top senders/domains, detection
   sources, and policies generating human-triage load.
3. **Automatic handling** - ZAP vs auto-remediation vs auto-resolve, confidence levels,
   delivery-action split.
4. **User-reported** - reported vs auto-detected, reported-but-benign, auto-adjudicated vs
   needs-admin-review.
5. **Raw data** (optional per source) - the pulled rows for drill-down/audit.
6. **README sheet** - scopes used, window, honest-proxy caveats, generated timestamp.

## 5. Script structure (monolith)

`Invoke-MDOPhishNoiseReport.ps1`, top to bottom:
1. `#Requires -Version 7.0`, comment-based help.
2. **Editable settings:** `$Upn`, `$Days` (default 30), `$OutputPath` (Desktop).
3. Module bootstrap: ensure `Microsoft.Graph.Authentication` + `ImportExcel` (TLS/NuGet/
   PSGallery hardening; clear error if it cannot install).
4. Connect: prompt for UPN if blank -> `Connect-MgGraph -Scopes ... -TenantId <domain>`.
5. `Invoke-MDOGraph` retry wrapper (429/503, Retry-After).
6. Pull functions per source, each wrapped so a missing scope / 403 / beta-unavailable
   **degrades gracefully** (that sheet shows a "not available - needs scope X" note; the rest
   still render).
7. Bucketing + aggregation in memory.
8. `Export-Excel` - one call per sheet, tables + a couple of charts, autosize.
9. Print the workbook path.

## 6. Error handling & degradation

- Read-only: no `-WhatIf` needed; nothing mutates the tenant.
- Per-source try/catch: a 403 (scope not consented) or beta-unavailable marks that source
  unavailable and annotates its sheet, rather than aborting the run.
- Transient Graph errors (429/503) retried with backoff honoring `Retry-After`.
- Advanced hunting 429 (CPU quota) -> back off and note partial data.

## 7. Testing

- Pure functions (bucketing, aggregation, ISO date window) unit-tested with Pester against
  canned alert/email objects - no network.
- Analyzer: `PSScriptAnalyzer` clean (0 Warnings/Errors); `PSAvoidUsingWriteHost` excluded
  (interactive tooling). Monolith, so no per-file line limit.
- Manual: run read-only against a tenant, confirm the workbook opens with all sheets.

## References
- alerts_v2 + investigationState: https://learn.microsoft.com/en-us/graph/api/resources/security-alert
- incidents: https://learn.microsoft.com/en-us/graph/api/security-list-incidents
- runHuntingQuery: https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery
- EmailEvents: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- EmailPostDeliveryEvents: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table
- emailThreatSubmission (beta): https://learn.microsoft.com/en-us/graph/api/resources/security-emailthreatsubmission?view=graph-rest-beta
- AIR auto-remediation: https://learn.microsoft.com/en-us/defender-office-365/air-auto-remediation
