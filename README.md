# MDOPhishNoiseReport

A single, **read-only** PowerShell 7 script that analyzes the Microsoft Defender for
Office 365 (MDO) phishing alert/incident load and categorizes it by **how Defender
processes each item** — auto-resolved vs escalated for manual review — then writes a
multi-sheet Excel workbook. It answers "where is the manual-review noise coming from" and
serves as the baseline for automating triage.

Nothing is written to the tenant. Reads only.

## Requirements

- PowerShell 7.0+
- `Microsoft.Graph.Authentication` and `ImportExcel` modules (auto-installed on first run)
- An admin with **Security Reader** (or higher)
- Graph delegated scopes (all read-only, admin-consent): `SecurityAlert.Read.All`,
  `SecurityIncident.Read.All`, `ThreatHunting.Read.All`, `ThreatSubmission.Read.All`

Any scope that isn't consented just makes its sheet(s) show a "not available" note — the
rest of the workbook still renders.

## Run

Edit `$Upn` at the top of the script to skip the prompt, or leave it blank and you'll be
asked. Then interactive sign-in follows.

```powershell
# allow scripts (one-time), if needed
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

.\Invoke-MDOPhishNoiseReport.ps1
.\Invoke-MDOPhishNoiseReport.ps1 -Upn admin@contoso.onmicrosoft.com -Days 14
.\Invoke-MDOPhishNoiseReport.ps1 -OutputPath C:\Reports\mdo.xlsx
```

The workbook is written to your Desktop by default and the path is printed at the end.

## Processing-path buckets

| Bucket | Signal |
|---|---|
| Auto-resolved | `investigationState ∈ {successfullyRemediated, benign, suppressedAlert}` |
| Auto-resolved (proxy) | `status=resolved` **and** no owner (no `resolvedBy` field exists) |
| Escalated (manual review) | `investigationState ∈ {pendingApproval, partiallyRemediated, …}` or `status ∈ {new, inProgress}` or an owner is set |
| Manual-resolved | `status=resolved` with an owner |
| Auto-blocked at delivery | `EmailEvents.DeliveryAction ∈ {Blocked, Junked, Replaced}` |

Honest gaps (noted in the workbook's **Info** sheet): no `resolvedBy` actor on
alerts/incidents; alert-tuning rules aren't API-enumerable; advanced-hunting email data
retains ~30 days.

## Sheets

Summary (buckets), classification split, trend by day, manual-review drivers (detection &
titles), noisy senders/domains, policy attribution, automatic handling (post-delivery,
delivery split, detection methods), user-reported, incidents, raw alerts, and an Info sheet.

## Data sources

- `GET /security/alerts_v2` (filtered to `serviceSource eq 'microsoftDefenderForOffice365'`)
- `GET /security/incidents?$expand=alerts`
- `POST /security/runHuntingQuery` (KQL over `EmailEvents`, `EmailPostDeliveryEvents`)
- `GET /beta/security/threatSubmission/emailThreats`

## Develop

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSScriptAnalyzerSettings.psd1
Invoke-Pester tests/
```
