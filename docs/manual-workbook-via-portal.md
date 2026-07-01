# Building the workbook manually via the Defender portal (no API / no admin consent)

This reproduces the same workbook by hand from the Microsoft Defender portal
(`https://security.microsoft.com`), using only exports and Excel. Use it when you can't or
don't want to grant the Graph admin consent the script needs.

**Start here:** download the blank template
[`templates/MDO-Phish-Noise-Report-Template.xlsx`](../templates/MDO-Phish-Noise-Report-Template.xlsx).
It already has every sheet with headers and a placeholder row - just paste each export over the
placeholder (keep the header row). Regenerate it any time with
`templates/New-MDOWorkbookTemplate.ps1`.

**Role required:** **Security Reader** is enough to view and **Export** every surface below
(also satisfied by Security Operator / Security Administrator / Global Reader). Security
Reader cannot *submit* messages or *schedule* report emails, but it can read and export
everything this guide uses.

> The advanced-hunting queries below are validated against Microsoft's `Kusto.Language`
> parser (the same grammar the portal uses) - paste them as-is.

## Sheet -> portal source map

| Workbook sheet | Portal source | Export |
|---|---|---|
| Summary - buckets / classification / trend | Alerts queue export (+ Excel pivots) | CSV, max 10,000 |
| Manual drivers - detection / titles | Alerts queue export, filtered to escalated | CSV |
| Noisy senders | Advanced hunting (KQL) | CSV/Excel, max 100,000 |
| Policy attribution | Advanced hunting (KQL) | CSV/Excel |
| Auto - post-delivery / delivery split / detection methods | Advanced hunting (KQL) | CSV/Excel |
| User-reported | Submissions > User reported | CSV |
| Incidents | Incidents queue export | CSV, max 10,000 |

---

## 1. Export the MDO alerts

1. Go to **Incidents & alerts > Alerts**.
2. **Filter > Service/detection sources > Microsoft Defender for Office 365**.
3. Set the **date range** (Custom range) to your window (e.g. last 30 days).
4. **Customize columns** and enable: Severity, Status, Classification, Investigation state
   (a.k.a. Automated investigation state), Category, Detection source, Service source,
   Assigned to, Created time, Title.
5. **Export** (top of the queue) -> CSV. (Cap: 10,000 rows; narrow the date range if you hit it.)
6. Open the CSV in Excel and rename the sheet **`Alerts (raw)`**.

## 2. Add the processing-path bucket column (Excel)

In a new column (e.g. `Bucket`), reproduce the script's logic. Portal exports use **display
names**, not API values, so match those. Adjust the cell references to your columns
(here: `E`=Status, `F`=Investigation state, `G`=Assigned to):

```excel
=IF(OR(F2="Remediated",F2="No threats found",F2="Benign",F2="Suppressed"),"Auto-resolved",
 IF(OR(F2="Pending approval",F2="Pending action",F2="Partially remediated",F2="Partially investigated",F2="Queued",F2="Running",F2="Pending resource"),"Escalated (manual review)",
 IF(OR(E2="New",E2="In progress"),"Escalated (manual review)",
 IF(AND(E2="Resolved",G2=""),"Auto-resolved (proxy)",
 IF(E2="Resolved","Manual-resolved","Uncategorized")))))
```

Fill it down the whole column. (`Auto-resolved (proxy)` = resolved with no owner - there is no
`resolvedBy` field, so this is a proxy, same caveat as the script.)

## 3. Build the Summary sheets (Excel pivot tables)

On the `Alerts (raw)` sheet, **Insert > PivotTable** three times:

- **Summary - buckets:** Rows = `Bucket`, Values = Count of Title. Add a % column.
- **Summary - classification:** Rows = `Classification`, Values = Count.
- **Trend by day:** Rows = `Created time` (right-click > Group > Days), Values = Count.

For **Manual drivers**, filter the pivot to `Bucket = "Escalated (manual review)"`:
- **Manual drivers - detection:** Rows = `Detection source`, Values = Count.
- **Manual drivers - titles:** Rows = `Title`, Values = Count (top 30).

## 4. Export the incidents

1. **Incidents & alerts > Incidents**.
2. **Filter > Service/detection sources > Microsoft Defender for Office 365**; set the date range.
3. **Customize columns**: Severity, Status, Classification, Determination, Assigned to,
   Active alerts.
4. **Export** -> CSV. Paste into a sheet named **`Incidents`**.

## 5. Advanced hunting -> senders / policy / auto-handling sheets

**Hunting > Advanced hunting**, paste each query, **Run**, then **Export > CSV** (or Excel).
Cap: 100,000 rows, last 30 days. Put each result on the named sheet.

**Noisy senders** ->  sheet `Noisy senders`
```kql
EmailEvents
| where Timestamp > ago(30d) and EmailDirection == "Inbound" and ThreatTypes has "Phish"
| summarize Total=count(), Delivered=countif(DeliveryAction=="Delivered"), Blocked=countif(DeliveryAction=="Blocked"), Junked=countif(DeliveryAction=="Junked"), Replaced=countif(DeliveryAction=="Replaced") by SenderFromDomain
| top 30 by Total
```

**Delivery split** (auto-blocked at delivery) -> sheet `Auto - delivery split`
```kql
EmailEvents
| where Timestamp > ago(30d) and ThreatTypes has "Phish"
| summarize Count=count() by DeliveryAction, DeliveryLocation
| sort by Count desc
```

**Detection methods** -> sheet `Detection methods`
```kql
EmailEvents
| where Timestamp > ago(30d) and ThreatTypes has "Phish"
| summarize Count=count() by DetectionMethods, ConfidenceLevel
| sort by Count desc
```

**Policy attribution** -> sheet `Policy attribution`
```kql
EmailEvents
| where Timestamp > ago(30d) and isnotempty(EmailActionPolicy)
| summarize Count=count() by EmailActionPolicy, OrgLevelPolicy, EmailAction
| top 30 by Count
```

**Post-delivery auto vs manual** -> sheet `Auto - post-delivery`
```kql
EmailPostDeliveryEvents
| where Timestamp > ago(30d)
| summarize Count=count() by ActionType, ActionTrigger
| sort by Count desc
```
`ActionTrigger == "Automation"` (or `ActionType` "Phish ZAP"/"Malware ZAP"/"Automated
Remediation") = automatic; `ActionType == "Manual remediation"` = analyst-driven.

## 6. Export user-reported messages

1. **Actions & submissions > Submissions** (direct: `/reportsubmission`), open the
   **User reported** tab (`?viewid=user`).
2. **Filter** by Date reported; optionally Reported reason = Phish.
3. **Export** -> CSV. Columns include Reported by, Sender, Reported reason, Result/verdict,
   Marked as (admin review). Put it on sheet **`User-reported`**.
   - Handling: rows with a **Marked as / Marked by** value = manual review; rows with only a
     Microsoft **Result** = auto-adjudicated.

## 7. Bonus - pre-aggregated reports (no KQL)

**Reports > Email & collaboration** (`/emailandcollabreport`) - each has an **Export**:
- **Threat protection status** - phishing volumes + detection-technology breakdown + delivery
  actions (View data by Email > Phish, Chart breakdown by Detection technology).
- **User reported messages** - Not junk / Phish / Spam counts (needs audit logging on).
- **Mailflow status summary** - blocked vs delivered volumes, incl. edge-blocked.

## 8. Assemble

Put every sheet into one workbook and name the tabs to match the script output: `Summary -
buckets`, `Summary - classification`, `Trend by day`, `Manual drivers - detection`, `Manual
drivers - titles`, `Noisy senders`, `Policy attribution`, `Auto - post-delivery`, `Auto -
delivery split`, `Detection methods`, `User-reported`, `Incidents`, `Alerts (raw)`, `Info`.

On an **`Info`** sheet, record the window, the date generated, and the honest caveats: no
`resolvedBy` field (proxy used), alert-tuning rules aren't API-enumerable, advanced-hunting
data retains ~30 days.

---

**Sources:** [Investigate alerts](https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts) ·
[Incident queue](https://learn.microsoft.com/en-us/defender-xdr/incident-queue) ·
[Export incidents/alerts](https://learn.microsoft.com/en-us/defender-xdr/export-incidents-queue) ·
[Advanced hunting results](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-results) ·
[Submissions](https://learn.microsoft.com/en-us/defender-office-365/submissions-admin) ·
[Email security reports](https://learn.microsoft.com/en-us/defender-office-365/reports-email-security)
