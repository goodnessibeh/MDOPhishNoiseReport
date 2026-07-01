#Requires -Version 7.0
<#
.SYNOPSIS
    Generates the blank MDO Phishing Noise Report Excel template (one labelled sheet per
    analysis, each with a header row + a placeholder row to paste exported content over).
.DESCRIPTION
    Run this to (re)create templates/MDO-Phish-Noise-Report-Template.xlsx. Requires ImportExcel.
    Fill the workbook by exporting each source from the Defender portal and pasting the rows
    over the blank placeholder row - see docs/manual-workbook-via-portal.md.
#>
[CmdletBinding()]
param([string]$OutputPath)

Import-Module ImportExcel -ErrorAction Stop

if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot 'MDO-Phish-Noise-Report-Template.xlsx' }
Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue

function Get-MDOPlaceholderRow {
    <# Returns a single blank [pscustomobject] whose properties are the given column headers. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string[]]$Column)
    $o = [ordered]@{}
    foreach ($c in $Column) { $o[$c] = '' }
    return [pscustomobject]$o
}

$bucketFormula = '=IF(OR(F2="Remediated",F2="No threats found",F2="Benign",F2="Suppressed"),"Auto-resolved",' +
    'IF(OR(F2="Pending approval",F2="Pending action",F2="Partially remediated",F2="Partially investigated",F2="Queued",F2="Running"),"Escalated (manual review)",' +
    'IF(OR(E2="New",E2="In progress"),"Escalated (manual review)",' +
    'IF(AND(E2="Resolved",G2=""),"Auto-resolved (proxy)",IF(E2="Resolved","Manual-resolved","Uncategorized")))))'

$info = @(
    [pscustomobject]@{ Field = 'How to use'; Detail = 'Export each source from the Defender portal (see docs/manual-workbook-via-portal.md) and paste the rows over the blank placeholder row on the matching sheet, keeping the header row.' }
    [pscustomobject]@{ Field = 'Window'; Detail = '<enter the date window you exported, e.g. last 30 days>' }
    [pscustomobject]@{ Field = 'Generated'; Detail = '<enter the date you built this>' }
    [pscustomobject]@{ Field = 'Bucket formula (Alerts raw, column H)'; Detail = $bucketFormula }
    [pscustomobject]@{ Field = 'Caveat'; Detail = 'No resolvedBy field exists; Auto-resolved (proxy) = resolved + no owner.' }
    [pscustomobject]@{ Field = 'Caveat'; Detail = 'Alert-tuning rules are not API-enumerable; investigation state = Suppressed is the nearest signal.' }
    [pscustomobject]@{ Field = 'Caveat'; Detail = 'Advanced-hunting email data retains ~30 days; max 100,000 rows per query.' }
)

# Sheet name -> ordered column headers for the placeholder row.
$sheets = [ordered]@{
    'Summary - buckets'         = @('Bucket', 'Count', 'Percent')
    'Summary - classification'  = @('Classification', 'Count')
    'Trend by day'              = @('Date', 'Alerts')
    'Manual drivers - detection' = @('DetectionSource', 'EscalatedCount')
    'Manual drivers - titles'   = @('AlertTitle', 'EscalatedCount')
    'Noisy senders'             = @('SenderFromDomain', 'Total', 'Delivered', 'Blocked', 'Junked', 'Replaced')
    'Policy attribution'        = @('EmailActionPolicy', 'OrgLevelPolicy', 'EmailAction', 'Count')
    'Auto - post-delivery'      = @('ActionType', 'ActionTrigger', 'Count')
    'Auto - delivery split'     = @('DeliveryAction', 'DeliveryLocation', 'Count')
    'Detection methods'         = @('DetectionMethods', 'ConfidenceLevel', 'Count')
    'User-reported'             = @('ReportedBy', 'Sender', 'ReportedReason', 'Result', 'MarkedAs', 'Handling')
    'Incidents'                 = @('DisplayName', 'Severity', 'Status', 'Classification', 'Determination', 'AssignedTo', 'AlertCount')
    'Alerts (raw)'              = @('Severity', 'Status', 'Classification', 'Investigation state', 'Category', 'Detection source', 'Service source', 'Assigned to', 'Created time', 'Title', 'Bucket')
}

$pkg = $info | Export-Excel -Path $OutputPath -WorksheetName 'Info' -AutoSize -TableName 'Info' -Title 'MDO Phishing Noise Report - manual template. Fill each sheet; see docs/manual-workbook-via-portal.md.' -TitleBold -PassThru

foreach ($name in $sheets.Keys) {
    $title = "Paste the exported rows over the blank row below (keep the header row). Sheet: $name"
    $table = ($name -replace '[^0-9A-Za-z]', '')
    Get-MDOPlaceholderRow -Column $sheets[$name] |
        Export-Excel -ExcelPackage $pkg -WorksheetName $name -AutoSize -TableName $table -Title $title -TitleBold -PassThru | Out-Null
}

Close-ExcelPackage $pkg
Write-Host "Template written: $OutputPath" -ForegroundColor Green
