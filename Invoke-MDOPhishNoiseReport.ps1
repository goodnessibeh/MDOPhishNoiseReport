#Requires -Version 7.0
<#
.SYNOPSIS
    Read-only analysis of the Microsoft Defender for Office 365 (MDO) phishing alert/incident
    load, categorized by how Defender processes each item (auto-resolved vs escalated for
    manual review), written to a multi-sheet Excel workbook.

.DESCRIPTION
    A single monolith script. It signs in with interactive delegated OAuth (Connect-MgGraph),
    pulls MDO alerts (alerts_v2), incidents, advanced-hunting email aggregates, and user
    submissions, buckets each item by processing path, and exports an Excel workbook with one
    sheet per analysis. Nothing is written to the tenant - reads only. Each data source
    degrades gracefully: a missing scope / 403 / beta-unavailable annotates that sheet and the
    rest still render.

.PARAMETER Upn
    Admin UPN to sign in with. EDIT the default below to skip the prompt, or leave blank to be
    prompted at run time. The tenant is derived from the UPN domain.

.PARAMETER Days
    Rolling window in days (default 30). Advanced-hunting email data is capped at 30 days.

.PARAMETER OutputPath
    Full path for the .xlsx. Defaults to the Desktop.

.EXAMPLE
    .\Invoke-MDOPhishNoiseReport.ps1
    .\Invoke-MDOPhishNoiseReport.ps1 -Upn admin@contoso.onmicrosoft.com -Days 14
#>
[CmdletBinding()]
param(
    # ---- EDIT HERE: set your admin UPN to skip the prompt, or leave '' to be prompted ----
    [string]$Upn = '',
    [int]$Days = 30,
    [string]$OutputPath = ''
)

$Script:MDOScopes = @(
    'SecurityAlert.Read.All',      # alerts_v2
    'SecurityIncident.Read.All',   # incidents
    'ThreatHunting.Read.All',      # advanced hunting (EmailEvents / EmailPostDeliveryEvents)
    'ThreatSubmission.Read.All'    # user submissions (beta)
)

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

function Write-MDOStatus {
    <# Consistent coloured status line (PSAvoidUsingWriteHost excluded in analyzer settings). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('OK', 'INFO', 'WARN', 'FAIL')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $colour = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Cyan' } }
    Write-Host ('  [{0,-4}] {1}' -f $Level, $Message) -ForegroundColor $colour
}

function Get-MDOProp {
    <# Safe property/key read (Graph returns hashtables); returns $Default when absent. #>
    [CmdletBinding()]
    [OutputType([object])]
    param($Object, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] } else { return $Default }
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value } else { return $Default }
}

function Initialize-MDOModule {
    <# Ensures a module is installed + imported, bootstrapping TLS/NuGet/PSGallery if needed. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if (Get-Module $Name) { return }
    if (Get-Module $Name -ListAvailable) { Import-Module $Name -ErrorAction Stop; return }

    Write-MDOStatus -Level INFO -Message "$Name not found - installing for the current user..."
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Scope CurrentUser -Force | Out-Null
        }
        Install-Module $Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
    }
    catch {
        throw "Could not install $Name automatically ($($_.Exception.Message)). Install it manually: Install-Module $Name -Scope CurrentUser -Force"
    }
    Import-Module $Name -ErrorAction Stop
}

function Connect-MDOGraph {
    <# Prompts for the UPN when blank, then connects interactively to that tenant. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$UserPrincipalName, [string[]]$Scopes)

    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        $UserPrincipalName = Read-Host 'Admin UPN (e.g. admin@contoso.onmicrosoft.com)'
    }
    if ($UserPrincipalName -notmatch '@') { throw "A valid admin UPN (name@domain) is required." }
    $domain = ($UserPrincipalName -split '@', 2)[1].Trim()

    $existing = Get-MgContext -ErrorAction SilentlyContinue
    if ($existing -and $existing.Account -and (($existing.Account -split '@', 2)[-1] -ne $domain)) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        $existing = $null
    }
    if (-not $existing) {
        Write-MDOStatus -Level INFO -Message "Sign in as '$UserPrincipalName' (or another admin of '$domain')."
        Connect-MgGraph -Scopes $Scopes -TenantId $domain -NoWelcome -ErrorAction Stop
    }
    Write-MDOStatus -Level OK -Message "Connected to '$domain'."
    return $domain
}

function Invoke-MDOGraph {
    <# GET wrapper with 429/503 retry honoring Retry-After. Returns the parsed response. #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)][string]$Uri, [int]$MaxRetries = 4)

    for ($attempt = 0; ; $attempt++) {
        try { return Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop }
        catch {
            $status = $null
            $resp = $_.Exception.Response
            if ($resp -and $resp.StatusCode) { $status = [int]$resp.StatusCode }
            if ($status -notin @(429, 503, 504) -or $attempt -ge $MaxRetries) {
                throw "Graph GET $Uri failed$(if ($status) { " (HTTP $status)" }): $($_.Exception.Message)"
            }
            $delay = [Math]::Min([Math]::Pow(2, $attempt), 30)
            if ($resp -and $resp.Headers -and $resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) {
                $delay = $resp.Headers.RetryAfter.Delta.TotalSeconds
            }
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-MDOGraphPaged {
    <# Follows @odata.nextLink and returns the concatenated .value collection. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$Uri)
    $items = @()
    $next = $Uri
    while ($next) {
        $page = Invoke-MDOGraph -Uri $next
        $items += @(Get-MDOProp $page 'value')
        $next = Get-MDOProp $page '@odata.nextLink'
    }
    return $items
}

function Invoke-MDOHunting {
    <# Runs an advanced-hunting KQL query; returns rows, or $null if the scope/endpoint is unavailable. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$Query, [int]$Days = 30)
    try {
        $body = @{ Query = $Query; Timespan = "P$([Math]::Min($Days, 30))D" } | ConvertTo-Json
        $resp = Invoke-MgGraphRequest -Method POST -Uri '/v1.0/security/runHuntingQuery' -Body $body -ContentType 'application/json' -ErrorAction Stop
        return @(Get-MDOProp $resp 'results')
    }
    catch {
        Write-MDOStatus -Level WARN -Message "Advanced hunting unavailable ($($_.Exception.Message))."
        return $null
    }
}

function Get-MDOBucket {
    <# Categorizes an alert by processing path from investigationState + status/assignedTo proxy. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$InvestigationState, [string]$Status, [string]$AssignedTo)

    $auto = @('successfullyRemediated', 'benign', 'suppressedAlert')
    $manual = @('pendingApproval', 'partiallyRemediated', 'partiallyInvestigated', 'pendingResource', 'queued', 'running')
    if ($InvestigationState -in $auto) { return 'Auto-resolved' }
    if ($InvestigationState -in $manual) { return 'Escalated (manual review)' }
    if ($Status -in @('new', 'inProgress')) { return 'Escalated (manual review)' }
    if ($Status -eq 'resolved' -and [string]::IsNullOrWhiteSpace($AssignedTo)) { return 'Auto-resolved (proxy)' }
    if ($Status -eq 'resolved') { return 'Manual-resolved' }
    return 'Uncategorized'
}

function Add-MDOSheet {
    <# Appends one worksheet (or a note row when there is no data) and returns the package. #>
    [CmdletBinding()]
    [OutputType([object])]
    param([object]$Package, [string]$Path, [Parameter(Mandatory)][string]$Name, $Data, [string]$Note)
    $rows = @($Data)
    if ($rows.Count -eq 0) {
        $rows = @([pscustomobject]@{ Note = $(if ($Note) { $Note } else { 'No data available for this section.' }) })
    }
    $table = ($Name -replace '[^0-9A-Za-z]', '')
    if ($null -eq $Package) {
        return ($rows | Export-Excel -Path $Path -WorksheetName $Name -AutoSize -TableName $table -PassThru)
    }
    return ($rows | Export-Excel -ExcelPackage $Package -WorksheetName $Name -AutoSize -TableName $table -PassThru)
}

# ---------------------------------------------------------------------------------------------
# Main (skipped when the script is dot-sourced, so the pure functions can be unit-tested)
# ---------------------------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {

Write-MDOStatus -Level INFO -Message "MDO Phishing Noise Report - window: last $Days day(s), read-only."

Initialize-MDOModule -Name 'Microsoft.Graph.Authentication'
Initialize-MDOModule -Name 'ImportExcel'

$null = Connect-MDOGraph -UserPrincipalName $Upn -Scopes $Script:MDOScopes
$since = (Get-Date).ToUniversalTime().AddDays(-1 * $Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$hd = [Math]::Min($Days, 30)

# ---- Alerts (MDO, in window) ----
$alertRows = @()
try {
    $filter = "serviceSource eq 'microsoftDefenderForOffice365' and createdDateTime ge $since"
    $uri = "/v1.0/security/alerts_v2?`$filter=$([uri]::EscapeDataString($filter))&`$top=100"
    $alerts = Get-MDOGraphPaged -Uri $uri
    Write-MDOStatus -Level OK -Message "Pulled $(@($alerts).Count) MDO alert(s)."
    $alertRows = foreach ($a in $alerts) {
        $st = [string](Get-MDOProp $a 'status'); $inv = [string](Get-MDOProp $a 'investigationState')
        $assn = [string](Get-MDOProp $a 'assignedTo')
        [pscustomobject]@{
            Created         = [string](Get-MDOProp $a 'createdDateTime')
            Title           = [string](Get-MDOProp $a 'title')
            Severity        = [string](Get-MDOProp $a 'severity')
            Status          = $st
            Classification  = [string](Get-MDOProp $a 'classification' 'unknown')
            Determination   = [string](Get-MDOProp $a 'determination' 'unknown')
            DetectionSource = [string](Get-MDOProp $a 'detectionSource')
            InvestigationState = $inv
            AssignedTo      = $assn
            Bucket          = Get-MDOBucket -InvestigationState $inv -Status $st -AssignedTo $assn
        }
    }
}
catch { Write-MDOStatus -Level WARN -Message "Alerts unavailable ($($_.Exception.Message))." }

# ---- Incidents (in window, MDO-linked) ----
$incidentRows = @()
try {
    $ifilter = "createdDateTime ge $since"
    $iuri = "/v1.0/security/incidents?`$filter=$([uri]::EscapeDataString($ifilter))&`$expand=alerts&`$top=50"
    $incidents = Get-MDOGraphPaged -Uri $iuri
    $incidentRows = foreach ($i in $incidents) {
        $ialerts = @(Get-MDOProp $i 'alerts')
        $isMdo = $ialerts | Where-Object { (Get-MDOProp $_ 'serviceSource') -eq 'microsoftDefenderForOffice365' }
        if (-not $isMdo) { continue }
        [pscustomobject]@{
            DisplayName    = [string](Get-MDOProp $i 'displayName')
            Severity       = [string](Get-MDOProp $i 'severity')
            Status         = [string](Get-MDOProp $i 'status')
            Classification = [string](Get-MDOProp $i 'classification' 'unknown')
            Determination  = [string](Get-MDOProp $i 'determination' 'unknown')
            AssignedTo     = [string](Get-MDOProp $i 'assignedTo')
            AlertCount     = @($ialerts).Count
        }
    }
    Write-MDOStatus -Level OK -Message "Pulled $(@($incidentRows).Count) MDO-linked incident(s)."
}
catch { Write-MDOStatus -Level WARN -Message "Incidents unavailable ($($_.Exception.Message))." }

# ---- Advanced hunting aggregates ----
$senders = Invoke-MDOHunting -Days $hd -Query @"
EmailEvents
| where Timestamp > ago(${hd}d) and EmailDirection == "Inbound" and ThreatTypes has "Phish"
| summarize Total=count(), Delivered=countif(DeliveryAction=="Delivered"), Blocked=countif(DeliveryAction=="Blocked"), Junked=countif(DeliveryAction=="Junked"), Replaced=countif(DeliveryAction=="Replaced") by SenderFromDomain
| top 30 by Total
"@

$delivery = Invoke-MDOHunting -Days $hd -Query @"
EmailEvents
| where Timestamp > ago(${hd}d) and ThreatTypes has "Phish"
| summarize Count=count() by DeliveryAction, DeliveryLocation
| sort by Count desc
"@

$detection = Invoke-MDOHunting -Days $hd -Query @"
EmailEvents
| where Timestamp > ago(${hd}d) and ThreatTypes has "Phish"
| summarize Count=count() by DetectionMethods, ConfidenceLevel
| sort by Count desc
"@

$policy = Invoke-MDOHunting -Days $hd -Query @"
EmailEvents
| where Timestamp > ago(${hd}d) and isnotempty(EmailActionPolicy)
| summarize Count=count() by EmailActionPolicy, OrgLevelPolicy, EmailAction
| top 30 by Count
"@

$postDelivery = Invoke-MDOHunting -Days $hd -Query @"
EmailPostDeliveryEvents
| where Timestamp > ago(${hd}d)
| summarize Count=count() by ActionType, ActionTrigger
| sort by Count desc
"@

# ---- User submissions (beta; graceful degrade) ----
$submissionRows = $null
try {
    $subs = Get-MDOGraphPaged -Uri '/beta/security/threatSubmission/emailThreats?$top=100'
    $submissionRows = foreach ($s in $subs) {
        $result = Get-MDOProp $s 'result'
        $adminReview = Get-MDOProp $s 'adminReview'
        [pscustomobject]@{
            Created          = [string](Get-MDOProp $s 'createdDateTime')
            Source           = [string](Get-MDOProp $s 'source')
            OriginalCategory = [string](Get-MDOProp $s 'originalCategory')
            ResultCategory   = [string](Get-MDOProp $result 'category')
            AdminReviewedBy  = [string](Get-MDOProp $adminReview 'reviewBy')
            Handling         = if (Get-MDOProp $adminReview 'reviewBy') { 'Manual review' } else { 'Auto-adjudicated' }
        }
    }
    Write-MDOStatus -Level OK -Message "Pulled $(@($submissionRows).Count) submission(s)."
}
catch { Write-MDOStatus -Level WARN -Message "Submissions (beta) unavailable ($($_.Exception.Message))." }

# ---- Aggregations ----
$total = @($alertRows).Count
$bucketSummary = @($alertRows) | Group-Object Bucket | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{ Bucket = $_.Name; Count = $_.Count; Percent = if ($total) { [math]::Round(100 * $_.Count / $total, 1) } else { 0 } }
}
$classSummary = @($alertRows) | Group-Object Classification | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{ Classification = $_.Name; Count = $_.Count }
}
$trend = @($alertRows) | Where-Object { $_.Created } |
    Group-Object { ([datetime]$_.Created).ToString('yyyy-MM-dd') } | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ Date = $_.Name; Alerts = $_.Count }
    }
$escalated = @($alertRows) | Where-Object { $_.Bucket -like 'Escalated*' }
$driversByDetection = $escalated | Group-Object DetectionSource | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{ DetectionSource = $_.Name; EscalatedCount = $_.Count }
}
$driversByTitle = $escalated | Group-Object Title | Sort-Object Count -Descending |
    Select-Object -First 30 | ForEach-Object { [pscustomobject]@{ AlertTitle = $_.Name; EscalatedCount = $_.Count } }

$info = @(
    [pscustomobject]@{ Item = 'Window (days)'; Value = "$Days (hunting capped at $hd)" }
    [pscustomobject]@{ Item = 'Generated (UTC)'; Value = (Get-Date).ToUniversalTime().ToString('u') }
    [pscustomobject]@{ Item = 'Scopes'; Value = ($Script:MDOScopes -join ', ') }
    [pscustomobject]@{ Item = 'Proxy note'; Value = 'No resolvedBy field exists; Auto-resolved (proxy) = resolved + no owner.' }
    [pscustomobject]@{ Item = 'Proxy note'; Value = 'Alert-tuning rules are not API-enumerable; investigationState=suppressedAlert is the nearest signal.' }
    [pscustomobject]@{ Item = 'Hunting note'; Value = 'EmailEvents/EmailPostDeliveryEvents retain ~30 days; empty sheets mean the scope was not consented or no matching data.' }
)

# ---- Workbook ----
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $desktop = [Environment]::GetFolderPath('Desktop'); if (-not $desktop) { $desktop = Join-Path $HOME 'Desktop' }
    $OutputPath = Join-Path $desktop ("MDO-Phish-Noise-Report-{0}.xlsx" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
}
Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue

$huntNote = 'Advanced hunting returned no data - the ThreatHunting.Read.All scope may not be consented, or there were no matching messages in the window.'
$subNote = 'Submissions unavailable - ThreatSubmission.Read.All (beta) may not be consented, or the beta endpoint is not available in this cloud.'

$pkg = $null
$pkg = Add-MDOSheet -Package $pkg -Path $OutputPath -Name 'Summary - buckets' -Data $bucketSummary -Note 'No MDO alerts in the window (or SecurityAlert.Read.All not consented).'
$pkg = Add-MDOSheet -Package $pkg -Name 'Summary - classification' -Data $classSummary
$pkg = Add-MDOSheet -Package $pkg -Name 'Trend by day' -Data $trend
$pkg = Add-MDOSheet -Package $pkg -Name 'Manual drivers - detection' -Data $driversByDetection
$pkg = Add-MDOSheet -Package $pkg -Name 'Manual drivers - titles' -Data $driversByTitle
$pkg = Add-MDOSheet -Package $pkg -Name 'Noisy senders' -Data $senders -Note $huntNote
$pkg = Add-MDOSheet -Package $pkg -Name 'Policy attribution' -Data $policy -Note $huntNote
$pkg = Add-MDOSheet -Package $pkg -Name 'Auto - post-delivery' -Data $postDelivery -Note $huntNote
$pkg = Add-MDOSheet -Package $pkg -Name 'Auto - delivery split' -Data $delivery -Note $huntNote
$pkg = Add-MDOSheet -Package $pkg -Name 'Detection methods' -Data $detection -Note $huntNote
$pkg = Add-MDOSheet -Package $pkg -Name 'User-reported' -Data $submissionRows -Note $subNote
$pkg = Add-MDOSheet -Package $pkg -Name 'Incidents' -Data $incidentRows
$pkg = Add-MDOSheet -Package $pkg -Name 'Alerts (raw)' -Data $alertRows
$pkg = Add-MDOSheet -Package $pkg -Name 'Info' -Data $info
Close-ExcelPackage $pkg

Write-MDOStatus -Level OK -Message "Workbook written: $OutputPath"

}
