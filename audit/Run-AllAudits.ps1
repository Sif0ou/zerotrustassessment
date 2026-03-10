<#
.SYNOPSIS
    Runs all Zero Trust audit scripts and produces a consolidated Excel/CSV report.

.DESCRIPTION
    Executes every Audit-*.ps1 script generated under audit/scripts/<Pillar>/
    and aggregates results into a single report.

.PARAMETER ScriptsDir
    Directory containing the pillar sub-folders with audit scripts.

.PARAMETER OutputPath
    Path for the output report file (.csv or .xlsx if ImportExcel is installed).

.PARAMETER Pillar
    (Optional) Run only scripts for a specific pillar: Identity, Devices, Network, Data.

.PARAMETER RiskLevel
    (Optional) Run only scripts matching a risk level: High, Medium, Low.

.PARAMETER ExportExcel
    If set, exports to .xlsx using the ImportExcel module (auto-installed if missing).

.EXAMPLE
    .\Run-AllAudits.ps1
    .\Run-AllAudits.ps1 -Pillar Identity -RiskLevel High
    .\Run-AllAudits.ps1 -ExportExcel
#>
[CmdletBinding()]
param(
    [string]$ScriptsDir  = (Join-Path $PSScriptRoot 'scripts'),
    [string]$OutputPath  = (Join-Path $PSScriptRoot "ZeroTrust-AuditReport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    [ValidateSet('Identity','Devices','Network','Data','')]
    [string]$Pillar = '',
    [ValidateSet('High','Medium','Low','')]
    [string]$RiskLevel = '',
    [switch]$ExportExcel
)

$ErrorActionPreference = 'Continue'

# ── Banner ────────────────────────────────────────────────────────────────
Write-Host @"

 ╔══════════════════════════════════════════════════════════╗
 ║        Zero Trust Security Assessment - Audit Runner    ║
 ║        $(Get-Date -Format 'yyyy-MM-dd HH:mm')                                 ║
 ╚══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# ── Discover scripts ──────────────────────────────────────────────────────
$searchPath = if ($Pillar) { Join-Path $ScriptsDir $Pillar } else { $ScriptsDir }
if (-not (Test-Path $searchPath)) {
    Write-Error "Scripts directory not found: $searchPath. Run Generate-AuditScripts.ps1 first."
    return
}

$scripts = Get-ChildItem -Path $searchPath -Filter 'Audit-*.ps1' -Recurse | Sort-Object Name
Write-Host "Found $($scripts.Count) audit scripts" -ForegroundColor White

# ── Prerequisites ─────────────────────────────────────────────────────────
Write-Host "`nChecking Microsoft Graph connection..." -ForegroundColor Yellow
try {
    $ctx = Get-MgContext -ErrorAction Stop
    if ($ctx) {
        Write-Host "  Connected as: $($ctx.Account) | TenantId: $($ctx.TenantId)" -ForegroundColor Green
    } else {
        Write-Warning "  Not connected to Microsoft Graph. Some audits will fail."
        Write-Host "  Run: Connect-MgGraph -Scopes 'Directory.Read.All','Policy.Read.All','DeviceManagementConfiguration.Read.All'" -ForegroundColor Yellow
    }
} catch {
    Write-Warning "  Microsoft Graph SDK not available. Install: Install-Module Microsoft.Graph"
}

# ── Execute audits ────────────────────────────────────────────────────────
$allResults = [System.Collections.Generic.List[PSObject]]::new()
$total      = $scripts.Count
$current    = 0
$passed     = 0
$failed     = 0
$review     = 0
$manual     = 0
$errors     = 0

foreach ($script in $scripts) {
    $current++
    $pct = [math]::Round(($current / $total) * 100)
    Write-Progress -Activity "Running Zero Trust Audits" -Status "$current / $total - $($script.BaseName)" -PercentComplete $pct

    try {
        $r = & $script.FullName -OutputFormat JSON 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue

        if (-not $r) {
            $r = [PSCustomObject]@{
                TestId    = ($script.BaseName -replace 'Audit-','')
                Title     = ''
                Pillar    = $script.Directory.Name
                Category  = ''
                RiskLevel = ''
                Status    = 'Error'
                Details   = 'Script returned no output'
                AuditDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Auditor   = $env:USERNAME
            }
        }

        # Filter by risk level if specified
        if ($RiskLevel -and $r.RiskLevel -ne $RiskLevel) { continue }

        $allResults.Add($r)

        switch ($r.Status) {
            'Pass'        { $passed++ }
            'Fail'        { $failed++ }
            'Review'      { $review++ }
            'ManualCheck' { $manual++ }
            'Error'       { $errors++ }
        }
    } catch {
        $errors++
        $allResults.Add([PSCustomObject]@{
            TestId    = ($script.BaseName -replace 'Audit-','')
            Title     = ''
            Pillar    = $script.Directory.Name
            Category  = ''
            RiskLevel = ''
            Status    = 'Error'
            Details   = $_.Exception.Message
            AuditDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Auditor   = $env:USERNAME
        })
    }
}

Write-Progress -Activity "Running Zero Trust Audits" -Completed

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host "`n═══════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " AUDIT SUMMARY" -ForegroundColor White
Write-Host "═══════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " Total controls audited : $($allResults.Count)" -ForegroundColor White
Write-Host " Pass                   : $passed" -ForegroundColor Green
Write-Host " Fail                   : $failed" -ForegroundColor Red
Write-Host " Needs Review           : $review" -ForegroundColor Yellow
Write-Host " Manual Check Required  : $manual" -ForegroundColor Cyan
Write-Host " Errors                 : $errors" -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════" -ForegroundColor DarkGray

# ── Export results ────────────────────────────────────────────────────────
$exportData = $allResults | Select-Object TestId, Title, Pillar, Category, RiskLevel, Status, Details, AuditDate, Auditor

if ($ExportExcel) {
    # Try ImportExcel module
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Host "`nInstalling ImportExcel module..." -ForegroundColor Yellow
        Install-Module ImportExcel -Force -Scope CurrentUser
    }

    $xlsxPath = "$OutputPath.xlsx"
    $exportData | Export-Excel -Path $xlsxPath -AutoSize -AutoFilter `
        -WorksheetName 'Audit Results' `
        -Title 'Zero Trust Security Assessment - Audit Report' `
        -TitleBold `
        -ConditionalText $(
            New-ConditionalText -Text 'Fail' -BackgroundColor '#FF6B6B' -ConditionalTextColor White
            New-ConditionalText -Text 'Pass' -BackgroundColor '#51CF66' -ConditionalTextColor White
            New-ConditionalText -Text 'Review' -BackgroundColor '#FFD43B' -ConditionalTextColor Black
            New-ConditionalText -Text 'Error' -BackgroundColor '#CC5DE8' -ConditionalTextColor White
            New-ConditionalText -Text 'ManualCheck' -BackgroundColor '#74C0FC' -ConditionalTextColor Black
        )

    # Add summary sheet
    $summary = @(
        [PSCustomObject]@{ Metric = 'Total Controls'; Value = $allResults.Count }
        [PSCustomObject]@{ Metric = 'Pass'; Value = $passed }
        [PSCustomObject]@{ Metric = 'Fail'; Value = $failed }
        [PSCustomObject]@{ Metric = 'Needs Review'; Value = $review }
        [PSCustomObject]@{ Metric = 'Manual Check'; Value = $manual }
        [PSCustomObject]@{ Metric = 'Errors'; Value = $errors }
        [PSCustomObject]@{ Metric = 'Audit Date'; Value = (Get-Date -Format 'yyyy-MM-dd HH:mm') }
        [PSCustomObject]@{ Metric = 'Auditor'; Value = $env:USERNAME }
    )
    $summary | Export-Excel -Path $xlsxPath -AutoSize -WorksheetName 'Summary' -Append

    Write-Host "`nExcel report saved: $xlsxPath" -ForegroundColor Green
} else {
    $csvPath = "$OutputPath.csv"
    $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nCSV report saved: $csvPath" -ForegroundColor Green
}

# ── Return results for pipeline use ──────────────────────────────────────
return $allResults
