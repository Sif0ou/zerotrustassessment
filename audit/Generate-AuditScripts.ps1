<#
.SYNOPSIS
    Generates individual PowerShell audit scripts for each Zero Trust security control.

.DESCRIPTION
    Reads the ZeroTrust-SecurityControls.csv and creates one .ps1 audit script per control
    under audit/scripts/<Pillar>/Audit-<TestId>.ps1

.EXAMPLE
    .\Generate-AuditScripts.ps1
    .\Generate-AuditScripts.ps1 -CsvPath .\ZeroTrust-SecurityControls.csv -OutputDir .\scripts
#>
[CmdletBinding()]
param(
    [string]$CsvPath = (Join-Path $PSScriptRoot 'ZeroTrust-SecurityControls.csv'),
    [string]$OutputDir = (Join-Path $PSScriptRoot 'scripts')
)

$ErrorActionPreference = 'Stop'

# ── Load controls ──────────────────────────────────────────────────────────
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV not found at $CsvPath"
    return
}

$controls = Import-Csv -Path $CsvPath -Encoding UTF8

Write-Host "Loaded $($controls.Count) controls from CSV" -ForegroundColor Cyan

# ── Audit‑logic templates per category / pillar ────────────────────────────
# Each template returns a scriptblock body string keyed on a pattern match.
# This provides meaningful audit logic rather than empty stubs.

$auditTemplates = @{
    # ── IDENTITY PILLAR ────────────────────────────────────────────────────
    'ConditionalAccess' = @'
    # Retrieve Conditional Access policies
    $policies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" |
        Select-Object -ExpandProperty value

    if (-not $policies) {
        $result.Status  = 'Fail'
        $result.Details = 'No Conditional Access policies found.'
        return $result
    }

    $enabledPolicies = $policies | Where-Object { $_.state -eq 'enabled' -or $_.state -eq 'enabledForReportingButNotEnforced' }
    $result.Details = "Found $($enabledPolicies.Count) / $($policies.Count) active Conditional Access policies."
    $result.Status  = if ($enabledPolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
    $result.RawData = $enabledPolicies
'@

    'PrivilegedAccess' = @'
    # Check privileged role assignments via PIM
    $roleAssignments = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" |
        Select-Object -ExpandProperty value

    $result.Details = "Found $($roleAssignments.Count) role assignments to review."
    $result.Status  = 'Review'
    $result.RawData = $roleAssignments
'@

    'ApplicationManagement' = @'
    # Retrieve app registrations
    $apps = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/applications?\$top=999" |
        Select-Object -ExpandProperty value

    $result.Details = "Found $($apps.Count) application registrations to review."
    $result.Status  = 'Review'
    $result.RawData = $apps
'@

    'CredentialManagement' = @'
    # Check authentication methods policy
    $authPolicy = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"

    $methods = $authPolicy.authenticationMethodConfigurations
    $enabledMethods = $methods | Where-Object { $_.state -eq 'enabled' }

    $result.Details = "Enabled authentication methods: $(($enabledMethods.id) -join ', ')"
    $result.Status  = 'Review'
    $result.RawData = $enabledMethods
'@

    'ExternalCollaboration' = @'
    # Check external collaboration settings
    $extSettings = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"

    $guestInvite = $extSettings.allowInvitesFrom
    $result.Details = "Guest invite setting: $guestInvite"
    $result.Status  = if ($guestInvite -eq 'adminsAndGuestInviters' -or $guestInvite -eq 'none') { 'Pass' } else { 'Review' }
    $result.RawData = $extSettings
'@

    'Monitoring' = @'
    # Check diagnostic settings for Entra ID
    $diag = $null
    try {
        $diag = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$top=1"
    } catch {
        $result.Status  = 'Fail'
        $result.Details = "Unable to query audit logs: $($_.Exception.Message)"
        return $result
    }

    $result.Details = 'Audit log access verified successfully.'
    $result.Status  = 'Pass'
'@

    # ── DEVICES PILLAR ─────────────────────────────────────────────────────
    'DeviceManagement' = @'
    # Check Intune device compliance policies
    $compliancePolicies = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" |
        Select-Object -ExpandProperty value

    $result.Details = "Found $($compliancePolicies.Count) compliance policies."
    $result.Status  = if ($compliancePolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
    $result.RawData = $compliancePolicies
'@

    # ── NETWORK PILLAR ─────────────────────────────────────────────────────
    'GlobalSecureAccess' = @'
    # Check Global Secure Access configuration
    # Note: Requires specific GSA permissions and endpoints
    $result.Details = 'Global Secure Access audit requires manual verification via Entra Admin Center > Global Secure Access.'
    $result.Status  = 'ManualCheck'
'@

    'AzureNetworkSecurity' = @'
    # Check Azure network security resources
    # Requires Az module: Install-Module Az.Network
    try {
        $firewalls = Get-AzFirewall -ErrorAction Stop
        $result.Details = "Found $($firewalls.Count) Azure Firewall(s)."
        $result.Status  = if ($firewalls.Count -gt 0) { 'Review' } else { 'Fail' }
        $result.RawData = $firewalls
    } catch {
        $result.Details = "Azure Firewall check requires Az.Network module and Azure authentication. Error: $($_.Exception.Message)"
        $result.Status  = 'ManualCheck'
    }
'@

    # ── DATA PILLAR ────────────────────────────────────────────────────────
    'SensitivityLabels' = @'
    # Check sensitivity labels configuration
    # Requires Security & Compliance PowerShell
    try {
        $labels = Get-Label -ErrorAction Stop
        $result.Details = "Found $($labels.Count) sensitivity labels configured."
        $result.Status  = if ($labels.Count -gt 0) { 'Pass' } else { 'Fail' }
        $result.RawData = $labels
    } catch {
        $result.Details = "Sensitivity labels check requires Security & Compliance PowerShell connection. Error: $($_.Exception.Message)"
        $result.Status  = 'ManualCheck'
    }
'@

    'InformationProtection' = @'
    # Check Information Protection policies
    try {
        $labelPolicies = Get-LabelPolicy -ErrorAction Stop
        $result.Details = "Found $($labelPolicies.Count) label policies."
        $result.Status  = if ($labelPolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
        $result.RawData = $labelPolicies
    } catch {
        $result.Details = "Information Protection check requires Security & Compliance PowerShell. Error: $($_.Exception.Message)"
        $result.Status  = 'ManualCheck'
    }
'@

    'DLP' = @'
    # Check DLP policies
    try {
        $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction Stop
        $result.Details = "Found $($dlpPolicies.Count) DLP policies."
        $result.Status  = if ($dlpPolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
        $result.RawData = $dlpPolicies
    } catch {
        $result.Details = "DLP check requires Security & Compliance PowerShell. Error: $($_.Exception.Message)"
        $result.Status  = 'ManualCheck'
    }
'@

    'RightsManagement' = @'
    # Check Azure Rights Management status
    try {
        $irmConfig = Get-AipServiceConfiguration -ErrorAction Stop
        $result.Details = "Azure RMS status: Enabled=$($irmConfig.RightsManagementServiceEnabled)"
        $result.Status  = if ($irmConfig.RightsManagementServiceEnabled) { 'Pass' } else { 'Fail' }
        $result.RawData = $irmConfig
    } catch {
        $result.Details = "RMS check requires AIPService module. Error: $($_.Exception.Message)"
        $result.Status  = 'ManualCheck'
    }
'@

    'Default' = @'
    # This control requires manual verification.
    # Refer to the Microsoft documentation for specific audit steps.
    $result.Details = 'This control requires manual verification. Check the Microsoft Entra / Intune / Purview admin portal.'
    $result.Status  = 'ManualCheck'
'@
}

# ── Map category text → template key ──────────────────────────────────────
function Get-TemplateKey {
    param([string]$Category, [string]$Pillar)

    switch -Regex ($Category) {
        'Access control'                 { return 'ConditionalAccess' }
        'Privileged'                     { return 'PrivilegedAccess' }
        'Application management|Tenant'  { return 'ApplicationManagement' }
        'Credential'                     { return 'CredentialManagement' }
        'External'                       { return 'ExternalCollaboration' }
        'Monitor'                        { return 'Monitoring' }
        'Device'                         { return 'DeviceManagement' }
        'Global Secure|Private Access|Network|Role management' { return 'GlobalSecureAccess' }
        'Azure Network'                  { return 'AzureNetworkSecurity' }
        'Sensitivity|Label'              { return 'SensitivityLabels' }
        'Information|OME|Advanced Label'  { return 'InformationProtection' }
        'DLP|Data Loss'                  { return 'DLP' }
        'Rights Management|Encryption'   { return 'RightsManagement' }
        'Data Security|Insider'          { return 'InformationProtection' }
        'Entra'                          { return 'ConditionalAccess' }
        'SharePoint'                     { return 'SensitivityLabels' }
        default                          { return 'Default' }
    }
}

# ── Generate scripts ──────────────────────────────────────────────────────
$generated = 0

foreach ($ctrl in $controls) {
    $pillarDir = Join-Path $OutputDir ($ctrl.Pillar -replace '[^a-zA-Z0-9]', '')
    if (-not (Test-Path $pillarDir)) { New-Item -Path $pillarDir -ItemType Directory -Force | Out-Null }

    $templateKey = Get-TemplateKey -Category $ctrl.Category -Pillar $ctrl.Pillar
    $auditBody   = $auditTemplates[$templateKey]

    $safeTitle = $ctrl.Title -replace "'", "''"
    $scriptContent = @"
<#
.SYNOPSIS
    Audit: $($ctrl.Title)

.DESCRIPTION
    Control ID  : $($ctrl.TestId)
    Pillar      : $($ctrl.Pillar)
    Category    : $($ctrl.Category)
    Risk Level  : $($ctrl.RiskLevel)
    Impl. Cost  : $($ctrl.ImplementationCost)

    Checks whether: $($ctrl.Title)

.NOTES
    Requires: Microsoft.Graph PowerShell SDK (Install-Module Microsoft.Graph)
    Some checks may also require: Az, ExchangeOnlineManagement, AIPService modules.

.EXAMPLE
    .\Audit-$($ctrl.TestId).ps1
    .\Audit-$($ctrl.TestId).ps1 -OutputFormat JSON
#>
[CmdletBinding()]
param(
    [ValidateSet('Console','JSON','CSV')]
    [string]`$OutputFormat = 'Console'
)

`$ErrorActionPreference = 'Continue'

# ── Result object ─────────────────────────────────────────────────────────
`$result = [PSCustomObject]@{
    TestId             = '$($ctrl.TestId)'
    Title              = '$safeTitle'
    Pillar             = '$($ctrl.Pillar)'
    Category           = '$($ctrl.Category)'
    RiskLevel          = '$($ctrl.RiskLevel)'
    ImplementationCost = '$($ctrl.ImplementationCost)'
    Status             = 'NotRun'   # Pass | Fail | Review | ManualCheck | NotRun | Error
    Details            = ''
    RawData            = `$null
    AuditDate          = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Auditor            = `$env:USERNAME
}

# ── Prerequisites check ──────────────────────────────────────────────────
try {
    `$null = Get-MgContext -ErrorAction Stop
} catch {
    Write-Warning "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'Directory.Read.All','Policy.Read.All','DeviceManagementConfiguration.Read.All'"
    `$result.Status  = 'Error'
    `$result.Details = 'Not connected to Microsoft Graph.'
}

# ── Audit logic ──────────────────────────────────────────────────────────
if (`$result.Status -ne 'Error') {
    try {
$auditBody
    } catch {
        `$result.Status  = 'Error'
        `$result.Details = "Audit error: `$(`$_.Exception.Message)"
    }
}

# ── Output ────────────────────────────────────────────────────────────────
switch (`$OutputFormat) {
    'JSON' {
        `$result | Select-Object TestId, Title, Pillar, Category, RiskLevel, Status, Details, AuditDate, Auditor |
            ConvertTo-Json -Depth 3
    }
    'CSV' {
        `$result | Select-Object TestId, Title, Pillar, Category, RiskLevel, Status, Details, AuditDate, Auditor |
            ConvertTo-Csv -NoTypeInformation
    }
    default {
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        Write-Host "Control  : [$($ctrl.TestId)] $($ctrl.Title)" -ForegroundColor White
        Write-Host "Pillar   : $($ctrl.Pillar) | Risk: $($ctrl.RiskLevel)" -ForegroundColor Gray

        `$statusColor = switch (`$result.Status) {
            'Pass'        { 'Green' }
            'Fail'        { 'Red' }
            'Review'      { 'Yellow' }
            'ManualCheck' { 'Cyan' }
            'Error'       { 'Magenta' }
            default       { 'Gray' }
        }
        Write-Host "Status   : `$(`$result.Status)" -ForegroundColor `$statusColor
        Write-Host "Details  : `$(`$result.Details)" -ForegroundColor Gray
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    }
}

return `$result
"@

    $scriptPath = Join-Path $pillarDir "Audit-$($ctrl.TestId).ps1"
    Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8 -Force
    $generated++
}

Write-Host "`n✅ Generated $generated audit scripts in: $OutputDir" -ForegroundColor Green
Write-Host "   Pillars:" -ForegroundColor Cyan
Get-ChildItem -Path $OutputDir -Directory | ForEach-Object {
    $count = (Get-ChildItem -Path $_.FullName -Filter '*.ps1').Count
    Write-Host "   - $($_.Name): $count scripts" -ForegroundColor White
}
