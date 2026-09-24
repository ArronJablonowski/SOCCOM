# Dependency-free regression suite. All network and Active Directory calls are mocked.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'SOCCOM.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors) { throw ($parseErrors.Message -join "`n") }
# Load function definitions without executing the CLI, creating outputs, or importing modules.
$ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$script:testCount = 0
function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "$Message -- expected [$Expected], got [$Actual]" }
    $script:testCount++
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    Assert-Equal $threw $true $Message
}
function Invoke-Item { param($LiteralPath, $Path) }
function Start-Sleep { param($Seconds, $s) }
function Clear-Host {}
function Invoke-WebRequest { throw 'Unexpected network request in offline test' }
function Invoke-RestMethod { throw 'Unexpected network request in offline test' }
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('soccom-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$originalLocation = Get-Location
$keyNames = 'SOCCOM_URLSCAN_API_KEY','SOCCOM_VIRUSTOTAL_API_KEY','SOCCOM_APIVOID_API_KEY','SOCCOM_URLVOID_API_KEY','SOCCOM_ABUSEIPDB_API_KEY'
$savedKeys = @{}
foreach ($name in $keyNames) {
    $savedKeys[$name] = [Environment]::GetEnvironmentVariable($name)
    [Environment]::SetEnvironmentVariable($name, $null)
}
try {
    Set-Location $testRoot
    Assert-Equal (ConvertTo-SafeReportUrl 'javascript:alert(1)') '' 'Script URLs rejected'
    Assert-Equal (ConvertTo-SafeReportUrl 'data:text/html,test') '' 'Data URLs rejected'
    Assert-Equal (ConvertTo-SafeReportUrl 'https://example.com/a') 'https://example.com/a' 'HTTPS URLs accepted'
    Assert-Equal (New-ReportLink 'unsafe' 'javascript:alert(1)') $null 'Unsafe provider link omitted'
    Assert-Equal (Test-IPAddress '8.8.8.8') $true 'IPv4 accepted'
    Assert-Equal (Test-IPAddress '2001:db8::1') $true 'IPv6 accepted'
    foreach ($value in '1234','127.1','0x7f000001','0177.0.0.1','999.1.1.1') {
        Assert-Equal (Test-IPAddress $value) $false "Reject ambiguous or invalid IP $value"
    }
    Assert-Equal (Get-DomainOnly 'https://www.example.com/path') 'www.example.com' 'Do not change investigated hostname'
    Assert-Equal (Get-DomainOnly 'ftp://files.example.com/path') 'files.example.com' 'Parse URI scheme correctly'
    Assert-Equal (Get-DomainOnly 'https://bücher.example/path') 'xn--bcher-kva.example' 'IDN hostname is normalized'
    Assert-Equal (Get-InvestigationReportName 'https://example.com/path?a,b') 'example.com' 'URL filename uses hostname'
    Assert-Equal (ConvertTo-SafeFileName 'a<>:"/\|?*b') 'a_________b' 'Cross-platform filename characters'
    Assert-Equal (ConvertTo-SafeFileName '...') 'investigation' 'Empty normalized filename gets fallback'
    Assert-Equal (ConvertTo-SafeFileName 'CON.txt') '_CON.txt' 'Reserved device filename gets prefix'
    Assert-Equal ((New-TimestampedReportFileName 'example') -ne (New-TimestampedReportFileName 'example')) $true 'Repeated report names are unique'
    Assert-Equal (Test-IPInCidr ([Net.IPAddress]::Parse('2001:db8::1')) '2001:db8::/32') $true 'IPv6 CIDR matching'
    Assert-Equal (Test-IPInCidr ([Net.IPAddress]::Parse('8.8.8.8')) '8.8.4.0/24') $false 'IPv4 nonmatch'
    Assert-Equal (ConvertTo-LdapFilterValue "o'brien*(x)\") "o'brien\2a\28x\29\5c" 'LDAP values escaped literally'

    $listPath = Join-Path $testRoot 'indicators[1].txt'
    @(' 8.8.8.8 ', '', '  ', ' https://example.com/a,b ') | Set-Content -LiteralPath $listPath
    $list = @(Get-SoccomInputList $listPath)
    Assert-Equal $list.Count 2 'Blank list lines ignored and brackets in path preserved'
    Assert-Equal $list[0] '8.8.8.8' 'List entries trimmed'
    Assert-Equal $list[1] 'https://example.com/a,b' 'URL list entry preserved'
    Set-Content -LiteralPath $listPath -Value '   '
    Assert-Throws { Get-SoccomInputList $listPath } 'Empty list rejected'
    Assert-Throws { Get-SoccomInputList (Join-Path $testRoot 'missing.txt') } 'Missing list rejected'

    $logFilePath = Join-Path $testRoot 'queue.csv'
    'Domain,URLScanResult,VirusTotalScanID' | Set-Content -LiteralPath $logFilePath -Encoding UTF8
    & {
        function UrlScan { 'https://urlscan.io/result/test/' }
        function SubmitVirusTotalURL { 'scan-id' }
        $original = 'https://example.com/a,b?x="quoted"&q=é'
        checkDomain $original
        checkIPAddress '2001:db8::1'
        $rows = @(Import-Csv -LiteralPath $logFilePath)
        Assert-Equal $rows.Count 2 'Queue contains both records'
        Assert-Equal $rows[0].Domain $original 'URL CSV round trip preserves commas quotes and Unicode'
        Assert-Equal $rows[0].URLScanResult 'https://urlscan.io/result/test/' 'URLScan ID column preserved'
        Assert-Equal $rows[0].VirusTotalScanID 'scan-id' 'VirusTotal ID column preserved'
        Assert-Equal $rows[1].Domain '2001:db8::1' 'IP CSV round trip'
    }

    $apikeyUrlScan = ''; $apikeyVirusTotal = ''; $apiKeyAPIVoid = ''; $apikeyAbuseIPDB = ''
    Assert-Equal (UrlScan 'example.com') 'Null_Value' 'Missing URLScan key skips submission'
    Assert-Equal (SubmitVirusTotalURL 'example.com') 'Null_Value' 'Missing VirusTotal key skips submission'
    $apikeyVirusTotal = 'test'; $apiKeyAPIVoid = 'test'; $apikeyAbuseIPDB = 'test'
    & {
        function Invoke-RestMethod { throw 'Mocked provider outage' }
        $failedAbuse = Get-AbuseIPReport '8.8.8.8'
        Assert-Equal $failedAbuse.LookupSucceeded $false 'AbuseIPDB outage marked unavailable'
        Assert-Equal (Get-URLVoidReport 'example.com').Count 'n/a' 'APIVoid outage is not zero detections'
        $script:ReportIndicators = New-Object System.Collections.ArrayList
        function Get-WhoIsIPAddressText { '' }
        function Get-VirusTotalIPReport { throw 'Mocked VT outage' }
        IPScanInfo '8.8.8.8'
        $reportPath = Join-Path $testRoot 'report[1].html'
        Write-ModernHtmlReport -Path $reportPath
        $html = Get-Content -LiteralPath $reportPath -Raw
        Assert-Equal $html.Contains('Lookup unavailable') $true 'HTML labels failed AbuseIPDB query unavailable'
        Assert-Equal $html.Contains('No active match') $false 'HTML does not imply a failed query was clean'
    }
    & {
        function Invoke-RestMethod { [pscustomobject]@{} }
        Assert-Equal (Get-AbuseIPReport '8.8.8.8').LookupSucceeded $false 'Empty AbuseIPDB response is unavailable'
        Assert-Equal (Get-URLVoidReport 'example.com').Count 'n/a' 'Empty APIVoid response is unavailable'
    }
    & {
        function Invoke-RestMethod {
            [pscustomobject]@{ data = [pscustomobject]@{ abuseConfidenceScore=0; totalReports=0 } }
        }
        $clean = Get-AbuseIPReport '8.8.8.8'
        Assert-Equal $clean.LookupSucceeded $true 'Successful clean response recognized'
        Assert-Equal $clean.Score 0 'Genuine zero score preserved'
    }
    & {
        function Invoke-RestMethod {
            [pscustomobject]@{ blacklists = [pscustomobject]@{ detections=0; engines=[pscustomobject]@{} } }
        }
        Assert-Equal (Get-URLVoidReport 'example.com').Count '0' 'Successful zero APIVoid detections preserved'
    }
    & {
        function Get-VirusTotalURLReport { [pscustomobject]@{ response_code=-2; verbose_msg='queued' } }
        Assert-Equal (Get-VirusTotalUrlSummary 'scan-id').Ratio 'n/a' 'Pending VT report is unavailable'
    }
    & {
        function Get-VirusTotalURLReport { [pscustomobject]@{ response_code=1; positives=0; total=90; permalink='https://example.com/report' } }
        Assert-Equal (Get-VirusTotalUrlSummary 'scan-id').Ratio '0 / 90' 'Completed VT report retained'
    }
    & {
        function Get-UrlScanResult { $null }
        function Get-VirusTotalUrlSummary { [pscustomobject]@{Ratio='n/a'} }
        function Get-URLVoidReport { [pscustomobject]@{Count='n/a';Detections='n/a';DomainRegistration='Unknown'} }
        function Get-WhoIsDomainText { '<script>alert(1)</script>' }
        $script:ReportIndicators = New-Object System.Collections.ArrayList
        URLScanInfo 'https://www.example.com/a,b?<tag>' $null 'Null_Value'
        $script:ReportIndicators[0].Screenshot = 'javascript:alert(1)'
        $script:ReportIndicators[0].PrimaryHref = 'data:text/html,unsafe'
        $script:ReportIndicators[0].Links = @([pscustomobject]@{Label='bad';Href='javascript:alert(1)'})
        $reportPath = Join-Path $testRoot 'domain.html'
        Write-ModernHtmlReport $reportPath
        $html = Get-Content -LiteralPath $reportPath -Raw
        Assert-Equal $html.Contains('&lt;script&gt;alert(1)&lt;/script&gt;') $true 'API-sourced report text is escaped'
        Assert-Equal $html.Contains('https://www.example.com/a,b?&lt;tag&gt;') $true 'Indicator text is escaped'
        Assert-Equal $html.Contains('javascript:') $false 'Renderer rejects unsafe links and screenshots'
        Assert-Equal $html.Contains('data:text/html') $false 'Renderer rejects unsafe primary link'
    }

    $installDirectory = Join-Path $testRoot 'install[1]'
    New-Item -ItemType Directory $installDirectory | Out-Null
    $installedScript = Join-Path $installDirectory 'SOCCOM.ps1'
    $originalScript = 'param([string]$Investigate) # original'
    Set-Content -LiteralPath $installedScript -Value $originalScript
    & {
        function Invoke-WebRequest { param($Uri,$OutFile) Set-Content -LiteralPath $OutFile -Value 'param([string]$Investigate) # updated' }
        UpdateSOCCOM -ScriptPath $installedScript
        Assert-Equal ((Get-Content -LiteralPath $installedScript -Raw).Trim()) 'param([string]$Investigate) # updated' 'Updater replaces installed script from other directory'
        $backups = @(Get-ChildItem -LiteralPath $installDirectory -Filter 'SOCCOM.backup_*.ps1')
        Assert-Equal $backups.Count 1 'Updater creates backup'
        Assert-Equal ((Get-Content -LiteralPath $backups[0].FullName -Raw).Trim()) $originalScript 'Backup preserves original script'
        Assert-Equal (Test-Path -LiteralPath (Join-Path $testRoot 'SOCCOM.ps1')) $false 'Updater does not write into working directory'
    }
    & {
        function Invoke-WebRequest { param($Uri,$OutFile) Set-Content -LiteralPath $OutFile -Value 'param(' }
        $before = Get-Content -LiteralPath $installedScript -Raw
        Assert-Throws { UpdateSOCCOM -ScriptPath $installedScript } 'Invalid update rejected'
        Assert-Equal (Get-Content -LiteralPath $installedScript -Raw) $before 'Invalid download leaves installation unchanged'
        Assert-Equal @(Get-ChildItem -LiteralPath $installDirectory -Filter 'SOCCOM.update_*.ps1').Count 0 'Invalid update temp file removed'
    }
    & {
        function Invoke-WebRequest { param($Uri,$OutFile) Set-Content -LiteralPath $OutFile -Value 'param([string]$Investigate) # replacement' }
        function Copy-Item { throw 'Mocked backup permission failure' }
        $before = Get-Content -LiteralPath $installedScript -Raw
        Assert-Throws { UpdateSOCCOM -ScriptPath $installedScript } 'Backup failure stops update'
        Assert-Equal (Get-Content -LiteralPath $installedScript -Raw) $before 'Backup failure leaves installation unchanged'
    }
    & {
        function Invoke-WebRequest { throw 'Mocked network failure' }
        Assert-Throws { UpdateSOCCOM -ScriptPath $installedScript } 'Download failure reported'
        Assert-Equal @(Get-ChildItem -LiteralPath $installDirectory -Filter 'SOCCOM.update_*.ps1').Count 0 'Failed download temp files removed'
    }

    & {
        function Get-ADComputer { throw 'Mocked missing computer' }
        function Get-ADObject { throw 'MUST NOT QUERY RECOVERY OBJECTS' }
        $message = ''
        try { Get_BitlockerRecoveryKey 'missing' } catch { $message = $_.Exception.Message }
        Assert-Equal $message 'Mocked missing computer' 'BitLocker stops if computer lookup fails'
    }
    # Real CLI integration, with OS-opening and network calls blocked above.
    $command = Get-Command $sourcePath
    Assert-Equal $command.Parameters.ContainsKey('SOCCOM_Update') $true 'Update switch is callable'
    Assert-Equal ($command.Parameters.Search_ADUsername.Aliases -contains 'SearchAD_Username') $true 'Documented AD alias accepted'
    Assert-Throws { & $sourcePath -Search_ADUsername '   ' } 'Blank AD query rejected before searching'
    New-Item -ItemType Directory Results,Logs -Force | Out-Null
    Set-Content -LiteralPath './Results/Report.html' -Value 'existing report'
    Set-Content -LiteralPath './Logs/LogFile.csv' -Value 'existing queue'
    & $sourcePath -Make_IRTemplate | Out-Null
    & $sourcePath -Make_IRTemplate | Out-Null
    Assert-Equal @(Get-ChildItem -LiteralPath './Investigations' -Filter '*.md').Count 2 'Repeated notes creation does not overwrite'
    Assert-Equal ((Get-Content -LiteralPath './Results/Report.html' -Raw).Trim()) 'existing report' 'Unrelated runs preserve existing report'
    Assert-Equal ((Get-Content -LiteralPath './Logs/LogFile.csv' -Raw).Trim()) 'existing queue' 'Unrelated runs preserve existing queue'
    Assert-Equal @(Get-ChildItem -LiteralPath './Logs' -Filter 'LogFile_*.csv').Count 0 'Notes command creates no scan queue'

    & {
        # Mock imports only for AD. Keep the bundled module's real import covered.
        function Import-Module {
            param([Parameter(ValueFromPipeline=$true)]$Name, [switch]$Force)
            process { if ($Name -ne 'ActiveDirectory') { Microsoft.PowerShell.Core\Import-Module $Name -Force:$Force } }
        }
        function Get-ADUser {
            param($LDAPFilter,$Properties)
            [void]$seenFilters.Add($LDAPFilter)
            [pscustomobject]@{SamAccountName="o'brien"; MemberOf=@()}
        }
        $seenFilters = New-Object System.Collections.Generic.List[string]
        Set-Content -LiteralPath './users[1].txt' -Value @(' ', " o'brien ")
        Set-Content -LiteralPath './Results/UsersNotFoundList.csv' -Value 'stale miss'
        & $sourcePath -SearchAD_UserList './users[1].txt' | Out-Null
        Assert-Equal $seenFilters.Count 1 'AD list skips blank lines'
        Assert-Equal $seenFilters[0] "(sAMAccountName=o'brien)" 'AD apostrophe query stays literal'
        Assert-Equal (Test-Path -LiteralPath './Results/UsersNotFoundList.csv') $false 'Stale AD misses removed'
        Assert-Equal @(Import-Csv -LiteralPath './Results/UserList.csv').Count 1 'AD results exported'
        function Get-ADUser { param($LDAPFilter,$Properties) }
        & $sourcePath -Search_ADUsername 'missing' | Out-Null
        Assert-Equal $? $true 'Missing AD user does not crash group formatting'
        & $sourcePath -Search_ADUserList './users[1].txt' | Out-Null
        Assert-Equal ((Get-Content -LiteralPath './Results/UsersNotFoundList.csv' -Raw).Trim()) "o'brien" 'Current AD misses written'
        Set-Content -LiteralPath './Results/UserList.csv' -Value 'previous results'
        Assert-Throws { & $sourcePath -Search_ADUserList './missing-users.txt' } 'Missing AD list fails clearly'
        Assert-Equal ((Get-Content -LiteralPath './Results/UserList.csv' -Raw).Trim()) 'previous results' 'Invalid AD list preserves previous results'
    }
    & {
        function Invoke-RestMethod { throw 'Mocked offline RDAP failure' }
        Set-Content -LiteralPath './mixed[1].txt' -Value @(' 8.8.8.8 ', '', ' https://www.example.com/a,b?x="quoted" ')
        & $sourcePath -Investigate_List './mixed[1].txt' | Out-Null
        $reports = @(Get-ChildItem -LiteralPath './Results' -Filter 'mixed*.html')
        Assert-Equal $reports.Count 1 'Mixed list writes one combined report'
        $html = Get-Content -LiteralPath $reports[0].FullName -Raw
        Assert-Equal ([regex]::Matches($html, '<article class="indicator-card"').Count) 2 'Mixed report contains two indicators'
        Assert-Equal $html.Contains('https://www.example.com/a,b?x=&quot;quoted&quot;') $true 'Full CLI preserves URL through queue and renderer'
        Assert-Equal $html.Contains('Lookup unavailable') $true 'Full CLI renders missing-key provider state'
        Assert-Equal @(Get-ChildItem -LiteralPath './Logs' -Filter 'LogFile_*.csv').Count 0 'Successful investigation cleans its own queue'
        Assert-Equal ((Get-Content -LiteralPath './Logs/LogFile.csv' -Raw).Trim()) 'existing queue' 'Investigation preserves another run queue'
        & $sourcePath -Investigate '2001:db8::1' | Out-Null
        Assert-Equal @(Get-ChildItem -LiteralPath './Results' -Filter '2001_db8__1_*.html').Count 1 'Single IPv6 investigation writes report'
    }
    Write-Host "PASS: $script:testCount regression assertions" -ForegroundColor Green
}
finally {
    Set-Location $originalLocation
    foreach ($name in $keyNames) { [Environment]::SetEnvironmentVariable($name, $savedKeys[$name]) }
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
