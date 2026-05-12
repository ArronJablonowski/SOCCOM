<#
.Synopsis
   SOCCOM.ps1 simplifies and automates common Security Operations Center tasks.  

.DESCRIPTION
 # Script by:  Arron Jablonowski #
 # Version 0.5.5                 #
 # Last modified: 5.12.2026      #  
 
 SOCCOM's functions include:
   - Investigate and report on Domain names, and IP Addresses.
   - Lookup Usernames and Computer names in Active Directory. 
   - Create IR templates to document the IR process. 

.EXAMPLE
   SOCCOM.ps1 Examples
   - Investigate an IP, domain, URL, or full URI
        .\SOCCOM.ps1 -Investigate <domain, URL/URI, IPv4, or IPv6>

   - Search a User's Name in Active Directory  
        .\SOCCOM.ps1 -SearchAD_Username <a username>

   - Search a Computer Name in Active Directory 
        .\SOCCOM.ps1 -SearchAD_ComputerName <computer name>
   
   - Investigate a List of Domains and/or IPAddresses
        .\SOCCOM.ps1 -Investigate_List <~\Path\to\list\of\domains\and\IPs\file.txt>

   - Search a List of Usernames in Active Directory
        .\SOCCOM.ps1 -SearchAD_UserList <~\Path\to\list\of\userNames\file.txt>

   - Search a List of Computer Names in Active Directory
        .\SOCCOM.ps1 -SearchAD_ComputerList <~\Path\to\list\of\computerNames\file.txt>

   - Create an incident response notes template
        .\SOCCOM.ps1 -Make_IRTemplate

   - Update the SOCCOM script from the project GitHub repository
        .\SOCCOM.ps1 -SOCCOM_Update
          
.LINK
   - APIs
        https://www.virustotal.com/en/documentation/public-api/
        https://urlscan.io/about-api/
        https://www.urlvoid.com/api/
        https://www.apivoid.com/api/domain-reputation/

   - 3rd Party Binaries
        https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
        
#>

[CmdletBinding()]
param (	
        # IP, domain, URL, or full URI to scan.
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Indicator')]
        [string]$Investigate,

        # Domain to scan. Prefer -Investigate for new usage.
        [Parameter(Mandatory=$false)]
        [string]$Investigate_Domain, 
       
        # IP to scan. Prefer -Investigate for new usage.
        [Parameter(Mandatory=$false)]
        [string]$Investigate_IPAddress,
       
        # List of Domains/IPs to scan.
        [Parameter(Mandatory=$false)]
        [Alias('Listof_DomainsAndIPs')]
        [string]$Investigate_List,

        # Search UserName in AD.
        [Parameter(Mandatory=$false)]
        [string]$SearchAD_Username,
       
        # Search Computer Name in AD.
        [Parameter(Mandatory=$false)]
        [string]$SearchAD_ComputerName,
       
        # Search UserNameList in AD.
        [Parameter(Mandatory=$false)]
        [Alias('Listof_Usernames')]
        [string]$SearchAD_UserList,
        
        # Search ComputerNameList in AD.  
        [Parameter(Mandatory=$false)]
        [Alias('Listof_ComputerNames')]
        [string]$SearchAD_ComputerList,
        
        # Enable PSRemoting - via PsExec.
        # [Parameter(Mandatory=$false, Position=0)]
        # [string]$Enable_PSRemoting_PsExec,
       
        # Enable PSRemoting - via PsExec.
        # [Parameter(Mandatory=$false, Position=0)]
        # [string]$Disable_PSRemoting_PsExec,
 
        # Lookup Bitlocker Key 
        [Parameter(Mandatory=$false)]
        [string]$Get_BitlockerRecoveryKey,

        # Create an incident response notes template.
        [Alias('New_IRNotesTemplate')]
        [switch]$Make_IRTemplate
        
        # Update SOCCOM 
        # [switch]$SOCCOM_Update 
)

######################################################################################
######################################################################################
                        ## !! ONLY MODIFY API KEYS !! ##
                        ### <<< API KEYS GO HERE >>> ###

# Example: -  $apikeyUrlScan = "76XX8471-Xfff-4XX3-XX69-15XXXXXXXXe"

# UrlScan.io
$apikeyUrlScan = if ($env:SOCCOM_URLSCAN_API_KEY) { $env:SOCCOM_URLSCAN_API_KEY } else { "xxxxxxxx-7fff-4ba3-a969-153bxxxxxxxx" }
# VirusTotal
$apikeyVirusTotal = if ($env:SOCCOM_VIRUSTOTAL_API_KEY) { $env:SOCCOM_VIRUSTOTAL_API_KEY } else { "4134xxxxxxxxxxxxxxxxxx31533af8231e8c4a94e5bc71af4xxxxxxxxxx86a90" }
# APIVoid Domain Reputation. URLVoid moved its API to APIVoid.
$apiKeyAPIVoid = if ($env:SOCCOM_APIVOID_API_KEY) { $env:SOCCOM_APIVOID_API_KEY } elseif ($env:SOCCOM_URLVOID_API_KEY) { $env:SOCCOM_URLVOID_API_KEY } else { "GK6ODvPuW.ZM9uqCGNMZyqxxxxxxxxxxxxxxxxxxxxxxxUWIcNQVCJrsy7t6zqBIA" }

# AbuseIPDB
$apikeyAbuseIPDB = if ($env:SOCCOM_ABUSEIPDB_API_KEY) { $env:SOCCOM_ABUSEIPDB_API_KEY } else { "2005ee4b1xxxd75f3ac16e767e44c2183c8xxxxxxxxxxxxxxxxc3fb91abfec794dfxxxa79f0xxx8f2" }
                        ### <<<<< END API Keys >>>>> ###
######################################################################################
######################################################################################


# Folder layout used by the script. Results are HTML reports, Investigations are Markdown
# case notes, and Logs are transient CSV files used between the submit and report phases.
$resultsFolder = ".\Results"
$investigationsFolder = ".\Investigations"
$logsFolder = ".\Logs"
$script:TempFolder = [System.IO.Path]::GetTempPath()
if (!(Test-Path -PathType Container -Path $resultsFolder)) { New-Item -ItemType Directory -Force -Path $resultsFolder}
if (!(Test-Path -PathType Container -Path $investigationsFolder)) { New-Item -ItemType Directory -Force -Path $investigationsFolder}
if (!(Test-Path -PathType Container -Path $logsFolder)) { New-Item -ItemType Directory -Force -Path $logsFolder}

# Regex for IPv4
$regexIPv4 = "\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b" 

# The CSV log is a short-lived queue. The scan phase writes each indicator plus API IDs;
# the report phase reads it back to assemble one consolidated HTML report.
$logFilePath = '.\Logs\LogFile.csv' # Used to hold results
If(Test-Path $logFilePath){
    Remove-Item $logFilePath # if the file exists, remove it.
}

$global:htmlReport = '.\Results\Report.html' # Used to hold the path to the Report  
If(Test-Path $global:htmlReport){
    Remove-Item $global:htmlReport # if the file exists, remove it. 
}

# Force TLS 1.2 for older Windows PowerShell hosts that may default to weaker protocols.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# User Agent 
#$userAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
$userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0'
# $userAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Opera
# $userAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Safari
# $userAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer

# Randomize sleeps between external API calls to reduce rate-limit collisions.
function randomSleep(){
   $ran = Get-Random -Minimum 18 -Maximum 22 
   Write-Host " ~ Sleeping $ran`s to avoid rate control. "
   Start-Sleep -Seconds $ran       
}

# Time Stamp 
Function timeStamp() {
    $date = Get-Date
    $timeStamp = $date.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    Return $timeStamp
}

$script:ReportIndicators = New-Object System.Collections.ArrayList

# Escape all report-bound text before injecting it into the HTML template.
function ConvertTo-SafeHtml {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

# Build stable, readable HTML anchor IDs for each indicator card.
function ConvertTo-ReportSlug {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $slug = $Value.ToLowerInvariant() -replace '[^a-z0-9]+', '-'
    return ($slug.Trim('-'))
}

# Windows and macOS disagree about valid filename characters. Normalize report names
# aggressively so URLs, IPv6 addresses, and domains can all become file names.
function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $invalidCharacters = [regex]::Escape((-join ([System.IO.Path]::GetInvalidFileNameChars() + [char[]]'<>:"/\|?*')))
    $safeName = $Value -replace "[$invalidCharacters]", '_'
    $safeName = $safeName -replace '\s+', '_'
    return $safeName.Trim('_')
}

# Choose the report filename base from the user's original input. Full URLs are analyzed
# as URLs, but the output file is named after the hostname to keep filenames readable.
function Get-InvestigationReportName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Indicator
    )

    $inputValue = $Indicator.Trim()
    $parsedUri = $null
    if ([System.Uri]::TryCreate($inputValue, [System.UriKind]::Absolute, [ref]$parsedUri) -and -not [string]::IsNullOrWhiteSpace($parsedUri.Host)) {
        return ConvertTo-SafeFileName -Value $parsedUri.Host
    }

    if (-not (Test-IPAddress -Value $inputValue)) {
        # Treat bare domains like URIs only long enough to detect whether path/query
        # details were provided. Simple domains keep their original domain filename.
        $candidate = if ($inputValue -match '^[a-z][a-z0-9+.-]*://') { $inputValue } else { "http://$inputValue" }
        if ([System.Uri]::TryCreate($candidate, [System.UriKind]::Absolute, [ref]$parsedUri) -and -not [string]::IsNullOrWhiteSpace($parsedUri.Host)) {
            $hasUriDetail = -not [string]::IsNullOrWhiteSpace($parsedUri.AbsolutePath.Trim('/')) -or -not [string]::IsNullOrWhiteSpace($parsedUri.Query)
            if ($hasUriDetail) {
                return ConvertTo-SafeFileName -Value $parsedUri.Host
            }
        }
    }

    return ConvertTo-SafeFileName -Value $inputValue
}

# Timestamp report names so repeated investigations do not overwrite each other.
function New-TimestampedReportFileName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BaseName
    )

    $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    return "{0}_{1}.html" -f $BaseName, $timestamp
}

function ConvertTo-UrlComponent {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    return [System.Uri]::EscapeDataString($Value)
}

# Accepts both IPv4 and IPv6. This is the canonical IP detector used by -Investigate.
function Test-IPAddress {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $parsedAddress = $null
    return [System.Net.IPAddress]::TryParse($Value.Trim(), [ref]$parsedAddress)
}

# Small value object used by the HTML report renderer for Lookup Resources buttons.
function New-ReportLink {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Label,

        [AllowNull()]
        [string]$Href
    )

    if ([string]::IsNullOrWhiteSpace($Href) -or $Href -eq 'Null_Value') {
        return $null
    }

    [pscustomobject]@{
        Label = $Label
        Href  = $Href
    }
}

# Report builders add one normalized indicator object at a time. The final renderer only
# needs this collection, regardless of whether the source indicator was an IP or domain.
function Add-ReportIndicator {
    param(
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Indicator
    )

    [void]$script:ReportIndicators.Add($Indicator)
}

# Normalize domains and URLs down to a bare hostname for reputation and RDAP services.
function Get-DomainOnly {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputValue
    )

    $candidate = $InputValue.Trim()
    if ($candidate -notmatch '^https?://') {
        $candidate = "http://$candidate"
    }

    try {
        $uri = [System.Uri]$candidate
        return ($uri.Host -replace '^www\.', '')
    }
    catch {
        return (($InputValue -replace '^https?://', '') -replace '^www\.', '').Split('/')[0]
    }
}

# Defang URLs before rendering them as evidence text so analysts can copy safely.
function ConvertTo-DefangedUrl {
    param(
        [AllowNull()]
        [string]$Url
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return ''
    }

    return $Url.Replace('https://', 'hxxps://').Replace('http://', 'hxxp://')
}

# External APIs return timestamps in several shapes. Convert whatever we can into a
# consistent UTC display value, and gracefully fall back to the original text.
function ConvertTo-UtcReportTimestamp {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
    }

    $text = [string]$Value
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        $text = $text.Trim()
        try {
            return ([datetime]$text).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
        }
        catch {
            $clean = $text.Replace('T', ' ').Replace('Z', '')
            if ($clean.Contains('.')) {
                $clean = $clean.Substring(0, $clean.IndexOf('.'))
            }

            if (-not [string]::IsNullOrWhiteSpace($clean)) {
                try {
                    return ([datetime]$clean).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
                }
                catch {
                    return "$clean UTC"
                }
            }
        }
    }

    return "$(timeStamp) UTC"
}

# Pull the HTTP status code out of web exceptions across Windows PowerShell and PS 7.
function Get-WebExceptionStatusCode {
    param(
        [AllowNull()]
        [object]$ErrorRecord
    )

    if ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.StatusCode) {
        try { return [int]$ErrorRecord.Exception.Response.StatusCode } catch { return $null }
    }

    return $null
}

# Convert noisy web exception objects into one readable CLI line.
function Get-WebExceptionMessage {
    param(
        [AllowNull()]
        [object]$ErrorRecord
    )

    $responseText = ''
    try {
        if ($ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
            $responseText = $ErrorRecord.ErrorDetails.Message
        }
        elseif ($ErrorRecord.Exception.Response) {
            $stream = $ErrorRecord.Exception.Response.GetResponseStream()
            if ($stream) {
                $reader = [System.IO.StreamReader]::new($stream)
                $responseText = $reader.ReadToEnd()
                $reader.Dispose()
            }
        }
    }
    catch {
        $responseText = ''
    }

    if (-not [string]::IsNullOrWhiteSpace($responseText)) {
        try {
            $json = $responseText | ConvertFrom-Json
            if ($json.message) { return [string]$json.message }
            if ($json.description) { return [string]$json.description }
            if ($json.errors -and $json.errors[0].detail) { return [string]$json.errors[0].detail }
        }
        catch {
            return (($responseText -replace '\s+', ' ').Trim())
        }
    }

    if ($ErrorRecord.Exception.Message) {
        return $ErrorRecord.Exception.Message
    }

    return 'Unknown error'
}

# Decode a small HTML fragment into readable text. Some legacy reputation sources and
# module output can return HTML snippets instead of clean text.
function ConvertFrom-HtmlFragment {
    param(
        [AllowNull()]
        [string]$Html
    )

    if ([string]::IsNullOrWhiteSpace($Html)) {
        return ''
    }

    $text = $Html
    $text = $text -replace '(?is)<script\b[^>]*>.*?</script>', ''
    $text = $text -replace '(?is)<style\b[^>]*>.*?</style>', ''
    $text = $text -replace '(?i)<br\s*/?>', [Environment]::NewLine
    $text = $text -replace '(?i)</(div|p|tr|li|h[1-6]|section|article)>', [Environment]::NewLine
    $text = $text -replace '(?is)<[^>]+>', ''
    $text = [System.Net.WebUtility]::HtmlDecode($text)

    return (($text -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine)
}

# Extract the text contained in a specific CSS class from an HTML response.
function Get-HtmlClassText {
    param(
        [AllowNull()]
        [string]$Html,

        [Parameter(Mandatory=$true)]
        [string]$ClassName
    )

    if ([string]::IsNullOrWhiteSpace($Html)) {
        return ''
    }

    $class = [regex]::Escape($ClassName)
    $pattern = "(?is)<(?<tag>[a-z0-9]+)[^>]*class\s*=\s*['""][^'""]*\b$class\b[^'""]*['""][^>]*>(?<content>.*?)</\k<tag>>"
    $matches = [regex]::Matches($Html, $pattern)
    if ($matches.Count -eq 0) {
        return ''
    }

    return ConvertFrom-HtmlFragment -Html $matches[$matches.Count - 1].Groups['content'].Value
}

# Keep embedded helper files in the OS temp directory instead of the repo/workspace.
function Get-SoccomTempPath {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FileName
    )

    return (Join-Path -Path $script:TempFolder -ChildPath $FileName)
}

$script:RdapBootstrapCache = @{}

# IANA RDAP bootstrap data maps TLDs and IP ranges to their authoritative RDAP servers.
# Cache each bootstrap file so multi-indicator investigations do not re-download it.
function Get-RdapBootstrap {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('dns', 'ipv4', 'ipv6')]
        [string]$Type
    )

    if (-not $script:RdapBootstrapCache.ContainsKey($Type)) {
        $script:RdapBootstrapCache[$Type] = Invoke-RestMethod -Uri "https://data.iana.org/rdap/$Type.json" -Headers @{ Accept = 'application/json' } -UserAgent $userAgent
    }

    return $script:RdapBootstrapCache[$Type]
}

# Convert IPv4 to an integer so IANA bootstrap CIDR ranges can be compared quickly.
function ConvertTo-IPv4Integer {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )

    $bytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    if ($bytes.Count -ne 4) {
        throw "Only IPv4 addresses are supported by this lookup path: $IPAddress"
    }

    return (([uint64]$bytes[0] -shl 24) -bor ([uint64]$bytes[1] -shl 16) -bor ([uint64]$bytes[2] -shl 8) -bor [uint64]$bytes[3])
}

# IPv4-specific CIDR matching used by the legacy IPv4 RDAP lookup path.
function Test-IPv4InCidr {
    param(
        [Parameter(Mandatory=$true)]
        [uint64]$Address,

        [Parameter(Mandatory=$true)]
        [string]$Cidr
    )

    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) {
        return $false
    }

    $network = ConvertTo-IPv4Integer -IPAddress $parts[0]
    $prefix = [int]$parts[1]
    if ($prefix -lt 0 -or $prefix -gt 32) {
        return $false
    }

    $allIPv4Bits = [uint64]4294967295
    $mask = if ($prefix -eq 0) { [uint64]0 } else { ($allIPv4Bits -shl (32 - $prefix)) -band $allIPv4Bits }
    return (($Address -band $mask) -eq ($network -band $mask))
}

# Address-family aware CIDR matching for both IPv4 and IPv6 RDAP bootstrap ranges.
function Test-IPInCidr {
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.IPAddress]$Address,

        [Parameter(Mandatory=$true)]
        [string]$Cidr
    )

    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) {
        return $false
    }

    $networkAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$networkAddress)) {
        return $false
    }

    if ($Address.AddressFamily -ne $networkAddress.AddressFamily) {
        return $false
    }

    $addressBytes = $Address.GetAddressBytes()
    $networkBytes = $networkAddress.GetAddressBytes()
    $maxPrefix = $addressBytes.Count * 8
    $prefix = [int]$parts[1]
    if ($prefix -lt 0 -or $prefix -gt $maxPrefix) {
        return $false
    }

    $fullBytes = [Math]::Floor($prefix / 8)
    $remainingBits = $prefix % 8

    for ($i = 0; $i -lt $fullBytes; $i++) {
        if ($addressBytes[$i] -ne $networkBytes[$i]) {
            return $false
        }
    }

    if ($remainingBits -gt 0) {
        $mask = [byte]((0xff -shl (8 - $remainingBits)) -band 0xff)
        if (($addressBytes[$fullBytes] -band $mask) -ne ($networkBytes[$fullBytes] -band $mask)) {
            return $false
        }
    }

    return $true
}

# Join an RDAP service base URL with a lookup path without double slashes.
function Join-RdapUrl {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BaseUrl,

        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    return ('{0}/{1}' -f $BaseUrl.TrimEnd('/'), $Path.TrimStart('/'))
}

# Find the authoritative RDAP endpoint for a domain's TLD, falling back to rdap.org.
function Get-RdapDomainUrl {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    $domainOnly = Get-DomainOnly -InputValue $Domain
    $labels = $domainOnly.Split('.') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($labels.Count -lt 2) {
        throw "Domain does not include a registrable suffix: $Domain"
    }

    $tld = $labels[-1].ToLowerInvariant()
    $bootstrap = Get-RdapBootstrap -Type 'dns'
    foreach ($service in $bootstrap.services) {
        if (@($service[0]) -contains $tld) {
            $baseUrl = @($service[1] | Where-Object { $_ -like 'https://*' } | Select-Object -First 1)
            if ($baseUrl.Count -eq 0) {
                $baseUrl = @($service[1] | Select-Object -First 1)
            }
            if ($baseUrl.Count -gt 0) {
                return Join-RdapUrl -BaseUrl $baseUrl[0] -Path "domain/$domainOnly"
            }
        }
    }

    return Join-RdapUrl -BaseUrl 'https://rdap.org' -Path "domain/$domainOnly"
}

# Kept for compatibility with earlier IPv4 logic. Newer code uses Get-RdapIPUrl.
function Get-RdapIPv4Url {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )

    $addressInt = ConvertTo-IPv4Integer -IPAddress $IPAddress
    $bootstrap = Get-RdapBootstrap -Type 'ipv4'
    foreach ($service in $bootstrap.services) {
        foreach ($range in @($service[0])) {
            if ($range -like '*/*' -and (Test-IPv4InCidr -Address $addressInt -Cidr $range)) {
                $baseUrl = @($service[1] | Where-Object { $_ -like 'https://*' } | Select-Object -First 1)
                if ($baseUrl.Count -eq 0) {
                    $baseUrl = @($service[1] | Select-Object -First 1)
                }
                if ($baseUrl.Count -gt 0) {
                    return Join-RdapUrl -BaseUrl $baseUrl[0] -Path "ip/$IPAddress"
                }
            }
        }
    }

    return Join-RdapUrl -BaseUrl 'https://rdap.org' -Path "ip/$IPAddress"
}

# Find the authoritative RDAP endpoint for either an IPv4 or IPv6 address.
function Get-RdapIPUrl {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )

    $parsedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$parsedAddress)) {
        throw "Invalid IP address: $IPAddress"
    }

    $bootstrapType = if ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 'ipv6' } else { 'ipv4' }
    $bootstrap = Get-RdapBootstrap -Type $bootstrapType
    foreach ($service in $bootstrap.services) {
        foreach ($range in @($service[0])) {
            if ($range -like '*/*' -and (Test-IPInCidr -Address $parsedAddress -Cidr $range)) {
                $baseUrl = @($service[1] | Where-Object { $_ -like 'https://*' } | Select-Object -First 1)
                if ($baseUrl.Count -eq 0) {
                    $baseUrl = @($service[1] | Select-Object -First 1)
                }
                if ($baseUrl.Count -gt 0) {
                    return Join-RdapUrl -BaseUrl $baseUrl[0] -Path "ip/$IPAddress"
                }
            }
        }
    }

    return Join-RdapUrl -BaseUrl 'https://rdap.org' -Path "ip/$IPAddress"
}

# Shared RDAP request wrapper. Centralizing this keeps headers/user-agent consistent.
function Invoke-RdapQuery {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri
    )

    Invoke-RestMethod -Uri $Uri -Headers @{ Accept = 'application/rdap+json, application/json' } -UserAgent $userAgent
}

# RDAP entities store contact data as jCard/vCard arrays. Pull out the fields analysts
# usually need without dumping the whole nested structure into the report.
function ConvertFrom-RdapVCard {
    param(
        [AllowNull()]
        $Entity
    )

    if ($null -eq $Entity.vcardArray -or $Entity.vcardArray.Count -lt 2) {
        return ''
    }

    $properties = @($Entity.vcardArray[1])
    $name = ''
    $email = ''
    $telephone = ''
    foreach ($property in $properties) {
        if ($property.Count -lt 4) {
            continue
        }

        switch ([string]$property[0]) {
            'fn' { if (-not $name) { $name = [string]$property[3] } }
            'email' { if (-not $email) { $email = [string]$property[3] } }
            'tel' { if (-not $telephone) { $telephone = [string]$property[3] } }
        }
    }

    $parts = @($name, $email, $telephone) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    return ($parts -join ' | ')
}

# Flatten RDAP JSON into a concise text block for the collapsible RDAP / WHOIS section.
function ConvertTo-RdapReportText {
    param(
        [Parameter(Mandatory=$true)]
        $Rdap,

        [Parameter(Mandatory=$true)]
        [string]$QueryUri
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("RDAP query: $QueryUri")
    if ($Rdap.objectClassName) { $lines.Add("Object class: $($Rdap.objectClassName)") }
    if ($Rdap.ldhName) { $lines.Add("Domain: $($Rdap.ldhName)") }
    if ($Rdap.unicodeName) { $lines.Add("Unicode name: $($Rdap.unicodeName)") }
    if ($Rdap.handle) { $lines.Add("Handle: $($Rdap.handle)") }
    if ($Rdap.name) { $lines.Add("Name: $($Rdap.name)") }
    if ($Rdap.type) { $lines.Add("Type: $($Rdap.type)") }
    if ($Rdap.startAddress -or $Rdap.endAddress) { $lines.Add("Range: $($Rdap.startAddress) - $($Rdap.endAddress)") }
    if ($Rdap.ipVersion) { $lines.Add("IP version: $($Rdap.ipVersion)") }
    if ($Rdap.country) { $lines.Add("Country: $($Rdap.country)") }
    if ($Rdap.parentHandle) { $lines.Add("Parent handle: $($Rdap.parentHandle)") }
    if ($Rdap.port43) { $lines.Add("Port 43 WHOIS: $($Rdap.port43)") }
    if ($Rdap.status) { $lines.Add("Status: $(@($Rdap.status) -join ', ')") }

    if ($Rdap.events) {
        $lines.Add('')
        $lines.Add('Events:')
        foreach ($event in @($Rdap.events)) {
            $lines.Add(" - $($event.eventAction): $($event.eventDate)")
        }
    }

    if ($Rdap.entities) {
        $lines.Add('')
        $lines.Add('Entities:')
        foreach ($entity in @($Rdap.entities)) {
            $roles = if ($entity.roles) { @($entity.roles) -join ', ' } else { 'unknown role' }
            $entityText = ConvertFrom-RdapVCard -Entity $entity
            if ([string]::IsNullOrWhiteSpace($entityText)) {
                $entityText = $entity.handle
            }
            if (-not [string]::IsNullOrWhiteSpace($entityText)) {
                $lines.Add(" - $roles`: $entityText")
            }
        }
    }

    if ($Rdap.notices) {
        $lines.Add('')
        $lines.Add('Notices:')
        foreach ($notice in @($Rdap.notices | Select-Object -First 4)) {
            if ($notice.title) { $lines.Add(" - $($notice.title)") }
        }
    }

    return ($lines -join [Environment]::NewLine)
}

### Submit Functions ###
# Submit a public URLScan job. The result URL is saved now; detailed results are polled
# later because URLScan can take longer than the initial submission response.
Function UrlScan($url) {
    Write-Host " - URLScan"
    try {
        $body = @{
            url    = $url
            public = 'on'
        } | ConvertTo-Json
        $Invoke = Invoke-WebRequest -Headers @{"API-Key" = "$apikeyUrlScan"} -Method Post -Body $body -Uri 'https://urlscan.io/api/v1/scan/' -ContentType 'application/json' -ErrorAction Stop
        $URLScanResult = $Invoke.Content | ConvertFrom-Json
        return $URLScanResult.result
    }
    catch {
        $message = Get-WebExceptionMessage -ErrorRecord $_
        Write-Host " ~ URLScan submission skipped for $url. $message"
        return 'Null_Value'
    }
}

# Extract the URLScan UUID from a result URL before querying the result API.
function Get-UrlScanUuidFromResultUrl {
    param(
        [AllowNull()]
        [string]$ResultUrl
    )

    if ([string]::IsNullOrWhiteSpace($ResultUrl) -or $ResultUrl -eq 'Null_Value') {
        return $null
    }

    if ($ResultUrl -match '/result/([^/]+)/?') {
        return $Matches[1]
    }

    return $ResultUrl.Trim().TrimEnd('/')
}

# Poll URLScan's result endpoint. A 404 can mean "scan not finished yet", so retry
# before falling back to a partial report.
function Get-UrlScanResult {
    param(
        [AllowNull()]
        [string]$Uuid,

        [int]$MaxAttempts = 6,

        [int]$DelaySeconds = 10
    )

    if ([string]::IsNullOrWhiteSpace($Uuid) -or $Uuid -eq 'Null_Value') {
        Write-Host " ~ URLScan result UUID was not available; continuing without URLScan details."
        return $null
    }

    $resultUri = "https://urlscan.io/api/v1/result/$Uuid/"
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $invoke = Invoke-WebRequest -Uri $resultUri -ErrorAction Stop
            return ($invoke.Content | ConvertFrom-Json)
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $message = $_.Exception.Message
            if ($statusCode -eq 404 -and $attempt -lt $MaxAttempts) {
                Write-Host " ~ URLScan result is not ready yet. Waiting ${DelaySeconds}s before retry $($attempt + 1)/$MaxAttempts."
                Start-Sleep -Seconds $DelaySeconds
                continue
            }

            Write-Warning "URLScan result lookup failed for UUID $Uuid. $message"
            return $null
        }
    }
}
# Submit the URL to VirusTotal and return the scan ID used later to retrieve a report.
Function SubmitVirusTotalURL($url) {
    Write-Host " ~ Sleeping 20s to avoid rate control."
    Start-Sleep -Seconds 20 
    Write-Host " - VirusTotal"
    try {
        $scanReport = Submit-VirusTotalURL -URL $url -APIKey $apikeyVirusTotal
        if ($scanReport -and $scanReport.scan_id) {
            Return $scanReport.scan_id
        }
    }
    catch {
        Write-Host " ~ VirusTotal submission skipped for $url. $($_.Exception.Message)"
    }

    return 'Null_Value'
}
### END Submit Functions ### 

### Get Info Functions ###
# RDAP lookup for domains. Older function names still refer to WhoIs, but this now uses
# authoritative RDAP where available.
function Get-WhoIsDomainText {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    Write-Host " - RDAP Report"
    try {
        $rdapUri = Get-RdapDomainUrl -Domain $Domain
        $rdap = Invoke-RdapQuery -Uri $rdapUri
        return ConvertTo-RdapReportText -Rdap $rdap -QueryUri $rdapUri
    }
    catch {
        $statusCode = Get-WebExceptionStatusCode -ErrorRecord $_
        if ($statusCode -eq 404) {
            Write-Host " ~ RDAP record not found for $Domain; continuing."
        }
        else {
            Write-Host " ~ RDAP lookup skipped for $Domain. $(Get-WebExceptionMessage -ErrorRecord $_)"
        }
        return ''
    }
}

# RDAP lookup for IPv4/IPv6 addresses.
function Get-WhoIsIPAddressText {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )

    Write-Host " - RDAP Report"
    try {
        $rdapUri = Get-RdapIPUrl -IPAddress $IPAddress
        $rdap = Invoke-RdapQuery -Uri $rdapUri
        return ConvertTo-RdapReportText -Rdap $rdap -QueryUri $rdapUri
    }
    catch {
        $statusCode = Get-WebExceptionStatusCode -ErrorRecord $_
        if ($statusCode -eq 404) {
            Write-Host " ~ RDAP record not found for $IPAddress; continuing."
        }
        else {
            Write-Host " ~ RDAP lookup skipped for $IPAddress. $(Get-WebExceptionMessage -ErrorRecord $_)"
        }
        return ''
    }
}

# Backward-compatible wrappers for existing function names.
function whoDotIs($fullDomain) { Get-WhoIsDomainText -Domain $fullDomain }
function whoDotIsIPAddress($ip) { Get-WhoIsIPAddressText -IPAddress $ip }

# Query AbuseIPDB's API and normalize the response into a report-friendly object.
function Get-AbuseIPReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )

    Write-Host " - AbuseIPdb Report"
    try {
        if ([string]::IsNullOrWhiteSpace($apikeyAbuseIPDB)) {
            throw "AbuseIPDB API key is not configured."
        }

        $encodedIPAddress = [System.Uri]::EscapeDataString($IPAddress)
        $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$encodedIPAddress&maxAgeInDays=90"
        $headers = @{
            Accept = 'application/json'
            Key    = $apikeyAbuseIPDB
        }
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -UserAgent $userAgent
        $data = $response.data
        $score = [int]$data.abuseConfidenceScore
        $reportCount = [int]$data.totalReports
        $isMatch = ($score -gt 0 -or $reportCount -gt 0)
        $status = if ($isMatch) { 'FOUND in AbuseIPDB' } else { 'not found in AbuseIPDB reports from the last 90 days' }

        $details = @(
            "Abuse confidence: $score%"
            "Reports: $reportCount"
            if (-not [string]::IsNullOrWhiteSpace([string]$data.countryCode)) { "Country: $($data.countryCode)" }
            if (-not [string]::IsNullOrWhiteSpace([string]$data.isp)) { "ISP: $($data.isp)" }
            if (-not [string]::IsNullOrWhiteSpace([string]$data.domain)) { "Domain: $($data.domain)" }
            if (-not [string]::IsNullOrWhiteSpace([string]$data.usageType)) { "Usage: $($data.usageType)" }
            if ($null -ne $data.isTor) { "Tor: $($data.isTor)" }
            if ($null -ne $data.isWhitelisted) { "Whitelisted: $($data.isWhitelisted)" }
            if (-not [string]::IsNullOrWhiteSpace([string]$data.lastReportedAt)) { "Last reported: $($data.lastReportedAt)" }
        )
        $detailTable = [ordered]@{
            'Status'           = $status
            'Abuse Confidence' = "$score%"
            'Reports'          = $reportCount
            'Country'          = $data.countryCode
            'ISP'              = $data.isp
            'Domain'           = $data.domain
            'Usage'            = $data.usageType
            'Tor'              = $data.isTor
            'Whitelisted'      = $data.isWhitelisted
            'Last Reported'    = $data.lastReportedAt
        }

        [pscustomobject]@{
            Message        = "$IPAddress was $status. $($details -join '; ')"
            IsMatch        = $isMatch
            Score          = $score
            TotalReports   = $reportCount
            LastReportedAt = $data.lastReportedAt
            Details        = $detailTable
        }
    }
    catch {
        Write-Warning "AbuseIPdb lookup failed for $IPAddress. $($_.Exception.Message)"
        [pscustomobject]@{
            Message        = "AbuseIPdb lookup failed or returned no result."
            IsMatch        = $false
            Score          = $null
            TotalReports   = $null
            LastReportedAt = $null
            Details        = [ordered]@{
                'Status' = 'Lookup failed or returned no result'
            }
        }
    }
}

function AbuseIP($ip) { Get-AbuseIPReport -IPAddress $ip }

# Convert a VirusTotal URL report into the few fields shown in the HTML summary.
function Get-VirusTotalUrlSummary {
    param(
        [AllowNull()]
        [string]$ResourceID
    )

    Write-Host " - VirusTotal Report"
    if ([string]::IsNullOrWhiteSpace($ResourceID) -or $ResourceID -eq 'Null_Value') {
        return [pscustomobject]@{
            Positives = $null
            Total     = $null
            Permalink = $null
            Ratio     = 'n/a'
        }
    }

    try {
        $VTReport = Get-VirusTotalURLReport -Resource $ResourceID -APIKey $apikeyVirusTotal
    }
    catch {
        Write-Host " ~ VirusTotal report unavailable. $($_.Exception.Message)"
        return [pscustomobject]@{
            Positives = $null
            Total     = $null
            Permalink = $null
            Ratio     = 'n/a'
        }
    }

    [pscustomobject]@{
        Positives = $VTReport.positives
        Total     = $VTReport.total
        Permalink = $VTReport.permalink
        Ratio     = "$($VTReport.positives) / $($VTReport.total)"
    }
}

function GetVirusTotalInfo($ResourceID) {
    (Get-VirusTotalUrlSummary -ResourceID $ResourceID).Permalink
}

# Query APIVoid's domain reputation API. The function name retains URLVoid wording
# because earlier versions exposed URLVoid in the report.
function Get-URLVoidReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )

    Write-Host " - APIVoid Domain Reputation Report"
    try {
        if ([string]::IsNullOrWhiteSpace($apiKeyAPIVoid)) {
            throw "APIVoid API key is not configured."
        }

        $body = @{ host = $DomainName } | ConvertTo-Json
        $response = Invoke-RestMethod `
            -Method Post `
            -Uri "https://api.apivoid.com/v2/domain-reputation" `
            -Headers @{
                'Content-Type' = 'application/json'
                'X-API-Key'   = $apiKeyAPIVoid
            } `
            -Body $body `
            -UserAgent $userAgent

        $detections = @(
            $response.blacklists.engines.PSObject.Properties.Value |
            Where-Object { $_.detected } |
            ForEach-Object { $_.name }
        )
        $count = [string]$response.blacklists.detections
        $domainRegistration = $response.security_checks.domain_creation_date

        if ([string]::IsNullOrWhiteSpace($count)) {
            $count = "0"
        }
        if ([string]::IsNullOrWhiteSpace($domainRegistration)) {
            $domainRegistration = "Unknown"
        }

        [pscustomobject]@{
            Count              = $count
            Detections         = if ($detections) { $detections -join ', ' } else { 'n/a' }
            DomainRegistration = $domainRegistration
        }
    }
    catch {
        Write-Warning "APIVoid domain reputation lookup failed for $DomainName. $($_.Exception.Message)"
        [pscustomobject]@{
            Count              = '0'
            Detections         = 'n/a'
            DomainRegistration = 'Unknown'
        }
    }
}

function URLVoid($domainName) { Get-URLVoidReport -DomainName $domainName }
### END Get Info Functions ###

# First phase for domains: submit long-running scans and store their IDs in the CSV
# queue. The report phase uses these IDs once enough time has passed.
Function checkDomain($domain) {
    $URLScanResultUrl = UrlScan($domain)
    $VirusTotalScanID = SubmitVirusTotalURL($domain)    
    Add-Content -Path $logFilePath -Value "$domain,$URLScanResultUrl,$VirusTotalScanID"
}

# IPs do not require URLScan/VirusTotal URL submission, so enqueue placeholders.
Function checkIPAddress($checkIPAddress) { 
    Write-Host " - IP Logged"   
    Add-Content -Path $logFilePath -Value "$checkIPAddress,Null_Value,Null_Value"
}

# Route a user-supplied indicator into the right first-phase queue path.
function Invoke-IndicatorInvestigation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Indicator
    )

    $inputValue = $Indicator.Trim()
    if ([string]::IsNullOrWhiteSpace($inputValue)) {
        throw "No indicator was provided."
    }

    Write-Host "$inputValue"
    if (Test-IPAddress -Value $inputValue) {
        checkIPAddress $inputValue
    }
    else {
        checkDomain $inputValue
    }
}

# Finalize a single-indicator investigation: build the shared report, copy it to a
# timestamped file, open it for the analyst, then remove the transient report path.
function Write-IndicatorInvestigationReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Indicator
    )

    writeReport
    $reportName = Get-InvestigationReportName -Indicator $Indicator
    $newReport = "$resultsFolder\$(New-TimestampedReportFileName -BaseName $reportName)"
    Copy-Item -Path $global:htmlReport -Destination $newReport -Force
    Invoke-Item $newReport
    Remove-Item $global:htmlReport
}

# Build the normalized report object for an IP indicator. The HTML renderer consumes
# this object later, so keep display formatting out of this function where possible.
Function IPScanInfo($ipAddress) {
    $scanTime = "$(timeStamp) UTC"
    $encodedIP = ConvertTo-UrlComponent -Value $ipAddress
    $abuseIPReport = Get-AbuseIPReport -IPAddress $ipAddress
    try {
        $vtIPReport = Get-VirusTotalIPReport -IPAddress $ipAddress -APIKey $apikeyVirusTotal
    }
    catch {
        Write-Warning "VirusTotal IP lookup failed for $ipAddress. $($_.Exception.Message)"
        $vtIPReport = [pscustomobject]@{
            detected_urls = @()
            resolutions   = @()
            asn           = $null
            country       = $null
            verbose_msg   = 'VirusTotal lookup failed or returned no result.'
            as_owner      = $null
        }
    }
    # Normalize optional VirusTotal fields before assembling the final report object.
    $detections = $vtIPReport.detected_urls
    $resolutions = $vtIPReport.resolutions
    $asn = $vtIPReport.asn
    $country = $vtIPReport.country
    $ifFound = $vtIPReport.verbose_msg # if found in data set 
    $asOwner = $vtIPReport.as_owner
    $VTReportLink = "https://www.virustotal.com/en/ip-address/$encodedIP/information/"
    # if null 
    If ([string]::IsNullOrEmpty($ifFound)) {
        $ifFound = "Error"
    }
    If ([string]::IsNullOrEmpty($country)) {
        $country = "n/a"
    }
    If ([string]::IsNullOrEmpty($asn)) {
        $asn = "unknown"
    }
    If ([string]::IsNullOrEmpty($asOwner)) {
        $asOwner = "unknown"
    }

    Write-Host " - VirusTotal Report"
    $resolvedHosts = @()
    if ($resolutions) {
        foreach ($element in $resolutions) {
            $resolvedHosts += "last_resolved=$($element.last_resolved) hostname=$($element.hostname)"
        }
    }

    $detectedUrls = @()
    if ($detections) {
        foreach ($element in $detections) {
            $detectedUrls += ConvertTo-DefangedUrl -Url $element.url
        }
    }

    Add-ReportIndicator ([pscustomobject]@{
        Type         = 'IP'
        Value        = $ipAddress
        Timestamp    = $scanTime
        PrimaryHref  = "https://dnslytics.com/ip/$encodedIP"
        AbuseIP      = $abuseIPReport
        Summary      = [ordered]@{
            'Data Set'          = $ifFound
            'Country'           = $country
            'ASN'               = $asn
            'Autonomous System' = $asOwner
        }
        Sections     = @(
            [pscustomobject]@{ Title = 'Resolved Host Names'; Items = $resolvedHosts; EmptyText = 'No resolved hosts captured.' },
            [pscustomobject]@{ Title = 'Detected URLs'; Items = $detectedUrls; EmptyText = 'No detected URLs captured.' },
            [pscustomobject]@{ Title = 'RDAP / WHOIS'; Items = @((Get-WhoIsIPAddressText -IPAddress $ipAddress)); EmptyText = 'No RDAP details captured.' }
        )
        Screenshot   = $null
        Links        = @(
            New-ReportLink 'DomainTools' "https://whois.domaintools.com/$encodedIP"
            New-ReportLink 'Who.Is' "https://who.is/whois-ip/ip-address/$encodedIP"
            New-ReportLink 'IBMcloud.com' "https://exchange.xforce.ibmcloud.com/ip/$encodedIP"
            New-ReportLink 'VirusTotal' $VTReportLink
            New-ReportLink 'AbuseIPdb.com' "https://www.abuseipdb.com/check/$encodedIP"
            New-ReportLink 'ThreatMiner.org' "https://www.threatminer.org/host.php?q=$encodedIP"
            New-ReportLink 'AlienVault.com' "https://otx.alienvault.com/indicator/ip/$encodedIP"
            New-ReportLink 'Robtex.com' "https://www.robtex.com/dns-lookup/$encodedIP"
            New-ReportLink 'Shodan.io' "https://www.shodan.io/search?query=$encodedIP"
            New-ReportLink 'Securi.net' "https://sitecheck.sucuri.net/results/$encodedIP"
            New-ReportLink 'DNS.ninja' "https://www.dns.ninja/?dns=$encodedIP"
        )
    })
}

# Build the normalized report object for a domain/URL indicator. URLScan may still be
# processing, so this function falls back to the submitted domain when URLScan data is absent.
function URLScanInfo($domain,$uuid,$VirusTotalScanIDNumber) {
    Write-Host " - URLScan Report"
    # Get results from URLScan.io and assign the results to variables.
    $hashTablePage = Get-UrlScanResult -Uuid $uuid
    $asnInfo = $null
    if ($hashTablePage) {
        $asnInfo = $hashTablePage.data.requests.response.asn | Select-Object -First 1
    }

    # Pull useful URLScan fields into flat variables for the report summary.
    $submittedURL = if ($hashTablePage.task.url) { $hashTablePage.task.url } else { $domain } #Original URL 
    $finalDestinationDomain = $hashTablePage.page.domain #Final Domain
    $effectiveURL = $hashTablePage.page.url # Final URL - Redirects/Effective URL 
    $ipAddress = $hashTablePage.page.ip #IP Address
    $countryCode = $hashTablePage.page.country #Country code 
    $city = $hashTablePage.page.city #City 
    $registrationDate = $asnInfo.date #Regestration Date 
    $asnName = $hashTablePage.page.asnname #ASNName
    $asnNumber = $hashTablePage.page.asn #ASN number  
    $serverInfo = $hashTablePage.page.server #server 
    $malware = $hashTablePage.stats.malicious #Malware?
    $adsBlocked = $hashTablePage.stats.adBlocked #ads Blocked  
    $numberOfSubdomains = $hashTablePage.stats.domainStats.Count #Subdomains 
    $scanTime = $hashTablePage.task.time #TIME Of Scan 
    $urlScanReport = $hashTablePage.task.reportURL
    $screenShot = $hashTablePage.task.screenshotURL
    #$outgoingLinksCount = $hashTablePage.stats.totalLinks #Outgoing Links 
    $outgoingLinks = $hashTablePage.lists.linkDomains #Outgoing LInks Uniqe
    #$uniqCountryCount = $hashTablePage.stats.uniqCountries #number of uniqCountries
    #$uniqCountryCodes = $hashTablePage.lists.countries  #Country Codes 
    $domainOnly = Get-DomainOnly -InputValue $submittedURL
    if ([string]::IsNullOrWhiteSpace($domainOnly)) {
        $domainOnly = Get-DomainOnly -InputValue $domain
    }
    $formatScanTime = ConvertTo-UtcReportTimestamp -Value $scanTime
    $vtSummary = Get-VirusTotalUrlSummary -ResourceID $VirusTotalScanIDNumber
    $urlVoidReport = Get-URLVoidReport -DomainName $domainOnly

    Add-ReportIndicator ([pscustomobject]@{
        Type         = 'Domain'
        Value        = $domain
        Timestamp    = $formatScanTime
        PrimaryHref  = "https://dnslytics.com/domain/$domainOnly"
        AbuseIP      = $null
        Summary      = [ordered]@{
            'Submitted URL'         = $submittedURL
            'Effective URL'         = $effectiveURL
            'Landing Domain'        = $finalDestinationDomain
            'IP Address'            = $ipAddress
            'Server'                = $serverInfo
            'Country'               = $countryCode
            'City'                  = $city
            'ASN Name'              = $asnName
            'ASN Number'            = $asnNumber
            'ASN Registration'      = $registrationDate
            'Malware'               = $malware
            'Ads Blocked'           = $adsBlocked
            'Outgoing Links'        = ($outgoingLinks -join ', ')
            'VirusTotal Detections' = $vtSummary.Ratio
            'APIVoid Detections'    = $urlVoidReport.Count
            'APIVoid Blacklists'    = $urlVoidReport.Detections
            'Domain Registration'   = $urlVoidReport.DomainRegistration
        }
        Sections     = @(
            [pscustomobject]@{ Title = 'RDAP / WHOIS'; Items = @((Get-WhoIsDomainText -Domain $domainOnly)); EmptyText = 'No RDAP details captured.' }
        )
        Screenshot   = $screenShot
        Links        = @(
            New-ReportLink 'DomainTools' "https://whois.domaintools.com/$domainOnly"
            New-ReportLink 'Who.Is' "https://who.is/rdap/$domainOnly"
            New-ReportLink 'URLScan.io' $urlScanReport
            New-ReportLink 'URLVoid.com' "https://www.urlvoid.com/scan/$domainOnly/"
            New-ReportLink 'IBMcloud.com' "https://exchange.xforce.ibmcloud.com/url/$domainOnly"
            New-ReportLink 'VirusTotal' $vtSummary.Permalink
            New-ReportLink 'AbuseIPdb.com' "https://www.abuseipdb.com/check/$domainOnly"
            New-ReportLink 'ThreatMiner.org' "https://www.threatminer.org/domain.php?q=$domainOnly"
            New-ReportLink 'AlienVault.com' "https://otx.alienvault.com/indicator/domain/$domainOnly"
            New-ReportLink 'Robtex.com' "https://www.robtex.com/dns-lookup/$domainOnly"
            New-ReportLink 'Shodan.io' "https://www.shodan.io/search?query=$domainOnly"
            New-ReportLink 'Securi.net' "https://sitecheck.sucuri.net/results/$domainOnly"
            New-ReportLink 'DNS.ninja' "https://www.dns.ninja/?dns=$domainOnly"
            New-ReportLink 'SecurityTrails.com' "https://securitytrails.com/domain/$domainOnly/history/a"
        )
    })
}
# Second phase of report generation. Read queued indicators from LogFile.csv and build
# one normalized report object per row.
Function getInfoBuildReport() {
    $importedCSV = Import-Csv $logFilePath
    #$domainCount = ($importedCSV."Domain").Count    
    foreach ($row in $importedCSV) {
        $domainName = $row.Domain
        $URLScanResultLink = $row.URLScanResult
        $VirusTotalScanIDNumber = $row.VirusTotalScanID
        $uuid = Get-UrlScanUuidFromResultUrl -ResultUrl $URLScanResultLink
        # If $domainName is an IP address.
        if(Test-IPAddress -Value $domainName){
            Write-Host "$domainName"
            randomSleep 
            IPScanInfo $domainName
        }Else{ # treat the $domainName var as a domain
            Write-Host "$domainName"
            randomSleep
            URLScanInfo $domainName $uuid $VirusTotalScanIDNumber
        }        
   }
}

# Query AD for BitLocker recovery material associated with a computer object.
function Get_BitlockerRecoveryKey($Hostname){
    $Computer = Get-ADComputer $Hostname 

    Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' `
        -SearchBase $Computer.DistinguishedName `
        -Properties whenCreated, msFVE-RecoveryPassword `
        | Sort-Object whenCreated -Descending `
        | Select-Object whenCreated, @{N='PasswordID';E={$_.name.Split("{")[1].Replace("}","")}}, msFVE-RecoveryPassword `
        | Format-List
}

# Generate a fresh Markdown investigation notes file from the embedded template.
# The standalone SOC_Investigation_Template.md should be kept in sync with this block.
function New-IRNotesTemplate {
    param(
        [string]$OutputDirectory = $investigationsFolder
    )

    if (!(Test-Path -PathType Container -Path $OutputDirectory)) {
        New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    }

    $timestampFile = (Get-Date).ToString("yyyy-MM-dd_HH_mm_sszzz").Replace(':','')
    $timestampInFile = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")
    $templateFileName = "$timestampFile`_Investigation.md"
    $templatePath = Join-Path -Path $OutputDirectory -ChildPath $templateFileName

    $templateText = @'
# SOC Investigation

| Field | Value |
| --- | --- |
| Investigation started | __INVESTIGATION_START_TIME__ |
| Investigation status | `[New / Investigating / Contained / Monitoring / Closed]` |
| Analyst(s) | `[Name]` |
| Case / Ticket | `[Case ID](127.0.0.1/link/to/case/ticket/detection)` |
| Detection / Incident | `[Alert name or incident title]` |
| Incident Category | `[Malware / Phishing / Credential Abuse / Suspicious Network Activity / Policy Violation / Data Exposure / Vulnerability Exploitation / Other]` |
| Severity | `[Low / Medium / High / Critical]` |
| Disposition | `[True Positive / False Positive / Benign / Needs Review]` |

### Executive Summary / BLUF (bottom line up front)

- `[Short summary of what happened, business impact, and final analyst call]`

## At-a-Glance

- Impact: `[Business or operational impact]`
- Current risk: `[Low / Medium / High / Critical]`
- Biggest concern: `[What could go wrong if we are wrong?]`
- Known impacted: `[users / hosts / indicators]`
- Immediate next step: `[next action]`

## Current Status

| Item | Complete | Time | Notes |
| --- | --- | --- | --- |
| Initial alert reviewed | `[ ]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[notes]` |
| Evidence preserved | `[ ]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[notes]` |
| Scope reviewed | `[ ]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[notes]` |
| Containment required | `[Yes / No / Unknown]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[notes]` |
| Escalation required | `[Yes / No / Unknown]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[notes]` |
| Customer / business owner notified, if needed | `[ ]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[notes]` |
| Stakeholders notified | `[ ]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[notes]` |
| Case notes finalized | `[ ]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[notes]` |

## Links

- Original detection / incident: `[URL]`
- SOCCOM report: `[URL or file path]`
- EDR console: `[URL]`
- SIEM searches: `[URL]`
- Sandbox analysis: `[URL]`
- Identity protection: `[URL]`

## Handoff Notes

- [ ] Case summary is complete
- [ ] Timeline is complete
- [ ] Evidence links are included
- [ ] Open actions are assigned
- [ ] Final disposition is documented

## Next Actions

| Action | Owner | Due / Follow-up Time | Status | Notes |
| --- | --- | --- | --- | --- |
| `[action]` | `[owner]` | `[YYYY-MM-DD HH:mm:ss zzz]` | `[open / in progress / complete / blocked]` | `[notes]` |

---

# Detection and Analysis

## Detection Metadata

| Field | Value |
| --- | --- |
| Detection source | `[SIEM / EDR / Email / Proxy / User Report / Other]` |
| Rule / Alert name | `[Name]` |
| Alert ID | `[ID or URL]` |
| Triggering event time | `[YYYY-MM-DD HH:mm:ss zzz]` |
| Log source | `[Source]` |
| Detection confidence | `[Low / Medium / High]` |
| Known false positive pattern | `[Pattern or N/A]` |

## Indicators

| Indicator | Type | First Seen | Last Seen | Source | Enrichment Source | Reputation | Verdict | Action Taken | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `[indicator]` | `[IP / Domain / URL / Hash / Email]` | `[time]` | `[time]` | `[source]` | `[SOCCOM / VT / AbuseIPDB / URLScan / Other]` | `[malicious / suspicious / benign / unknown]` | `[TP / FP / BTP / Needs Review]` | `[blocked / monitored / none]` | `[notes]` |

## Event Timeline

| Time (RFC 3339) | Event | Source | Analyst Notes |
| --- | --- | --- | --- |
| `[YYYY-MM-DDTHH:mm:ss-06:00]` | `[event]` | `[log source / tool]` | `[notes]` |

## Evidence Log

| Time Collected | Evidence | Source Tool | Query / Link | Analyst | Notes |
| --- | --- | --- | --- | --- | --- |
| `[YYYY-MM-DD HH:mm:ss zzz]` | `[evidence item]` | `[tool or platform]` | `[query, URL, or file path]` | `[analyst]` | `[notes]` |

## Scope Assessment

| Field | Value |
| --- | --- |
| Known affected hosts | `[count and/or hostnames]` |
| Known affected users | `[count and/or accounts]` |
| Known affected indicators | `[count and/or indicators]` |
| Time window searched | `[start time through end time]` |
| Data sources searched | `[SIEM / EDR / DNS / Proxy / Email / Identity / Other]` |
| Scope confidence | `[Low / Medium / High]` |

## Scoping Checklist

- [ ] Identify first known activity - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Identify last known activity - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Search for matching IOCs across SIEM / EDR / proxy / DNS - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Search for similar command lines, filenames, hashes, or parent processes - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Review lateral movement indicators - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Review persistence indicators - `[YYYY-MM-DD HH:mm:ss zzz]`

## Affected Assets

### Hosts

| Hostname | IP Address | User | Role / Department | Notes |
| --- | --- | --- | --- | --- |
| `[hostname]` | `[ip]` | `[user]` | `[role]` | `[notes]` |

### Users / Accounts

| Account | Display Name | Department | Risk | Notes |
| --- | --- | --- | --- | --- |
| `[user]` | `[name]` | `[department]` | `[risk]` | `[notes]` |

## Credential / Identity Review

| Review Item | Result | Source | Notes |
| --- | --- | --- | --- |
| MFA events reviewed | `[Yes / No / N/A]` | `[source]` | `[notes]` |
| Failed logons reviewed | `[Yes / No / N/A]` | `[source]` | `[notes]` |
| Impossible travel / risky sign-ins reviewed | `[Yes / No / N/A]` | `[source]` | `[notes]` |
| Password reset or session revocation needed | `[Yes / No / Unknown]` | `[source]` | `[notes]` |
| Account lockouts reviewed | `[Yes / No / N/A]` | `[source]` | `[notes]` |
| Privileged group changes reviewed | `[Yes / No / N/A]` | `[source]` | `[notes]` |
| Suspicious mailbox rules or forwarding reviewed | `[Yes / No / N/A]` | `[source]` | `[notes]` |

## SIEM Queries

```text
// Query 1 - command line review
{host/user} AND CommandLine | table([@timestamp, ComputerName, UserName, CommandLine], limit=20000)

// Query 2 - parent process review
{host/user} AND CommandLine | table([@timestamp, UserName, ParentBaseFileName, CommandLine], limit=20000)

// Query 3 - network activity review
{host} AND RemoteAddressIP4 | table([@timestamp, ContextBaseFileName, RemoteAddressIP4], limit=20000)
```

## Live Incident Response

### Live Response via EDR

- `[YYYY-MM-DD HH:mm:ss zzz]` - `[command or action]` - `[result]`

### Kansa / birtha

- `[YYYY-MM-DD HH:mm:ss zzz]` - `[collection action]` - `[result / evidence path]`

## Communication Log

| Time | Person / Team | Method | Message / Decision | Follow-up |
| --- | --- | --- | --- | --- |
| `[YYYY-MM-DD HH:mm:ss zzz]` | `[person or team]` | `[ticket / chat / email / call]` | `[summary]` | `[owner and due date]` |

## Data Sources Reviewed

| Source | Time Range | Query / Filter | Result | Link |
| --- | --- | --- | --- | --- |
| `[SIEM / EDR / DNS / Proxy / Email / Identity / Other]` | `[start time through end time]` | `[query or filter]` | `[summary of result]` | `[URL or file path]` |

## Escalation Criteria / Escalation Notes

| Field | Value |
| --- | --- |
| Escalated to | `[person / team / N/A]` |
| Reason | `[why escalation is or is not needed]` |
| Escalation time | `[YYYY-MM-DD HH:mm:ss zzz]` |
| Accepted by | `[name / team / N/A]` |
| Next owner | `[owner / N/A]` |

---

# Containment, Eradication, and Recovery

## Containment / Eradication / Recovery Checklist

- [ ] Host isolated or containment decision documented - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Malicious process stopped or file quarantined - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Account disabled, password reset, or sessions revoked - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Network, DNS, email, or web control blocks requested - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Recovery steps completed - `[YYYY-MM-DD HH:mm:ss zzz]`
- [ ] Monitoring or post-remediation validation completed - `[YYYY-MM-DD HH:mm:ss zzz]`

## Host / Account Containment Decision

| Field | Value |
| --- | --- |
| Containment required | `[Yes / No / Unknown]` |
| Decision | `[Contain / Monitor / No Action / Escalate]` |
| Approver | `[Name / Role / N/A]` |
| Reason | `[Why this decision was made]` |
| Decision time | `[YYYY-MM-DD HH:mm:ss zzz]` |

## Remediation Actions

| Time | Action | Owner | Status | Notes |
| --- | --- | --- | --- | --- |
| `[YYYY-MM-DD HH:mm:ss zzz]` | `[action]` | `[owner]` | `[open / complete]` | `[notes]` |

---

# Post-Incident Activities and Lessons Learned

## MITRE ATT&CK Mapping

*Optional section. Complete only when ATT&CK mapping adds value for triage, reporting, detection engineering, or escalation.*

| Tactic | Technique | Evidence | Confidence |
| --- | --- | --- | --- |
| `[tactic]` | `[technique]` | `[evidence]` | `[low / medium / high]` |
| `[tactic]` | `[technique]` | `[evidence]` | `[low / medium / high]` |
| `[tactic]` | `[technique]` | `[evidence]` | `[low / medium / high]` |

## Recommendations

### Prevention

- `[Recommendation]`

### Detection

- `[Recommendation]`

## Tuning Suggestions

- `[Detection, SIEM, EDR, allowlist, suppression, or enrichment improvement]`

## Lessons Learned / Follow-up Work

| Item | Owner | Due Date | Status | Notes |
| --- | --- | --- | --- | --- |
| `[process gap, logging gap, playbook update, control improvement, or follow-up task]` | `[owner]` | `[YYYY-MM-DD]` | `[open / in progress / complete]` | `[notes]` |

## Blockers / Constraints

- `[Issue, missing data, access limitation, or dependency]`

---

# Closeout / Disposition Rationale

| Field | Value |
| --- | --- |
| Investigation ended | `[YYYY-MM-DD HH:mm:ss zzz]` |
| Final disposition | `[True Positive / False Positive / Benign True Positive / Needs Review]` |
| Benign explanation | `[Why this is not malicious, if applicable]` |
| Expected activity owner | `[User / team / system / vendor]` |
| Supporting evidence | `[Evidence links or notes]` |
| Repeat alert expected | `[Yes / No / Unknown]` |
| Tuning needed | `[Yes / No / Unknown]` |

## Minimum Closeout Checklist

- [ ] Final disposition selected
- [ ] Scope documented
- [ ] Evidence links included
- [ ] Containment decision documented
- [ ] Next actions closed or assigned
- [ ] Stakeholders notified if required

### Open Questions

- `[Question]`
'@

    $lines = ($templateText -replace '__INVESTIGATION_START_TIME__', $timestampInFile) -split "`r?`n"

    Set-Content -Path $templatePath -Value $lines -Encoding UTF8
    Write-Host ""
    Write-Host "IR notes template created: $templatePath"
    Write-Host ""
    Invoke-Item $templatePath

    return $templatePath
}

# Render key/value dictionaries as HTML table rows. All values are escaped here.
function ConvertTo-ReportTableRows {
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.IDictionary]$Data
    )

    $rows = foreach ($entry in $Data.GetEnumerator()) {
        if (-not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            '<tr><th>{0}</th><td>{1}</td></tr>' -f (ConvertTo-SafeHtml $entry.Key), (ConvertTo-SafeHtml $entry.Value)
        }
    }

    return ($rows -join [Environment]::NewLine)
}

# Render text lists as preformatted blocks, or a friendly empty state when no data exists.
function ConvertTo-ReportTextBlock {
    param(
        [AllowNull()]
        [object[]]$Items,

        [Parameter(Mandatory=$true)]
        [string]$EmptyText
    )

    $values = @($Items | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($values.Count -eq 0) {
        return '<p class="empty">{0}</p>' -f (ConvertTo-SafeHtml $EmptyText)
    }

    return '<pre>{0}</pre>' -f (ConvertTo-SafeHtml ($values -join [Environment]::NewLine))
}

# Count visible report lines so collapsible sections can show useful item counts.
function Get-SectionItemCount {
    param(
        [AllowNull()]
        [object[]]$Items
    )

    $values = @($Items | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($values.Count -eq 0) {
        return 0
    }

    return (($values -join [Environment]::NewLine) -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
}

# Centralized report styling. Keeping CSS in one function makes the HTML renderer mostly
# about data layout instead of visual details.
function New-ReportCss {
    @'
    :root {
      color-scheme: light;
      --page: #f5f7fb;
      --surface: #ffffff;
      --surface-soft: #f9fbfd;
      --surface-strong: #10251f;
      --text: #172033;
      --muted: #647083;
      --line: #d9e1ec;
      --accent: #087a5b;
      --accent-soft: #e9f8f2;
      --accent-strong: #056348;
      --danger: #b42318;
      --danger-soft: #fff1f0;
      --warning-soft: #fffbeb;
      --warning-line: #f3d49a;
      --shadow: 0 18px 45px rgba(23, 32, 51, 0.08);
      --radius: 8px;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body { margin: 0; min-height: 100vh; background: linear-gradient(180deg, #edf3f8 0%, var(--page) 420px), var(--page); color: var(--text); font-size: 16px; line-height: 1.5; }
    a { color: var(--accent-strong); text-decoration: none; }
    a:hover { text-decoration: underline; text-underline-offset: 3px; }
    .page { width: min(1320px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 56px; }
    .report-header { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 24px; align-items: end; margin-bottom: 20px; padding: 30px; border: 1px solid rgba(5, 99, 72, 0.14); border-radius: var(--radius); background: var(--surface-strong); color: #ffffff; box-shadow: var(--shadow); }
    .eyebrow { margin: 0 0 8px; color: #9ee6cf; font-size: 0.78rem; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; }
    h1, h2, h3, p { margin-top: 0; }
    h1 { margin-bottom: 10px; font-size: clamp(2rem, 5vw, 3.55rem); line-height: 1.08; letter-spacing: 0; }
    .header-copy { max-width: 760px; margin: 0; color: #d6f7eb; font-size: 1rem; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, minmax(150px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .metric { min-height: 96px; padding: 16px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); box-shadow: 0 10px 28px rgba(23, 32, 51, 0.05); }
    .metric span { display: block; color: var(--muted); font-size: 0.75rem; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; }
    .metric strong { display: block; margin-top: 8px; font-size: clamp(1.35rem, 3vw, 2rem); line-height: 1.1; }
    .report-layout { display: grid; grid-template-columns: 280px minmax(0, 1fr); gap: 22px; align-items: start; }
    .indicator-nav { position: sticky; top: 16px; max-height: calc(100vh - 32px); overflow: auto; padding: 16px; border: 1px solid var(--line); border-radius: var(--radius); background: rgba(255, 255, 255, 0.92); box-shadow: var(--shadow); backdrop-filter: blur(10px); }
    .nav-title { margin: 0 0 12px; color: var(--muted); font-size: 0.75rem; font-weight: 850; letter-spacing: 0.08em; text-transform: uppercase; }
    .nav-list { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
    .nav-list a { display: grid; gap: 2px; padding: 10px 12px; border: 1px solid transparent; border-radius: var(--radius); color: var(--text); font-weight: 800; overflow-wrap: anywhere; }
    .nav-list a:hover { border-color: rgba(8, 122, 91, 0.3); background: var(--accent-soft); color: var(--accent-strong); text-decoration: none; }
    .nav-list small { color: var(--muted); font-weight: 650; }
    .indicator-stack { display: grid; gap: 18px; }
    .indicator-card { overflow: hidden; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); box-shadow: var(--shadow); scroll-margin-top: 18px; }
    .indicator-head { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 16px; align-items: start; padding: 22px 24px; border-bottom: 1px solid var(--line); background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%); }
    .indicator-title { margin: 0; font-size: clamp(1.35rem, 3vw, 2.1rem); line-height: 1.15; overflow-wrap: anywhere; }
    .timestamp { display: inline-flex; align-items: center; min-height: 34px; padding: 8px 12px; border: 1px solid var(--line); border-radius: 999px; background: var(--surface-soft); color: #344054; font-size: 0.86rem; font-weight: 800; white-space: nowrap; }
    .pill-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
    .pill { display: inline-flex; align-items: center; min-height: 32px; padding: 7px 10px; border: 1px solid var(--line); border-radius: 999px; background: var(--surface-soft); color: #344054; font-size: 0.84rem; font-weight: 750; }
    .pill.danger { border-color: #f5c2bd; background: var(--danger-soft); color: var(--danger); }
    .indicator-body { display: grid; grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.05fr); gap: 18px; padding: 22px 24px 24px; }
    .panel, details { min-width: 0; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
    .panel.full, details.full { grid-column: 1 / -1; }
    .panel-title, summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; min-height: 48px; padding: 13px 16px; border-bottom: 1px solid var(--line); background: var(--surface-soft); font-size: 0.92rem; font-weight: 850; }
    details:not([open]) summary { border-bottom: 0; }
    summary { cursor: pointer; list-style: none; }
    summary::-webkit-details-marker { display: none; }
    summary::after { content: "+"; display: inline-grid; place-items: center; width: 24px; height: 24px; border: 1px solid var(--line); border-radius: 999px; color: var(--accent-strong); font-weight: 900; flex: 0 0 auto; }
    details[open] summary::after { content: "-"; }
    .panel-count { color: var(--muted); font-size: 0.78rem; font-weight: 800; white-space: nowrap; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; min-width: 520px; border-collapse: collapse; }
    th, td { padding: 13px 15px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; word-break: break-word; }
    th { color: #344054; font-size: 0.75rem; font-weight: 850; letter-spacing: 0.05em; text-transform: uppercase; }
    .summary-table { min-width: 680px; table-layout: fixed; }
    .summary-table th { width: 210px; min-width: 210px; white-space: nowrap; }
    .summary-table td { overflow-wrap: anywhere; }
    tr:last-child th, tr:last-child td { border-bottom: 0; }
    .callout { margin: 0; padding: 14px 16px; color: var(--danger); font-weight: 800; background: var(--danger-soft); }
    .callout.neutral { color: #344054; background: var(--surface-soft); }
    pre { max-height: 360px; margin: 0; padding: 16px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; color: #27364f; background: #fbfdff; font: 0.88rem/1.5 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
    details.rdap-whois pre { max-height: none; }
    .empty { margin: 0; padding: 16px; color: var(--muted); font-weight: 700; }
    .screenshot-link { display: block; padding: 16px; }
    .screenshot-link img { display: block; width: min(100%, 540px); height: auto; border: 1px solid var(--line); border-radius: var(--radius); }
    .link-grid { display: flex; flex-wrap: wrap; gap: 10px; margin: 0; padding: 16px; list-style: none; }
    .link-grid a { display: inline-flex; align-items: center; min-height: 34px; padding: 7px 11px; border: 1px solid var(--line); border-radius: 999px; background: var(--surface-soft); color: #1d2939; font-size: 0.86rem; font-weight: 800; }
    .link-grid a:hover { border-color: rgba(8, 122, 91, 0.45); background: var(--accent-soft); color: var(--accent-strong); text-decoration: none; }
    .note { margin: 24px 0 0; padding: 14px 16px; border: 1px solid var(--warning-line); border-radius: var(--radius); background: var(--warning-soft); color: #7a4d00; font-size: 0.94rem; }
    .report-credit { margin: 16px 0 0; color: var(--muted); font-size: 0.88rem; font-weight: 700; text-align: center; }
    .report-credit a { color: var(--accent-strong); font-weight: 850; }
    @media (max-width: 980px) { .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .report-layout { grid-template-columns: 1fr; } .indicator-nav { position: static; max-height: none; } .nav-list { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); } .indicator-body { grid-template-columns: 1fr; } }
    @media (max-width: 680px) { .page { width: min(100% - 20px, 1320px); padding: 10px 0 32px; } .report-header, .indicator-head { grid-template-columns: 1fr; } .report-header, .indicator-head, .indicator-body { padding: 20px; } .summary-grid { grid-template-columns: 1fr; } .timestamp { width: fit-content; white-space: normal; } }
'@
}

# Render the normalized indicator objects into the final standalone HTML report.
function Write-ModernHtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $indicators = @($script:ReportIndicators)
    # Use real timestamps when available; otherwise keep the report usable with
    # fallback text rather than failing the whole render.
    $parsedTimestamps = @($indicators | ForEach-Object {
        try { [datetime](([string]$_.Timestamp) -replace ' UTC$', 'Z') } catch { $null }
    } | Where-Object { $null -ne $_ } | Sort-Object)
    if ($parsedTimestamps.Count -gt 0) {
        $firstTimestamp = $parsedTimestamps[0].ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
        $lastTimestamp = $parsedTimestamps[-1].ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
    }
    else {
        $firstTimestamp = if ($indicators.Count -gt 0) { $indicators[0].Timestamp } else { 'Unknown' }
        $lastTimestamp = if ($indicators.Count -gt 0) { $indicators[-1].Timestamp } else { 'Unknown' }
    }
    $countries = @($indicators | ForEach-Object { $_.Summary['Country'] } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    $asns = @($indicators | ForEach-Object { $_.Summary['ASN']; $_.Summary['ASN Number'] } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    $abuseMatches = @($indicators | Where-Object { $_.AbuseIP -and $_.AbuseIP.IsMatch }).Count

    # Build the left-side indicator index and attach a matching anchor to each card.
    $navItems = for ($i = 0; $i -lt $indicators.Count; $i++) {
        $indicator = $indicators[$i]
        $id = "indicator-$(ConvertTo-ReportSlug $indicator.Value)-$($i + 1)"
        $indicator | Add-Member -NotePropertyName ReportId -NotePropertyValue $id -Force
        @"
          <li>
            <a href="#$(ConvertTo-SafeHtml $id)">
              <span>$(ConvertTo-SafeHtml $indicator.Value)</span>
              <small>$($i + 1) - $(ConvertTo-SafeHtml $indicator.Timestamp)</small>
            </a>
          </li>
"@
    }

    # Each card is assembled from the same normalized object shape produced by IP/domain
    # builders, which keeps the renderer independent from enrichment source details.
    $cards = for ($i = 0; $i -lt $indicators.Count; $i++) {
        $indicator = $indicators[$i]
        $sectionHtml = foreach ($section in @($indicator.Sections)) {
            $count = Get-SectionItemCount -Items $section.Items
            $isRdapWhois = $section.Title -eq 'RDAP / WHOIS'
            $open = if ($isRdapWhois -or $count -le 12) { ' open' } else { '' }
            $sectionClass = if ($isRdapWhois) { ' class="rdap-whois"' } else { '' }
            $countLabel = if ($count -eq 1) { '1 item' } else { "$count items" }
            @"
            <details$sectionClass$open>
              <summary><span>$(ConvertTo-SafeHtml $section.Title)</span><span class="panel-count">$(ConvertTo-SafeHtml $countLabel)</span></summary>
              $(ConvertTo-ReportTextBlock -Items $section.Items -EmptyText $section.EmptyText)
            </details>
"@
        }

        $abusePanel = if ($indicator.AbuseIP) {
            $abuseCalloutClass = if ($indicator.AbuseIP.IsMatch) { 'callout' } else { 'callout neutral' }
            $abuseStatus = if ($indicator.AbuseIP.IsMatch) { 'Match found' } else { 'No active match' }
            @"
            <details open>
              <summary><span>AbuseIPdb.com</span></summary>
              <p class="$(ConvertTo-SafeHtml $abuseCalloutClass)">$(ConvertTo-SafeHtml $abuseStatus)</p>
              <div class="table-wrap">
                <table>
                  $(ConvertTo-ReportTableRows -Data $indicator.AbuseIP.Details)
                </table>
              </div>
            </details>
"@
        } else {
            ''
        }

        $screenshotPanel = if (-not [string]::IsNullOrWhiteSpace($indicator.Screenshot)) {
            @"
            <details class="full" open>
              <summary><span>URLScan Screenshot</span></summary>
              <a class="screenshot-link" href="$(ConvertTo-SafeHtml $indicator.Screenshot)" target="_blank" rel="noopener noreferrer"><img src="$(ConvertTo-SafeHtml $indicator.Screenshot)" alt="URLScan screenshot for $(ConvertTo-SafeHtml $indicator.Value)"></a>
            </details>
"@
        } else {
            ''
        }

        $links = foreach ($link in @($indicator.Links | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace([string]$_.Href) })) {
            '<li><a href="{0}" target="_blank" rel="noopener noreferrer">{1}</a></li>' -f (ConvertTo-SafeHtml $link.Href), (ConvertTo-SafeHtml $link.Label)
        }

        $hostCount = ($indicator.Sections | Where-Object { $_.Title -eq 'Resolved Host Names' } | ForEach-Object { Get-SectionItemCount -Items $_.Items } | Select-Object -First 1)
        if ($null -eq $hostCount) { $hostCount = 0 }
        $urlCount = ($indicator.Sections | Where-Object { $_.Title -eq 'Detected URLs' } | ForEach-Object { Get-SectionItemCount -Items $_.Items } | Select-Object -First 1)
        if ($null -eq $urlCount) { $urlCount = 0 }
        $typePill = if ($indicator.Type -eq 'IP') { 'IP address' } else { 'Domain or URL' }
        $countryPill = if ($indicator.Summary['Country']) { $indicator.Summary['Country'] } else { 'Unknown country' }
        $asnPill = if ($indicator.Summary['ASN']) { "ASN $($indicator.Summary['ASN'])" } elseif ($indicator.Summary['ASN Number']) { "ASN $($indicator.Summary['ASN Number'])" } else { 'Unknown ASN' }
        $dangerPill = if ($indicator.AbuseIP -and $indicator.AbuseIP.IsMatch) { '<span class="pill danger">AbuseIP match</span>' } else { '' }

        @"
        <article class="indicator-card" id="$(ConvertTo-SafeHtml $indicator.ReportId)">
          <header class="indicator-head">
            <div>
              <p class="eyebrow">Indicator $($i + 1)</p>
              <h2 class="indicator-title"><a href="$(ConvertTo-SafeHtml $indicator.PrimaryHref)" target="_blank" rel="noopener noreferrer">$(ConvertTo-SafeHtml $indicator.Value)</a></h2>
              <div class="pill-row">
                <span class="pill">$(ConvertTo-SafeHtml $typePill)</span>
                $dangerPill
                <span class="pill">$(ConvertTo-SafeHtml $countryPill)</span>
                <span class="pill">$(ConvertTo-SafeHtml $asnPill)</span>
                <span class="pill">$hostCount hosts</span>
                <span class="pill">$urlCount URLs</span>
              </div>
            </div>
            <div class="timestamp">$(ConvertTo-SafeHtml $indicator.Timestamp)</div>
          </header>

          <div class="indicator-body">
            $abusePanel
            <details open>
              <summary><span>Investigation Summary</span></summary>
              <div class="table-wrap">
                <table class="summary-table">
                  $(ConvertTo-ReportTableRows -Data $indicator.Summary)
                </table>
              </div>
            </details>
            $($sectionHtml -join [Environment]::NewLine)
            $screenshotPanel
            <details class="full">
              <summary><span>Lookup Resources</span></summary>
              <ul class="link-grid">
                $($links -join [Environment]::NewLine)
              </ul>
            </details>
          </div>
        </article>
"@
    }

    $title = if ($indicators.Count -eq 1) { $indicators[0].Value } else { 'Indicator Intelligence Report' }
    $css = New-ReportCss
    $html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SOCCOM Investigation Report - $(ConvertTo-SafeHtml $title)</title>
  <style>
$css
  </style>
</head>
<body>
  <main class="page">
    <header class="report-header">
      <div>
        <p class="eyebrow">SOCCOM</p>
        <h1>$(ConvertTo-SafeHtml $title)</h1>
        <p class="header-copy">A SOC-focused evidence report for quickly reviewing suspicious indicators and the intelligence gathered around them.</p>
      </div>
      <div class="timestamp">$(ConvertTo-SafeHtml $firstTimestamp) to $(ConvertTo-SafeHtml $lastTimestamp)</div>
    </header>

    <section class="summary-grid" aria-label="Report summary">
      <div class="metric"><span>Total Indicators</span><strong>$($indicators.Count)</strong></div>
      <div class="metric"><span>Countries</span><strong>$($countries.Count)</strong></div>
      <div class="metric"><span>Unique ASNs</span><strong>$($asns.Count)</strong></div>
      <div class="metric"><span>AbuseIP Matches</span><strong>$abuseMatches</strong></div>
    </section>

    <div class="report-layout">
      <aside class="indicator-nav" aria-label="Indicator index">
        <p class="nav-title">Indicator Index</p>
        <ol class="nav-list">
          $($navItems -join [Environment]::NewLine)
        </ol>
      </aside>

      <section class="indicator-stack" aria-label="Indicator details">
        $($cards -join [Environment]::NewLine)
      </section>
    </div>

    <p class="note">This report is an enrichment aid, not a final verdict. Indicators may still be malicious even when no source flags them.</p>
    <footer class="report-credit">Generated by <a href="https://github.com/ArronJablonowski/SOCCOM" target="_blank" rel="noopener noreferrer">SOCCOM</a> | Created by <a href="https://github.com/ArronJablonowski" target="_blank" rel="noopener noreferrer">Arron Jablonowski</a></footer>
  </main>
</body>
</html>
"@

    Set-Content -Path $Path -Value $html -Encoding UTF8
}

# Build out the modern HTML report from the queued scan results.
function writeReport() {
    Write-Verbose -Verbose "BUILDING REPORT"
    $script:ReportIndicators.Clear()
    getInfoBuildReport
    Write-ModernHtmlReport -Path $global:htmlReport
}
# Initialize the transient queue file used by indicator investigation runs.
If(!(Test-Path $logFilePath)){ 
    Add-Content -Path $logFilePath -Value "Domain,URLScanResult,VirusTotalScanID"
}

# Self-update from GitHub. The downloaded script is syntax-checked before it replaces
# the local copy, and the current script is backed up for rollback.
Function UpdateSOCCOM() {
    $repoUrl = "https://github.com/ArronJablonowski/SOCCOM"
    $candidateUrls = @(
        "$repoUrl/raw/main/SOCCOM.ps1",
        "$repoUrl/raw/master/SOCCOM.ps1"
    )
    $currentScript = Join-Path -Path (Get-Location) -ChildPath "SOCCOM.ps1"
    $downloadPath = Join-Path -Path (Get-Location) -ChildPath "SOCCOM.update.ps1"
    $backupPath = Join-Path -Path (Get-Location) -ChildPath ("SOCCOM.backup_{0}.ps1" -f (Get-Date).ToString("yyyyMMdd_HHmmss"))
    $downloaded = $false

    # Support both main and master so the updater survives common default branch names.
    foreach ($candidateUrl in $candidateUrls) {
        try {
            Write-Host "Checking for SOCCOM update from: $candidateUrl"
            Invoke-WebRequest -Uri $candidateUrl -OutFile $downloadPath -ErrorAction Stop
            $downloaded = $true
            break
        }
        catch {
            Write-Warning "Unable to download from $candidateUrl. $($_.Exception.Message)"
        }
    }

    if (-not $downloaded -or !(Test-Path $downloadPath)) {
        Write-Host "SOCCOM update was not found on GitHub."
        Write-Host "Please confirm SOCCOM.ps1 has been uploaded to $repoUrl."
        Write-Host
        Exit
    }

    # Never replace the local tool with a downloaded file that fails PowerShell parsing.
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $downloadPath), [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors) {
        Remove-Item -Path $downloadPath -Force
        Write-Host "Downloaded update failed PowerShell syntax validation. Local SOCCOM.ps1 was not changed."
        $parseErrors | ForEach-Object { Write-Host " - $($_.Message)" }
        Write-Host
        Exit
    }

    # Remove generated helper files so a fresh run recreates dependencies after update.
    foreach ($tempFile in 'PsExec.exe', 'VirusTotal.psm1') {
        $tempPath = Get-SoccomTempPath -FileName $tempFile
        If(Test-Path $tempPath) {Remove-Item $tempPath}
    }

    if (Test-Path $currentScript) {
        Copy-Item -Path $currentScript -Destination $backupPath -Force
    }

    Move-Item -Path $downloadPath -Destination $currentScript -Force
    Write-Host "SOCCOM updated from GitHub."
    Write-Host "Backup created: $backupPath"
}

#################################################################################################################
############################################# Base64 Embedded Files #############################################
#################################################################################################################

# Materialize the embedded VirusTotal helper module into the temp directory. This keeps
# SOCCOM portable while preserving the old module-based API wrappers.
Function VirusTotalPSModule() { 
    $virusTotalModulePath = Get-SoccomTempPath -FileName 'VirusTotal.psm1'
    If(!(Test-Path $virusTotalModulePath)) { # - VirusTotal.psm1 - http://www.darkoperator.com
        $virustotal_psm1_Base64 = "PCMNCi5TeW5vcHNpcw0KICAgR2V0IGEgVmlydXNUb3RhbCBSZXBvcnQgZm9yIGEgZ2l2ZW4gSVB2NCBBZGRyZXNzDQouREVTQ1JJUFRJT04NCiAgIEdldCBhIFZpcnVzVG90YWwgUmVwb3J0IGZvciBhIGdpdmVuIElQdjQgQWRkcmVzcyB0aGF0IGhhdmUgYmVlbiBwcmV2aW91c2x5IHNjYW5uZWQuDQouRVhBTVBMRQ0KICAgR2V0LVZpcnR1c1RvdGFsSVBSZXBvcnQgLUlQQWRkcmVzcyA5MC4xNTYuMjAxLjE4IC1BUElLZXkgJEtleQ0KLkxJTksNCiAgICBodHRwOi8vd3d3LmRhcmtvcGVyYXRvci5jb20NCiAgICBodHRwczovL3d3dy52aXJ1c3RvdGFsLmNvbS9lbi9kb2N1bWVudGF0aW9uL3B1YmxpYy1hcGkvDQojPg0KZnVuY3Rpb24gR2V0LVZpcnVzVG90YWxJUFJlcG9ydA0Kew0KICAgIFtDbWRsZXRCaW5kaW5nKCldDQogICAgUGFyYW0NCiAgICAoDQogICAgICAgICMgSVAgQWRkcmVzcyB0byBzY2FuIGZvci4NCiAgICAgICAgW1BhcmFtZXRlcihNYW5kYXRvcnk9JHRydWUsDQogICAgICAgICAgICAgICAgICAgVmFsdWVGcm9tUGlwZWxpbmVCeVByb3BlcnR5TmFtZT0kdHJ1ZSwNCiAgICAgICAgICAgICAgICAgICBQb3NpdGlvbj0wKV0NCiAgICAgICAgW3N0cmluZ10kSVBBZGRyZXNzLA0KDQogICAgICAgICMgVmlydXNUb3JhbCBBUEkgS2V5Lg0KICAgICAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kdHJ1ZSldDQogICAgICAgIFtzdHJpbmddJEFQSUtleQ0KICAgICkNCg0KICAgIEJlZ2luDQogICAgew0KICAgICAgICAkVVJJID0gJ2h0dHBzOi8vd3d3LnZpcnVzdG90YWwuY29tL3Z0YXBpL3YyL2lwLWFkZHJlc3MvcmVwb3J0Jw0KICAgIH0NCiAgICBQcm9jZXNzDQogICAgew0KICAgICAgICBUcnkNCiAgICAgICAgew0KICAgICAgICAgICAgJElQUmVwb3J0ID0gSW52b2tlLVJlc3RNZXRob2QgLVVyaSAkVVJJIC1tZXRob2QgZ2V0IC1Cb2R5IEB7J2lwJz0gJElQQWRkcmVzczsgJ2FwaWtleSc9ICRBUElLZXl9DQogICAgICAgICAgICAkSVBSZXBvcnQucHN0eXBlbmFtZXMuaW5zZXJ0KDAsJ1ZpcnVzVG90YWwuSVAuUmVwb3J0JykNCiAgICAgICAgICAgICRJUFJlcG9ydA0KICAgICAgICB9DQogICAgICAgIENhdGNoIFtOZXQuV2ViRXhjZXB0aW9uXQ0KICAgICAgICB7DQogICAgICAgICAgICBpZiAoJEVycm9yWzBdLlRvU3RyaW5nKCkgLWxpa2UgIio0MDMqIikNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBXcml0ZS1FcnJvciAiQVBJIGtleSBpcyBub3QgdmFsaWQuIg0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgZWxzZWlmICgkRXJyb3JbMF0uVG9TdHJpbmcoKSAtbGlrZSAiKjIwNCoiKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIFdyaXRlLUVycm9yICJBUEkga2V5IHJhdGUgaGFzIGJlZW4gcmVhY2hlZC4iDQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQogICAgRW5kDQogICAgew0KICAgIH0NCn0NCg0KPCMNCi5TeW5vcHNpcw0KICAgR2V0IGEgVmlydXNUb3RhbCBSZXBvcnQgZm9yIGEgZ2l2ZW4gRG9tYWluDQouREVTQ1JJUFRJT04NCiAgIEdldCBhIFZpcnVzVG90YWwgUmVwb3J0IGZvciBhIGdpdmVuIERvbWlhbiB0aGF0IGhhdmUgYmVlbiBwcmV2aW91c2x5IHNjYW5uZWQuDQouRVhBTVBMRQ0KICAgR2V0LVZpcnVzVG90YWxEb21haW5SZXBvcnQgLURvbWFpbiAnMDI3LnJ1JyAtQVBJS2V5ICRLZXkNCi5MSU5LDQogICAgaHR0cDovL3d3dy5kYXJrb3BlcmF0b3IuY29tDQogICAgaHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20vZW4vZG9jdW1lbnRhdGlvbi9wdWJsaWMtYXBpLw0KIz4NCmZ1bmN0aW9uIEdldC1WaXJ1c1RvdGFsRG9tYWluUmVwb3J0DQp7DQogICAgW0NtZGxldEJpbmRpbmcoKV0NCiAgICBQYXJhbQ0KICAgICgNCiAgICAgICAgIyBEb21haW4gdG8gc2Nhbi4NCiAgICAgICAgW1BhcmFtZXRlcihNYW5kYXRvcnk9JHRydWUsDQogICAgICAgICAgICAgICAgICAgVmFsdWVGcm9tUGlwZWxpbmVCeVByb3BlcnR5TmFtZT0kdHJ1ZSwNCiAgICAgICAgICAgICAgICAgICBQb3NpdGlvbj0wKV0NCiAgICAgICAgW3N0cmluZ10kRG9tYWluLA0KDQogICAgICAgICMgVmlydXNUb3JhbCBBUEkgS2V5Lg0KICAgICAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kdHJ1ZSldDQogICAgICAgIFtzdHJpbmddJEFQSUtleQ0KICAgICkNCg0KICAgIEJlZ2luDQogICAgew0KICAgICAgICAkVVJJID0gJ2h0dHBzOi8vd3d3LnZpcnVzdG90YWwuY29tL3Z0YXBpL3YyL2RvbWFpbi9yZXBvcnQnDQogICAgfQ0KICAgIFByb2Nlc3MNCiAgICB7DQogICAgICAgIFRyeQ0KICAgICAgICB7DQogICAgICAgICAgICAkRG9tYWluUmVwb3J0ID0gSW52b2tlLVJlc3RNZXRob2QgLVVyaSAkVVJJIC1tZXRob2QgZ2V0IC1Cb2R5IEB7J2RvbWFpbic9ICREb21haW47ICdhcGlrZXknPSAkQVBJS2V5fQ0KICAgICAgICAgICAgJERvbWFpblJlcG9ydC5wc3R5cGVuYW1lcy5pbnNlcnQoMCwnVmlydXNUb3RhbC5Eb21haW4uUmVwb3J0JykNCiAgICAgICAgICAgICREb21haW5SZXBvcnQNCiAgICAgICAgfQ0KICAgICAgICBDYXRjaCBbTmV0LldlYkV4Y2VwdGlvbl0NCiAgICAgICAgew0KICAgICAgICAgICAgaWYgKCRFcnJvclswXS5Ub1N0cmluZygpIC1saWtlICIqNDAzKiIpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgV3JpdGUtRXJyb3IgIkFQSSBrZXkgaXMgbm90IHZhbGlkLiINCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIGVsc2VpZiAoJEVycm9yWzBdLlRvU3RyaW5nKCkgLWxpa2UgIioyMDQqIikNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBXcml0ZS1FcnJvciAiQVBJIGtleSByYXRlIGhhcyBiZWVuIHJlYWNoZWQuIg0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgfQ0KICAgIEVuZA0KICAgIHsNCiAgICB9DQp9DQoNCg0KPCMNCi5TeW5vcHNpcw0KICAgR2V0IGEgVmlydXNUb3RhbCBSZXBvcnQgZm9yIGEgZ2l2ZW4gRmlsZQ0KLkRFU0NSSVBUSU9ODQogICBHZXQgYSBWaXJ1c1RvdGFsIFJlcG9ydCBmb3IgYSBnaXZlbiBGaWxlIHRoYXQgaGF2ZSBiZWVuIHByZXZpb3VzbHkgc2Nhbm5lZC4NCiAgIEEgTUQ1LCBTSEExIG9yIFNIQTIgQ3J5cHRwZ3JhcGhpYyBIYXNoIGNhbiBiZSBwcm92aWRlZCBvciBhIFNjYW5JRCBmb3IgYSBGaWxlLg0KICAgVXAgdG8gNCBmaWxlIHJlcG9yc3QgY2FuIGJlIHJldHJpZXZlIGF0IHRoZSBzYW1lIHRpbWUuDQouRVhBTVBMRQ0KICAgR2V0LVZpcnVzVG90YWxGaWxlUmVwb3J0IC1SZXNvdXJjZSA5OTAxN2Y2ZWViYmFjMjRmMzUxNDE1ZGQ0MTBkNTIyZCAtQVBJS2V5ICRLZXkNCi5MSU5LDQogICAgaHR0cDovL3d3dy5kYXJrb3BlcmF0b3IuY29tDQogICAgaHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20vZW4vZG9jdW1lbnRhdGlvbi9wdWJsaWMtYXBpLw0KIz4NCmZ1bmN0aW9uIEdldC1WaXJ1c1RvdGFsRmlsZVJlcG9ydA0Kew0KICAgIFtDbWRsZXRCaW5kaW5nKCldDQogICAgUGFyYW0NCiAgICAoDQogICAgICAgICMgRmlsZSBNRDUgQ2hlY2tzdW0sIEZpbGUgU0hBMSBDaGVja3N1bSwgRmlsZSBTSEEyNTYgQ2hlY2tzdW0gb3IgU2NhbklEIHRvIHF1ZXJ5Lg0KICAgICAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kdHJ1ZSwNCiAgICAgICAgICAgICAgICAgICBWYWx1ZUZyb21QaXBlbGluZUJ5UHJvcGVydHlOYW1lPSR0cnVlLA0KICAgICAgICAgICAgICAgICAgIFBvc2l0aW9uPTApXQ0KICAgICAgICBbVmFsaWRhdGVDb3VudCgxLDQpXQ0KICAgICAgICBbc3RyaW5nW11dJFJlc291cmNlLA0KDQogICAgICAgICMgVmlydXNUb3JhbCBBUEkgS2V5Lg0KICAgICAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kdHJ1ZSldDQogICAgICAgIFtzdHJpbmddJEFQSUtleQ0KICAgICkNCg0KICAgIEJlZ2luDQogICAgew0KICAgICAgICAkVVJJID0gJ2h0dHBzOi8vd3d3LnZpcnVzdG90YWwuY29tL3Z0YXBpL3YyL2ZpbGUvcmVwb3J0Jw0KICAgIH0NCiAgICBQcm9jZXNzDQogICAgew0KICAgICAgICAkUXVlcnlSZXNvdXJjZXMgPSAgJFJlc291cmNlIC1qb2luICIsIg0KDQogICAgICAgIFRyeQ0KICAgICAgICB7DQogICAgICAgICAgICAkUmVwb3J0UmVzdWx0ID1JbnZva2UtUmVzdE1ldGhvZCAtVXJpICRVUkkgLW1ldGhvZCBnZXQgLUJvZHkgQHsncmVzb3VyY2UnPSAkUXVlcnlSZXNvdXJjZXM7ICdhcGlrZXknPSAkQVBJS2V5fQ0KICAgICAgICAgICAgZm9yZWFjaCAoJEZpbGVSZXBvcnQgaW4gJFJlcG9ydFJlc3VsdCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAkRmlsZVJlcG9ydC5wc3R5cGVuYW1lcy5pbnNlcnQoMCwnVmlydXNUb3RhbC5GaWxlLlJlcG9ydCcpDQogICAgICAgICAgICAgICAgJEZpbGVSZXBvcnQNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KICAgICAgICBDYXRjaCBbTmV0LldlYkV4Y2VwdGlvbl0NCiAgICAgICAgew0KICAgICAgICAgICAgaWYgKCRFcnJvclswXS5Ub1N0cmluZygpIC1saWtlICIqNDAzKiIpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgV3JpdGUtRXJyb3IgIkFQSSBrZXkgaXMgbm90IHZhbGlkLiINCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIGVsc2VpZiAoJEVycm9yWzBdLlRvU3RyaW5nKCkgLWxpa2UgIioyMDQqIikNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBXcml0ZS1FcnJvciAiQVBJIGtleSByYXRlIGhhcyBiZWVuIHJlYWNoZWQuIg0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgfQ0KICAgIEVuZA0KICAgIHsNCiAgICB9DQp9DQoNCg0KPCMNCi5TeW5vcHNpcw0KICAgR2V0IGEgVmlydXNUb3RhbCBSZXBvcnQgZm9yIGEgZ2l2ZW4gVVJMDQouREVTQ1JJUFRJT04NCiAgIEdldCBhIFZpcnVzVG90YWwgUmVwb3J0IGZvciBhIGdpdmVuIFVSTCB0aGF0IGhhdmUgYmVlbiBwcmV2aW91c2x5IHNjYW5uZWQuDQogICBBIFVSTCBvciBhIFNjYW5JRCBmb3IgcHJldm91cyBzY2FuLiBVcCB0byA0IFVSTCByZXBvcnN0IGNhbiBiZSByZXRyaWV2ZSBhdCB0aGUgc2FtZSB0aW1lLg0KLkVYQU1QTEUNCiAgIEdldC1WaXJ1c1RvdGFsVVJMUmVwb3J0IC1SZXNvdXJjZSBodHRwOi8vd3d3LmRhcmtvcGVyYXRvci5jb20gLUFQSUtleSAkS2V5DQouTElOSw0KICAgIGh0dHA6Ly93d3cuZGFya29wZXJhdG9yLmNvbQ0KICAgIGh0dHBzOi8vd3d3LnZpcnVzdG90YWwuY29tL2VuL2RvY3VtZW50YXRpb24vcHVibGljLWFwaS8NCiM+DQpmdW5jdGlvbiBHZXQtVmlydXNUb3RhbFVSTFJlcG9ydA0Kew0KICAgIFtDbWRsZXRCaW5kaW5nKCldDQogICAgUGFyYW0NCiAgICAoDQogICAgICAgICMgVVJMIG9yIFNjYW5JRCB0byBxdWVyeS4NCiAgICAgICAgW1BhcmFtZXRlcihNYW5kYXRvcnk9JHRydWUsDQogICAgICAgICAgICAgICAgICAgVmFsdWVGcm9tUGlwZWxpbmVCeVByb3BlcnR5TmFtZT0kdHJ1ZSwNCiAgICAgICAgICAgICAgICAgICBQb3NpdGlvbj0wKV0NCiAgICAgICAgW1ZhbGlkYXRlQ291bnQoMSw0KV0NCiAgICAgICAgW3N0cmluZ1tdXSRSZXNvdXJjZSwNCg0KICAgICAgICAjIFZpcnVzVG9yYWwgQVBJIEtleS4NCiAgICAgICAgW1BhcmFtZXRlcihNYW5kYXRvcnk9JHRydWUpXQ0KICAgICAgICBbc3RyaW5nXSRBUElLZXksDQoNCiAgICAgICAgIyBBdXRvbWF0aWNhbGx5IHN1Ym1pdCB0aGUgVVJMIGZvciBhbmFseXNpcyBpZiBubyByZXBvcnQgaXMgZm91bmQgZm9yIGl0IGluIFZpcnVzVG90YWwuDQogICAgICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSRmYWxzZSldDQogICAgICAgIFtzd2l0Y2hdJFNjYW4NCiAgICApDQoNCiAgICBCZWdpbg0KICAgIHsNCiAgICAgICAgJFVSSSA9ICdodHRwczovL3d3dy52aXJ1c3RvdGFsLmNvbS92dGFwaS92Mi91cmwvcmVwb3J0Jw0KICAgICAgICBpZiAoJFNjYW4pDQogICAgICAgIHsNCiAgICAgICAgICAgICRzY2FudXJsID0gMQ0KICAgICAgICB9DQogICAgICAgIGVsc2UNCiAgICAgICAgew0KICAgICAgICAgICAgJHNjYW51cmwgPSAwDQogICAgICAgIH0NCiAgICB9DQogICAgUHJvY2Vzcw0KICAgIHsNCiAgICAgICAgJFF1ZXJ5UmVzb3VyY2VzID0gICRSZXNvdXJjZSAtam9pbiAiLCINCg0KICAgICAgICBUcnkNCiAgICAgICAgew0KICAgICAgICAgICAgJFJlcG9ydFJlc3VsdCA9IEludm9rZS1SZXN0TWV0aG9kIC1VcmkgJFVSSSAtbWV0aG9kIGdldCAtQm9keSBAeydyZXNvdXJjZSc9ICRRdWVyeVJlc291cmNlczsgJ2FwaWtleSc9ICRBUElLZXk7ICdzY2FuJz0kc2NhbnVybH0NCiAgICAgICAgICAgIGZvcmVhY2ggKCRVUkxSZXBvcnQgaW4gJFJlcG9ydFJlc3VsdCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAkVVJMUmVwb3J0LnBzdHlwZW5hbWVzLmluc2VydCgwLCdWaXJ1c1RvdGFsLlVSTC5SZXBvcnQnKQ0KICAgICAgICAgICAgICAgICRVUkxSZXBvcnQNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KICAgICAgICBDYXRjaCBbTmV0LldlYkV4Y2VwdGlvbl0NCiAgICAgICAgew0KICAgICAgICAgICAgaWYgKCRFcnJvclswXS5Ub1N0cmluZygpIC1saWtlICIqNDAzKiIpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgV3JpdGUtRXJyb3IgIkFQSSBrZXkgaXMgbm90IHZhbGlkLiINCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIGVsc2VpZiAoJEVycm9yWzBdLlRvU3RyaW5nKCkgLWxpa2UgIioyMDQqIikNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBXcml0ZS1FcnJvciAiQVBJIGtleSByYXRlIGhhcyBiZWVuIHJlYWNoZWQuIg0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgfQ0KICAgIEVuZA0KICAgIHsNCiAgICB9DQp9DQoNCg0KPCMNCi5TeW5vcHNpcw0KICAgU3VibWl0IGEgVVJMIGZvciBzY2FubmluZyBieSBWaXJ1c1RvdGFsDQouREVTQ1JJUFRJT04NCiAgIFN1Ym1pdCBhIFVSTCBmb3Igc2Nhbm5pbmcgYnkgVmlydXNUb3RhbC4gVXAgdG8gNCBVUkxjYW4gYmUgc3VibWl0dGVkIGF0IHRoZSBzYW1lIHRpbWUuDQouRVhBTVBMRQ0KICAgU3VibWl0LVZpcnVzVG90YWxVUkwgLVVSTCAiaHR0cDovL3d3dy5kYXJrb3BlcmF0b3IuY29tIiwiaHR0cDovL2dhbWlsLmNvbSIgLUFQSUtleSAkS2V5DQouTElOSw0KICAgIGh0dHA6Ly93d3cuZGFya29wZXJhdG9yLmNvbQ0KICAgIGh0dHBzOi8vd3d3LnZpcnVzdG90YWwuY29tL2VuL2RvY3VtZW50YXRpb24vcHVibGljLWFwaS8NCiM+DQpmdW5jdGlvbiBTdWJtaXQtVmlydXNUb3RhbFVSTA0Kew0KICAgIFtDbWRsZXRCaW5kaW5nKCldDQogICAgUGFyYW0NCiAgICAoDQogICAgICAgICMgVVJMIG9yIFNjYW5JRCB0byBxdWVyeS4NCiAgICAgICAgW1BhcmFtZXRlcihNYW5kYXRvcnk9JHRydWUsDQogICAgICAgICAgICAgICAgICAgVmFsdWVGcm9tUGlwZWxpbmVCeVByb3BlcnR5TmFtZT0kdHJ1ZSwNCiAgICAgICAgICAgICAgICAgICBQb3NpdGlvbj0wKV0NCiAgICAgICAgW1ZhbGlkYXRlQ291bnQoMSw0KV0NCiAgICAgICAgW3N0cmluZ1tdXSRVUkwsDQoNCiAgICAgICAgIyBWaXJ1c1RvcmFsIEFQSSBLZXkuDQogICAgICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSR0cnVlKV0NCiAgICAgICAgW3N0cmluZ10kQVBJS2V5LA0KDQogICAgICAgICMgQXV0b21hdGljYWxseSBzdWJtaXQgdGhlIFVSTCBmb3IgYW5hbHlzaXMgaWYgbm8gcmVwb3J0IGlzIGZvdW5kIGZvciBpdCBpbiBWaXJ1c1RvdGFsLg0KICAgICAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kZmFsc2UpXQ0KICAgICAgICBbc3dpdGNoXSRTY2FuDQogICAgKQ0KDQogICAgQmVnaW4NCiAgICB7DQogICAgICAgICRVUkkgPSAnaHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20vdnRhcGkvdjIvdXJsL3NjYW4nDQogICAgICAgIGlmICgkU2NhbikNCiAgICAgICAgew0KICAgICAgICAgICAgJHNjYW51cmwgPSAxDQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICAkc2NhbnVybCA9IDANCiAgICAgICAgfQ0KICAgIH0NCiAgICBQcm9jZXNzDQogICAgew0KICAgICAgICAkVVJMTGlzdCA9ICAkVVJMIC1qb2luICJgbiINCg0KICAgICAgICBUcnkNCiAgICAgICAgew0KICAgICAgICAgICAgJFN1Ym1pdGVkTGlzdCA9IEludm9rZS1SZXN0TWV0aG9kIC1VcmkgJFVSSSAtbWV0aG9kIFBvc3QgLUJvZHkgQHsndXJsJz0gJFVSTExpc3Q7ICdhcGlrZXknPSAkQVBJS2V5fQ0KICAgICAgICAgICAgZm9yZWFjaCgkc3VibWl0ZWQgaW4gJFN1Ym1pdGVkTGlzdCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAkc3VibWl0ZWQucHN0eXBlbmFtZXMuaW5zZXJ0KDAsJ1ZpcnVzVG90YWwuVVJMLlN1Ym1pc3Npb24nKQ0KICAgICAgICAgICAgICAgICRzdWJtaXRlZA0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgICAgIENhdGNoIFtOZXQuV2ViRXhjZXB0aW9uXQ0KICAgICAgICB7DQogICAgICAgICAgICBpZiAoJEVycm9yWzBdLlRvU3RyaW5nKCkgLWxpa2UgIio0MDMqIikNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBXcml0ZS1FcnJvciAiQVBJIGtleSBpcyBub3QgdmFsaWQuIg0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgZWxzZWlmICgkRXJyb3JbMF0uVG9TdHJpbmcoKSAtbGlrZSAiKjIwNCoiKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIFdyaXRlLUVycm9yICJBUEkga2V5IHJhdGUgaGFzIGJlZW4gcmVhY2hlZC4iDQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQogICAgRW5kDQogICAgew0KICAgIH0NCn0NCg0KPCMNCi5TeW5vcHNpcw0KICAgU3VibWl0IGEgRmlsZSBmb3Igc2Nhbm5pbmcgYnkgVmlydXNUb3RhbA0KLkRFU0NSSVBUSU9ODQogICBTdWJtaXQgYSBGaWxlIGZvciBzY2FubmluZyBieSBWaXJ1c1RvdGFsLiBGaWxlIHNpemUgaXMgbGltaXRlZCB0byAyME1CLg0KLkVYQU1QTEUNCiAgIFN1Ym1pdC1WaXJ1c1RvdGFsRmlsZSAtRmlsZSBDOlxiYWNrZG9vci5kbGwgLUFQSUtleSAkS2V5DQouTElOSw0KICAgIGh0dHA6Ly93d3cuZGFya29wZXJhdG9yLmNvbQ0KICAgIGh0dHBzOi8vd3d3LnZpcnVzdG90YWwuY29tL2VuL2RvY3VtZW50YXRpb24vcHVibGljLWFwaS8NCiM+DQpmdW5jdGlvbiBTdWJtaXQtVmlydXNUb3RhbEZpbGUNCnsNCiAgICBbQ21kbGV0QmluZGluZygpXQ0KICAgIFBhcmFtDQogICAgKA0KICAgICAgICAjIFVSTCBvciBTY2FuSUQgdG8gcXVlcnkuDQogICAgICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSR0cnVlLA0KICAgICAgICAgICAgICAgICAgIFZhbHVlRnJvbVBpcGVsaW5lQnlQcm9wZXJ0eU5hbWU9JHRydWUsDQogICAgICAgICAgICAgICAgICAgUG9zaXRpb249MCldDQogICAgICAgIFtWYWxpZGF0ZVNjcmlwdCh7VGVzdC1QYXRoICRfIC1QYXRoVHlwZSBMZWFmfSldDQogICAgICAgIFtzdHJpbmddJEZpbGUsDQoNCiAgICAgICAgIyBWaXJ1c1RvcmFsIEFQSSBLZXkuDQogICAgICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSR0cnVlKV0NCiAgICAgICAgW3N0cmluZ10kQVBJS2V5DQogICAgKQ0KDQogICAgQmVnaW4NCiAgICB7DQogICAgICAgICRVUkkgPSAiaHR0cDovL3d3dy52aXJ1c3RvdGFsLmNvbS92dGFwaS92Mi9maWxlL3NjYW4iDQogICAgfQ0KICAgIFByb2Nlc3MNCiAgICB7DQogICAgICAgICRmaWxlaW5mbyA9IEdldC1JdGVtUHJvcGVydHkgLVBhdGggJEZpbGUNCg0KICAgICAgICAjIENoZWNrIHRoZSBmaWxlIHNpemUNCiAgICAgICAgaWYgKCRmaWxlaW5mby5sZW5ndGggLWd0IDY0bWIpDQogICAgICAgIHsNCiAgICAgICAgICAgIFdyaXRlLUVycm9yICJWaXJ1c1RvdGFsIGhhcyBhIGxpbWl0IG9mIDY0TUIgcGVyIGZpbGUgc3VibWl0ZWQiIC1FcnJvckFjdGlvbiBTdG9wDQogICAgICAgIH0NCiAgIA0KICAgICAgICAkcmVxID0gW1N5c3RlbS5OZXQuaHR0cFdlYlJlcXVlc3RdW1N5c3RlbS5OZXQuV2ViUmVxdWVzdF06OkNyZWF0ZSgiaHR0cDovL3d3dy52aXJ1c3RvdGFsLmNvbS92dGFwaS92Mi9maWxlL3NjYW4iKQ0KICAgICAgICAkcmVxLkhlYWRlcnMgPSAkaGVhZGVycw0KICAgICAgICAkcmVxLk1ldGhvZCA9ICJQT1NUIg0KICAgICAgICAkcmVxLkFsbG93V3JpdGVTdHJlYW1CdWZmZXJpbmcgPSAkdHJ1ZTsNCiAgICAgICAgJHJlcS5TZW5kQ2h1bmtlZCA9ICRmYWxzZTsNCiAgICAgICAgJHJlcS5LZWVwQWxpdmUgPSAkdHJ1ZTsNCg0KICAgICAgICAkaGVhZGVycyA9IE5ldy1PYmplY3QgLVR5cGVOYW1lIFN5c3RlbS5OZXQuV2ViSGVhZGVyQ29sbGVjdGlvbg0KDQogICAgICAgICMgUHJlcCB0aGUgUE9TVCBIZWFkZXJzIGZvciB0aGUgbWVzc2FnZQ0KICAgICAgICAkaGVhZGVycy5hZGQoImFwaWtleSIsJGFwaWtleSkNCiAgICAgICAgJGJvdW5kYXJ5ID0gIi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0iICsgW0RhdGVUaW1lXTo6Tm93LlRpY2tzLlRvU3RyaW5nKCJ4IikNCiAgICAgICAgJHJlcS5Db250ZW50VHlwZSA9ICJtdWx0aXBhcnQvZm9ybS1kYXRhOyBib3VuZGFyeT0iICsgJGJvdW5kYXJ5DQogICAgICAgIFtieXRlW11dJGJvdW5kYXJ5Ynl0ZXMgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRCeXRlcygiYHJgbi0tIiArICRib3VuZGFyeSArICJgcmBuIikNCiAgICAgICAgW3N0cmluZ10kZm9ybWRhdGFUZW1wbGF0ZSA9ICJgcmBuLS0iICsgJGJvdW5kYXJ5ICsgImByYG5Db250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9YCJ7MH1gIjtgcmBuYHJgbnsxfSINCiAgICAgICAgW3N0cmluZ10kZm9ybWl0ZW0gPSBbc3RyaW5nXTo6Rm9ybWF0KCRmb3JtZGF0YVRlbXBsYXRlLCAiYXBpa2V5IiwgJGFwaWtleSkNCiAgICAgICAgW2J5dGVbXV0kZm9ybWl0ZW1ieXRlcyA9IFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjguR2V0Qnl0ZXMoJGZvcm1pdGVtKQ0KICAgICAgICBbc3RyaW5nXSRoZWFkZXJUZW1wbGF0ZSA9ICJDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9YCJ7MH1gIjsgZmlsZW5hbWU9YCJ7MX1gImByYG5Db250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbWByYG5gcmBuIg0KICAgICAgICBbc3RyaW5nXSRoZWFkZXIgPSBbc3RyaW5nXTo6Rm9ybWF0KCRoZWFkZXJUZW1wbGF0ZSwgImZpbGUiLCAoZ2V0LWl0ZW0gJGZpbGUpLm5hbWUpDQogICAgICAgIFtieXRlW11dJGhlYWRlcmJ5dGVzID0gW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRCeXRlcygkaGVhZGVyKQ0KICAgICAgICBbc3RyaW5nXSRmb290ZXJUZW1wbGF0ZSA9ICJDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9YCJVcGxvYWRgImByYG5gcmBuU3VibWl0IFF1ZXJ5YHJgbiIgKyAkYm91bmRhcnkgKyAiLS0iDQogICAgICAgIFtieXRlW11dJGZvb3RlckJ5dGVzID0gW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRCeXRlcygkZm9vdGVyVGVtcGxhdGUpDQoNCg0KICAgICAgICAjIFJlYWQgdGhlIGZpbGUgYW5kIGZvcm1hdCB0aGUgbWVzc2FnZQ0KICAgICAgICAkc3RyZWFtID0gJHJlcS5HZXRSZXF1ZXN0U3RyZWFtKCkNCiAgICAgICAgJHJkciA9IG5ldy1vYmplY3QgU3lzdGVtLklPLkZpbGVTdHJlYW0oJGZpbGVpbmZvLkZ1bGxOYW1lLCBbU3lzdGVtLklPLkZpbGVNb2RlXTo6T3BlbiwgW1N5c3RlbS5JTy5GaWxlQWNjZXNzXTo6UmVhZCkNCiAgICAgICAgW2J5dGVbXV0kYnVmZmVyID0gbmV3LW9iamVjdCBieXRlW10gJHJkci5MZW5ndGgNCiAgICAgICAgW2ludF0kdG90YWwgPSBbaW50XSRjb3VudCA9IDANCiAgICAgICAgJHN0cmVhbS5Xcml0ZSgkZm9ybWl0ZW1ieXRlcywgMCwgJGZvcm1pdGVtYnl0ZXMuTGVuZ3RoKQ0KICAgICAgICAkc3RyZWFtLldyaXRlKCRib3VuZGFyeWJ5dGVzLCAwLCAkYm91bmRhcnlieXRlcy5MZW5ndGgpDQogICAgICAgICRzdHJlYW0uV3JpdGUoJGhlYWRlcmJ5dGVzLCAwLCRoZWFkZXJieXRlcy5MZW5ndGgpDQogICAgICAgICRjb3VudCA9ICRyZHIuUmVhZCgkYnVmZmVyLCAwLCAkYnVmZmVyLkxlbmd0aCkNCiAgICAgICAgZG97DQogICAgICAgICAgICAkc3RyZWFtLldyaXRlKCRidWZmZXIsIDAsICRjb3VudCkNCiAgICAgICAgICAgICRjb3VudCA9ICRyZHIuUmVhZCgkYnVmZmVyLCAwLCAkYnVmZmVyLkxlbmd0aCkNCiAgICAgICAgfXdoaWxlICgkY291bnQgPiAwKQ0KICAgICAgICAkc3RyZWFtLldyaXRlKCRib3VuZGFyeWJ5dGVzLCAwLCAkYm91bmRhcnlieXRlcy5MZW5ndGgpDQogICAgICAgICRzdHJlYW0uV3JpdGUoJGZvb3RlckJ5dGVzLCAwLCAkZm9vdGVyQnl0ZXMuTGVuZ3RoKQ0KICAgICAgICAkc3RyZWFtLmNsb3NlKCkNCg0KICAgICAgICBUcnkNCiAgICAgICAgew0KICAgICAgICAgICAgIyBVcGxvYWQgdGhlIGZpbGUNCiAgICAgICAgICAgICRyZXNwb25zZSA9ICRyZXEuR2V0UmVzcG9uc2UoKQ0KDQogICAgICAgICAgICAjIFJlYWQgdGhlIHJlc3BvbnNlDQogICAgICAgICAgICAkcmVzcHN0cmVhbSA9ICRyZXNwb25zZS5HZXRSZXNwb25zZVN0cmVhbSgpDQogICAgICAgICAgICAkc3IgPSBuZXctb2JqZWN0IFN5c3RlbS5JTy5TdHJlYW1SZWFkZXIgJHJlc3BzdHJlYW0NCiAgICAgICAgICAgICRyZXN1bHQgPSAkc3IuUmVhZFRvRW5kKCkNCiAgICAgICAgICAgIENvbnZlcnRGcm9tLUpzb24gJHJlc3VsdA0KICAgICAgICB9DQogICAgICAgIENhdGNoIFtOZXQuV2ViRXhjZXB0aW9uXQ0KICAgICAgICB7DQogICAgICAgICAgICBpZiAoJEVycm9yWzBdLlRvU3RyaW5nKCkgLWxpa2UgIio0MDMqIikNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBXcml0ZS1FcnJvciAiQVBJIGtleSBpcyBub3QgdmFsaWQuIg0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgZWxzZWlmICgkRXJyb3JbMF0uVG9TdHJpbmcoKSAtbGlrZSAiKjIwNCoiKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIFdyaXRlLUVycm9yICJBUEkga2V5IHJhdGUgaGFzIGJlZW4gcmVhY2hlZC4iDQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQogICAgRW5kDQogICAgew0KICAgIH0NCn0="
        $Content = [System.Convert]::FromBase64String($virustotal_psm1_Base64)
        [System.IO.File]::WriteAllBytes($virusTotalModulePath, $Content)
        Start-Sleep -Seconds 1
    }
}
VirusTotalPSModule
# Import the generated VirusTotal module before any investigation switches execute.
Import-Module (Get-SoccomTempPath -FileName 'VirusTotal.psm1')

##################################################################################################
############################################# Banner #############################################
##################################################################################################
Clear-Host 
Write-Host "[ SOCCOM ]------------------------------------------------"
Write-Host "   _____  ____   _____  _____ ____  __  __"
Write-Host "  / ____|/ __ \ / ____|/ ____/ __ \|  \/  |"
Write-Host " | (___ | |  | | |    | |   | |  | | \  / |"
Write-Host "  \___ \| |  | | |    | |   | |  | | |\/| |"
Write-Host "  ____) | |__| | |____| |___| |__| | |  | |"
Write-Host " |_____/ \____/ \_____|\_____\____/|_|  |_|"
Write-Host ""
Write-Host " Security Operations Center Central Command"
Write-Host " SOCCOM by: Arron Jablonowski"
Write-Host "------------------------------------------------[ v0.5.4 ]"
Write-Host " "

################################################################################################
############################### Where the Magic Happens. SOCCOM. ###############################
################################################################################################

# Main dispatcher. Each branch handles one supported switch and exits through that
# workflow. Prefer -Investigate for new indicator lookups; legacy switches remain for
# compatibility with older usage.
If (!([string]::IsNullOrEmpty($Investigate))){	 ### SWITCH: -Investigate ###
    Invoke-IndicatorInvestigation -Indicator $Investigate
    Write-IndicatorInvestigationReport -Indicator $Investigate
}ElseIf (!([string]::IsNullOrEmpty($Investigate_IPAddress))) {	 ### SWITCH: -Investigate_IPAddress ###
    if (-not (Test-IPAddress -Value $Investigate_IPAddress)) {
        Write-Host "Invalid IP address: $Investigate_IPAddress"
        Exit
    }
    Invoke-IndicatorInvestigation -Indicator $Investigate_IPAddress
    Write-IndicatorInvestigationReport -Indicator $Investigate_IPAddress
}ElseIf (!([string]::IsNullOrEmpty($Investigate_Domain))) {	 ### SWITCH: -Investigate_Domain ###
    Invoke-IndicatorInvestigation -Indicator $Investigate_Domain
    Write-IndicatorInvestigationReport -Indicator $Investigate_Domain
}ElseIf (!([string]::IsNullOrEmpty($Investigate_List))) {### SWITCH: -Investigate_List ### 
    $filebasename = [System.IO.Path]::GetFileNameWithoutExtension($Investigate_List)
    $input = $Investigate_List.Trim() 
    Write-Host "Reading File: $input"
    If(Test-Path $input) { # If file found 
        # List investigations reuse the same CSV queue but write one combined report.
        foreach($line in Get-Content $input) { # read file line by line
            if(Test-IPAddress -Value $line){ # line is an IP address 
             Write-Host "$line"
             checkIPAddress($line)
            }Else{ # treat the line as a domain
             Write-Host "$line"
             checkDomain($line)
            }
        }
    writeReport
    $safeFileBaseName = ConvertTo-SafeFileName -Value $filebasename
    $newReport = "$resultsFolder\$(New-TimestampedReportFileName -BaseName $safeFileBaseName)"
    Copy-Item -Path $global:htmlReport -Destination $newReport -Force
    Invoke-Item $newReport
    Remove-Item $global:htmlReport    
    }Else{ # if filePath not found 
        Write-Host "File was not found."
        Exit
    }
}ElseIf (!([string]::IsNullOrEmpty($SearchAD_Username))) {	 ### SWITCH: -SearchAD_Username###
    import-module activedirectory
    $input = $SearchAD_Username.Trim()
    Write-Host "Searching Active Directory: $input"
    Get-ADUser -Filter "samaccountname -like '$input*'" -Properties * | Select-Object -Property SamAccountName,GivenName,Othername,Surname,EmployeeID,employeeType,Enabled,DisplayName,Description,Title,Department,Manager,MobilePhone,TelephoneNumber,OfficePhone,EmailAddress,StreetAddress,City,State,PostalCode,PasswordNeverExpires,PasswordNotRequired,PasswordLastSet,LastBadPasswordAttempt,LastLogonDate,LockedOut,WhenCreated,WhenChanged,logonCount,LogonWorkstations,SID | Format-List
    #Next 2 lines added by Josh Hall
    Write-Host "Groups" -BackgroundColor "Cyan" -ForegroundColor "Black"
    (Get-ADUser -Filter "samaccountname -like '$input*'" -Properties * | Select-Object -Property MemberOf).MemberOf | Sort-Object | ForEach-Object {$_.split(",")[0].replace("CN=","")}
}ElseIf (!([string]::IsNullOrEmpty($SearchAD_UserList))) { ### SWITCH: -SearchAD_UserList ###
    import-module activedirectory
    $userListPath = "$resultsFolder\UserList.csv"
    $not_found_users = "$resultsFolder\UsersNotFoundList.csv"
    If(Test-Path $userListPath) { # If file found
        Remove-Item $userListPath # remove log file   
    }
    $input = $SearchAD_UserList.Trim()  
    Write-Host "Reading File: $input"
    # Keep found users and misses in separate CSV outputs so analysts can act on both.
    $newFile = foreach($user in Get-Content $input) {
       Write-Host "$user"  
       Start-Sleep -s 1
       $aduser = Get-ADUser -Filter "samaccountname -like '$user'" -Properties * | Select-Object -Property SamAccountName,GivenName,Othername,Surname,EmployeeID,employeeType,Enabled,DisplayName,Description,Title,Department,Manager,MobilePhone,TelephoneNumber,OfficePhone,EmailAddress,StreetAddress,City,State,PostalCode,PasswordNeverExpires,PasswordNotRequired,PasswordLastSet,LastBadPasswordAttempt,LastLogonDate,LockedOut,WhenCreated,WhenChanged,logonCount,LogonWorkstations,SID,MemberOf
       if ($aduser -eq $null ){
        Write-Host "USER NOT FOUND: $user" -ForegroundColor Yellow
            Add-Content -Path $not_found_users -Value $user
       }
       $aduser 
    } 
    $newFile | Export-Csv -Path $userListPath -Force
    Invoke-Item $userListPath
    Invoke-Item $not_found_users
}ElseIf (!([string]::IsNullOrEmpty($SearchAD_ComputerList))) { ### SWITCH: -SearchAD_ComputerList ###
    import-module activedirectory
    $compListPath = "$resultsFolder\ComputerList.csv"
    If(Test-Path $compListPath) { # If file found
        Remove-Item $compListPath # remove log file   
    }
    $input = $SearchAD_ComputerList.Trim()  
    Write-Host "Reading File: $input"
    # Export a compact inventory view for each requested hostname prefix.
    $newFile = foreach($comp in Get-Content $input) {
        $input = $comp.Trim()
        Write-Host "$input"  
       Get-ADComputer -Filter "DNSHostName -like '$input*'" -Property * | Select-Object Name,OperatingSystem,LastLogonDate,OperatingSystemServicePack,OperatingSystemVersion,SID,Description,DNSHostName,IPV4Address
    } 
    $newFile | Export-Csv -Path $compListPath -Force
    Invoke-Item $compListPath
}ElseIf (!([string]::IsNullOrEmpty($SearchAD_ComputerName))) {	 ### SWITCH: -SearchAD_ComputerName ###
    import-module activedirectory
    $input = $SearchAD_ComputerName.Trim()
    Write-Host "Searching Active Directory: $input"
    Get-ADComputer -Filter "DNSHostName -like '$input*'" -Property * | Select-Object Name,OperatingSystem,LastLogonDate,OperatingSystemServicePack,OperatingSystemVersion,SID,Description,DNSHostName,IPV4Address | format-list # Export-CSV AllWindows.csv -NoTypeInformation -Encoding UTF8
}
<#ElseIf (!([string]::IsNullOrEmpty($Enable_PSRemoting_PsExec))) {	 ### SWITCH: -Enable_PSRemoting_PsExec ###
    PsExec #Make sure PsExec is on system - if not, drop it in appdata\local\temp
    $timeStamp = timeStamp
    Write-Host "-- Enable Powershell Remoting on: $Enable_PSRemoting_PsExec --"
    Write-Host "--------------------------------------------------------------------"
    Write-Host "Starting PsExec Service..."
    $pcName = $Enable_PSRemoting_PsExec
    $runPsExec = Get-SoccomTempPath -FileName 'PsExec.exe'
    $cmd = '-s -d cmd /c "powershell enable-psremoting" '
    Start-Process -Filepath "$runPsExec" -ArgumentList "\\$pcName $cmd" -NoNewWindow -Wait
    Write-Host "--------------------------------------------------------------------"
    Write-Host " "
}
ElseIf (!([string]::IsNullOrEmpty($Disable_PSRemoting_PsExec))) {	 ### SWITCH: -Disable_PSRemoting_PsExec ###
    PsExec #Make sure PsExec is on system - if not, drop it in appdata\local\temp
    $timeStamp = timeStamp
    Write-Host "-- Disable Powershell Remoting on: $Disable_PSRemoting_PsExec --"
    Write-Host "--------------------------------------------------------------------"
    Write-Host "Starting PsExec Service..."
    $pcName = $Disable_PSRemoting_PsExec
    $runPsExec = Get-SoccomTempPath -FileName 'PsExec.exe'
    $cmd = '-s -d cmd /c "powershell disable-psremoting" '
    Start-Process -Filepath "$runPsExec" -ArgumentList "\\$pcName $cmd" -NoNewWindow -Wait
    Write-Host "--------------------------------------------------------------------"
    Write-Host " "
}#>
ElseIf (!([string]::IsNullOrEmpty($Get_BitlockerRecoveryKey))){
    # Get_BitlockerRecoveryKey
    Write-Host "Bitlocker Recovery Key for: $Get_BitlockerRecoveryKey"
    Get_BitlockerRecoveryKey $Get_BitlockerRecoveryKey
    Write-Host "" 

}ElseIf ($Make_IRTemplate) {
    New-IRNotesTemplate | Out-Null

}Else{ # Check Switches or eval for possible No Input errors. Exit 
    $errorCount = 1 #Counter holds the value of Zero unless a Switch is selected.
    
    #Switch function created to run commands with switches that do not require input variables 
    Switch ($PSBoundParameters.GetEnumerator().Where({$_.Value -eq $true}).Key){
        #Update SOCCOM - write VBS to perform the update 
        'SOCCOM_Update' {
            Write-Host 'SOCCOM Updating...'
            #Write-Host ' '
            UpdateSOCCOM
            Write-Host 'SOCCOM Updated.'  
            Write-Host ' ' 
            $errorCount = 0 
         }
    }#End Switch functions 
  
    #If $errorCount == 1, then input error - no switch supplied -or- no switch supplied with the proper input 
    If ($errorCount -eq 1){ 
        Write-Host "s0m37h1ng SOCCOM w3n7 wr0ng. pl34s3 7ry 4g14n."
        Write-Host " "
    } 
    Exit
}#End Main If 
