# SOCCOM

**Security Operations Center Central Command**

SOCCOM is a PowerShell-based SOC assistant for speeding up common analyst workflows. It enriches IPs, domains, URLs, and full URIs, builds portable HTML investigation reports, and includes Active Directory lookups for users, computers, and BitLocker recovery keys.

The project is designed for security operations teams that need quick triage, repeatable enrichment, and case-ready evidence without jumping between several web portals.

## Features

- Investigate IPv4 and IPv6 addresses.
- Investigate domains, URLs, and full URIs.
- Investigate lists of indicators in bulk.
- Generate timestamped HTML reports with collapsible sections.
- Include RDAP / WHOIS registration data.
- Include AbuseIPDB IP reputation data.
- Include VirusTotal URL/IP enrichment.
- Include URLScan screenshot and scan details for URL/domain investigations.
- Include APIVoid domain reputation results.
- Search Active Directory users and computers.
- Search Active Directory user and computer lists.
- Retrieve BitLocker recovery keys from Active Directory.

## Report Output

SOCCOM produces analyst-friendly HTML reports under the `Results` directory. Reports include:

- Investigation summary
- AbuseIPDB results
- RDAP / WHOIS data
- URLScan screenshots
- VirusTotal detections
- APIVoid detections
- Lookup resource links
- Timestamped filenames for easier case tracking

The report is self-contained enough to attach to cases, share with teammates, or preserve investigation context.

## Requirements

- Windows PowerShell or PowerShell 7+
- Network access to enrichment services
- Active Directory PowerShell module for AD-related functions
- API keys for full enrichment coverage

Primary script:

```powershell
.\SOCCOM-modern.ps1
```

## API Keys

SOCCOM supports API keys through environment variables. This is the recommended way to run the tool because it avoids hardcoding secrets in the script.

```powershell
$env:SOCCOM_URLSCAN_API_KEY = "your-urlscan-key"
$env:SOCCOM_VIRUSTOTAL_API_KEY = "your-virustotal-key"
$env:SOCCOM_APIVOID_API_KEY = "your-apivoid-key"
$env:SOCCOM_ABUSEIPDB_API_KEY = "your-abuseipdb-key"
```

## Usage

### Investigate a Single Indicator

Use `-Investigate` for IPv4, IPv6, domains, URLs, or full URIs.

```powershell
.\SOCCOM-modern.ps1 -Investigate 8.8.8.8
.\SOCCOM-modern.ps1 -Investigate 2001:df7:3c00:800a::446:34dc
.\SOCCOM-modern.ps1 -Investigate cyberciti.biz
.\SOCCOM-modern.ps1 -Investigate https://www.cyberciti.biz/linux-command/
```

### Investigate a List of Indicators

```powershell
.\SOCCOM-modern.ps1 -Investigate_List .\indicators.txt
```

The list can contain a mix of IPv4 addresses, IPv6 addresses, domains, URLs, and full URIs.

### Search Active Directory

Search for a single user:

```powershell
.\SOCCOM-modern.ps1 -SearchAD_Username jsmith
```

Search for a single computer:

```powershell
.\SOCCOM-modern.ps1 -SearchAD_ComputerName workstation-01
```

Search for a list of users:

```powershell
.\SOCCOM-modern.ps1 -SearchAD_UserList .\users.txt
```

Search for a list of computers:

```powershell
.\SOCCOM-modern.ps1 -SearchAD_ComputerList .\computers.txt
```

### Retrieve a BitLocker Recovery Key

```powershell
.\SOCCOM-modern.ps1 -Get_BitlockerRecoveryKey workstation-01
```

## Recommended Workflow

1. Collect the indicator from an alert, email, proxy log, EDR event, or case note.
2. Run SOCCOM with `-Investigate`.
3. Review the generated HTML report in `Results`.
4. Use the report as supporting evidence for triage, escalation, or case documentation.

## Important Note

SOCCOM is an enrichment aid, not a final verdict. Indicators may still be malicious even when no source flags them. Use analyst judgment and supporting telemetry before making containment or closure decisions.

## Project Structure

```text
SOCCOM-modern.ps1    Primary SOCCOM script
Results/             Generated reports and CSV outputs
Logs/                Runtime log files
```

## Roadmap Ideas

- Additional enrichment providers
- Hash and file reputation workflows
- Email header analysis
- Case export templates
- Safer secret management
- More Active Directory response actions
- Optional JSON or Markdown report output

## Author

Created by [Arron Jablonowski](https://github.com/ArronJablonowski).

Project repository: [ArronJablonowski/SOCCOM](https://github.com/ArronJablonowski/SOCCOM)
