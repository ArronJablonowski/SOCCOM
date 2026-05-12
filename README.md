# SOCCOM

**Security Operations Center Central Command**

SOCCOM is a PowerShell-based SOC investigation assistant built to speed up common analyst workflows. It enriches indicators, generates portable HTML intelligence reports, performs Active Directory lookups, retrieves BitLocker recovery keys, and creates structured incident response notes for fast-moving investigations.

The goal is simple: help analysts move from alert to documented decision faster, without losing context across browser tabs, enrichment portals, notes, and case updates.

## What SOCCOM Does

- Investigates IPv4 addresses, IPv6 addresses, domains, URLs, and full URIs from one primary `-Investigate` switch.
- Processes mixed indicator lists and builds a combined HTML report.
- Generates timestamped, analyst-friendly reports in `Results/`.
- Creates Markdown incident response templates in `Investigations/`.
- Supports Active Directory searches for users, computers, user lists, and computer lists.
- Retrieves BitLocker recovery keys from Active Directory.
- Uses cleaner CLI error handling so failed enrichment sources do not break the investigation run.
- Includes a self-update function designed to pull from the SOCCOM GitHub repository after the project script is published.

## Enrichment Sources

SOCCOM currently supports enrichment and lookup workflows using:

- AbuseIPDB
- VirusTotal
- URLScan.io
- APIVoid domain reputation
- RDAP / WHOIS registration data
- Shodan lookup links
- DomainTools lookup links
- Who.Is RDAP lookup links
- IBM X-Force Exchange lookup links
- AlienVault OTX lookup links
- ThreatMiner lookup links
- Robtex lookup links
- Sucuri SiteCheck lookup links
- DNS.ninja lookup links
- SecurityTrails domain history links

When an enrichment provider fails, returns no result, rate limits, or cannot resolve an indicator, SOCCOM continues the investigation and records the available data instead of stopping the run.

## Report Output

SOCCOM generates portable HTML reports under `Results/`. Reports include:

- Investigation summary
- AbuseIPDB reputation details
- VirusTotal detections and report links
- URLScan screenshots and scan details when available
- APIVoid domain reputation results
- RDAP / WHOIS registration data
- Lookup resource buttons for pivoting into external tools
- Collapsible report sections for faster review
- Timestamped filenames for easier case tracking
- Author and project links in the report footer

Full URI investigations are normalized so the output filename uses the URI hostname instead of the entire URI.

## Incident Response Notes

The `-Make_IRTemplate` switch creates a timestamped Markdown investigation template under `Investigations/`.

The template is designed for SOC analysts working under pressure and includes:

- Executive summary / BLUF
- Current status tracking
- Handoff notes
- Next actions
- Detection metadata
- Indicator tracking
- Event timeline
- Evidence log
- Scope assessment
- Affected hosts and users
- Credential and identity review
- SIEM query placeholders
- Live incident response notes
- Communication log
- Data sources reviewed
- Escalation notes
- Containment, eradication, and recovery tracking
- MITRE ATT&CK mapping
- Recommendations, tuning ideas, lessons learned, and closeout rationale

## Requirements

- PowerShell 7+ recommended
- Windows PowerShell supported for multiple OS types - Tested on Windows, MacOS, & Ubuntu. 
- Network access to enrichment providers
- Active Directory PowerShell module for AD-related functions
- Valid API keys for full enrichment coverage

Active Directory and BitLocker workflows are intended for domain-connected Windows environments with the required permissions.

## API Keys

SOCCOM supports API keys through environment variables. This is the recommended approach because it avoids storing secrets directly in the script.

```powershell
$env:SOCCOM_URLSCAN_API_KEY = "your-urlscan-key"
$env:SOCCOM_VIRUSTOTAL_API_KEY = "your-virustotal-key"
$env:SOCCOM_APIVOID_API_KEY = "your-apivoid-key"
$env:SOCCOM_ABUSEIPDB_API_KEY = "your-abuseipdb-key"
```

`SOCCOM_URLVOID_API_KEY` is also accepted as a legacy fallback for the APIVoid domain reputation key.

## Quick Start

From the project root:

```powershell
.\SOCCOM.ps1 -Investigate example.com
```

Investigate an IPv4 address:

```powershell
.\SOCCOM.ps1 -Investigate 8.8.8.8
```

Investigate an IPv6 address:

```powershell
.\SOCCOM.ps1 -Investigate 2001:df7:3c00:800a::446:34dc
```

Investigate a full URI:

```powershell
.\SOCCOM.ps1 -Investigate https://www.cyberciti.biz/linux-command/
```

Investigate a mixed list of indicators:

```powershell
.\SOCCOM.ps1 -Investigate_List .\list.txt
```

Create a Markdown incident response notes template:

```powershell
.\SOCCOM.ps1 -Make_IRTemplate
```

## Command Reference

| Command | Purpose |
| --- | --- |
| `-Investigate <indicator>` | Investigate an IPv4 address, IPv6 address, domain, URL, or full URI. |
| `-Investigate_List <path>` | Investigate a file containing mixed IPs, domains, URLs, or URIs. |
| `-SearchAD_Username <username>` | Search Active Directory for a user and show detailed account properties and group membership. |
| `-SearchAD_ComputerName <hostname>` | Search Active Directory for a computer. |
| `-SearchAD_UserList <path>` | Search Active Directory for a list of users and export results to CSV. |
| `-SearchAD_ComputerList <path>` | Search Active Directory for a list of computers and export results to CSV. |
| `-Get_BitlockerRecoveryKey <hostname>` | Retrieve BitLocker recovery key information for a computer from Active Directory. |
| `-Make_IRTemplate` | Create a timestamped Markdown SOC investigation notes file. |

Legacy aliases are still present for earlier function names, but new usage should prefer the command names above.

## Example Indicator List

```text
185.200.118.46
20.163.14.5
2001:df7:3c00:800a::446:34dc
pubnub.com
https://www.cyberciti.biz/linux-command/
```

Run it with:

```powershell
.\SOCCOM.ps1 -Investigate_List .\list.txt
```

## Output Locations

```text
SOCCOM.ps1                       Main SOCCOM script
SOC_Investigation_Template.md    Markdown source template reference
Results/                         Generated HTML reports and CSV exports
Investigations/                  Generated Markdown investigation notes
Logs/                            Runtime queue and log files
```

## Design Notes

SOCCOM is built for SOC triage and investigation support. It does not replace analyst judgment, SIEM/EDR telemetry, containment procedures, or escalation requirements.

The HTML report includes this reminder:

> Absence of a malicious verdict in this report does not guarantee the indicator is benign. Validate findings against internal telemetry, business context, and current threat intelligence before closing or containing.

## Roadmap Ideas

- Hash and file reputation workflows
- Email header analysis
- Optional JSON or Markdown enrichment report output
- Case-management export templates
- Stronger local secret management
- Additional identity and endpoint response actions
- More enrichment providers with configurable enable/disable options
- Improved logging and execution summaries for bulk investigations

## Author

Created by [Arron Jablonowski](https://github.com/ArronJablonowski).

Project repository: [ArronJablonowski/SOCCOM](https://github.com/ArronJablonowski/SOCCOM)
