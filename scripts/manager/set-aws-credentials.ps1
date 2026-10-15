#Requires -Version 7
<#
  set-aws-credentials.ps1 - write the CloudTrail reader's access key to a locked credentials file (profile [wazuh])
  from the .csv AWS lets you download when you create the key (docs/05-cloudtrail.md).

  Why the .csv: pasting a secret into a hidden Read-Host prompt delivered Ctrl+V as ONE character in my console,
  and the AWS console's copy icon left the clipboard empty. The .csv route is deterministic, and nothing is typed.
  The secret is never displayed, never on a command line, never in shell history. The .csv is deleted afterwards.

  Run in a STANDALONE PowerShell 7 window:
    pwsh -File scripts\manager\set-aws-credentials.ps1 [-OutFile C:\wazuh\secrets\aws-credentials]
  Then mount the file read-only into the manager at /root/.aws/credentials (wazuh/manager/docker-compose-changes.yml).
#>
param([string] $OutFile = 'C:\wazuh\secrets\aws-credentials')
$ErrorActionPreference = 'Stop'
trap { Write-Host "FAILED at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
$dir = Split-Path $OutFile

# 1. Find the newest AWS access-key CSV in Downloads
$dl  = Join-Path $env:USERPROFILE 'Downloads'
$csv = Get-ChildItem -Path $dl -Filter '*.csv' -File |
       Where-Object { $_.Name -match 'accessKeys|access_key|credentials' } |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $csv) { throw "No access-key .csv found in $dl. In AWS, click 'Download .csv file' on the Retrieve access keys page, then run this again." }
Write-Host "Using: $($csv.FullName) (saved $($csv.LastWriteTime))"

$row = Import-Csv -Path $csv.FullName | Select-Object -First 1
$keyId  = ($row.'Access key ID').Trim()
$secret = ($row.'Secret access key').Trim()
if ($keyId -notmatch '^AKIA[A-Z0-9]{16}$') { throw 'The .csv has no valid "Access key ID" column (AKIA + 16 characters).' }
if ($secret.Length -ne 40) { throw "The .csv secret is $($secret.Length) characters; expected 40." }

# 2. Folder locked to the current user only
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
icacls $dir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null

if (Test-Path $OutFile) {
    $ans = Read-Host "$OutFile already exists. Overwrite? (yes/no)"
    if ($ans -ne 'yes') { Write-Host 'Nothing changed.'; exit 0 }
}

# 3. Write the credentials file (LF endings, no BOM)
$content = "[wazuh]`naws_access_key_id = $keyId`naws_secret_access_key = $secret`n"
[System.IO.File]::WriteAllText($OutFile, $content, [System.Text.UTF8Encoding]::new($false))
$secret = $null; $content = $null; $row = $null

# 4. Verify the file parses back, then remove the .csv (it is a second plaintext copy of the secret)
$check = Get-Content -Raw $OutFile
if ($check -notmatch "aws_access_key_id = $keyId" -or $check -notmatch 'aws_secret_access_key = \S{40}') { throw 'Written file did not verify. The .csv was NOT deleted.' }
$check = $null
Remove-Item -LiteralPath $csv.FullName -Force
if (Test-Path -LiteralPath $csv.FullName) { throw "Could not delete $($csv.FullName). Delete it by hand." }

$masked = $keyId.Substring(0,6) + '...' + $keyId.Substring($keyId.Length-4)
Write-Host "Saved profile [wazuh] with key $masked to $OutFile" -ForegroundColor Green
Write-Host "Deleted $($csv.Name) from Downloads." -ForegroundColor Green
