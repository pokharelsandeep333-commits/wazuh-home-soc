#Requires -Version 7
<#
  set-discord-webhook.ps1 - add the Discord alert integration (level >= 10) to the Wazuh manager config
  without the webhook URL ever appearing on screen, on a command line or in a backup (docs/06-discord-alerts.md).

  1. Discord -> channel settings -> Integrations -> Webhooks -> New Webhook -> Copy Webhook URL.
  2. Paste it into a text file (default: C:\wazuh\secrets\discord-webhook.txt) and save.
  3. Run in a STANDALONE PowerShell 7 window (embedded terminals can mishandle hidden input and exit silently):
       pwsh -File scripts\manager\set-discord-webhook.ps1 -ConfPath <path to wazuh_manager.conf>
  4. Recreate the manager:  docker compose up -d --force-recreate --no-deps wazuh.manager
  5. Delete the .txt file, so the only copy of the secret is in the config.

  Written for Docker Desktop on Windows. On a Linux host, paste wazuh/manager/ossec-integration-discord.xml
  into wazuh_manager.conf with an editor instead.
#>
param(
  [Parameter(Mandatory)] [string] $ConfPath,
  [string] $SourceFile = 'C:\wazuh\secrets\discord-webhook.txt',
  [string] $BackupDir  = 'C:\wazuh\backups'
)
$ErrorActionPreference = 'Stop'
trap { Write-Host "FAILED at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $SourceFile)) { throw "Missing $SourceFile - paste the Discord webhook URL into it and save." }
$url = (Get-Content -Raw $SourceFile).Trim()
if ($url -notmatch '^https://(discord|discordapp)\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,80}$') {
    throw "The file does not contain a plain Discord webhook URL (https://discord.com/api/webhooks/<id>/<token>)."
}
$hook = "$url/slack"

$text = Get-Content -Raw $ConfPath
if ($text -match '<name>slack</name>') { throw 'A slack/Discord integration already exists in the config. Nothing changed.' }

# Backup BEFORE inserting, so the backup contains no secret
New-Item -ItemType Directory -Force $BackupDir | Out-Null
$bk = Join-Path $BackupDir "wazuh_manager.conf.pre-discord-$(Get-Date -Format yyyyMMdd-HHmm)"
Copy-Item -LiteralPath $ConfPath -Destination $bk

# {"ts": null} is required for Discord: see wazuh/manager/ossec-integration-discord.xml
$block = @"

  <!-- Discord notifications: built-in slack integration -> Discord Slack-compatible webhook. Level >= 10 only.
       The hook URL is a secret (anyone with it can post to the channel). -->
  <integration>
    <name>slack</name>
    <hook_url>$hook</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
    <options>{"ts": null, "pretext": "WAZUH Alert - Triage: open your playbook and find the Rule ID below"}</options>
  </integration>
"@

# Insert right before the end of the first <ossec_config> block
$end = $text.IndexOf('</ossec_config>')
if ($end -lt 0) { throw '</ossec_config> not found.' }
$new = $text.Substring(0, $end) + $block + "`n" + $text.Substring($end)
[System.IO.File]::WriteAllText($ConfPath, $new, [System.Text.UTF8Encoding]::new($false))
$url = $null; $hook = $null; $new = $null

# Verify without printing the URL
$check = Get-Content -Raw $ConfPath
$ok = ($check -match '<name>slack</name>') -and ($check -match '<hook_url>https://(discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+/slack</hook_url>')
$check = $null
if (-not $ok) { Copy-Item -LiteralPath $bk -Destination $ConfPath -Force; throw 'Verification failed - config restored from backup.' }
Write-Host "Integration added (level >= 10). Backup without the secret: $bk" -ForegroundColor Green
Write-Host "Next: recreate the manager, send a test alert, confirm it IN DISCORD, then delete $SourceFile."
