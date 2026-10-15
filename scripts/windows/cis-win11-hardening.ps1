#Requires -RunAsAdministrator
<#
  cis-win11-hardening.ps1 - CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 hardening for an always-on
  homelab box that is managed over SSH (docs/04-detections.md, "CIS"). Result on my machine: SCA 25% -> 45%.
  Batches: A (audit policy), B (login & network auth), C (unused services), D (misc).
  Backups first -> $BackupDir ; log -> $LogFile. Reboot afterwards to fully apply SMB/UAC changes.
  Run it as SYSTEM (one-time scheduled task) if you are connected over SSH: some changes refuse remote sessions.

  READ IT BEFORE RUNNING. It disables RDP, WinRM, Print Spooler, Bluetooth and more (batch C).

  DELIBERATE EXCEPTIONS (never touched here):
    - 5.12  OpenSSH Server (sshd) stays Automatic: it is how this box is managed.
    - 9.3.4/9.3.5 Public firewall "apply local rules/connection security rules = No": would disable
      the local rule that admits SSH -> lockout.
    - 5.26  Server service (LanmanServer) stays on (no shares exist; signing is enforced instead).
    - LSA "RunAsPPL with UEFI lock": the lock can only be undone in firmware.
    - Console-convenience items (Ctrl+Alt+Del, hide last user, logon banner) and BitLocker: not in scope.
#>
param(
  [string] $BackupDir = "C:\homelab\backups\cis-$(Get-Date -Format yyyy-MM-dd)",
  [string] $LogFile   = 'C:\homelab\logs\cis-hardening.log'
)
$ErrorActionPreference = 'Continue'
$B = $BackupDir; $L = $LogFile
New-Item -ItemType Directory -Force $B, (Split-Path $L) | Out-Null
function Log($m) { $line = "$(Get-Date -Format s)  $m"; Add-Content -Path $L -Value $line; $line }
function RegSet($path, $name, $value, $type = 'DWord') {
  try {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force -ErrorAction Stop | Out-Null
    Log "  OK   reg  $path\$name = $value"
  } catch { Log "  FAIL reg  $path\$name : $($_.Exception.Message)" }
}

Log "=== BACKUP ==="
if (-not (Test-Path "$B\secpol-before.inf")) {
  secedit /export /cfg "$B\secpol-before.inf" /quiet | Out-Null
  auditpol /backup /file:"$B\auditpol-before.csv" | Out-Null
  Get-CimInstance Win32_Service | Select-Object Name, StartMode, State | Export-Csv "$B\services-before.csv" -NoTypeInformation
  Get-NetFirewallProfile | Select-Object Name, LogFileName, LogMaxSizeKilobytes, LogBlocked, LogAllowed, NotifyOnListen | Export-Csv "$B\firewall-profiles-before.csv" -NoTypeInformation
  $keys = @{
    'lsa'          = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    'sam'          = 'HKLM\SYSTEM\CurrentControlSet\Control\SAM'
    'lanmanserver' = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    'lanmanwks'    = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    'tcpip'        = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    'pol-system'   = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    'pol-explorer' = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    'policies'     = 'HKLM\SOFTWARE\Policies'
  }
  foreach ($k in $keys.Keys) { & reg.exe export $keys[$k] "$B\$k-before.reg" /y 2>&1 | Out-Null }
  Log "  backups written to $B ($(@(Get-ChildItem $B).Count) files)"
} else { Log "  backup already exists, not overwritten" }

Log "=== A. AUDIT POLICY ==="
$audit = [ordered]@{
  'Credential Validation'='/success:enable /failure:enable'; 'Application Group Management'='/success:enable /failure:enable'
  'User Account Management'='/success:enable /failure:enable'; 'Plug and Play Events'='/success:enable'
  'Process Creation'='/success:enable'; 'Account Lockout'='/success:enable /failure:enable'
  'Group Membership'='/success:enable'; 'Other Logon/Logoff Events'='/success:enable /failure:enable'
  'Detailed File Share'='/failure:enable'; 'File Share'='/success:enable /failure:enable'
  'Other Object Access Events'='/success:enable /failure:enable'; 'Removable Storage'='/success:enable /failure:enable'
  'Authorization Policy Change'='/success:enable'; 'MPSSVC Rule-Level Policy Change'='/success:enable /failure:enable'
  'Other Policy Change Events'='/failure:enable'; 'Sensitive Privilege Use'='/success:enable /failure:enable'
  'IPsec Driver'='/success:enable /failure:enable'; 'Security System Extension'='/success:enable'
}
foreach ($s in $audit.Keys) {
  $out = cmd /c "auditpol /set /subcategory:`"$s`" $($audit[$s])" 2>&1
  if ($LASTEXITCODE -eq 0) { Log "  OK   audit $s" } else { Log "  FAIL audit $s : $out" }
}
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1                       # 2.3.2.1
RegSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
& wevtutil sl Security /ms:201326592; Log "  OK   Security log max size 192 MB (more events now)"

Log "=== B. LOGIN & NETWORK AUTH ==="
$o = net accounts /minpwlen:14 /uniquepw:24 /minpwage:1 /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 2>&1
Log "  net accounts: $(($o | Select-Object -Last 1))"
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' 'RelaxMinimumPasswordLengthLimits' 1                    # 1.1.6
RegSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'MaxDevicePasswordFailedAttempts' 10 # 2.3.7.3
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
RegSet $lsa 'RestrictAnonymous' 1            # 2.3.10.3
RegSet $lsa 'DisableDomainCreds' 1           # 2.3.10.4
RegSet $lsa 'UseMachineId' 1                 # 2.3.11.1
RegSet $lsa 'LmCompatibilityLevel' 5         # 2.3.11.7 NTLMv2 only, refuse LM & NTLM
RegSet "$lsa\MSV1_0" 'NTLMMinClientSec' 537395200     # 2.3.11.9
RegSet "$lsa\MSV1_0" 'NTLMMinServerSec' 537395200     # 2.3.11.10
RegSet "$lsa\MSV1_0" 'AuditReceivingNTLMTraffic' 2    # 2.3.11.11
RegSet "$lsa\MSV1_0" 'RestrictSendingNTLMTraffic' 1   # 2.3.11.12 (audit all)
RegSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' 2147483640  # 2.3.11.4
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1  # 2.3.8.1
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1       # 2.3.9.2
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature' 1        # 2.3.9.3
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SmbServerNameHardeningLevel' 1    # 2.3.9.5

Log "=== C. UNUSED SERVICES ==="
$svcs = 'BTAGService','bthserv','MapsBroker','lfsvc','lltdsvc','MSiSCSI','Spooler','wercplsupport','RasAuto',
        'SessionEnv','TermService','UmRdpService','RpcLocator','SSDPSRV','upnphost','WerSvc','Wecsvc',
        'WMPNetworkSvc','icssvc','WpnService','PushToInstall','WinRM','XboxGipSvc','XblAuthManager','XblGameSave','XboxNetApiSvc'
foreach ($n in $svcs) {
  if ($n -eq 'sshd' -or $n -eq 'LanmanServer') { continue }   # exceptions, never touched
  $s = Get-Service $n -ErrorAction SilentlyContinue
  if (-not $s) { Log "  --   svc  $n not installed"; continue }
  if ($s.Status -eq 'Running') { Stop-Service $n -Force -ErrorAction SilentlyContinue }
  $r = & sc.exe config $n start= disabled 2>&1
  if ($LASTEXITCODE -eq 0) { Log "  OK   svc  $n disabled (was $($s.StartType), $($s.Status))" }
  else { RegSet "HKLM:\SYSTEM\CurrentControlSet\Services\$n" 'Start' 4 }
}
RegSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'RegisterSpoolerRemoteRpcEndPoint' 2   # 18.7.1

Log "=== D. MISC HARDENING ==="
RegSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1            # 18.10.7.1
RegSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1          # 18.10.7.2
RegSet 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255  # 18.10.7.3
RegSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' 0        # 18.9.35.2
RegSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited' 0
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
RegSet $sys 'FilterAdministratorToken' 1      # 2.3.17.1
RegSet $sys 'ConsentPromptBehaviorAdmin' 2    # 2.3.17.2 prompt for consent on the secure desktop
RegSet $sys 'ConsentPromptBehaviorUser' 0     # 2.3.17.3 auto-deny for standard users
RegSet $sys 'PromptOnSecureDesktop' 1         # 2.3.17.7
RegSet $sys 'InactivityTimeoutSecs' 900       # 2.3.7.4 lock after 15 min idle at the console
RegSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1                    # 18.10.75.2.1
RegSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Block' 'String'
RegSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCustomSSPsAPs' 0                   # 18.9.26.1
RegSet 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'AllowProtectedCreds' 1   # 18.9.4.2
RegSet 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'PerformRouterDiscovery' 0       # 18.5.8
foreach ($p in @(@('DomainProfile','domainfw'), @('PrivateProfile','privatefw'), @('PublicProfile','publicfw'))) {   # 9.x logging + notifications only
  $k = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$($p[0])"
  RegSet $k 'DisableNotifications' 1
  RegSet "$k\Logging" 'LogFilePath' "%SystemRoot%\System32\logfiles\firewall\$($p[1]).log" 'String'
  RegSet "$k\Logging" 'LogFileSize' 16384
  RegSet "$k\Logging" 'LogDroppedPackets' 1
  RegSet "$k\Logging" 'LogSuccessfulConnections' 1
}

Log "=== SANITY ==="
$sshd = Get-Service sshd -ErrorAction SilentlyContinue
Log "  sshd: $($sshd.Status)/$($sshd.StartType)   WazuhSvc: $((Get-Service WazuhSvc -ErrorAction SilentlyContinue).Status)   Tailscale: $((Get-Service Tailscale -ErrorAction SilentlyContinue).Status)"
Log "=== DONE (reboot to fully apply SMB/UAC changes) ==="
