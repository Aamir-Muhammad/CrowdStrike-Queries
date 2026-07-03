// The Gentlemen RaaS - Custom Backdoors and Evolving Tactics (Securelist 29 Jun 2026)
// Source - securelist.com/the-gentlemen-raas/120447/
// Author - Aamir Muhammad
| case {

    // TTP 1 - netsh packet capture to ADMIN$ share (recon sniffing)
    #event_simpleName = ProcessRollup2 AND FileName = /^netsh\.exe$/iF AND CommandLine = /trace start capture=yes/iF
        | HuntLogic := "Netsh_Trace_Packet_Capture" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 2 - SharpADWS / AD recon via SOAP-wrapped LDAP
    #event_simpleName = ProcessRollup2 AND CommandLine = /SharpADWS/iF
        | HuntLogic := "SharpADWS_AD_Recon" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 3 - Network scanners (NetScan / Advanced IP Scanner)
    #event_simpleName = ProcessRollup2 AND FileName = /^(netscan|netscan64|advanced_ip_scanner.*|advanced_ip_scanner_console|advanced_port_scanner|advanced_port_scanner_console)\.exe$/iF
        | HuntLogic := "Network_Scanner_Execution" | SeverityTier := "Medium" | HuntObject := FileName;

    // TTP 4 - Defender real-time protection disabled via Set-MpPreference
    #event_simpleName = ProcessRollup2 AND CommandLine = /Set-MpPreference/iF AND CommandLine = /DisableRealtimeMonitoring|EnableControlledFolderAccess\s+Disabled/iF
        | HuntLogic := "Defender_Disable_via_SetMpPreference" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 5 - Defender exclusion added via Add-MpPreference
    #event_simpleName = ProcessRollup2 AND CommandLine = /Add-MpPreference/iF AND CommandLine = /ExclusionProcess|ExclusionPath/iF
        | HuntLogic := "Defender_Exclusion_Added" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 6 - Defender disabled via registry (reg.exe DisableAntiSpyware / DisableBehaviorMonitoring)
    #event_simpleName = ProcessRollup2 AND FileName = /^reg\.exe$/iF AND CommandLine = /Windows Defender/iF AND CommandLine = /DisableAntiSpyware|DisableBehaviorMonitoring|DisableOnAccessProtection|DisableScanOnRealtimeEnable/iF
        | HuntLogic := "Defender_Disable_via_Registry_RegExe" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 7a - Defender disable registry write - RegGenericValueUpdate
    #event_simpleName = RegGenericValueUpdate AND RegObjectName = /Windows Defender/iF AND RegValueName = /DisableAntiSpyware|DisableBehaviorMonitoring|DisableOnAccessProtection|DisableScanOnRealtimeEnable|DisableRealtimeMonitoring/iF AND RegNumericValue = 1
        | HuntLogic := "Defender_Disable_RegEvent" | SeverityTier := "Critical" | HuntObject := RegObjectName;

    // TTP 7b - Defender disable registry write - SuspiciousRegAsepUpdate
    #event_simpleName = SuspiciousRegAsepUpdate AND RegObjectName = /Windows Defender/iF AND RegValueName = /DisableAntiSpyware|DisableBehaviorMonitoring|DisableOnAccessProtection|DisableScanOnRealtimeEnable|DisableRealtimeMonitoring/iF AND RegNumericValue = 1
        | HuntLogic := "Defender_Disable_RegEvent" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 8 - Kaspersky uninstall via kavrmvr.exe
    #event_simpleName = ProcessRollup2 AND FileName = /^kavrmvr\.exe$/iF
        | HuntLogic := "Kaspersky_Uninstall_kavrmvr" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 9 - EDR-kill / rootkit tooling (Windows Kernel Explorer / OpenArk64)
    #event_simpleName = ProcessRollup2 AND FileName = /^(openark64|kernelexplorer|windows.?kernel.?explorer)\.exe$/iF
        | HuntLogic := "Kernel_Rootkit_EDR_Kill_Tool" | SeverityTier := "Critical" | HuntObject := FileName;

    // TTP 10 - BYOVD vulnerable driver written to disk
    #event_simpleName = NewExecutableWritten AND TargetFileName = /\\(processmonitordriver|wamsdk|gamedriverx64|biontdrv|biontdrv_wink|biontdrv_winbs|inpoutx64|wsddprm|wsftprm|havoc)\.sys$/iF
        | HuntLogic := "BYOVD_Vulnerable_Driver_Dropped" | SeverityTier := "Critical" | HuntObject := TargetFileName;

    // TTP 11 - GPO lateral movement script (deploy_gpo.ps1)
    #event_simpleName = ProcessRollup2 AND CommandLine = /deploy_gpo\.ps1/iF
        | HuntLogic := "GPO_Lateral_Movement_Script" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 12 - PsExec download from live.sysinternals
    #event_simpleName = ProcessRollup2 AND CommandLine = /Invoke-WebRequest|iwr\s/iF AND CommandLine = /live\.sysinternals\.com\/PsExec/iF
        | HuntLogic := "PsExec_Download_Sysinternals" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 13 - RSAT AD tools install for domain enumeration
    #event_simpleName = ProcessRollup2 AND CommandLine = /Rsat\.ActiveDirectory\.DS-LDS\.Tools|RSAT-AD-PowerShell/iF
        | HuntLogic := "RSAT_AD_Tools_Install_Recon" | SeverityTier := "Medium" | HuntObject := CommandLine;

    // TTP 14 - Hyper-V VM stop before encryption
    #event_simpleName = ProcessRollup2 AND CommandLine = /Get-VM/iF AND CommandLine = /Stop-VM\s+-Force\s+-TurnOff/iF
        | HuntLogic := "HyperV_VM_Stop_PreEncryption" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 15 - Persistence scheduled task UpdateUser / TaskSystem
    #event_simpleName = ProcessRollup2 AND FileName = /^schtasks\.exe$/iF AND CommandLine = /\"UpdateUser\"|TaskSystem/iF
        | HuntLogic := "Ransomware_Persistence_SchedTask" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 16 - Persistence Run key GupdateS
    #event_simpleName = ProcessRollup2 AND FileName = /^reg\.exe$/iF AND CommandLine = /CurrentVersion\\Run/iF AND CommandLine = /GupdateS/iF
        | HuntLogic := "Ransomware_Persistence_RunKey" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 17 - ACL override via takeown + icacls Everyone grant
    #event_simpleName = ProcessRollup2 AND FileName = /^icacls\.exe$/iF AND CommandLine = /grant\s+\*?S-1-1-0:F/iF
        | HuntLogic := "ACL_Override_Everyone_FullControl" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 18 - Shadow copy deletion (anti-recovery)
    #event_simpleName = ProcessRollup2 AND FileName = /^(vssadmin|wmic)\.exe$/iF AND CommandLine = /delete\s+shadows|shadowcopy\s+delete/iF
        | HuntLogic := "Shadow_Copy_Deletion" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 19 - Event log clearing via wevtutil
    #event_simpleName = ProcessRollup2 AND FileName = /^wevtutil\.exe$/iF AND CommandLine = /\bcl\b\s+(System|Application|Security)/iF
        | HuntLogic := "Event_Log_Clearing_wevtutil" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 20 - Forensic anti-recovery deletion (Prefetch / Defender Support / RDP logs / Recycle Bin)
    #event_simpleName = ProcessRollup2 AND FileName = /^cmd\.exe$/iF AND CommandLine = /\\Windows\\Prefetch\\|Windows Defender\\Support\\|LogFiles\\RDP|\$Recycle\.Bin/iF
        | HuntLogic := "AntiForensic_Artifact_Deletion" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 21 - Ransom note dropped (README-GENTLEMEN / READ-ME GEN-TLE-MEN)
    #event_simpleName = NewExecutableWritten AND TargetFileName = /README-GENTLEMEN\.txt$|-READ-ME-+-GEN-TLE-MEN-+\.txt$/iF
        | HuntLogic := "Gentlemen_Ransom_Note_Written" | SeverityTier := "Critical" | HuntObject := TargetFileName;

    // IOC Sweep - Go ransomware, C ransomware, backdoor, driver, scanner MD5 hashes
    MD5HashData = /^(3B46A729DB7AE6AF8B19711C9452194D|02944C8A5535CDB5B2CBB893DB2D5ACF|10CA9A4040001560D053B7E7885C1B95|3C471EBC947CDF32240A90FFADF49B13|4BE8BB62F0EBBCF4CE52C35AB6F794F5|53C616677BC7E2A0A03127F19166D007|5C3B9821FC82A9028CB63B9671950919|5F0B2C6D9F442754258BF4DD841C8341|608FAF58353B65C45EF9833358AC3787|6AE7C9A7EA0B8C40A64225734F6BD01D|846DC77C1246DB20D976346E0E359502|ADAC9984B3CC43D66A0D33079BBEC299|AE0E536766788478263BF448A9381641|B3E418D30312C1B2C58A791286868F42|C2764744DCB4B0E1DB79CA1E8BF65368|D12A5B36DD00586CC374A1CAE43EFED4|D2F72897E8986303D5567EB2384932B8|DE1522F9219497632F30F8A6E72F26B6|FDAE2BEB813778B4540A997706862096|B9986A0F1F1F1A798DC3F0C59A80A1A3|554E699C96B332468F1AE69C1AE81EF9|5761BD63DA03686FC480245DA7BD1E9F|B6B51508AD6F462C45FE102C85D246C8|8F0577D28C4FF5F71B149F444BFABA8E|525EF6014F0EF20E44FE47C1D9980B69|407B6A136BBAA7172EB44EF9D08BB58A|9321A61A25C7961D9F36852ECAA86F55|73F0A8C3EA794A04E80C32038249F044|EEF8A950952696B018AA9C6DA2F5D7AD|EDB1C480295250DD1A38F3AA1357DEAE|5537C708EDB9A2C21F88E34E8A0F1744)$/i
        | HuntLogic := "Gentlemen_IOC_Hash_Match" | SeverityTier := "Critical" | HuntObject := MD5HashData;

    // IOC Sweep - Backdoor C2 IP 
    RemoteAddressIP4 = /^(81\.177\.215\.15)$/
        | HuntLogic := "Gentlemen_IOC_IP_Match" | SeverityTier := "Critical" | HuntObject := RemoteAddressIP4;

  // TTP 22 - PsExec remote execution to admin share (lateral movement)
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        (FileName = /^psexec(64)?\.exe$/iF OR OriginalFilename = /^psexec/iF)
        CommandLine = /\\\\[^\s]+\s/iF
        CommandLine = /-accepteula|-s\b|-d\b/iF
        | HuntLogic := "PsExec_Remote_Execution" | SeverityTier := "High" | HuntObject := CommandLine;
  }
|ParentBaseFileName!=/MpCmdRun.exe/iF
| $ProcessTree2()
|$vthash()
| groupBy(
    [ComputerName, HuntLogic, SeverityTier, UserName, HuntObject, ProcessTree,VT],
    function=min(@timestamp, as=FirstSeen_epoch),
    limit=max
  )

| sort([SeverityTier, FirstSeen_epoch], order=[asc, desc], limit=max)
| formatTime(format="%e %b %Y %r", field=FirstSeen_epoch, as=FirstSeen, locale=en_UAE, timezone="Asia/Dubai")
| select([FirstSeen, ComputerName, HuntLogic,VT, SeverityTier, UserName,ProcessTree, HuntObject])
