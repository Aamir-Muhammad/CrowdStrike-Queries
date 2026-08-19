// Akira Ransomware - Safe Mode EDR Bypass (Huntress, 12 Aug 2026)
// Source - huntress.com/blog/akira-hits-safe-mode-ransomware-rebooting-around-edr
// Chain - SonicWall VPN spray -> RDP to DC -> AD enum -> WinRAR+s5cmd exfil -> AnyDesk C2 -> Safe Mode reboot -> akira.exe
// Author: Aamir Muhammad
event_platform = "Win"
| #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2|CreateService|ServiceStarted|RegGenericValueUpdate|SuspiciousRegAsepUpdate|NewExecutableWritten|PeFileWritten|NetworkConnectIP4|NetworkReceiveAcceptIP4|SensorEnteredSafemode|UserLogon|ActiveDirectory|SsoUserLogon|SsoApplicationAccess/iF or (#Vendor=microsoft AND #event.outcome=success)
| case {

    // TTP 1 - AD enumeration with unlimited format output (Akira signature recon)
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        FileName = /^(powershell|pwsh)\.exe$/iF
        CommandLine = /Get-ADUser|Get-ADComputer/iF
        CommandLine = /formatenumerationlimit/iF
        | HuntLogic := "Akira_AD_Enum_Unlimited_Format" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 2 - AD enum output written to ProgramData (AdUsers.txt / AdComp.txt)
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        CommandLine = /ProgramData\\(AdUsers|AdComp)\.txt/iF
        | HuntLogic := "Akira_AD_Dump_ProgramData" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 3 - WinRAR with Akira-specific flags for collection for Network shares
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        (FileName = /^WinRAR\.exe$/iF OR OriginalFilename = /^WinRAR\.exe$/iF) 
  (CommandLine=/a\s+-ep1\s+-scul\s+-r0\s+-iext\s+-imon1/iF OR (CommandLine = /\-ep1/iF CommandLine = /\-scul/iF CommandLine = /\-r0\b/iF CommandLine = /\-iext/iF CommandLine = /\-imon1/iF)) CommandLine=/\\\\/iF
        | HuntLogic := "Akira_WinRAR_Collection" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 4 - s5cmd.exe S3 exfiltration tool
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        (FileName = /^s5cmd\.exe$/iF OR OriginalFilename = /^s5cmd/iF)
        CommandLine = /cp|s3:/iF
        | HuntLogic := "S5cmd_S3_Exfiltration" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 5 - AnyDesk installed as service (C2 + delivery channel)
    #event_simpleName = CreateService
        ServiceImagePath = /AnyDesk/iF
        | HuntLogic := "AnyDesk_Service_Installed" | SeverityTier := "High" | HuntObject := ServiceImagePath;

    // TTP 5b - AnyDesk service started
    #event_simpleName = ServiceStarted
        ImageFileName = /AnyDesk/iF
        | HuntLogic := "AnyDesk_Service_Started" | SeverityTier := "High" | HuntObject := ImageFileName;

    // TTP 6a - Safe Mode registry addition for persistence tool (reg.exe adding to SafeBoot\Network)
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        FileName = /^reg\.exe$/iF
        CommandLine = /SafeBoot\\Network/iF
        | HuntLogic := "SafeMode_Registry_Tool_Addition" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 6b - SafeBoot registry write via RegGenericValueUpdate
    #event_simpleName = RegGenericValueUpdate
        RegObjectName = /SafeBoot\\Network/iF
        RegObjectName != /CSFalconService|CrowdStrike/iF
        | HuntLogic := "SafeMode_Registry_Write" | SeverityTier := "Critical" | HuntObject := RegObjectName;

    // TTP 6c - SafeBoot registry write via SuspiciousRegAsepUpdate
    #event_simpleName = SuspiciousRegAsepUpdate
        RegObjectName = /SafeBoot\\Network/iF
        RegObjectName != /CSFalconService|CrowdStrike/iF
        | HuntLogic := "SafeMode_Registry_Write" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 7 - msconfig.exe or bcdedit.exe boot configuration change (Safe Mode trigger)
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        FileName = /^(msconfig|bcdedit)\.exe$/iF
        CommandLine = /safeboot|safebootalternateshell|minimal|network/iF
        | HuntLogic := "BootConfig_SafeMode_Change" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 8 - CrowdStrike sensor entered Safe Mode (native sensor event)
    #event_simpleName = SensorEnteredSafemode
  |case {
    ConfigSwitchReason = 0   | ConfigSwitchReason := "Undefined";
    ConfigSwitchReason = 1   | ConfigSwitchReason := "Boot Phase Passed";
    ConfigSwitchReason = 2   | ConfigSwitchReason := "Provisioning Switch";
    ConfigSwitchReason = 3   | ConfigSwitchReason := "Failed Config Load";
    ConfigSwitchReason = 4   | ConfigSwitchReason := "Cloud Request";
    ConfigSwitchReason = 5   | ConfigSwitchReason := "Recovery Toolkit Request";
    ConfigSwitchReason = 6   | ConfigSwitchReason := "Cloud Migration";
    ConfigSwitchReason = 10  | ConfigSwitchReason := "Safe Mode - Sensor Crash Detected";
    ConfigSwitchReason = 11  | ConfigSwitchReason := "Safe Mode - Bad Channel File Identified";
    ConfigSwitchReason = 12  | ConfigSwitchReason := "Safe Mode - Watchdog Trigger";
    ConfigSwitchReason = 127 | ConfigSwitchReason := "Safe Mode - Switch Test";
    ConfigSwitchReason = 128 | ConfigSwitchReason := "Safe Mode - Watchdog Test";
    ConfigSwitchReason = 129 | ConfigSwitchReason := "Safe Mode - Test Failed";
    ConfigSwitchReason = 130 | ConfigSwitchReason := "CloudSim Test";
    ConfigSwitchReason = 131 | ConfigSwitchReason := "ConfigMgr Test";
    ConfigSwitchReason = 132 | ConfigSwitchReason := "Self Diagnostic Test";
    *                        | ConfigSwitchReason:=format(format="Unknown %s", field=[ConfigSwitchReason]);
}
        |ConfigSwitchReason!=/Sensor Crash Detected/iF
        | HuntLogic := "Sensor_Entered_SafeMode" | SeverityTier := "Medium" | HuntObject := ConfigSwitchReason;

    // TTP 9 - akira.exe or similar ransomware binary execution
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        (FileName = /^akira\.exe$/iF OR CommandLine = /akira.*\.exe/iF)
        | HuntLogic := "Akira_Ransomware_Execution" | SeverityTier := "Critical" | HuntObject := CommandLine;

    // TTP 10a - RDP from attacker jump host (WIN-DNCVG09TAT8)
    #event_simpleName = UserLogon
        LogonType = 10
        ClientComputerName = /WIN-DNCVG09TAT8/iF
        | HuntLogic := "Akira_RDP_From_JumpHost" | SeverityTier := "Critical" | HuntObject := ClientComputerName;
     // TTP 10b - Authenticaions via IDP of attacker jump host (WIN-DNCVG09TAT8)
    #event_simpleName = /ActiveDirectory/iF
        SourceEndpointHostName=/WIN-DNCVG09TAT8/iF
        | HuntLogic := "Akira_RDP_From_JumpHost" | SeverityTier := "Critical" | HuntObject := SourceEndpointHostName;    
  
    // TTP 11 - Notepad opening AD dump files (attacker reviewing recon output)
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF
        FileName = /^notepad\.exe$/iF
        CommandLine = /AdUsers\.txt|AdComp\.txt/iF
        | HuntLogic := "AD_Dump_Review_Notepad" | SeverityTier := "High" | HuntObject := CommandLine;

    // TTP 12 - s5cmd.exe dropped to disk
    #event_simpleName = /NewExecutableWritten|PeFileWritten/iF
        TargetFileName = /\\s5cmd\.exe$/iF
        | HuntLogic := "S5cmd_Binary_Dropped" | SeverityTier := "High" | HuntObject := TargetFileName;

    // TTP 13 - AnyDesk binary dropped to disk
    #event_simpleName = /NewExecutableWritten|PeFileWritten/iF
        TargetFileName = /\\AnyDesk\.exe$/iF
        | HuntLogic := "AnyDesk_Binary_Dropped" | SeverityTier := "Medium" | HuntObject := TargetFileName;

      // TTP 14 - Azure logins from Akira IP
    #event_simpleName=SsoApplicationAccess OR #event_simpleName=SsoUserLogon OR (#Vendor=microsoft AND #event.outcome=success)
       | SourceIP:=coalesce([SourceEndpointAddressIP4, SourceEndpointAddressIP6,source.ip])
       | SourceIP=/^(72\.23\.77\.35)$/ | SourceAccountUserName := coalesce([Vendor.properties.userPrincipalName, user.email,SourceAccountUserName])
        | HuntLogic := "Akira_Compromised_Email_Logins" | SeverityTier := "Critical" | HuntObject := SourceAccountUserName;
  
    // IOC Sweep - 2 SHA-256 hashes
    SHA256HashData = /^(e2356c742c74cce5c6b6100162d0071a3f71e2fed2ed895c2011061a95b3299a|414b9985f46714f44dd1bd63860d2a48dcfababcfe5c712a4b4f575378127a56)$/i
        | HuntLogic := "Akira_IOC_SHA256_Match" | SeverityTier := "Critical" | HuntObject := SHA256HashData;

    // IOC Sweep - Attacker VPN source IP (field-only, all network schemas)
    RemoteAddressIP4 = /^(72\.23\.77\.35)$/
        | HuntLogic := "Akira_IOC_VPN_Source_IP" | SeverityTier := "Critical" | HuntObject := RemoteAddressIP4
  }

| $ProcessTree2()

| groupBy(
    [ComputerName, HuntLogic, SeverityTier, UserName, HuntObject, ProcessTree],
    function=min(@timestamp, as=FirstSeen_epoch),
    limit=max
  )

| sort([SeverityTier, FirstSeen_epoch], order=[asc, desc], limit=max)
| formatTime(format="%e %b %Y %r", field=FirstSeen_epoch, as=FirstSeen, locale=en_UAE, timezone="Asia/Dubai")
| select([FirstSeen, ComputerName, HuntLogic, SeverityTier, UserName, ProcessTree, HuntObject])