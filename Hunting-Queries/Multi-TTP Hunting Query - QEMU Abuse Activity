/*

- https://www.sophos.com/en-us/blog/qemu-abused-to-evade-detection-and-enable-ransomware-delivery

Description:
This query searches for multiple indicators associated with the STAC4713 and STAC3725 
campaigns (often linked to PayoutsKing/GOLD ENCOUNTER). It utilizes a fast free-text 
pre-filter followed by a case statement to categorize specific TTPs, including QEMU abuse, 
rogue scheduled tasks, suspicious services/accounts, covert tunneling, and credential access.
*/

// 2. Filter to relevant event types and platform
| in(field=#event_simpleName, values=[ProcessRollup2, ScheduledTaskRegistered, UserAccountCreated, NetworkConnectIP4, NetworkConnectIP6])

// 3. Categorize matches into specific TTPs using distinct branches to avoid OR/AND precedence issues
| case {
    // TTP 1: QEMU execution with anomalous extensions (.db, .dll, .qcow2)
    // Tuning: Very low FP expected. If FPs occur, ensure target extensions are strictly enforced.
    #event_simpleName = ProcessRollup2 AND (ImageFileName = /\\qemu-system-x86_64\.exe$/i OR CommandLine = /qemu-system-x86_64/i) AND CommandLine = /(\.db|\.dll|\.qcow2)/i
        | Tactic := "Defense Evasion" | Technique := "QEMU Virtualization Abuse" | Matched := true ;

    // TTP 2a: Malicious Scheduled Task creation 'TPMProfiler' (Process)
    #event_simpleName = ProcessRollup2 AND CommandLine = /TPMProfiler/i
        | Tactic := "Persistence" | Technique := "Scheduled Task: TPMProfiler" | Matched := true ;
        
    // TTP 2b: Malicious Scheduled Task creation 'TPMProfiler' (Native Event)
    #event_simpleName = ScheduledTaskRegistered AND TaskName = /TPMProfiler/i
        | Tactic := "Persistence" | Technique := "Scheduled Task: TPMProfiler" | Matched := true ;

    // TTP 3a: 'CtxAppVCOMService' User Creation
    #event_simpleName = UserAccountCreated AND TargetUserName = /CtxAppVCOMService/i
        | Tactic := "Persistence" | Technique := "Rogue Account Creation" | Matched := true ;

    // TTP 3b: 'CtxAppVCOMService' referenced in Process execution
    #event_simpleName = ProcessRollup2 AND CommandLine = /CtxAppVCOMService/i
        | Tactic := "Persistence" | Technique := "Rogue Account Creation" | Matched := true ;

    // TTP 3c: 'AppMgmt' Service Creation via sc.exe
    // Tuning: 'AppMgmt' is a legitimate Windows service (Application Management). FPs may occur if 
    // administrators manually re-create or manage it. Filter by authorized admin usernames if needed.
    #event_simpleName = ProcessRollup2 AND CommandLine = /sc(?:\.exe)?\s+create\s+AppMgmt/i
        | Tactic := "Persistence" | Technique := "Rogue Service Creation" | Matched := true ;

    // TTP 4c: Port Forwarding commands
   ( #event_simpleName = ProcessRollup2 AND CommandLine = /(32567 |22022 )/ AND CommandLine = /(ssh |portproxy|forward )/i) or ((FileName = /ssh.exe/iF) CommandLine = /(32567|22022)/ (CommandLine=/-ssh/iF OR CommandLine=/-pw/iF OR CommandLine=/-R/iF OR CommandLine=/-R /iF OR CommandLine=/-L /iF OR CommandLine=/-P /iF) )
        | Tactic := "Command and Control" | Technique := "Port Forwarding/Tunneling" | Matched := true ;

    // TTP 5a: Credential Access via vssuirun.exe
    // Tuning: vssuirun.exe can be used by admins for VSS management. Correlate with unexpected users.
    #event_simpleName = ProcessRollup2 AND (ImageFileName = /\\vssuirun\.exe$/i OR CommandLine = /vssuirun\.exe/i)
        | Tactic := "Credential Access" | Technique := "NTDS.dit Extraction via VSS" | Matched := true ;

    // TTP 5b: Credential Access via print command copying NTDS.dit
    #event_simpleName = ProcessRollup2 AND CommandLine = /print\s/i AND CommandLine = /NTDS\.dit/i
        | Tactic := "Credential Access" | Technique := "NTDS.dit Extraction via Print" | Matched := true ;

    // TTP 6: DLL Sideloading via ADNotificationManager.exe (Loading vcruntime140_1.dll)
    // Tuning: ADNotificationManager is a native binary. To reduce FPs, verify if it executes 
    // outside of standard AD operational contexts, or correlate with 'ImageLoad' events for vcruntime140_1.dll.
   #event_simpleName=/(ClassifiedModuleLoad)/iF AND (TargetImageFileName = /\\ADNotificationManager\.exe$/i OR FileName = /vcruntime140_1\.dll/i)
        | Tactic := "Defense Evasion" | Technique := "DLL Sideloading" | Matched := true ;
  #event_simpleName=ScheduledTaskRegistered
| TaskName=/TPMProfiler/i
| TaskCommand=/qemu/i;
  // IOC
 in(field="SHA256HashData", values=["3a33b5bceb1eba4cc749534b03dd245f965d8f200aa02392baad78f5021a20ff","61c14c01460810f6f5f760daf8edbda82eea908b1a95052f8e0f9c4162c2900c","7ae413b76424508055154ee262c7567705dc1ac00607f5ac2e43d032221b34b3","a65f0144101d93656c5f9ad445b3993336e1f295a838351aeca6332c0949b463","c6b848c6a61685724fa9e2b3f6e3a118323ee0c165d1aa8c8a574205a4c4be59","f3194018d60645e43afabac33ceb4e852f95241b410cd726b1c40e3021589937"])| Technique := "IOCs" | Matched := true ;

  in(field="SHA1HashData", values=["25e4d0eacff44f67a0a9d13970656cf76e5fd78c","66dc383e9e0852523fe50def0851b9268865f779","6c09b0d102361888daa7fa4f191f603a19af47cb","8c8e75dc4b4e1f201b56133a00fa9d1d711ccb50","903edad58d54f056bd94c8165cc20e105b054fa8"])| Technique := "IOCs" | Matched := true ;

  in(field="MD5HashData", values=["6f55743091410dad6cdb0b7e474f03e7","b186baf2653c6c874e7b946647b048cc","b752ebfc1004f2c717609145e28243f3","f7a11aeaa4f0c748961bbebb2f9e12b6"])| Technique := "IOCs" | Matched := true ;

  in(field="RemoteIP", values=["144.208.127.190","158.158.0.165","194.110.172.152","74.242.216.76","98.81.138.214"])| Technique := "IOCs" | Matched := true ;

  in(field="DomainName", values=["vtps.us"])| Technique := "IOCs" | Matched := true ;
}

// 4. Filter only for positively matched TTPs
| Matched = true
| drop([Matched])

// 5. Present actionable data in a table format
| table([@timestamp, ContextBaseFileName, ComputerName, UserName, #event_simpleName, Tactic, Technique, ImageFileName, CommandLine, RemoteAddressIP4, RemotePort, LocalPort, TaskName, TargetUserName])
