// BITTER PapRAT and WmRAT Campaign IOC and Behavior Detection
// Source: https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat
// Author: Aamir Muhammad https://www.linkedin.com/in/aamirmohammad/
event_platform = "Win"
#event_simpleName = /ProcessRollup2|SyntheticProcessRollup2|DnsRequest|NetworkConnectIP4|NetworkReceiveAcceptIP4|MountedVolume|PeVersionInfo|Written$/iF
| FileRef := coalesce([TargetFileName, ImageFileName])
| case {
    SHA256HashData = /^(411c0b9a2f98b927d806a685faf0c1ab1005647b4816157008892347fb88546b|569a21b519aaac8c92f653d708ab6ef34e3f38ea967f47e041d1e2425f6a4b33|a3081df333ca7f18bd90d10a45125ab5011dcf9d2806feae2935f09cab07da4c|ccefbdec2718d864d9d33c743aabfcef88a8d7904d1c598bfcf15cf5f3591c88|e3992f8c945b0761242377cba32d91b0a390c7cecd79478439843d93e6d2b76b|a16f17c204840df2b06c431887ad2f0c5b62b3c92cd601010b439f8715a7b24c|f1060a81c9f68d6f3d23e28f2a1af50fa18ecb9b0a763ca5dcd4b294b6a3593c)$/i
        | HuntLogic := "BitterPapRAT_IOC_Hash_Match"
        | SeverityTier := "Critical"
        | HuntObject := format("%s | %s", field=[SHA256HashData, FileRef]);
    DomainName = /(^|\.)(netmansrvdns|rappellingaart|gomescareerplans|rivingtonclarks|felixfuturenext|goodnfortunes|techtalkhelp|chestergreenfarming)\.com/i
        | HuntLogic := "BitterPapRAT_IOC_Domain_Match"
        | SeverityTier := "Critical"
        | HuntObject := format("%s", field=[DomainName]);
    RemoteAddressIP4 = /^(185\.244\.151\.84|144\.208\.125\.110|46\.19\.143\.157|192\.142\.10\.5|84\.252\.95\.216|82\.221\.136\.1|176\.123\.0\.199)$/
        | HuntLogic := "BitterPapRAT_IOC_IP_Match"
        | SeverityTier := "Critical"
        | HuntObject := format("%s:%s", field=[RemoteAddressIP4, RemotePort]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF CommandLine = /(netmansrvdns|rappellingaart|gomescareerplans|rivingtonclarks|felixfuturenext|goodnfortunes|techtalkhelp|chestergreenfarming)\.com|Visa_Details\.msi|Imp_Details\.msi|Invitation\s+2026\.url|Majilis\s+2026|Belt\s+and\s+Road\s+Summit|HACGAM|Avn\s+Comd\s+and\s+Staff|NV-683\s+Request|Letter\s+from\s+the\s+Ambassador|MicrosoftUpdates\\updates(11678|88679)|BiosUpdates\\update101|banaNa\.php|\/Epistemological\/|\/b99\/\?kq=|ucl\.php\?svr=|@ssl\\secure-docs/iF
        | HuntLogic := "BitterPapRAT_IOC_CommandLine_Match"
        | SeverityTier := "Critical"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = PeVersionInfo OriginalFilename = /^bruzsvc\.exe$/iF
        | HuntLogic := "PapRAT_PE_OriginalFilename_Bruzsvc"
        | SeverityTier := "High"
        | HuntObject := format("%s | %s", field=[OriginalFilename, ImageFileName]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF (FileName = /^(bruzsvc|vnces)\.exe$/iF or OriginalFilename = /^bruzsvc\.exe$/iF)
        | HuntLogic := "PapRAT_WmRAT_Implant_Execution"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF ParentBaseFileName = /^(bruzsvc|vnces)\.exe$/iF
        | HuntLogic := "PapRAT_WmRAT_Child_Process"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF ParentBaseFileName = /^ftp\.exe$/iF FileName = /^(cmd|more|curl|powershell|conhost|schtasks|msg)\.(exe|com)$/iF CommandLine!=/conhost.exe 0xffffffff -ForceV1/iF
        | HuntLogic := "Ftp_LOLBin_Shell_Spawn"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF (FileName = /^ftp\.exe$/iF or OriginalFilename = /^ftp\.exe$/iF) CommandLine = /-s:\s*\S*\.ico\b|\b(icon|res)\.ico\b/iF
        | HuntLogic := "Ftp_Script_Execution_From_ICO"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF (FileName = /^schtasks\.exe$/iF or OriginalFilename = /^schtasks\.exe$/iF) CommandLine = /\b(MicrosoftUpdates\\updates|BiosUpdates\\update)\d+/iF
        | HuntLogic := "Bitter_Fake_Update_Scheduled_Task"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF (FileName = /^schtasks\.exe$/iF or OriginalFilename = /^schtasks\.exe$/iF) CommandLine = /conhost(\.exe)?\s+--headless|\bmore\b[^|]*\|\s*c\^?m\^?d|\b(err|talk)\.log\b/iF
        | HuntLogic := "Schtasks_Headless_More_Pipe_Cmd"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF FileName = /^conhost\.exe$/iF CommandLine = /--headless\s+cmd(\.exe)?\s+\/c\s+more\b/iF
        | HuntLogic := "Conhost_Headless_More_Pipe_Cmd"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF (FileName = /^curl\.exe$/iF or OriginalFilename = /^curl\.exe$/iF) CommandLine = /--ssl-no-revoke\s+-k|\bkq=|\bsvr=|\bvid=|file=@abc\.pdf|-o\s+\S*talk\.log/iF
        | HuntLogic := "Curl_Bitter_C2_Beacon_Or_Staging"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF FileName = /^msiexec\.exe$/iF CommandLine = /\\\\[^\\\s]+@ssl\\/iF
        | HuntLogic := "Msiexec_WebDAV_Remote_MSI_Install"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF FileName = /^cmd\.exe$/iF CommandLine = /\.msi\s*&\s*\S+\.(xls|xlsx|doc|docx|pdf)/iF
        | HuntLogic := "LNK_MSI_Install_With_Decoy_Document"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF (FileName = /^msg\.exe$/iF or OriginalFilename = /^msg\.exe$/iF) CommandLine = /unable\s+to\s+open\s+this\s+file/iF
        | HuntLogic := "Fake_Explorer_Error_Popup_Lure"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF CommandLine = /\\users\\public\\music\\err\.log|\\programdata\\talk\.log|%localappdata%\\abc\.pdf/iF
        | HuntLogic := "Bitter_Staged_Log_Script_Execution"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = /Written$/iF TargetFileName = /(\\Users\\Public\\Music\\err\.log|\\ProgramData\\talk\.log|\\AppData\\Local\\abc\.pdf|\\(Visa_Details|Imp_Details)\.msi|\\(vnces|bruzsvc)\.exe|\\Invitation\s+2026\.url|\\Official\s+Invitation\s+Majilis\s+2026\s+Gala\s+Dinner\.rar|\\Letter\s+from\s+the\s+Ambassador\s+-\s+11th\s+Belt\s+and\s+Road\s+Summit\.(lnk|vhdx)|\\NV-683\s+Request\s+for\s+Bilateral\s+Meeting\.pdf\.lnk|\\update\s+on\s+Avn\s+Comd\s+and\s+Staff\s+programme\.lnk)$/iF
        | HuntLogic := "Bitter_Dropped_File_Written"
        | SeverityTier := "High"
        | HuntObject := format("%s", field=[TargetFileName]);
    #event_simpleName = /ProcessRollup2|SyntheticProcessRollup2/iF FileName = /^powershell\.exe$/iF ParentBaseFileName = /^(cmd|conhost)\.exe$/iF CommandLine = /root\/SecurityCenter2/iF CommandLine = /AntivirusProduct/iF
        | HuntLogic := "Recon_AV_Enumeration_From_Cmd"
        | SeverityTier := "Medium"
        | HuntObject := format("%s", field=[CommandLine]);
    #event_simpleName = MountedVolume VirtualDriveFileName = /\\(Downloads|Desktop|Documents|Temp|AppData)\\[^\\]+\.vhdx$/iF
        | HuntLogic := "VHDX_Mounted_From_User_Path"
        | SeverityTier := "Medium"
        | HuntObject := format("%s", field=[VirtualDriveFileName]);
  }
| $ProcessTree2()
| default(field=UserName, value="-", replaceEmpty=true)
| default(field=ProcessTree, value="-", replaceEmpty=true)
| groupBy([ComputerName, UserName, HuntLogic, SeverityTier, ProcessTree, HuntObject], function=[min(@timestamp, as=FirstSeenEpoch), count(as=EventCount)], limit=max)
| FirstSeen := formatTime(format="%e %b %Y %r", field=FirstSeenEpoch, locale=en_UAE, timezone="Asia/Dubai")
| sort(SeverityTier, order=asc, limit=max)
| select([FirstSeen, ComputerName, HuntLogic, SeverityTier, UserName, ProcessTree, HuntObject, EventCount])
