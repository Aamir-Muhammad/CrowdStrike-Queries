```
// Fake Clawdbot VS Code Extension Installs ScreenConnect RAT
//Ref https://www.aikido.dev/blog/fake-clawdbot-vscode-extension-malware
|case{
DomainName=/clawdbot.getintwopc.site|darkgptprivate.com|bulletmailer.net|darkgptprivate.com|getintwopc.site|meeting.bulletmailer.net/iF;
(HostUrl=/clawdbot.getintwopc.site/iF OR ReferrerUrl=/clawdbot.getintwopc.site/iF) FileName=/config.json|lightshot.dll|lightshot.exe/iF;
(HostUrl=/dropbox.com/iF OR ReferrerUrl=/dropbox.com/iF) FileName=/zoomupdate.msi/iF;
RemoteIP=/^(178.16.54.253|179.43.176.32)/F;
in(field="SHA256HashData", values=["04ef48b104d6ebd05ad70f6685ade26c1905495456f52dfe0fb42f550bd43388","adbcdb613c04fd51936cb0863d2417604db0cd04792ab7cae02526d48944c77b","d1e0c26774cb8beabaf64f119652719f673fb530368d5b2166178191ad5fcbea","e20b920c7af988aa215c95bbaa365d005dd673544ab7e3577b60fecf11dcdea2"],ignoreCase=true);
#event_simpleName=/NetworkConnect/iF RemotePort=8041 |!cidr(RemoteIP, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32","100.64.0.0/10","fe80::/10"])
; // Outbound Connection
#event_simpleName=/ServiceStarted$/iF ServiceDisplayName=/ScreenConnect|ScreenConnect.*Client|083e4d30c7ea44f7/iF; // Windows Services for ScreenConnect Client
#event_simpleName=/Written/iF FilePath=/\\temp.*ScreenConnect/iF; // %TEMP%\Lightshot for any files and delete the entire folder
#event_simpleName=/Processrollup/iF FilePath=/\\temp/iF FileName=/Code.exe/iF; // Code.exe processes running from temp or unexpected directories
#event_simpleName=/Processrollup/iF FilePath=/\\temp/iF FileName=/ScreenConnect/iF; // ScreenConnect processes running from temp or unexpected directories
}
|asn(RemoteAddressIP4)
|groupBy([#event_simpleName,FilePath,DomainName,ComputerName,ContextBaseFileName,RemoteAddressIP4,RemoteAddressIP4.org])
```
