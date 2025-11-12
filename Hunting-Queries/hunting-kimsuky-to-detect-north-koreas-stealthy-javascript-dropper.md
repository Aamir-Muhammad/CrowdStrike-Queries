```
// Kimsuky JS Dropper Hunting Query - CQL Version
|case{
 #event_simpleName=DnsRequest (DomainName=/medianewsonline.com/iF OR DomainName=/iuh234.medianewsonline.com/iF)| IndicatorType := "Network Traffic";
 #event_simpleName=/FileWritten/iF FileName=/(Themes.js|L298306.tmp)$/iF TargetFileName=/APPDATA|temp|public/iF| IndicatorType := "File";
 #event_simpleName=ProcessRollup2 ImageFileName=/certutil.exe|script.exe/iF CommandLine=/-decode|-encode|Themes.js/iF| IndicatorType := "Initial Infection via Process Certutil/Wscript/Cscript";
 #event_simpleName=ProcessRollup2 (CommandLine=/cmd \/c systeminfo >|cmd \/c tasklist >/iF OR (CommandLine=/cmd \/c cd \/d/iF CommandLine="* > *"))| IndicatorType := "CMD /c arguments";
 #event_simpleName=ProcessRollup2 #event_simpleName=ProcessRollup2 CommandLine="*schtasks*create*Windows Theme Manager*" | IndicatorType := "Persistence via CMD/SCHTask Creation";
 #event_simpleName=ScheduledTaskRegistered TaskXml=/Themes.js|Windows Themes Manager/iF| IndicatorType := "Persistence via SCHTask Creation";
 #event_simpleName=/SuspiciousRegAsepUpdate|RegCrowdstrikeValueUpdate|AsepValueUpdate/iF RegStringValue=/\\Microsoft\\Windows\\Themes\\Themes.js/iF| IndicatorType := "Persistence via ASEP";
}
// Reference: https://blog.pulsedive.com/dissecting-the-infection-chain-technical-analysis-of-the-kimsuky-javascript-dropper/
```
