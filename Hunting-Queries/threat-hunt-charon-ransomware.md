```

defineTable(query={#event_simpleName=/Written|PeFileWritten/iF
|case{
  in(field="SHA256HashData", values=["f3c8b4986377b5a32c20fc665b0cbe0c44153369dadbcaa5e3d0e3c8545e4ba5","e0a23c0d99c45d40f6ef99c901bacf04bb12e9a3a15823b663b392abadd2444e","
5d0675f20eeb8f824097791711135a273680f77bf5e9f0e168074e97464f21b5","739e2cac9e2a15631c770236b34ba569aad1d1de87c6243f285bf1995af2cdc2"]) |rename(field="SHA256HashData", as="RansomeSHA256")|rename(field="FileName", as="RansomewareFileWritten")|Analysis:="Ransomware Package written to disk"; //5d0675f20eeb8f824097791711135a273680f77bf5e9f0e168074e97464f21b5 is not malicious
  FileName = /msedge.dll|TSMSISrv.dll|PulseBeaconX96311.dll|DumpStack.log/iF |rename(field="FileName", as="RansomewareFileWritten")|rename(field="SHA256HashData", as="RansomeSHA256") |Analysis:="Ransomware Package written to disk"; //Edge.exe is not malicious
  OriginalFileName=PulseBeaconX96311.dll |rename(field="FileName", as="RansomewareFileWritten") |rename(field="SHA256HashData", as="RansomeSHA256")|Analysis:="Ransomware Package written to disk"
}
|rename(field="@timestamp", as="RansomeFileWrittenTime")| RansomeFileWrittenTime := formatTime("%e %b %Y %r", field=RansomeFileWrittenTime, locale=en_UAE, timezone="Asia/Dubai")
|groupBy([FilePath,ComputerName,#event_simpleName],function=([collect([RansomeFileWrittenTime,RansomeSHA256,RansomewareFileWritten,Analysis],limit=200000),count(RansomewareFileWritten,distinct=true,as=FileCount)]))
|FileCount>1
}, include=[FilePath,FileCount,ComputerName,#event_simpleName,RansomeFileWrittenTime,RansomeSHA256,RansomewareFileWritten,Analysis], name="RansomeFileWritten")
|defineTable(query={
  #event_simpleName=/ClassifiedModuleLoad/iF
  |(TargetImageFileName = /\\Edge.exe/iF or OriginalFilename = /cookie_exporter.exe/iF) and (FileName = /msedge.dll|TSMSISrv.dll|PulseBeaconX96311.dll/iF)
    |rename(field="TargetProcessId", as="PID")
    |rename(field="TargetImageFileName", as="DllSideLoadProcess")
    |rename(field="OriginalFilename", as="DllSideLoadOriginalName")
    |rename(field="FileName", as="DllLoaded")
    |rename(field="FilePath", as="DllLoadedPath")
    |rename(field="@timestamp", as="SideloadTime")| SideloadTime := formatTime("%e %b %Y %r", field=SideloadTime, locale=en_UAE, timezone="Asia/Dubai")
    |rename(field="CommandLine", as="DllLoadedCommandLine")
    | Analysis:="Malicious DLL has been sideloaded"
}, include=[SideloadTime,PID,DllSideLoadProcess,DllLoadedCommandLine,DllSideLoadOriginalName,DllLoaded,DllLoadedPath,Analysis], name="DLLSideLoad")
|defineTable(query={#event_simpleName=/ProcessRollup2/iF
  |match(file="DLLSideLoad", field=[aid,ParentProcessId],column=[aid,PID],strict=true,include=[SideloadTime,PID,DllSideLoadProcess,DllSideLoadOriginalName,DllLoaded,DllLoadedPath])
  |rename(field="FileName", as="ChildProcess")
  |rename(field="CommandLine", as="ChildProcessCommandLine")
  |lower("ChildProcess")
  |Analysis:= if(ChidProcess==svchost.exe, then="Charon Ransomware Deployement Triggered", else="Charon Ransomware Deployement might NOT be Triggered as No SVCHOST.EXE process triggered")
}, include=[ChildProcess,ChildProcessCommandLine,SideloadTime,PID,DllSideLoadProcess,DllLoadedCommandLine,DllSideLoadOriginalName,DllLoaded,DllLoadedPath,Analysis], name="RansomwareDeploy")
|defineTable(query={#event_simpleName=/Written/iF
  |match(file="RansomwareDeploy", field=[TargetProcessId],column=[ContextProcessId],strict=true,include=[ChildProcess,ChildProcessCommandLine,SideloadTime,PID,DllSideLoadProcess,DllLoadedCommandLine,DllSideLoadOriginalName,DllLoaded,DllLoadedPath,Analysis])
  |case{
   FileName=/.charon$/iF                    |rename(field="FileName", as="RansomedFiles") |Analysis:="Charon Ransomware has been successfully deployed";
   FileName="How to Restore Your Files.txt" |rename(field="FileName", as="RansomwareNote")  |Analysis:="Charon Ransomware has been successfully deployed"
       }
  }, include=[RansomedFiles,RansomwareNote,Analysis,ChildProcess,ChildProcessCommandLine,SideloadTime,PID,DllSideLoadProcess,DllLoadedCommandLine,DllSideLoadOriginalName,DllLoaded,DllLoadedPath,Analysis], name="RansomeNote")
|defineTable(query={#event_simpleName=CreateService and (ServiceDisplayName=/WWC/iF or ServiceImagePath=/\\System32\\Drivers\\WWC.sys/iF)}, include=[*], name="ServiceCharon")
|readFile(["RansomeFileWritten","DLLSideLoad","RansomwareDeploy","RansomeNote","ServiceCharon"])
//https://www.trendmicro.com/en_dk/research/25/h/new-ransomware-charon.html

```
