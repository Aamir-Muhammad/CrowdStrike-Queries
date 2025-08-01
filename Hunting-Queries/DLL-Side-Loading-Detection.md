Dll-Side Loading Detection Query for Crowdstrike Falcon NGSIEM
```
//Tracing the ProcessId of a Process / File which is writting atleast 1 each EXE and DLL to same Path, Doing the Process Original name masquarading and atleast 1 File Author name is Microsoft in "DLL-Filewrite", tracking throughtout as SusProcessID
defineTable(query={#event_simpleName=/(PeFileWritten)/iF 
|lowercase("FileName")
|lowercase("OriginalFilename")
|(FileName="*" and OriginalFilename="*")
| regex("(?<DllFileName>^.*)\.dll", field=FileName, strict=false)
| regex("(?<EXEFileName>^.*)\.exe", field=FileName, strict=false)
| MasquraeCheck:=if(FileName==OriginalFilename, then="Normal", else="Masquarade") |MasquraeCheck!="Normal"
|SusProcessID:=format(format="%s%s", field=[aid,ContextProcessId])
|rename(field="SHA256HashData", as="SusHash")
|rename(field="FileName", as="FileWritten")
// Exclusions FOr Edge Browser
|OriginalFilename!=microsoftedgeupdate.exe OriginalFilename!=msedgeupdate.dll
|groupBy([SusProcessID,FilePath],function=([collect([DllFileName,EXEFileName,SusHash,FileWritten,OriginalFilename,CompanyName]),count(DllFileName,as=DllC),count(EXEFileName,as=EXEC)]),limit=max)
|DllC>=1 EXEC>=1 CompanyName=/Microsoft/iF 
}, include=[FilePath,FileWritten,OriginalFilename,SusHash,DllFileName,EXEFileName,CompanyName,SusProcessID,ComputerName,UserName], name="DLL-Filewrite")

// Then tracing the Parent File for files written operation in "DLL-Filewrite" getting FileWriteParent, tracked as "DLL-Parent"
|defineTable(query={#event_simpleName=/(ProcessRollup2)/iF  
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|match(file="DLL-Filewrite", field=[TargetProcessId],column=[SusProcessID],strict=true,include=[FilePath,FileWritten,OriginalFilename,SusHash,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="ParentBaseFileName", as="FileWriteParent")
|case{
CommandLine=* |regex("\"[^\"]+\"\\s+\"(?P<FullPath>[^\"]*\\\\)?", field=CommandLine)| regex(".*\\\\(?<FileNamey>[^\\\\\"]+?)\"?$", field=CommandLine);
*
}
|case{
  FullPath="*" or FileNamey="*" | FileWriteFileSource:=format(format="%s\n\t└-> %s", field=[FileNamey,FullPath]);
  FullPath!="*" FileNamey!="*" | FileWriteFileSource:=format(format="%s", field=[FileName]);
  *
}
| coalesce([FileNamey,FileName],as=FileWriteFile,ignoreEmpty=false)
}, include=[FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName], name="DLL-Parent")

// Then Tracing the DLL-side-Loading Process startup for "DLL-Parent", getting DLLSideLoadProcess, tracked as "DLLSideLoadProcess"
|defineTable(query={#event_simpleName=/(ProcessRollup2)/iF |DLLSideLoadProcess:=format(format="%s\n\t└-> %s", field=[ParentBaseFileName,FileName])
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|match(file="DLL-Parent", field=[ParentProcessId],column=[SusProcessID],strict=true,include=[FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="TargetProcessId", as="ModuleLoadId")
| rename(field="ProcessStartTime", as="ProcessStartTime")
}, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,ModuleLoadId,SusProcessID,ComputerName,UserName], name="DLLSideLoadProcess")

// Then tracing the DLL/EXE side loaded for DLLSideLoadProcess from "DLLSideLoadProcess", tracked as "DllLoading"
|defineTable(query={#event_simpleName=/(ClassifiedModuleLoad)/iF |rename(field="FileName", as="DllLoad") 
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|ContextProcessId:=format(format="%s%s", field=[aid,ContextProcessId])
| "DllLoaded Files":= format(format="%s\n\t└-> %s", field=[DllLoad,FilePath])
|match(file="DLLSideLoadProcess", field=[ContextProcessId],column=[ModuleLoadId],strict=true,include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="TargetProcessId", as="ModuleLoadId")

|case {
  ModuleLoadTelemetryClassification = 1
| ModuleLoadTelemetryClassification := "FIRST_LOAD\n\t\t└->This is the first time this module has been loaded into a process on the host";
  ModuleLoadTelemetryClassification = 2
| ModuleLoadTelemetryClassification := "RUNDLL32_TARGET\n\t\t└->This module is the target of a rundll32.exe invocation";
  ModuleLoadTelemetryClassification = 4
| ModuleLoadTelemetryClassification := "DETECT_TREE\n\t\t└->The module was loaded into a process that is in an active detect tree";
  ModuleLoadTelemetryClassification = 8
| ModuleLoadTelemetryClassification := "MAPPED_FROM_KERNEL_MODE\n\t\t└->The module was loaded into kernel mode address space";
  ModuleLoadTelemetryClassification = 16
| ModuleLoadTelemetryClassification := "UNUSUAL_EXTENSION\n\t\t└->The module has an unexpected, unusual or rare extension";
  ModuleLoadTelemetryClassification = 32
| ModuleLoadTelemetryClassification := "MOTW\n\t\t└->The module has the Mark of the Web zone identifier";
  ModuleLoadTelemetryClassification = 64
| ModuleLoadTelemetryClassification := "SIGN_INFO_CONTINUITY\n\t\t└->The module does not have a valid signature and it was loaded into a process with a primary module that does have a valid signature";
  ModuleLoadTelemetryClassification = 256
| ModuleLoadTelemetryClassification := "ORIGINAL_FILENAME_MISMATCH\n\t\t└->Module's ImageFileName doesn't match OriginalFileName";
  ModuleLoadTelemetryClassification = 512
| ModuleLoadTelemetryClassification := "REMOVABLE_MEDIA\n\t\t└->The module was loaded from removable media (ISO/IMG)";
  ModuleLoadTelemetryClassification = 1024
| ModuleLoadTelemetryClassification := "DATA_EXTENSION\n\t\t└->The module has a data type extension";
  ModuleLoadTelemetryClassification = 257
| ModuleLoadTelemetryClassification := "FIRST_LOAD_AND_FILENAME_MISMATCH\n\t\t└->This is the first time this module has been loaded into a process on the host and its ImageFileName doesnt match OriginalFileName";
  *
| ModuleLoadTelemetryClassification := format(format="Value=%s\n\t\t└->Multiple module load telemetry flags are set, Check ModuleLoadTelemetryClassification documentation", field=[ModuleLoadTelemetryClassification])
}

}, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName], name="DllLoading")

//Performing the aggregation in the presentable format + to prepare for matchup for MOTW URLS in next table
|defineTable(query={readFile([DllLoading])
|groupBy([ProcessStartTime,SusProcessID,ComputerName,UserName],function=([collect([FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash]),count("DllLoaded Files",distinct=true,as="DllLoaded Files Count")]),limit=max)},include=[ProcessStartTime,SusProcessID,ComputerName,FileWriteFile,UserName,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash,"DllLoaded Files Count"], name="Aggregation")

//Fetching MOTW URLS
|defineTable(query={#event_simpleName=MotwWritten 
|match(file="Aggregation", field=[ComputerName,FileName],column=[ComputerName,FileWriteFile],strict=true,ignoreCase=true, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName,"DllLoaded Files Count"])
|case{
  HostUrl!="" ReferrerUrl="" |FileWriteFileSourceURL:=format(format="Download URL= %s", field=[HostUrl]);
  HostUrl="" ReferrerUrl!="" |FileWriteFileSourceURL:=format(format="Referrer URL= %s", field=[ReferrerUrl]);
  HostUrl!="" OR ReferrerUrl!="" |FileWriteFileSourceURL:=format(format="Download URL= %s\nReferrer URL= %s", field=[HostUrl,ReferrerUrl]);
  *
}
}, include=[FileWriteFile,FileWriteFileSourceURL,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName,"DllLoaded Files Count"], name="MOTW")
|readFile(["Aggregation","MOTW"])
|case{
  FileWriteFileSourceURL!="*" |FileWriteFileSourceURL:=format(format="No URL Found", field=[]);
  * 
}
|groupBy([ProcessStartTime,SusProcessID,ComputerName,UserName],function=([collect([FileWriteFileSourceURL,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash,"DllLoaded Files Count"])]))
| ProcessStartTime:=ProcessStartTime*1000 |ProcessStartTime := formatTime("%e %b %Y %r", field=ProcessStartTime, locale=en_UAE, timezone="Asia/Dubai")
| rename([[FilePath,FileWrittenPath],[CompanyName,"ExeAuthorCompanyName"],[ModuleLoadTelemetryClassification,"DllLoaded Files Signature"]])
|drop([SusProcessID])
```
