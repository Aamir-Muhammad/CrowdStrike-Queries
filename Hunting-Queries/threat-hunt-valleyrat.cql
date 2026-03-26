// Threat Hunt On ValleyRAT
// https://hexastrike.com/resources/blog/threat-intelligence/valleyrat-exploiting-byovd-to-kill-endpoint-security/
// To join CreateService schema events to process creation use Joining of [aid,TargetProcessId] => [aid,RpcClientProcessId])
case{
  #event_simpleName=/CreateService/iF ServiceObjectName=/\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet\d*\\Services/iF ServiceImagePath=/\\(Users|ProgramData|Windows)\\[^\\]+\\AppData\\Local\\Temp\\.+|\\Temp\\.+/iF; // 1ttp  
  #event_simpleName=AsepValueUpdate RegObjectName=/\\SYSTEM\\ControlSet\d*\\Services/iF FilePath=/\\(Users|ProgramData|Windows)\\[^\\]+\\AppData\\Local\\Temp\\.+|\\Temp\\.+/iF; //2 ttp 
  #event_simpleName="DriverLoad" event_platform=Win FilePath=/\\(Users|ProgramData|Windows)\\[^\\]+\\AppData\\Local\\Temp\\.+|\\Temp\\.+/iF; //3 ttp
  #event_simpleName=DriverLoad event_platform=Win CompanyName=/Shandong Anzai Information Technology/iF; // Certificate Company Check
  in(field="SHA256HashData", values=["b4ac2e473c5d6c5e1b8430a87ef4f33b53b9ba0f585d3173365e437de4c816b2","206f27ae820783b7755bca89f83a0fe096dbb510018dd65b63fc80bd20c03261"],ignoreCase=true)
}
|RegObjectName!="\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\SymCloseUI" //Symantic AV component
|ServiceImagePath!=/C:\\WINDOWS\\TEMP\\TdkLimit64.sys$/iF // Lenovo Signed Driver
|groupBy([#event_simpleName,ComputerName,ParentProcessChain,VT,HA,CommandLineTree,RegObjectName,RegStringValue,FilePath,TargetSHA256HashData,ServiceObjectName,ServiceImagePath]) 
