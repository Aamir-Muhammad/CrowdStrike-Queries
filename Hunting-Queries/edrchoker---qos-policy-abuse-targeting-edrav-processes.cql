// // EDRCHOKER - QoS Policy abuse targeting EDR/AV processes (T1562 – Impair Defenses)
// // https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html
// Author: Aamir Muhammad
|case{
#event_simpleName=/ProcessRollup2|WmiCreateProcess/iF
CommandLine=/New-NetQosPolicy|Set-NetQosPolicy/iF
CommandLine=/ThrottleRateActionBitsPerSecond|AppPathNameMatchCondition/iF 
CommandLine=/(SenseIR\.exe|MsSense\.exe|MsMpEng\.exe|WinDefend\.exe|falcon-sensor\.exe|CSFalconService\.exe|SentinelService\.exe|SentinelAgent\.exe|CortexXDR\.exe|cyvera\.exe|pmsu\.exe|cb\.exe|carbonblack\.exe|edragent\.exe|HarfangLab\.exe|elastic-agent\.exe)/iF
| SuspectActivity := format( "QoS Policy Creation via Process Command Line: %s", field=[#event_simpleNam]);
#event_simpleName=/RegGenericValueUpdate|AsepValueUpdate|RegSystemConfigValueUpdate|RegistryHiveFileWritten|reg/iF
RegObjectName=/\\SOFTWARE\\Policies\\Microsoft\\Windows\\QOS/i
RegStringValue=/(SenseIR\.exe|MsSense\.exe|MsMpEng\.exe|WinDefend\.exe|falcon-sensor\.exe|CSFalconService\.exe|SentinelService\.exe|SentinelAgent\.exe|CortexXDR\.exe|cyvera\.exe|pmsu\.exe|cb\.exe|carbonblack\.exe|edragent\.exe|HarfangLab\.exe|elastic-agent\.exe)/i
| SuspectActivity := format("QoS Registry Manipulation targeting: %s", field=[RegStringValue])
}
|$ProcessTree2()
|groupBy([@timestamp,ComputerName,ProcessTree,CommandLine,#event_simpleName])
