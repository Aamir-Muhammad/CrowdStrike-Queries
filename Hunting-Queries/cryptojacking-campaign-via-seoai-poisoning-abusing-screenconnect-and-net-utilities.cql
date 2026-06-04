// Campaign: Cryptojacking via SEO/AI-poisoning → ScreenConnect → .NET process hollowing
// Source: https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/
// Author: Aamir Muhammad
//  TABLE 1: autorun.dll sideload (anchor for time-window join) 
defineTable(
    name  = "tbl_sideload",
    query = {
        #event_simpleName = /ClassifiedModuleLoad/iF
        | event_platform  = Win
        | FileName        = /^autorun\.dll$/iF
        | ImageFileName   = /Downloads|AppData\\Local\\Temp|AppData\\Roaming|ProgramData|Users\\Public|Desktop/iF
        | rename(field="ImageFileName",      as="LauncherPath")
        | rename(field="TargetImageFileName",as="LauncherName")
        | groupBy(
            [aid, ComputerName, LauncherName, LauncherPath],
            function = [min(timestamp, as=SideloadTime)]
        )
    },
    include = [aid, ComputerName, LauncherName, LauncherPath, SideloadTime]
)

//  TABLE 2: msiexec silent install within 30 min of autorun.dll sideload ─
| defineTable(
    name  = "tbl_sideload_msi",
    query = {
        #event_simpleName = ProcessRollup2
        | event_platform  = Win
        | FileName        = /^msiexec\.exe$/iF
        //| CommandLine     = /vcredist_x64/iF // commented out For a broader hunt
        | CommandLine     = /\/quiet|\/qn/iF
        | $ProcessTree2()
        | rename(field="ProcessTree", as="ProcTree")
        | MsiTime         := timestamp
        | match(table="tbl_sideload", field=aid, strict=true, nrows=max)
        | test(MsiTime >= SideloadTime)
        | test(MsiTime <= (SideloadTime + 1800000))
        | TTP := "T1574.002/T1218.007 — autorun.dll sideload then silent msiexec within 30 min"
        | groupBy(
            [aid, ComputerName, TTP, LauncherName, LauncherPath],
            function = [
                collect([CommandLine, ParentBaseFileName, UserName, ProcTree]),
                min(MsiTime, as=FirstSeen_epoch)
            ]
        )
    },
    include = [aid, ComputerName, TTP, LauncherName, LauncherPath,
               CommandLine, ParentBaseFileName, UserName, ProcTree, FirstSeen_epoch]
)

// TABLE 3: All Remaining TTPs
| defineTable(
    name  = "tbl_standalone",
    query = {
        #event_simpleName = /ProcessRollup2|FileCreateInfo|NewExecutableWritten|AsepValueUpdate|AsepKeyUpdate|RegGenericValueUpdate/iF
        | event_platform  = Win

        | case {

            // Branch 1: RuntimeHost.exe executing from Caches\D3F4E2A1
            #event_simpleName = ProcessRollup2
                AND ImageFileName = /RuntimeHost\.exe/iF
                AND ImageFileName = /Caches\\D3F4E2A1/iF
                | TTP := "T1036.005 — RuntimeHost.exe executing from Caches\\D3F4E2A1";

            // Branch 2: Scheduled task — Windows System Health family
            #event_simpleName = ProcessRollup2
                AND FileName    = /^schtasks\.exe$/iF
                AND CommandLine = /\/create/iF
                AND CommandLine = /Windows System Health/iF
                | TTP := "T1053.005 — Scheduled task 'Windows System Health*' created";

            // Branch 3: Process hollowing — .NET binary spawned by loader
            #event_simpleName = ProcessRollup2
                AND ImageFileName       = /InstallUtil\.exe$|RegAsm\.exe$|RegSvcs\.exe$|MSBuild\.exe$|AppLaunch\.exe$|AddInProcess\.exe$|aspnet_compiler\.exe$/iF
                AND (ParentBaseFileName = /^(RuntimeHost|SimpleRunPE|vlc)\.exe$/iF
                     OR ImageFileName  = /Caches\\D3F4E2A1/iF)
                | TTP := "T1055.012 — .NET binary spawned by RuntimeHost/SimpleRunPE for process hollowing";

            // Branch 4: Defender exclusion via Add-MpPreference
            #event_simpleName = ProcessRollup2
                AND CommandLine = /Add-MpPreference/iF
                AND CommandLine = /ExclusionPath|ExclusionProcess/iF
                | TTP := "T1562.001 — Defender exclusion added via Add-MpPreference";

            // Branch 5: RuntimeHost.lnk written to Startup folder
            #event_simpleName = /FileCreateInfo|NewExecutableWritten/iF
                AND TargetFileName = /Start Menu\\Programs\\Startup/iF
                AND TargetFileName = /RuntimeHost\.lnk$/iF
                | TTP := "T1547.009 — RuntimeHost.lnk written to Startup folder";

            // Branch 6: Registry Run key WinSysCache → RuntimeHost.exe
            #event_simpleName = /AsepValueUpdate|AsepKeyUpdate|RegGenericValueUpdate/iF
                AND RegObjectName   = /CurrentVersion\\Run/iF
                AND (RegValueName   = /^WinSysCache$/iF
                     OR RegStringValue = /Caches\\D3F4E2A1|RuntimeHost\.exe/iF)
                | TTP := "T1547.001 — Registry Run key WinSysCache pointing to RuntimeHost.exe"

        }

        | $ProcessTree2()
        | rename(field="ProcessTree", as="ProcTree")
        | groupBy(
            [aid, ComputerName, TTP],
            function = [
                collect([ImageFileName, FileName, CommandLine,
                         ParentBaseFileName, TargetFileName,
                         RegObjectName, RegValueName, RegStringValue,
                         ContextBaseFileName, UserName, ProcTree]),
                min(timestamp, as=FirstSeen_epoch),
                count(as=HitCount)
            ]
        )
    },
    include = [aid, ComputerName, TTP, ImageFileName, FileName,
               CommandLine, ParentBaseFileName, TargetFileName,
               RegObjectName, RegValueName, RegStringValue,
               ContextBaseFileName, UserName, ProcTree, FirstSeen_epoch, HitCount]
)

| readFile([tbl_sideload_msi, tbl_standalone])

| FirstSeen := formatTime(format="%e %b %Y %r", field=FirstSeen_epoch, locale=en_UAE, timezone="Asia/Dubai")
| sort(FirstSeen_epoch, order=desc,limit=max)

| table([
    ComputerName, aid, TTP,
    FirstSeen, HitCount,
    ProcTree,
    ImageFileName, FileName, CommandLine, ParentBaseFileName,
    TargetFileName, RegObjectName, RegValueName, RegStringValue,
    LauncherName, LauncherPath, ContextBaseFileName, UserName
])