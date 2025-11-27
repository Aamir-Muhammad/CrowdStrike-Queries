```
// References: https://www.koi.ai/incident/live-updates-sha1-hulud-the-second-coming-hundred-npm-packages-compromised
//https://safedep.io/shai-hulud-second-coming-supply-chain-attack/
|case{
    in(field="SHA256HashData", values=["a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a", // setup_bun.js
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0", // bun_environment.js
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068", // bun_environment.js
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"  // bun_environment.js
    ])|Analysis:="Confirmed Malicious Hashes";
    FileName="discussion.yaml" FilePath=/\.github[\\\/]workflows[\\\/]/ |Analysis:="Discussion.yaml";
      /* FP Consideration: The file 'discussion.yaml' is a specific indicator. However, a developer could theoretically create a file with this name. Further validation could involve checking file content for 'on: discussion' and 'runs-on: self-hosted'. */
      event_platform=/macOS|linux/iF #event_simpleName=ProcessRollup2 |in(field="CommandLine", values=["*find*","*shred*","*xargs*","*-delete*","*$HOME*"],ignoreCase=true)|Analysis:="Linux/macOS destructive command"; 
      event_platform=/win/iF #event_simpleName=ProcessRollup2 ParentBaseFileName=/cmd\.exe/i |in(field="CommandLine", values=["*/c*del*/f*/q*/s*","*%USERPROFILE%*"])|Analysis:="Windows destructive command";
      in(field="ParentBaseFileName", values=["npm.exe", "npm", "pnpm.exe", "pnpm"]) | CommandLine ="*setup_bun.js*" |Analysis:="Detect initial execution via npm preinstall script"
}
|$ProcessTree2()
|case{
  event_platform=/win/iF #event_simpleName=ProcessRollup2 ParentBaseFileName=/cmd\.exe/i ComputerName=/^PHISPCTXDA/iF |in(field="CommandLine", values=["*/S *"],ignoreCase=true) |Exception:="Yes";
  ProcessTree=/QualysAgent.exe|ADDMRemQuery_x86_64_v2.exe/iF |Exception:="Yes";
  *|Exception:="No";
}|Exception="No"
|groupBy([Analysis,ProcessTree,CommandLineTree,SHA256HashData],function=collect([ComputerName]))
|select([Analysis,ComputerName,ProcessTree,CommandLineTree,SHA256HashData])
```
