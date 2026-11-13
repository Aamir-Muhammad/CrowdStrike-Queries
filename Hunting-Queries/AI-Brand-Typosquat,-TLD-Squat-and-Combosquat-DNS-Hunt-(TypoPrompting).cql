// AI Brand Typosquat, TLD-Squat and Combosquat DNS Hunt (TypoPrompting)
// Source: https://www.island.io/blog/typoprompting-from-ai-typos-to-malware
// Author: Aamir Muhammad
#event_simpleName = DnsRequest
| Host := lower(DomainName)
| Host = /(?<base_label>[-a-z0-9]+)\.(?<tld>(?:(?:co|com|net|org|ai|gov|icu)\.)?[a-z]{2,24})$/
| RegDomain := format("%s.%s", field=[base_label, tld])
// Allowlist - official AI provider domains, extend with your sanctioned tools
| RegDomain != /^(claude\.ai|claude\.com|anthropic\.com|claudeusercontent\.com|chatgpt\.com|clau\.de|split\.io|deepseeksvc\.com|pilot\.com|opera\.software|opera\.com|openx\.net|cloud\.us|cludo\.com|copilot\.fun|cloud\.sap|cloud\.com|cloud\.run|openai\.com|cloud\.microsoft|chat\.com|oaistatic\.com|oaiusercontent\.com|sora\.com|deepseek\.com|google\.com|gemini\.com|gemini\.google|notebooklm\.google|perplexity\.ai|perplexity\.com|pplx\.ai|grok\.com|x\.ai|groq\.com|microsoft\.com|githubcopilot\.com|copilot\.com|mistral\.ai|midjourney\.com|elevenlabs\.io|cursor\.com|cursor\.sh|lovable\.dev|lovable\.app|character\.ai|runwayml\.com|manus\.im|suno\.com|suno\.ai|klingai\.com|hailuoai\.com|hailuo\.ai|heygen\.com|leonardo\.ai|huggingface\.co|hf\.co|synthesia\.io|qwen\.ai|kimi\.com|kimi\.ai|moonshot\.cn|windsurf\.com|replit\.com|pollo\.ai|viggle\.ai|monica\.im|speechma\.com)$/F
// Aggregate first - edit distance runs once per unique domain, not per DNS event
| groupBy([RegDomain, base_label, tld], function=[count(ComputerName, distinct=true, as=HostCount), count(as=QueryCount), min(@timestamp, as=FirstSeenEpoch), collect([ComputerName, DomainName], limit=200000)], limit=max)
| text:editDistanceAsArray(target=base_label, references=["claude","anthropic","chatgpt","openai","deepseek","gemini","perplexity","copilot","midjourney","elevenlabs","notebooklm","huggingface","synthesia","heygen","hailuo","klingai","runwayml","speechma","viggle","replit","character","cursor","runway","lovable","mistral","manus","kling","pollo","monica","sora","suno","grok","kimi","qwen","leonardo","windsurf"], maxDistance=4, ignoreCase=true)
| split(_distance)
| case {
    _distance.reference = "claude" RegDomain = /^(cloude\.ai|clsude\.ai|caude\.ai|cluade\.ai|claudie\.ai|ckaude\.ai|deepceek\.com|copiot\.com|elevenlebs\.io|vocie\.ai|perplixity\.ai|perplexty\.ai|perplecity\.ai|preplexity\.ai|hailou\.ai|haiulo\.ai|hygen\.ai|viggie\.ai|kiling\.ai|klig\.ai|klign\.ai|chatlgpt\.com|midj0urney\.org|deepsek\.icu|maccl0ude\.com|securetrackingnode\.com|biomimicrydevtech\.buzz|blockchainfuturedev\.buzz|a11\.click|deezyj\.com|netguardsite\.com|netguardprotect\.com|quickflashtool\.com|flashysearches\.com)$/F
        | HuntLogic := "TypoPrompting_IOC_Domain_Match"
        | SeverityTier := "Critical"
        | HuntObject := format("%s", field=[RegDomain]);
    _distance.reference = /^(character|cursor|runway|lovable|mistral|manus|kling|pollo|monica|sora|suno|grok|kimi|qwen|leonardo|windsurf)$/ tld = /^(ai|chat|app|dev|im|io|bot|so|icu|buzz|click|xyz|top|online|site)$/ _distance.distance < 2
        | HuntLogic := "AI_Brand_Typosquat_Generic_Name_AI_TLD"
        | SeverityTier := "High"
        | HuntObject := format("%s ~ %s (distance %s)", field=[RegDomain, _distance.reference, _distance.distance]);
    _distance.reference != /^(character|cursor|runway|lovable|mistral|manus|kling|pollo|monica|sora|suno|grok|kimi|qwen|leonardo|windsurf)$/ _distance.distance < 1
        | HuntLogic := "AI_Brand_TLD_Squat"
        | SeverityTier := "Medium"
        | HuntObject := format("%s ~ %s (distance %s)", field=[RegDomain, _distance.reference, _distance.distance]);
    _distance.reference = /^(perplexity|midjourney|elevenlabs|notebooklm|huggingface)$/ _distance.distance < 3
        | HuntLogic := "AI_Brand_Typosquat"
        | SeverityTier := "High"
        | HuntObject := format("%s ~ %s (distance %s)", field=[RegDomain, _distance.reference, _distance.distance]);
    _distance.reference != /^(character|cursor|runway|lovable|mistral|manus|kling|pollo|monica|sora|suno|grok|kimi|qwen|leonardo|windsurf)$/ _distance.distance < 2
        | HuntLogic := "AI_Brand_Typosquat"
        | SeverityTier := "High"
        | HuntObject := format("%s ~ %s (distance %s)", field=[RegDomain, _distance.reference, _distance.distance]);
    _distance.reference = /^(perplexity|midjourney|elevenlabs|notebooklm|huggingface)$/ _distance.distance < 4
        | HuntLogic := "AI_Brand_Typosquat_Loose"
        | SeverityTier := "Medium"
        | HuntObject := format("%s ~ %s (distance %s)", field=[RegDomain, _distance.reference, _distance.distance]);
    _distance.reference != /^(character|cursor|runway|lovable|mistral|manus|kling|pollo|monica|sora|suno|grok|kimi|qwen|leonardo|windsurf)$/ _distance.distance < 3
        | HuntLogic := "AI_Brand_Typosquat_Loose"
        | SeverityTier := "Medium"
        | HuntObject := format("%s ~ %s (distance %s)", field=[RegDomain, _distance.reference, _distance.distance]);
    _distance.reference = "claude" base_label = /cl[a0o]ude|anthropi[cv]|ch[a4]t-?gpt|open-?[a4]i|deeps[e3]{2}k|perplexity|midjourney|elevenlabs|notebooklm|huggingface/F
        | HuntLogic := "AI_Brand_Combosquat"
        | SeverityTier := "Medium"
        | HuntObject := format("%s", field=[RegDomain]);
  }
| groupBy([RegDomain, HuntLogic, SeverityTier, HuntObject], function=[selectLast([HostCount, QueryCount, FirstSeenEpoch, ComputerName, DomainName])], limit=max)
| HostCount <101
| FirstSeen := formatTime(format="%e %b %Y %r", field=FirstSeenEpoch, locale=en_UAE, timezone="Asia/Dubai")
| format("[%s](https://www.virustotal.com/gui/search/%s)", field=[RegDomain,RegDomain], as="RegDomain")
| drop([rootURL])
| sort(SeverityTier, order=asc, limit=max)
| select([FirstSeen, RegDomain, HuntLogic, SeverityTier, HuntObject, HostCount, QueryCount, ComputerName, DomainName])
