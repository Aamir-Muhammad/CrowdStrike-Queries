// https://www.huntress.com/blog/unpatched-ntlm-leak-windows-search-uri-handler
// Auther= Aamir Muhammad
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(?<scheme>search(-ms)?:).*crumb=location:(?<uncTarget>(\\\\|%5c%5c)[^\s"&]+)/iF
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, scheme, uncTarget, CommandLine])