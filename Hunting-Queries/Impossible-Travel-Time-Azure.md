Tracing Logins from two different countries with impossible travel times between consecutive logins per identity
```
in(field="#event_simpleName", values=[SsoApplicationAccess,SsoUserLogon])
//Excluding Mobile Devices since VPN is widely used on mobile devices
| ClientUserAgentString!=/ios /i and ClientUserAgentString!=/Safari/i and ClientUserAgentString!=/Android/i
//Exclude your proxy's cloud CIDR (if any)
| !cidr(SourceEndpointAddressIP4, subnet=["0.0.0.0/16"])
//Concatinate the IP4 and IP6 Sources IP addresses into single varibale
| SourceIP:=concat([SourceEndpointAddressIP4, SourceEndpointAddressIP6])
// Create UserName + SourceAccountAzureId Hash for sequencing of events
| UserHash:=concat([SourceAccountUserName, SourceAccountAzureId]) | UserHash:=crypto:md5([UserHash])
// Populating the emptied Hostname with Unregistered Device tag
|case{
   SourceEndpointHostName="" | SourceEndpointHostName:="{Unregistered Device}" ;
*;
}
// Perform initial aggregation; groupBy() will sort by UserHash then ContextTimeStamp
| groupBy([UserHash, ContextTimeStamp], function=[collect([SourceAccountUserName, SourceAccountAzureId, SourceIP, SourceEndpointHostName,ISPDomain,ClientUserAgentString,SourceEndpointHostName])], limit=max)
// Get geoIP for Remote IP
| ipLocation(SourceIP)
// Use new neighbor() function to get results for previous row
| neighbor([ContextTimeStamp, SourceIP,ISPDomain, UserHash, SourceIP.country, SourceIP.lat, SourceIP.lon, SourceEndpointHostName,ClientUserAgentString,SourceEndpointHostName], prefix=prev)
// Make sure neighbor() sequence do correlate same users only, might occur at the end of a sequence
| test(UserHash==prev.UserHash)
// Known Exception for Accounts in your environment for particular country
| SourceAccountUserName!=mr.example@corporate.com AND (prev.SourceIP.country!=PK OR SourceIP.country!=PK)
// Calculate login time delta in milliseconds from LogonTime to prev.LogonTime and round it off
| LogonDelta:=(ContextTimeStamp-prev.ContextTimeStamp)*1000
| LogonDelta:=round(LogonDelta)
// Turn logon time delta from milliseconds to human readable format
| TimeToTravel:=formatDuration(LogonDelta, precision=2)
// Calculate distance between Login 1 and Login 2
| DistanceKm:=(geography:distance(lat1="SourceIP.lat", lat2="prev.SourceIP.lat", lon1="SourceIP.lon", lon2="prev.SourceIP.lon"))/1000 | DistanceKm:=round(DistanceKm)
// Calculate speed required to get from Login 1 to Login 2
| SpeedKph:=DistanceKm/(LogonDelta/1000/60/60) | SpeedKph:=round(SpeedKph)
// SETING LOGIC THRESHOLD: MAXIMUM Speed used by Commercial Passenger aircraft is 900KM/h OR 0.9 MACH
| test(SpeedKph>900)
// Exclude Same Country travel
| test(SourceIP.country!=prev.SourceIP.country)
// Format LogonTime Values
| ContextTimeStamp:=ContextTimeStamp*1000           | formatTime(format="%e %b %Y %r %Z", as="ContextTimeStamp", field="ContextTimeStamp", locale=en_UAE, timezone="Asia/Dubai")
| prev.ContextTimeStamp:=prev.ContextTimeStamp*1000 | formatTime(format="%e %b %Y %r %Z", as="prev.ContextTimeStamp", field="prev.ContextTimeStamp", locale=en_UAE, timezone="Asia/Dubai")
// Beautification / Differential Analysis
| Travel:=format(format="%s → %s", field=[prev.SourceIP.country, SourceIP.country])
| IPs:=format(format="%s  → %s\n%s  → %s", field=[prev.SourceIP,SourceIP,prev.ISPDomain,ISPDomain])
| Logons:=format(format="%s → %s", field=[prev.ContextTimeStamp, ContextTimeStamp])
| UserAgent:=format(format="%s → %s", field=[prev.ClientUserAgentString, ClientUserAgentString])
| RegisteredDeviceName:=format(format="%s → %s", field=[prev.SourceEndpointHostName, SourceEndpointHostName])
// Output results to table and sort by highest speed
| table([SourceAccountUserName,RegisteredDeviceName, SourceAccountAzureId, Travel,UserAgent, IPs, TimeToTravel, DistanceKm, Logons, SpeedKph], limit=20000, sortby=DistanceKm, order=desc)
// Express SpeedKph as a value of MACH
| Mach:=SpeedKph/1234 | Mach:=round(Mach)
| Speed:=format(format="MACH %s", field=[Mach])
// Format distance and speed fields to include comma and unit of measure
| format("%,.0f km",field=["DistanceKm"], as="DistanceKm")
| format("%,.0f km/h",field=["SpeedKph"], as="SpeedKm/h")
| sort(SpeedKph)
// Drop unwanted fields
| drop([Mach,SpeedKph])
