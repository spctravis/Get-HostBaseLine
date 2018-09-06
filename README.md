# Get-HostData
 This function will bring back a single object of a number of host command-lets.
 
.DESCRIPTION 
     This function gets processes, services, BIOs info, networking info, and basic computer info.  The function can run against local or remote machines. 
 
.PARAMETER  N/A 
    None at this time
 
.EXAMPLE 
    PS C:\>$hostdata = Get-GetHostData
    PS C:\>$hostdata  
         
ComputerInfo : Netadaptor, Computername, etc
Services : All services
Processes  :  All Processes
NetConnections : All Network Connections
BIOsInfo : All BIOs Data

    PS C:\>$hostdata.Processes.Name

AGSService
ApplicationFrameHost
audiodg
AuditManagerService
Calculator
               
