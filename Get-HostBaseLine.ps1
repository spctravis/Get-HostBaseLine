Function Get-HostBaseLine
{ 
<# 
.SYNOPSIS 
    This function will bring back a single object of a number of host command-lets. 
 
.DESCRIPTION 
     This function gets processes, services, BIOs info, networking info, and basic computer info.  The function can run against local or remote machines. 
 
.PARAMETER  N/A 
    None at this time
 
.EXAMPLE 
    PS C:\>$hostdata = Get-GetHostBaseLine
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
                                     
   
.Notes 
LastModified: 9/21/2018 
Author:       Travis Anderson 
              Richard Hailey (Get-Netstat)
 
     
#> 
#------------------Set Each List to Null----------------------#
$HostKey = $null
$hostdata = $null
$InfoList = $null
$ServiceList = $null
$ProcessList = $null
$netstat = $null
$BiosInfoList = $null
#------------------Declare Each List--------------------------#
$HostKeyList =          New-Object System.Collections.Generic.List[System.Object]
$InfoList =             New-Object System.Collections.Generic.List[System.Object]
$ServiceList =          New-Object System.Collections.Generic.List[System.Object]
$ProcessList =          New-Object System.Collections.Generic.List[System.Object]
$BiosInfoList =         New-Object System.Collections.Generic.List[System.Object]
$NetworkList =          New-Object System.Collections.Generic.List[System.Object]
#------------------Tracking Key-------------------------------#
    $props = $null
    $props = @{}
    $props = @{
        HostFQDN = Get-WmiObject Win32_ComputerSystem -Property 'Name','Domain' | ForEach-Object {"$($_.Name).$($_.Domain)"}
        DateTimeRan = (Get-Date).ToString("yyyyMMddThhmmssmsmsZ")
                       }
           #Takes out nulls from props
           $notnullarray = $props.GetEnumerator() | where value -ne $null
           $notnullhash = @{}
           $notnullarray | foreach { $notnullhash[$_.Key] = $_.Value }
   
    $InfoObject = New-Object -TypeName PSCustomObject -Property $notnullhash
    $HostKeyList.add($InfoObject)


#------------------Basic Computer Info------------------------#
    $props = $null
    $props = @{}    
    $props = @{
        ComputerName = $env:COMPUTERNAME
        OperatingSystem = (Get-WmiObject -Class win32_OperatingSystem).Version
        HotFix = (Get-HotFix).HotFixID 
        PSVersion = $PSVersionTable        
        LogicalDisks = (Get-WmiObject -Class Win32_LogicalDisk)        
        USBHistory = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* -ErrorAction SilentlyContinue | select friendlyname, serial
        # Drivers = Get-WindowsDriver -online -all -ErrorAction SilentlyContinue
        ActiveUsers =  (Get-WmiObject Win32_LoggedOnUser -ComputerName $env:COMPUTERNAME).antecedent.name | Select-Object -Unique
        ScheduledTasks = Get-ScheduledTask
        AntiVirus = (Get-WmiObject -Namespace "root\SecurityCenter2" -query "SELECT * FROM AntiVirusProduct").displayname
        SDCVersion = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation).model
        InstalledPrograms =  Get-WmiObject -class win32_product | select Name,Version,InstallDate,InstallDate2,InstallLocation,InstallSource,Path,Vendor -ErrorAction SilentlyContinue
               } # end of props
           #Takes out nulls from props
           $notnullarray = $props.GetEnumerator() | where value -ne $null
           $notnullhash = @{}
           $notnullarray | foreach { $notnullhash[$_.Key] = $_.Value }
   
    $InfoObject = New-Object -TypeName PSCustomObject -Property $notnullhash
    $InfoList.add($InfoObject)
#------------------Networking Info-------------------------------#
    $props = $null
    $props = @{}
    $props = @{
        SMBShares = if (Get-Command Get-SmbShare) {
                        Get-SmbShare
                        } else {
                        Get-WmiObject -Class win32_share
                        }
        NetworkInfo = Get-NetIPConfiguration
        Domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        Route = Get-NetRoute
        DNSCache = Get-DnsClientCache
        NetAdapter = if (Get-Command Get-NetAdapter) {
                        Get-NetAdapter
                        } else {
                        Get-WmiObject -Class win32_networkadapter
                        }
                } #end of props
           #Takes out nulls from props
           $notnullarray = $props.GetEnumerator() | where value -ne $null
           $notnullhash = @{}
           $notnullarray | foreach { $notnullhash[$_.Key] = $_.Value }
   
    $InfoObject = New-Object -TypeName PSCustomObject -Property $notnullhash
    $NetworkList.add($InfoObject)

#------------------Iterate Through Each Commandlet------------#

Foreach ($Service in Get-Service) {
    $props = @{
        Name = $Service.ServiceName
        Status = $Service.Status
        StartType = $Service.StartType
               } # end of props
           #Takes out nulls from props
           $notnullarray = $props.GetEnumerator() | where value -ne $null
           $notnullhash = @{}
           $notnullarray | foreach { $notnullhash[$_.Key] = $_.Value }
    $ServiceObject = New-Object -TypeName PSCustomObject -Property $notnullhash
    $ServiceList.add($ServiceObject)
     } # End Service Foreach
$getmodule = Get-WmiObject -Class cim_processexecutable -Namespace root\cimv2
$getprocess = Get-WmiObject Win32_Process
Foreach ($Process in $getprocess) {
    if($process.ExecutablePath){
    $hash = Get-FileHash -Path $Process.ExecutablePath -Algorithm SHA1 -ErrorAction SilentlyContinue}
    $props = @{
        Name = $Process.ProcessName
        PID = $Process.ProcessId
        Path = $Process.ExecutablePath
        Company = $Process.Company
        Product = $Process.Product
        Modules = $Process.Modules
        StartTime = $Process.CreationDate 
        Commandline = $Process.CommandLine
        ProcessHash = $Hash.hash
        HashAlgorithm = $Hash.Algorithm
               } # end of props
           #Takes out nulls $from props
           $notnullarray = $props.GetEnumerator() | where value -ne $null
           $notnullhash = @{}
           $notnullarray | foreach { $notnullhash[$_.Key] = $_.Value }
    $ProcessObject = New-Object -TypeName PSCustomObject -Property $notnullhash
    $ProcessList.add($ProcessObject)
    }  # End Process Foreach
function Get-Netstat 
{              
<# 
.SYNOPSIS 
    This function uses the netstat command to get networking info. 
 
.DESCRIPTION 
     This function uses nestat -ano and uses REGEX to make the info objects.  The function can run against local or remote machines. 
 
.PARAMETER  N/A 
    None at this time
 
.EXAMPLE 
    PS C:\>$netstat = Get-Netstat
    PS C:\>$netstat  
         
Protocol          : TCP
LocalAddress      : [::]
LocalPort         : 49668
RemoteAddress     : [::]
RemotePort        : 0
State             : LISTENING
OwningProcess     : 888
ComputerName      : JEGWL-COS013
ProcessName       : lsass.exe
ParentProcessID   : 724
ParentProcessName : wininit.exe
                                     
   
.Notes 
LastModified: 9/21/2018 
Author:       Richard Hailey

Modified By:  Travis Anderson
 
     
#>

    $Netstat = & netstat -ano #Runs the Netstat command
    $Netstat = $Netstat[4..($Netstat.Length - 1)] #Removes the Header Info
    $ProcessList = $getprocess #Gets Processes

#------------------REGEX the TCP and UDP Connections----------#
    [regex]$TCP = '(?<Protocol>\S+)\s+(?<LAddress>\S+):(?<LPort>\S+)\s+(?<RAddress>\S+):(?<RPort>\S+)\s+(?<State>\S+)\s+(?<PID>\S+)'
    [regex]$UDP = '(?<Protocol>\S+)\s+(?<LAddress>\S+):(?<LPort>\S+)\s+(?<RAddress>\S+):(?<RPort>\S+)\s+(?<PID>\S+)'
#------------------Set up List and start Foreach Object Def---#
    $Return = New-Object 'System.Collections.Generic.List[System.Object]'

    foreach($Line in $Netstat)
    {
        $Obj = New-Object PSCustomObject
        switch -Regex ($Line.Trim())
        {
            $TCP
            {
                $Obj | Add-Member -MemberType NoteProperty -Name Protocol      -Value $Matches.Protocol
                $Obj | Add-Member -MemberType NoteProperty -Name LocalAddress  -Value $Matches.LAddress
                $Obj | Add-Member -MemberType NoteProperty -Name LocalPort     -Value $Matches.LPort
                $Obj | Add-Member -MemberType NoteProperty -Name RemoteAddress -Value $Matches.RAddress
                $Obj | Add-Member -MemberType NoteProperty -Name RemotePort    -Value $Matches.RPort
                $Obj | Add-Member -MemberType NoteProperty -Name State         -Value $Matches.State
                $Obj | Add-Member -MemberType NoteProperty -Name OwningProcess -Value $Matches.PID
                $Obj | Add-Member -MemberType NoteProperty -Name ComputerName  -Value $env:COMPUTERNAME
                foreach($I in $ProcessList)
                    {
                    if ($Obj.owningprocess -eq $I.ProcessId)
                        {
                            $Obj | Add-Member -MemberType NoteProperty -Name ProcessName -Value $I.Name
                            $Obj | Add-Member -MemberType NoteProperty -Name ParentProcessID -Value $I.ParentProcessID
                                foreach($B in $ProcessList)
                                    {
                                    if ($I.ParentProcessId -eq $B.ProcessId)
                                        {
                                        $Obj | Add-Member -MemberType NoteProperty -Name ParentProcessName -Value $B.Name
                                        }
                                        continue
                                   } #End Foreach on Parent Process Name 
                            continue
                        }
                    } #End Foreach For Adding Values to TCP                
                continue
            } #End TCP Values
            
            $UDP
            {
                $Obj | Add-Member -MemberType NoteProperty -Name Protocol      -Value $Matches.Protocol
                $Obj | Add-Member -MemberType NoteProperty -Name LocalAddress  -Value $Matches.LAddress
                $Obj | Add-Member -MemberType NoteProperty -Name LocalPort     -Value $Matches.LPort
                $Obj | Add-Member -MemberType NoteProperty -Name RemoteAddress -Value $Matches.RAddress
                $Obj | Add-Member -MemberType NoteProperty -Name RemotePort    -Value $Matches.RPort
                $Obj | Add-Member -MemberType NoteProperty -Name State         -Value $Matches.State
                $Obj | Add-Member -MemberType NoteProperty -Name OwningProcess -Value $Matches.PID
                $Obj | Add-Member -MemberType NoteProperty -Name ComputerName  -Value $env:COMPUTERNAME
                foreach($I in $ProcessList)
                    {
                    if ($Obj.owningprocess -eq $I.ProcessId)
                        {
                            $Obj | Add-Member -MemberType NoteProperty -Name ProcessName -Value $I.Name
                            $Obj | Add-Member -MemberType NoteProperty -Name ParentProcessID -Value $I.ParentProcessID
                                 foreach($B in $ProcessList)
                                    {
                                    if ($I.ParentProcessId -eq $B.ProcessId)
                                        {
                                        $Obj | Add-Member -MemberType NoteProperty -Name ParentProcessName -Value $B.Name
                                        }
                                        continue
                                     }#End Foreach on Parent Process Name
                            continue
                        }
                    }#End Foreach For Adding Values to UDP
                continue
            } #End UDP Values
        }
        $Return.Add($Obj)
    }
    return $Return
} #End Get-NetStat function
$netstat = Get-Netstat

$BiosInfo = Get-WmiObject -Class Win32_BIOS
    $props = @{
        Name = $BiosInfo.SMBIOSBIOSVersion
        Manufacturer = $BiosInfo.Manufacturer
        SerialNumber = $BiosInfo.SerialNumber
        Version = $BiosInfo.Version
               } #end of props
           #Takes out nulls from props
           $notnullarray = $props.GetEnumerator() | where value -ne $null
           $notnullhash = @{}
           $notnullarray | foreach { $notnullhash[$_.Key] = $_.Value }
    $BiosInfoObject = New-Object -TypeName PSCustomObject -Property $notnullhash
    $BiosInfoList.add($BiosInfoObject)

#------------------Add Object Properties-----------------------#
$hostdata = New-Object -TypeName pscustomobject 
        $hostdata | Add-Member -Name HostKey -MemberType NoteProperty -Value $HostKeyList
        $hostdata | Add-Member -name ComputerInfo -MemberType NoteProperty -Value $InfoList
        $hostdata | Add-Member -name NetworkInfo -MemberType NoteProperty -Value $NetworkList
        $hostdata | Add-Member -Name Services -MemberType NoteProperty -Value $ServiceList
        $hostdata | Add-Member -Name Processes -MemberType NoteProperty -Value $ProcessList
        $hostdata | Add-Member -Name Netstat -MemberType NoteProperty -Value $netstat
        $hostdata | Add-Member -Name BIOsInfo -MemberType NoteProperty -Value $BiosInfoList
return $hostdata
} # End of Function Get-HostBaseLine
