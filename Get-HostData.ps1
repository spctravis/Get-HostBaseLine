Function Get-HostData 
{ 
<# 
.SYNOPSIS 
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
                                     
   
.Notes 
LastModified: 9/5/2018 
Author:       Travis Anderson 
 
     
#> 
#------------------Set Each List to Null----------------------#
$hostdata = $null
$InfoList = $null
$ServiceList = $null
$ProcessList = $null
$TCPNetConnectionList = $null
$UDPNetConnectionList = $null
$BiosInfoList = $null
#------------------Declare Each List--------------------------#
$InfoList = New-Object System.Collections.Generic.List[System.Object]
$ServiceList = New-Object System.Collections.Generic.List[System.Object]
$ProcessList = New-Object System.Collections.Generic.List[System.Object]
$TCPNetConnectionList = New-Object System.Collections.Generic.List[System.Object]
$UDPNetConnectionList = New-Object System.Collections.Generic.List[System.Object]
$BiosInfoList = New-Object System.Collections.Generic.List[System.Object]
#------------------Basic Computer Info------------------------#
    
    $props = @{
        ComputerName = $env:COMPUTERNAME
        OperatingSystem = (Get-WmiObject -Class win32_OperatingSystem).Version
        HotFix = (Get-HotFix).HotFixID
        Domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
        PSVersion = $PSVersionTable
        NetAdapter = Get-NetAdapter
        LogicalDisks = (Get-CimInstance -ClassName Win32_LogicalDisk)
        SMBShares = Get-SmbShare
        USBHistory = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | select friendlyname, serial
        # Drivers = Get-WindowsDriver -online -all -ErrorAction SilentlyContinue
        ActiveUsers =  (Get-CimInstance Win32_LoggedOnUser -ComputerName $ComputerName).antecedent.name | Select-Object -Unique
        NetworkInfo = Get-NetIPConfiguration
        Route = Get-NetRoute
        ScheduledTasks = Get-ScheduledTask
        AntiVirus = (Get-WmiObject -Namespace "root\SecurityCenter2" -query "SELECT * FROM AntiVirusProduct").displayname
        SDCVersion = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation).model
        InstalledPrograms =  Get-WmiObject -class win32_product | select Name,Version,InstallDate,InstallDate2,InstallLocation,InstallSource,Path,Vendor -ErrorAction SilentlyContinue
        DateTimeRan = (Get-Date).ToString("yyyyMMddThhmmssmsmsZ")
               }
    $InfoObject = New-Object -TypeName PSCustomObject -Property $props
    $InfoList.add($InfoObject)

#------------------Iterate Through Each Commandlet------------#

Foreach ($Service in Get-Service) {
    $props = @{
        Name = $Service.ServiceName
        Status = $Service.Status
        StartType = $Service.StartType
               }
    $ServiceObject = New-Object -TypeName PSCustomObject -Property $props
    $ServiceList.add($ServiceObject)
     } # End Service Foreach

$getprocess = Get-Process
Foreach ($Process in $getprocess) {
    if($process.path){
    $hash = Get-FileHash -Path $Process.Path -Algorithm SHA1 -ErrorAction SilentlyContinue}
    $props = @{
        Name = $Process.ProcessName
        PID = $Process.Id
        Path = $Process.Path
        Company = $Process.Company
        Product = $Process.Product
        Modules = $Process.Modules
        StartTime = $Process.StartTime
        ProcessHash = $Hash.hash
        HashAlgorithm = $Hash.Algorithm
               } 
    $ProcessObject = New-Object -TypeName PSCustomObject -Property $props -ErrorAction SilentlyContinue
    $ProcessList.add($ProcessObject)
    }  # End Process Foreach

 Foreach ($NetConnection in Get-NetTCPConnection) { 
     $props = @{
        State = $NetConnection.State
        LocalAddress = $NetConnection.LocalAddress
        LocalPort = $NetConnection.LocalPort
        OwningProcess = $NetConnection.OwningProcess
        OwningProcessName = (Get-Process -ID $NetConnection.OwningProcess).Name
        RemoteAddress = $NetConnection.RemoteAddress
        RemotePort = $NetConnection.RemotePort
               }
    $NetConnectionObject = New-Object -TypeName PSCustomObject -Property $props
    $TCPNetConnectionList.add($NetConnectionObject)
     } # End NetConnection Foreach

 Foreach ($NetConnection in Get-NetUDPEndpoint) { 
     $props = @{
        LocalAddress = $NetConnection.LocalAddress
        LocalPort = $NetConnection.LocalPort
        OwningProcess = $NetConnection.OwningProcess
        OwningProcessName = (Get-Process -ID $NetConnection.OwningProcess).Name
               }
    $NetConnectionObject = New-Object -TypeName PSCustomObject -Property $props
    $UDPNetConnectionList.add($NetConnectionObject)
     } # End NetConnection Foreach

$BiosInfo = Get-CimInstance -ClassName Win32_BIOS
    $props = @{
        Name = $BiosInfo.SMBIOSBIOSVersion
        Manufacturer = $BiosInfo.Manufacturer
        SerialNumber = $BiosInfo.SerialNumber
        Version = $BiosInfo.Version
               }
    $BiosInfoObject = New-Object -TypeName PSCustomObject -Property $props
    $BiosInfoList.add($BiosInfoObject)

#------------------Add Object Properties-----------------------#
$hostdata = New-Object -TypeName pscustomobject 
        $hostdata | Add-Member -name ComputerInfo -MemberType NoteProperty -Value $InfoList
        $hostdata | Add-Member -Name Services -MemberType NoteProperty -Value $ServiceList
        $hostdata | Add-Member -Name Processes -MemberType NoteProperty -Value $ProcessList
        $hostdata | Add-Member -Name TCPNetConnections -MemberType NoteProperty -Value $TCPNetConnectionList
        $hostdata | Add-Member -Name UDPNetConnections -MemberType NoteProperty -Value $UDPNetConnectionList
        $hostdata | Add-Member -Name BIOsInfo -MemberType NoteProperty -Value $BiosInfoList
return $hostdata
} # End of Function Get-HostData 