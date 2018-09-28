$hostfile = "C:\Users\Twitchy\Documents\WorkingDir\Hosts.txt"
if (!$cred) { # checks if credentials need to be obtained
$cred = Get-Credential 
            } # end looking for $cred 
$hosts = Get-Content $hostfile
$opensessions = Get-PSSession
$hosts | ForEach-Object { if ($opensessions.computername -notcontains $_)
        {
    New-PSSession -ComputerName $_ -Credential $cred
        }       
            elseif ($opensessions.state -eq "broken") 
                        {
                $opensessions | where state -eq broken | Remove-PSSession
                        }
            elseif ($opensessions.state -eq "Disconnected")
                         {
                $opensessions | where state -eq Disconnected | Remove-PSSession
                           }
                        } # End foreach
$checksession = Get-PSSession
$hosts | ForEach-Object { if ($checksession.computername -notcontains $_)
        {
    New-PSSession -ComputerName $_ -Credential $cred
        }
        } # End foreach for the checksession
$session = Get-PSSession
write-host "Connected with the following computers:" 
$session | ft computername,id
