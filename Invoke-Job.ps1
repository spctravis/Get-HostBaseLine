
#Sets date format
$date = Get-Date -Format "MMddyyyyTHHmmss"

#Set Job Name here, uses date by default
$JobName = $date

#Pushes you command into remote systems. Only change the scriptblock ${function:Please-CHANGEME}
$AsJob = Invoke-Command -Session $session -ScriptBlock ${function:get-hostbaseline} -JobName $JobName -AsJob # -ErrorAction SilentlyContinue

$AsJob | wait-job 

$returndata = $AsJob | Receive-Job 