###Global parameters for Get-Response script stored below:###
param (
    ###Mandatory Computer Parameter###
    [Parameter(Mandatory=$true,Position=0)]
    [string]
    $ComputerName,

    ###Optional WinEvent Parameter used to collect windows Event logs###
    [Parameter(Mandatory=$false,Position=1)]
    [switch]
    $WinEvent,

    ###Optional ScheduleTask parameter used to collect scheduled tasks###
    [Parameter(Mandatory=$false,Position=2)]
    [switch]
    $ScheduleTask
    )

###check the connectivity to the remote computer###
Write-Host "Checking to see if $ComputerName is online. `n"
###If the ping fails end script###
if (-not (Test-Connection $ComputerName -Quiet)){
    Clear-Host
    Write-Host -foregroundcolor red "$ComputerName appears to be offline."
    break
    }

###Begin the stopwatch to time the script.###
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

###Global variables###
###get date for file creation###
$date = Get-Date -Format yyyyMMdd
###End global variables###

###Search if computer has been the subject of previous incident response cases.###
$fileExist = Get-ChildItem -Path C:\Temp\IncidentResponse -Recurse -Directory -Filter "${ComputerName}" | Select-Object -ExpandProperty FullName
    if ($fileExist -ne $null){
        Write-Host `n `t -ForegroundColor Red "Incident response script previously ran on host! See directory[s] below for more information:" `n
            foreach ($file in $fileExist){
                write-Host `t `t -ForegroundColor Yellow $file
            }
    }

###make local directories for target computer###
if((Test-Path C:\Temp\IncidentResponse\${date}) -eq $true) {
    Write-Host `t -ForegroundColor DarkGreen "C:\Temp\IncidentResponse\${date} already exist on ${env:COMPUTERNAME}." `n
    }
    else{
        Write-Host `t -ForegroundColor Yellow "Creating C:\Temp\IncidentResponse\${date} on ${env:COMPUTERNAME}." `n
        New-Item -Path C:\Temp\IncidentResponse -Name ${date} -ItemType Directory | Out-Null
        }
if((Test-Path C:\Temp\IncidentResponse\${date}\${ComputerName}) -eq $true) {
    Write-Host `t -ForegroundColor DarkGreen "C:\Temp\IncidentResponse\${date}\${ComputerName} already exist on ${env:COMPUTERNAME}." `n
    }
    else{
        Write-Host `t -ForegroundColor Yellow "Creating C:\Temp\IncidentResponse\${date}\${ComputerName} on ${env:COMPUTERNAME}." `n
        New-Item -Path C:\Temp\IncidentResponse\${date} -Name ${ComputerName} -ItemType Directory | Out-Null
        }


###Create PSDrive for target computer###
New-PSDrive -Name $ComputerName -PSProvider FileSystem -Root \\$ComputerName\c$ | Out-Null

###Test if target file directories exist###
    if ((Test-Path ${ComputerName}:\temp) -eq $true){
            Write-Host `t -ForegroundColor DarkGreen "C:\temp\ directory already exist on ${ComputerName}." `n
            }
                else{
                    Write-Host `t -ForegroundColor Yellow "Creating C:\temp directory on ${ComputerName}." `n
                    New-Item -Path ${ComputerName}:\ -Name temp -ItemType Directory -Force | Out-Null
                    }

    if ((Test-Path ${ComputerName}:\temp\${ComputerName}) -eq $true){
        Write-Host `t -ForegroundColor DarkGreen "C:\temp\${ComputerName} directory already exist on ${ComputerName}." `n
        }
            else{
                Write-Host `t -ForegroundColor Yellow "Creating C:\temp\${ComputerName} directory on ${ComputerName}." `n
                New-Item -Path ${ComputerName}:\temp\ -Name ${ComputerName} -ItemType Directory -Force | Out-Null
                }

###General Host Information###
function HostInfo{
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        ###Get computer info and export to text file###
        Write-Output -InputObject "Date/Time collected: $(get-date)" | Out-File C:\Temp\${env:COMPUTERNAME}\computerinfo.txt  
        Write-Output -InputObject "`n Currently Logged in user(s): "| Out-File C:\Temp\${env:COMPUTERNAME}\computerinfo.txt -Append
        quser | Out-File C:\Temp\${env:COMPUTERNAME}\computerinfo.txt -Append
        Write-Output -InputObject "`nGeneral computer information:" | Out-File C:\Temp\${env:COMPUTERNAME}\computerinfo.txt -Append
        Get-ComputerInfo | Out-File C:\Temp\${env:COMPUTERNAME}\computerinfo.txt -Append
        ###End get computer information###

        ###Get hotfix (KB's) information and export to CSV###
        Get-HotFix | Select-Object -Property HotFixID, Description, InstalledBy, InstalledOn, Caption | Export-Csv -Path c:\temp\${env:COMPUTERNAME}\hotfix.csv -NoTypeInformation
        ###End get hotfixes###

        ###Get local users created on the system###
        Get-LocalUser | Select-Object -Property * | Export-Csv -Path C:\Temp\${env:COMPUTERNAME}\LocalUsers.csv -NoTypeInformation
        ###End get local users###
        
        ###Get local group info###
        $groupOutput = @()
        $groups = (Get-LocalGroup).name
            ForEach ($group in $groups){
                if ((Get-LocalGroupMember -Group $group) -ne $null){
                    Get-LocalGroupMember -Group $group -OutVariable gusers | Out-Null
                        foreach ($guser in $gusers){
                            $g = [pscustomobject]@{
                                Group = $group
                                User = $guser.Name
                                SID = $guser.SID
                                PrincipalSource = $guser.PrincipalSource
                                ObjectClass = $guser.ObjectClass
                            }
                        $groupOutput += $g
                        }

                }
            }
        $groupOutput | Export-Csv -Path C:\Temp\${env:COMPUTERNAME}\LocalGroupOutput.csv -NoTypeInformation
        ###End local group info###
        
        ###Get installed applications###
        Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | where displayname -NE $null | Select-Object -Property DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, InstallSource | Export-Csv -Path C:\Temp\${env:COMPUTERNAME}\installedApps.csv -NoTypeInformation
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | where displayname -NE $null | Select-Object -Property DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, InstallSource | Export-Csv -Path C:\Temp\${env:COMPUTERNAME}\installedApps.csv -Append
        ###End get installed applications###
    }

} HostInfo ###End General Host Information###

function NetStat{
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    $data = (netstat -anob |select -skip 4 | Out-String) -replace '(?m)^  (TCP|UDP)', '$1' -replace '\r?\n\s+([^\[])', "`t`$1" -replace '\r?\n\s+\[', "`t[" -split "`n"

    [regex]$regex = '(?<protocol>TCP|UDP)\s+(?<sourceAddress>\d+.\d+.\d+.\d+|\[.*\]|):(?<sourcePort>\d+)\s+(?<destAddress>\d+.\d+.\d+.\d+|\[::\]|\[::1\]|\*):(?<destPort>\d+|\*)\s+(?<state>LISTENING|ESTABLISHED|CLOSE_WAIT|CLOSED|FIN_WAIT|FIN_WAIT_1|FIN_WAIT_2|SYN_SENT|SYN_RECV|LAST_ACK|TIME_WAIT|\s)\s+(?<pid>\d+)\s+(?<service>Can not obtain ownership information|\w+\s+\[.*.\]|\[.*.\]|)'
    $output = @()

    $data | foreach {
        $_ -match $regex |Out-Null

        $outputobj = @{
            Protocol = [string]$matches.protocol
            SourceAddress = [string]$matches.sourceAddress #-replace '\[::\]','[..]' -replace '\[::1\]','[..1]'
            SourcePort = [string]$matches.sourcePort
            DestAddress = [string]$matches.destAddress #-replace '\[::\]','[..]' -replace '\[::1\]','[..1]'
            DestPort = [string]$matches.destPort
            State = [string]$matches.state #-replace "\*:\*",'NA'
            PID = [string]$matches.pid
            Service = ([string]$matches.service -replace 'Can not obtain ownership information','[System' -split '.*\[')[1] -replace '\]',''
            Subservice = ([string]$matches.service  -replace 'Can not obtain ownership information','' -split '\[.*\]')[0]
        }
        $output += New-Object -TypeName PSobject -Property $outputobj
        }
    $output | Select-Object -Property Protocol, SourceAddress, SourcePort, DestAddress, DestPort, State, PID, Service, Subservice | Export-Csv -Path c:\temp\${env:COMPUTERNAME}\NetStat.csv -NoTypeInformation
    }
} NetStat

function getProcess{
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $ids = (get-process).Id
        $processes = @()

        Try {
            if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue){
                foreach ($id in $ids){
                    Get-CimInstance -Query "select * from win32_process where processid='$id'" | Select-Object name, parentprocessid, processid, creationdate, path, commandline -OutVariable CIMprocess -ErrorVariable CIMissue | Out-Null
                    Get-Process -Id $id -IncludeUserName | Select-Object -Property username -OutVariable process -ErrorAction SilentlyContinue | Out-Null
        
                    $p = [pscustomobject]@{
                        Name = $CIMprocess.name
                        ParentProcessId = $CIMprocess.parentprocessid
                        ProcessID = $CIMprocess.processid
                        User = $process.username
                        CreationTime = $CIMprocess.creationdate
                        Path = $CIMprocess.path
                        CommandLine = $CIMprocess.Commandline
                        #Modules = $process.modules
                    }
                    $processes += $p
                }
                $processes | Select-Object -Property Name, ParentProcessId, ProcessID, User, CreationTime, Path, CommandLine, Modules | Export-Csv -Path c:\temp\${env:COMPUTERNAME}\Processes.csv -NoTypeInformation 
            }
            else{
                foreach ($id in $ids){
                Get-WmiObject -Query "select * from win32_process where processid='$id'" | Select-Object name, parentprocessid, processid, creationdate, path, commandline -OutVariable WMIprocess -ErrorVariable CIMissue | Out-Null
                Get-Process -Id $id -IncludeUserName | Select-Object -Property username -OutVariable process -ErrorAction SilentlyContinue | Out-Null
        
                    $p = [pscustomobject]@{
                        Name = $WMIprocess.name
                        ParentProcessId = $WMIprocess.parentprocessid
                        ProcessID = $WMIprocess.processid
                        User = $process.username
                        CreationTime = $WMIprocess.creationdate
                        Path = $WMIprocess.path
                        CommandLine = $WMIprocess.Commandline
                        #Modules = $process.modules
                    }
                    $processes += $p
                }
                $processes | Select-Object -Property Name, ParentProcessId, ProcessID, User, CreationTime, Path, CommandLine, Modules | Export-Csv -Path c:\temp\${env:COMPUTERNAME}\Processes.csv -NoTypeInformation
            }
        }
            catch{
                Write-Host -ForegroundColor Red `t "Error occurred..." $Error[0]
            }
    }
} getProcess

function getService{
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Try {
            Get-CimInstance -query 'SELECT * FROM win32_service' | Select-Object -Property Name, State, servicetype, ProcessID, PathName, StartName, DisplayName | Export-Csv -Path C:\Temp\${env:COMPUTERNAME}\services.csv -NoTypeInformation
            ###see https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configa for the different service types###
        }
            catch{
                Write-Host -ForegroundColor Red `t "Error occurred..." $Error[0] -InformationVariable ProcessError
            }
        If ($ProcessError){
            Get-WMIObject -ComputerName $computername -query "SELECT * FROM win32_service "| Select-Object -Property Name, State, servicetype, ProcessID, PathName, StartName, DisplayName | Export-Csv -Path C:\Temp\${env:COMPUTERNAME}\services.csv -NoTypeInformation
        }
    }
} getService

If ($ScheduleTask -eq $true){
    function getScheduledTask{
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            ###This script gets a list scheduled task and includes commandline execution for each task###
            $set= @()
            $tasks = (get-scheduledtask | where state -NE disabled).taskname
            foreach ($task in $tasks) {
                Get-ScheduledTask -TaskName $task | Select-Object -ExpandProperty Actions | Select-Object Arguments,Execute -OutVariable status | Out-Null
                Get-ScheduledTask -TaskName $task | Select-Object -Property Author,Date,Description,TaskPath -OutVariable details | Out-Null
                Get-ScheduledTask -TaskName $task | Get-ScheduledTaskInfo | Select-Object LastRunTime,NextRunTime -OutVariable runtimes | Out-Null

                $x = [pscustomobject]@{
                    TaskName = $task
                    TaskAuthor = $details.author
                    DateCreated = $details.date
                    LastRunTime = $runtimes.LastRunTime
                    NextRunTime = $runtimes.NextRunTime
                    CommandExe = $status.execute
                    Arguments = $status.arguments
                    TaskPath = $details.TaskPath
                    Description = $details.description
                }

            $set += $x
            }

            $set | Export-Clixml -path C:\temp\ScheduledTask.xml -Force
            Import-Clixml -Path C:\Temp\ScheduledTask.xml | Export-Csv -Path C:\Temp\${env:COMPUTERNAME}\ScheduledTask.csv -NoTypeInformation

        }
    } getScheduledTask
###Cleanup Leftover File###
Remove-Item -Path ${ComputerName}:\temp\ScheduledTask.xml
}

if ($WinEvent -eq $true){
    function getEvents{
        Copy-Item -Path ${ComputerName}:\WINDOWS\System32\winevt\Logs -Recurse -Destination ${ComputerName}:\temp\${ComputerName}\ | Out-Null
        Compress-Archive -Path \\${ComputerName}\c$\temp\${ComputerName}\Logs -DestinationPath \\${ComputerName}\c$\temp\${ComputerName}\WinEventLogs.zip -CompressionLevel Optimal
        Remove-Item -Path ${ComputerName}:\temp\${ComputerName}\Logs -Recurse
    } getEvents
}

function getautoruns {
    ###Copy over Autorunsc.exe file###
    Copy-Item -Path C:\infosec\pstools\autorunsc.exe -Destination ${ComputerName}:\temp\${ComputerName}\

    ###Run autorunsc.exe remotely###
    Invoke-Command -ComputerName $ComputerName -ScriptBlock { 
        powershell.exe c:\temp\${env:COMPUTERNAME}\autorunsc.exe -accepteula -nobanner -a * -s -h -m -c -o C:\temp\${env:COMPUTERNAME}\autoruns.csv 
    }

    ###Remove autorunsc.exe from target host###
    Remove-Item -Path ${ComputerName}:\temp\${ComputerName}\autorunsc.exe

} getautoruns  

function getHistory {
    ###Copy over browsinghistoryview.exe file###
    Copy-Item -Path C:\browsinghistoryview\BrowsingHistoryView.exe -Destination ${ComputerName}:\temp\${ComputerName}\

    ###Run browsinghistoryview.exe remotely###
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        powershell.exe c:\temp\${env:COMPUTERNAME}\BrowsingHistoryView.exe /HistorySource 1 /VisitTimeFilterType 3 /VisitTimeFilterValue 10 /scomma "C:\Temp\${env:COMPUTERNAME}\BrowsingHistory.csv"
    }

    ###Remove browsinghistoryview.exe from target host###
    Remove-Item -Path ${ComputerName}:\temp\${ComputerName}\BrowsingHistoryView.exe
} getHistory

###Compress and copy output to local workstation###
Compress-Archive -Path \\${ComputerName}\c$\temp\${ComputerName}\ -DestinationPath C:\Temp\IncidentResponse\${date}\${ComputerName}\HostInfo.zip  -CompressionLevel Optimal

###date and hash zip file###
Get-Date | Out-File -FilePath C:\Temp\incidentresponse\${date}\${ComputerName}\ZipFileInfo.txt
Write-Output -InputObject "`n Zip file generated by ${env:USERDOMAIN}\${env:USERNAME} `n" | Out-File -FilePath C:\Temp\incidentresponse\${date}\${ComputerName}\ZipFileInfo.txt -Append
Get-FileHash C:\Temp\IncidentResponse\${date}\${ComputerName}\HostInfo.zip -Algorithm SHA256 | Out-File -FilePath C:\Temp\incidentresponse\${date}\${ComputerName}\ZipFileInfo.txt -Append

###CLEANUP###
if((Get-ItemProperty -Path ${ComputerName}:\temp | Select-Object -ExpandProperty CreationTime) -gt (Get-Date).AddMinutes(-10)){
    Write-Host `t -ForegroundColor Yellow "Removing Temp directory from target machine"
    Remove-Item -Path ${ComputerName}:\Temp -Recurse
    }
        else{
            Write-Host `t -ForegroundColor Yellow "Cleaning up files"
            Remove-Item -Path ${ComputerName}:\temp\${ComputerName} -Recurse -Force
        }


###Time to run script###
$stopwatch.Stop()
Write-Host "The data collection took $($stopwatch.Elapsed | select -ExpandProperty Minutes) minute(s) and $($stopwatch.Elapsed | select -ExpandProperty seconds) second(s) to run. `n"
Write-Host `t -ForegroundColor Cyan "The output is stored here: C:\temp\incidentresponse\${date}\${ComputerName}\HostInfo.zip"

###stop the script###
break
