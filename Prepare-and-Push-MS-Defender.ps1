$servers = get-content c:\DefenderServers.txt
$file1 = "c:\MS_DefenderInstall.ps1" #https://github.com/microsoft/mdefordownlevelserver/blob/main/Install.ps1
$file2 = "c:\md4ws.msi" #MS downloaded msi
$file3 = "c:\WindowsDefenderATPOnboardingScript.cmd" #MS downloaded .cmd

foreach ($server in $servers){
    if (Test-Path -Path \\$($server)\c$\temp){
        Copy-Item -Path $file1 -Destination \\$($server)\c$\temp
        Copy-Item -Path $file2 -Destination \\$($server)\c$\temp
        Copy-Item -Path $file3 -Destination \\$($server)\c$\temp
    }
    else{
        New-Item -Path \\$($server)\c$\ -Name temp -ItemType Directory -Force
        Copy-Item -Path $file1 -Destination \\$($server)\c$\temp
        Copy-Item -Path $file2 -Destination \\$($server)\c$\temp
        Copy-Item -Path $file3 -Destination \\$($server)\c$\temp
    }
}

foreach ($server in $servers){
    if (test-path \\$($server)\c$\defenderInstallOldServers.ps1){
        invoke-command -ComputerName $server -ScriptBlock { C:\DefenderInstallOldServers.ps1}
    }
}

foreach ($server in $servers){
    if (test-path \\$($server)\c$\WindowsDefenderATPOnboardingScript.cmd){
        invoke-command -ComputerName $server -ScriptBlock { C:\WindowsDefenderATPOnboardingScript.cmd}
    }
}
