$Lookup = Import-Csv -Path C:\Computers.csv

$printOut = foreach ($user in $Lookup.Primary){
    foreach ($uniqueUser in $user.Split(',') | Select-Object -First 1){
        $domain = $uniqueUser.split('\') | Select-Object -First 1
        $uniqueUserAccount = $uniqueUser.split('\') | Select-Object -Last 1
        Get-ADUser -Server $domain -Identity $uniqueUserAccount | Select-Object UserPrincipalName
    }
}

$printOut | Export-Csv C:\usersUPN.csv -NoTypeInformation
