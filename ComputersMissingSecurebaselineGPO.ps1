$Domains = (Get-ADForest).Domains
$shortDomain = foreach($doma1n in $domains){$doma1n.split('.')[0]}
#Get ALL OU's with computer's in them
Import-Module ActiveDirectory
$Data = @()

Function GatherOUs{
    foreach ($Domain in $Domains){
        $Computers = Get-ADComputer -Server $Domain -Filter * | Where-Object -Property DistinguishedName -NotLike "*CN=Computers*" 
            foreach ($Computer in $Computers){
                $DN = $Computer.DistinguishedName.Split(',')
                $DN[1..$($DN.Count)] -join ','
            }
    }
}


$OUs = GatherOUs | Select-Object -Unique 
#Get GP inheritance
foreach ($OU in $OUs){ 
    foreach ($domain in $domains){
    if ($ou -like '*DC='+$domain.split('.')[0]+'*'){
    $GPInheritance = Get-GPInheritance -Target $OU -Domain $domain | Select-Object -ExpandProperty InheritedGpoLinks  #| Where-object  {($_.Displayname -Like '*Securebaseline*') -and ($_.DisplayName -Notlike '*Exclusion*')}
        if ($GPInheritance.DisplayName -like '*Securebaseline'){
            $Securebaseline = "Applied"
            $Enabled = ($GPInheritance | where-object {($_.DisplayName -like '*Securebaseline')} | Select-Object -Property Enabled).Enabled
            }
                Else{
                    $Securebaseline = "Not Applied"
                    $Enabled = "False"
                }
    }
    }

    $y = [pscustomobject]@{
        OrgUnit = $OU
        Securebaseline = $Securebaseline
        Enabled = $Enabled
    }
    $Data += $y
}

#determine which OU's WITH computers that DO/DO NOT inherit securebaseline GPO's
Function NoSecureBaselineComputers{
    
    
    Foreach ($DataItem in $Data){
    
        if ($DataItem.Securebaseline -eq 'Not Applied'){
            foreach ($domain in $domains){
                if ($DataItem.OrgUnit -like '*DC='+$domain.split('.')[0]+'*'){
                    Get-ADComputer -Server $domain -SearchBase $DataItem.OrgUnit -SearchScope OneLevel -Filter * -Properties CanonicalName,Created,IPv4Address,LastLogonDate,OperatingSystem,OperatingSystemVersion| Select-Object -Property Name,Enabled,Created,OperatingSystem,OperatingSystemVersion,LastLogonDate,CanonicalName,IPv4Address,DistinguishedName
        }
    }
}
}
}
$MissingGPO = NoSecureBaselineComputers 
$ComputersOUs = @()
foreach ($domain in $domains){
    #$SearchBase = Get-ADOrganizationalUnit -Server $domain -Filter * | Select-Object -First 1 -ExpandProperty DistinguishedName
    $ComputersOU = get-adcomputer -Server $domain -filter * -Properties CanonicalName,Created,IPv4Address,LastLogonDate,OperatingSystem,OperatingSystemVersion | where {$_.DistinguishedName -like "*CN=Computers,DC=*"} | Select-Object -Property Name,Enabled,Created,OperatingSystem,OperatingSystemVersion,LastLogonDate,CanonicalName,IPv4Address,DistinguishedName
        foreach ($item in $ComputersOU){
            $x = [PSCustomObject]@{
            Name = $item.Name
            Enabled = $item.Enabled
            Created = $item.Created
            OperatingSystem = $item.OperatingSystem
            OperatingSystemVersion = $item.OperatingSystemVersion
            LastLogonDate = $item.LastLogonDate
            CanonicalName = $item.CanonicalName
            IPv4Address = $item.IPv4Address
            DistinguishedName = $item.DistinguishedName
            }
    $ComputersOUs += $x
    }
}


$AllComputersMissingGPO = $MissingGPO + $ComputersOUs 
$AllComputersMissingGPO | Export-Csv -Path c:\Output\MissingGPO.csv -NoTypeInformation
