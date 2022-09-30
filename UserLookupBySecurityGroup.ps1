$Domains = (Get-ADForest).Domains | Sort-Object {$_.length} | Select-Object -Skip 1
$SecGroup = Get-ADGroupMember -Identity "AD SECURITY GROUP" | Select-Object -Property name,samaccountname

$Users = foreach ($User in $SecGroup){
    foreach ($Domain in $Domains){
        try{
            Get-ADUser -server $Domain -Identity $User.samaccountname -Properties mail 
        }
        catch{
        }
    }
}

$Users | Export-Csv -Path c:\SecGroupUserList.csv -NoTypeInformation
