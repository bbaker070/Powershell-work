#Get AD security groups that are authorized for VPN use.
$VPNemployees = Get-ADGroupMember -Identity AD-vpn-group1
$VPNemployees += Get-ADGroupMember -Identity AD-vpn-group2
$VPNemployees += Get-ADGroupMember -Identity AD-vpn-group3
$VPNemployees = $VPNemployees | Select-Object -Unique

$VPNUPN = foreach ($employee in $VPNemployees){
    $userDomain = (($employee.distinguishedName -split ',' | Select-String -Pattern DC)[0] -split '=')[1]
    Get-ADUser -Server $userDomain -Identity $employee.distinguishedName -Properties ADProperties | Select-Object -Property userprincipalname #etc.
}

#Get list of user's email address for employees who are actually using VPN. Logs retrieved from VPN gateway connection logs.
$ActiveVPNUsers = Import-Csv -Path C:\UserConnectionList.csv | Select-Object -Property User

$InactiveVPNusers = Compare-Object -ReferenceObject $VPNUPN.userprincipalname -DifferenceObject $ActiveVPNUsers.user | Where-Object sideindicator -EQ "<=" | Select-Object -Property inputobject

$InactiveVPNUserList = foreach ($inactiveUser in $InactiveVPNusers.inputobject){
    $VPNUPN | Where-Object UserPrincipalName -EQ  $inactiveUser
}
#Export results to CSV
$InactiveVPNUserList | Export-Csv -Path C:\InactiveVPNusers.csv -NoTypeInformation
