Import-Module 'C:\ConfigurationManager.psd1'
$computers = Get-Content C:\computers.txt
foreach ($comp in $computers){
    Get-CMDevice -Name $comp | Select-Object Name, UserDomainName, UserName
    }
