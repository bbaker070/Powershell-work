Import-Module 'C:\Program Files (x86)\ConfigMgr Console\bin\ConfigurationManager.psd1'
$computers = Get-Content C:\computers.txt
foreach ($comp in $computers){
    Get-CMDevice -Name $comp | Select-Object Name, UserDomainName, UserName
    }
