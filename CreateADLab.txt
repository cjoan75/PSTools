# $PSVersionTable.PSVersion

# Check if AD Services is installed
# Add-WindowsFeature AD-Domain-Services
# Add-windowsfeature RSAT-ADDS

# Check if Administator password is not null
# net user Administrator P@ssw0rd2013
# net user Administrator /passwordreq:yes

Import-Module ADDSDeployment

$SafeModeAdministratorPasswordText = ‘P@ssw0rd2013’
$SafeModeAdministratorPassword = ConvertTo-SecureString -AsPlainText $SafeModeAdministratorPasswordText -Force

Install-ADDSForest -CreateDNSDelegation:$False -DatabasePath “c:\Windows\NTDS” -DomainMode ‘Win2012R2’ -DomainName "tst.com” -DomainNetbiosName “TSTAD” -ForestMode ‘Win2012R2’ -InstallDNS:$true -LogPath “C:\Windows\NTDS” -NoRebootOnCompletion:$false -Sysvolpath “C:\Windows\SYSVOL” -Force:$true -SafeModeAdministratorPassword $SafeModeAdministratorPassword
