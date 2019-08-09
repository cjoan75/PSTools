New-NetIPAddress –IPAddress 10.211.55.17 -DefaultGateway 10.211.55.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex

Set-DNSClientServerAddress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses 10.211.55.16

$hostname = "W12SrvrUtil"
#$hostname = "W12SrvrAD"
#$hostname = "W12SrvrApp"
$Domain = 'tst.com'

$username = "Administrator"
$password = ConvertTo-SecureString "P@ssw0rd2013" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential -ArguementList ($username, $password) 

Rename-Computer $hostname
Add-Computer -Domain $Domain -NewName $hostname -Credential $Credential -Restart -Force
