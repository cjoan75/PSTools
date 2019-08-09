New-NetIPAddress –IPAddress 10.211.55.17 -DefaultGateway 10.211.55.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex

Set-DNSClientServerAdress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses 10.211.55.16

$hostname = read-host 'W12SrvrUtil'
$Domain = 'tst.com'

$username = "Administrator"
$password = ConvertTo-SecureString "" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential -ArguementList ($username, $password) 

Rename-Computer $hostname
Add-Computer -Domain $Domain -NewName $hostname -Credential $Credential -Restart -Force
