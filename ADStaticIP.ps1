New-NetIPAddress –IPAddress 10.211.55.17 -DefaultGateway 10.211.55.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex

Set-DNSClientServerAdress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses 10.211.55.16
