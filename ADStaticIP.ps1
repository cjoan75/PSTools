New-NetIPAddress –IPAddress 10.211.55.16 -DefaultGateway 10.211.55.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex
