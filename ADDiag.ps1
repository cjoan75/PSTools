$svcs = "adws","dns","kdc","netlogon"
Get-Service -name $svcs -ComputerName $env:COMPUTERNAME

#DCDiag /c /v /e /fix /f:c:\DCDIAG.Log
