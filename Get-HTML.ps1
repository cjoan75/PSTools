<#
.SYNOPSIS

Test Script
version 5.1
Author: Rob Vance (http://www.ngosecurity.com)

	The MIT License
	-----------------------------------------------------------------------
	Copyright (c) 2015 NGO Security Solutions
	Permission is hereby granted, free of charge, to any person obtaining a 
	copy of this software and associated documentation files (the `"Software`"), 
	to deal in the Software without restriction, including without limitation 
	the rights to use, copy, modify, merge, publish, distribute, sublicense, 
	and/or sell copies of the Software, and to permit persons to whom the 
	Software is furnished to do so, subject to the following conditions:
	The above copyright notice and this permission notice shall be included 
	in all copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED `"AS IS`", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
	DEALINGS IN THE SOFTWARE.

#>

Param
(
    [Parameter(Position=0,Mandatory=$false)]
    [ValidateNotNullorEmpty()]
    [Alias('cn')][String[]]$ComputerName=$Env:COMPUTERNAME,
    [Array[]]$portList= @(80,443,8010,8011,8012,8015)
)
function testport($Computer,$port) {
    $Test = New-Object Net.Sockets.TcpClient
    $Test.BeginConnect( $Computer, $port, $Null, $Null ) | Out-Null
    $Timeout = ( Get-Date ).AddMilliseconds( 1000 )
    While( -not $Test.Connected -and ( Get-Date ) -lt $Timeout ){ Sleep -Milliseconds 50 }
    $results = $Test.Connected
    if($results -eq $true) { return $results }
    $Test.Close()
}
$Obj = @()
foreach($Computer in $ComputerName) {
$IPAddress = ([System.Net.DNS]::GetHostEntry($Computer).AddressList[0].IPAddressToString)
$i = 0
$csvport = @()
do {
    $tstport = testport $Computer $([string]$portList[$i])
    if($tstport -eq $true) { $csvport += $([string]$portList[$i]) }
    $i++
} until ($i -eq 20)
$ports = [string]$csvport -replace " ", ";"

foreach($port in ($ports -split ";")) {
    switch($port) {
        80 { $url = "http://$Computer" }
        443 { $url = "https://$Computer" }
    }
    
    $OutputString = [string]""

    $sHTTP = new-object -com msxml2.xmlhttp
    $sHTTP.open("OPTIONS",$url,$false)
    $sHTTP.send()

    $OutputString += ($Computer.ToUpper()).Trim() + "," + $url + "," + $port + "," + $sHTTP.status + "," + ($sHTTP.getResponseHeader("Allow") -replace "[,]", ";") + "," + ($sHTTP.getResponseHeader("Server")) + "," + ($sHTTP.getResponseHeader("X-Powered-By")) + "," + ($sHTTP.getResponseHeader("Content-Length"))

    $urlRobots = "$url/robots.txt"
    $robots = (Invoke-WebRequest -URI $urlRobots).Content
    if($robots -imatch "(sitemap|user-agent|disallow|allow)") { $robot = "Exists" } else { $robot = "Not Found" }

    $OutputString += $robot + ","

    $webrequest = Invoke-WebRequest -URI $url -SessionVariable websession 
    $cookie = (($webrequest.Headers).'Set-Cookie') -replace "[,]", "|"

    #$links = ($webrequest.Links | Select-Object href | %{$_.href} | Out-String) -replace "`n", "|"

    $OutputString += $cookie + "," + ($webrequest.Links.Count) + "," + ($webrequest.InputFields.Count) + "," + $webrequest.Scripts.Count

    $Obj += $OutputString
}
$Obj
}
