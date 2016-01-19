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
    [Alias('cn')][String[]]$ComputerName=$Env:COMPUTERNAME
)
$sw = [Diagnostics.Stopwatch]::StartNew()
foreach($Computer in $ComputerName) {
    if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $Computer -Quiet) {
        switch($Computer) {
            { $_ -match "." -and $_ -match "com" } { $logfn = "log" + ((($Computer.split("."))[0]).ToUpper() | %{ ($_.split("REG"))[3] }) + ".txt" }
            default { $logfn = "log" + (($_.ToUpper()).split("REG"))[3] + ".txt" }
        }
        if((Test-Path \\$Computer\C$\Logs\$logfn) -eq $true) {

            [array]$lines = Select-String -Path \\$Computer\C$\Logs\$logfn -Pattern "[\]]Ig(1|2|3|4|5|6|7|8)[\|]" -AllMatches
            foreach($line in $lines) {
                $a = ($line.ToString() -replace "\[1C\]","|").TrimEnd("]").Split("|") | where-object {$_ -ne " "}
                $outOBJ = New-Object -TypeName PSobject
                $outOBJ | Add-Member -MemberType NoteProperty -Name workstation -Value $Computer              
                foreach($b in $a) {
                    switch($b) {
                        {$_ -match "Ad(\d){14}" } { $Ad = ($_.ToString().Split("Ad"))[2]; $outOBJ | Add-Member -MemberType NoteProperty -Name Transaction_Date -Value $Ad }
                        {$_ -match "Ah" } { $Ah = ($_.ToString().Split("Ah"))[2]; $outOBJ | Add-Member -MemberType NoteProperty -Name Transaction_Number -Value $Ah }
                        {$_ -match "Bf(E|S)" } { $Bf = ($_.ToString().Split("Bf"))[2]; $outOBJ | Add-Member -MemberType NoteProperty -Name Entry_Mode -Value $Bf }
                        {$_ -match "Bq" } { $Bq = ($_.ToString().Split("Bq"))[2]; $outOBJ | Add-Member -MemberType NoteProperty -Name Card_Type -Value $Bq }
                        {$_ -match "Ic(\d){3}[-](\d){3}[-](\d){3}" } { $Ic = ($_.ToString().Split("Ic"))[2]; $outOBJ | Add-Member -MemberType NoteProperty -Name GSN -Value $Ic}
                        {$_ -match "Ig" } { $Ig = $_.ToString(); $outOBJ | Add-Member -MemberType NoteProperty -Name Encryption_Type -Value $Ig }
                        {$_ -match "(\d)[A-Z](\d){11}[A-Z](\d){6}" } { $VSN = $_.ToString(); $outOBJ | Add-Member -MemberType NoteProperty -Name VSN -Value $VSN }
                    }
                }
                ConvertTo-Csv -InputObject $outOBJ -Delimiter "," -NoTypeInformation
            }  
        }   
    }
}

$sw.Stop()
$ms = $sw.Elapsed.Milliseconds
$sec = $sw.Elapsed.Seconds
$min = $sw.Elapsed.Minutes
$hrs = $sw.Elapsed.Hours
$to = "$hrs`:$min`:$sec`:$ms"

Write-Host "Processed " -NoNewLine
Write-Host $ComputerName.Count -NoNewline
Write-Host " In $to"
