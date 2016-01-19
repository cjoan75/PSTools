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
$Obj = @()
foreach($Computer in $ComputerName) {
    if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $Computer -Quiet) {
        switch($Computer) {
            { $_ -match "." -and $_ -match "com" } { $logfn = "log" + ((($Computer.split("."))[0]).ToUpper() | %{ ($_.split("REG"))[3] }) + ".txt" }
            default { $logfn = "log" + (($_.ToUpper()).split("REG"))[3] + ".txt" }
        }
        if((Test-Path \\$Computer\C$\Logs\$logfn -ErrorAction SilentlyContinue) -eq $true) {  
            [array]$lines = Select-String -Path \\$Computer\C$\Logs\$logfn -Pattern "(\b(9F34[-](\d){6}|Ig(\d){1})\b)" -AllMatches
            foreach($line in $lines) {
                $a = ($line.ToString() -ireplace "\[1C\]","|").TrimEnd("]").Split("|") | where-object {$_ -ne " "}
                foreach($b in $a) {           
                    switch($b) {
                        {$_ -match "Ad(\d){14}" } { $Ad = ($_.ToString().Split("Ad"))[2] }                      
                        {$_ -match "Ah" } { $Ah = ($_.ToString().Split("Ah"))[2] }                    
                        {$_ -match "Bf(E|S)" -and $_ -notmatch "(FE(\d){5})" } { $Bf = ($_.ToString().Split("Bf"))[2] }                       
                        {$_ -match "Bq" } { $Bq = ($_.ToString().Split("Bq"))[2] }                   
                        {$_ -match "Ia" } { if($_.Split("Ia") -notmatch "([*]*)" ) { $Ia = "No" } else { $Ia = "Yes" } }
                        {$_ -match "Ic(\d){3}[-](\d){3}[-](\d){3}" } { $Ic = ($_.ToString().Split("Ic"))[2] }                       
                        {$_ -match "Ig" } { if($_.ToString() -match "(Ig4)") { $Ig = "Yes" } else { $Ig = "No" } }                 
                        {$_ -match "(\d)[A-Z](\d){11}[A-Z](\d){6}" } { $VSN = $_.ToString() }                   
                        {$_ -match "(9F34)" } {    
                            $option = [System.StringSplitOptions]::RemoveEmptyEntries
                            $e = ($_.Split("-",2,$option))[1]
                            if($e.length -eq 6) {                 
                                if(($e.SubString(2,2)) -notmatch "((1|4)(\d){1})") { $NIP = "No" } else { $NIP = "Yes" }
                            } else {
                                $NIP = "Unk"
                            }
                        }
                    }
                    $outSTR = "$Computer$Ad$Ah$Bf$Bq$Ia$Ic$Ig$VSN$NIP"
                    #if($VSN -and $Ic -and $NIP) {
                        if($outSTR -notcontains $outARRAY) {
                            $OutputString = [string]""
                            $OutputString += ($Computer.ToUpper()).Trim() + "," + $Ad + "," + $Ah + "," + $Bf + "," + $Bq + "," + $Ia + "," + $Ic + "," + $Ig + "," + $VSN + "," + $NIP
                            $Obj += $OutputString
                            [array]$outARRAY = $outSTR
                        }
                    #}    
                }
            }
        }
    }
    $Obj
}
