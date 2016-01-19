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
    [String]$logname="Security"
)
#Invoke-Command -ComputerName $ComputerName -Scriptblock { $PSVersionTable.PSVersion.Major }
$Obj = @()
function outcap($item) {
    $ac = ([regex]"(?i)\bAccount Name:\s+\w+\b").matches($item.Message) | select -prop value | %{ (($_.value -split ":")[1]) -replace "\s+","" }
    if($ac -match "($item.MachineName [A-Z]*)") { $ac = $ac.split(" ")[1] }
    $lt = ([regex]"(?i)\bLogon Type:\s+(\d){1,2}\b").matches($item.Message) | select -prop value | %{ (($_.value -split ":")[1]) -replace "\s+","" }
    $outOBJ | Add-Member -MemberType NoteProperty -Name workstation -Value ($Computer.ToUpper()).Trim()
    if($lt -ne 5 -or $ac -inotmatch "($item.MachineName)") {
        switch($lt) {
            2 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID;
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Interactive" 
                }
            3 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Network" 
                }
                        
            4 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Batch" 
                }
            5 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Service" 
                }
                            
            7 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Unlock" 
                }
            8 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Cleartext" 
                }
            10 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Remote" 
                }
            11 { $outOBJ | Add-Member -MemberType NoteProperty -Name AccountName -Value $ac;
                $outOBJ | Add-Member -MemberType NoteProperty -Name EventID -Value $item.EventID; 
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonType -Value $lt
                $outOBJ | Add-Member -MemberType NoteProperty -Name LogonTypeDesc -Value "Cache" 
                }
        }
        $outOBJ | Add-Member -MemberType NoteProperty -Name Hash -Value ($outOBJ.workstation + $outOBJ.AccountName + $outOBJ.EventID + $outOBJ.LogonType).ToString()
        if($outOBJ) { return $outOBJ }
    }
}
foreach($Computer in $ComputerName) {
    if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $Computer -Quiet) {       
        foreach($seclog in (Get-EventLog -AsBaseObject -LogName $logname -ComputerName $Computer | where { $_.TimeWritten -gt ((get-date).adddays(-2)) } -ErrorAction Stop ) ) {
            $outOBJ = New-Object -TypeName PSobject
            if($logname -imatch "Security") {
                switch($seclog.EventID) {
                    # Special privileges assigned
                    { $_ -match "(4672)" } { $outOBJ = outcap $seclog }
                    # Changed
                    { $_ -match "(47(20|22|23|24|38|67|81))" } { $outOBJ = outcap $seclog }
                    # Group Created
                    { $_ -match "(47(27|31|54))" } { $outOBJ = outcap $seclog }
                    # Group Changed
                    { $_ -match "(47(33|35|37|55))" } { $outOBJ = outcap $seclog }
                    # Logon Session Events - Remote re/dis connected
                    { $_ -match "(47(78|79))" } { $outOBJ = outcap $seclog }
                    # Logon Type
                    { $_ -match "(46(24|25))" } { $outOBJ = outcap $seclog }
                }
            }
            if($outOBJ.Hash -notcontains $outARRAY) {
                if($outOBJ.AccountName) {
                    $OutputString = [string]""
                    $OutputString += ($Computer.ToUpper()).Trim() + "," + $outOBJ.AccountName + "," + $outOBJ.EventID+ "," + $outOBJ.LogonType + "," + $outOBJ.LogonTypeDesc
                    $Obj += $OutputString
                    [array]$outARRAY = $outOBJ.Hash
                    #$OutputString
                }
            }
        }
    }
    $Obj
}
