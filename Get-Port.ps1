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
        $verifone = gwmi Win32_USBControllerDevice -ComputerName $Computer -ErrorAction SilentlyContinue | % { [wmi]($_.Dependent) } 
        if($verifone.Service -contains "VFIUNIUSB") {
            $vfnum = 0..($verifone.Name.Count - 1) | Where { $verifone.Name[$_] -match "Mx Family POS Terminal" }
            $COMStatus = $verifone.Name[$vfnum]
            if(($verifone.Name[$vfnum]) -match "(COM15)") { $ADEVICE = "Attached" } else { $ADEVICE = "Not Attached" }
            $outSTR = "$Computer$COMStatus$ColumnName$TableName"
            if($outSTR -notcontains $outARRAY) {
                $OutputString = [string]""
                $OutputString += ($Computer.ToUpper()).Trim() + "," + $COMStatus + "," + $ADEVICE
                $Obj += $OutputString
                [array]$outARRAY = $outSTR
            }
        }
    }
    $Obj
}
