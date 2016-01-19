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
function checkWMI ([string]$srv){  
# This checks to see if the workstation accepts WMI request in order to prevent the script from hanging
    $checkwmi = $null  
    $timeout = new-timespan -seconds 15  
    $Scope = new-object System.Management.ManagementScope "\\$srv\root\cimv2", $options -ErrorAction Continue
    try {
        $Scope.Connect()  
        $query = new-object System.Management.ObjectQuery "SELECT * FROM Win32_OperatingSystem"  
        $searcher = new-object System.Management.ManagementObjectSearcher $scope,$query  
        $SearchOption = $searcher.get_options()  
        $SearchOption.set_timeout($timeout)  
        $searcher.set_options($SearchOption)  
        $checkwmi = $searcher.get()  
        $lastBoot = $checkwmi | %{$_.lastbootuptime}  
        if($lastBoot){  
            return $true  
        } else {  
            return $false  
        }
    } catch {
        continue
    }
} 
$Obj = @()
foreach($Computer in $ComputerName) {
    if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $Computer -Quiet) {
        if((checkWMI $Computer) -eq $true) {
            $tmpPath = "\\$Computer\C$\Temp"
            $IPFile = "$Computer`_DISPLAYDNS.txt"
            $outDNS = "\\nicsrv10\tts\labcde"
            if((Get-ChildItem -Path $tmpPath).Exists -eq $true) { 
                $remoteDNS = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd /c ipconfig.exe /displaydns > c:\temp\$IPFile") -ComputerName $Computer -ErrorAction SilentlyContinue
                if((Get-ChildItem -Path $tmpPath -Filter $IPFile).Exists -eq $true) {
                    $RmtExecute = "Yes"
                } else {
                    $RmtExecute = "No"
                }
                Copy-Item -path "$tmpPath\$IPFile" -Destination $outDNS -force 
                if((Get-ChildItem -Path $outDNS).Exists -eq $true) {
                    $RmtDownload = "Yes"
                } else {
                    $RmtDownload = "No"
                }
                Copy-Item -Path $outDNS -Destination $tmpPath -force 
                if((Get-ChildItem -Path "$tmpPath\$IPFile").Exists -eq $true) {
                    $RmtUpload = "Yes"
                } else {
                    $RmtUpload = "No"
                }
            } else {
                $RmtExecute = "No"
                $RmtDownload = "No"
                $RmtUpload = "No" 
            }
        } else {
            $RmtExecute = "Unk"
            $RmtDownload = "Unk"
            $RmtUpload = "Unk"  
        }
        $outSTR = "$Computer$RmtExecute$RmtDownload$RmtUpload"
        if($outSTR -notcontains $outARRAY) {
            $OutputString = [string]""
            $OutputString += ($Computer.ToUpper()).Trim() + "," + $RmtExecute + "," + $RmtDownload + "," + $RmtUpload
            $Obj += $OutputString
            [array]$outARRAY = $outSTR
        }
    }
    $Obj
}
 
