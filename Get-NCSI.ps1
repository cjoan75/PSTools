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
        try { 
            $WinReg_HKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer) 
            $chkCDMS = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NLaSvc\Parameters\Internet").GetValue("EnableActiveProbing"))
            switch($chkCDMS) {
                0 { $EnableActiveProbing = "Disabled" }
                1 { $EnableActiveProbing = "Allowed" }
            }
            $ActiveWebProbeHost = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbeHost')
            $ActiveWebProbePath = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbePath')
            $ActiveWebProbeContent = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveWebProbeContent')
            $ActiveDnsProbeContent = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveDnsProbeContent')
            $ActiveDnsProbeHost = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('ActiveDnsProbeHost')
            $chkPOLL = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('PassivePollPeriod')
            switch($chkPOLL) {
                5 { $PassivePollPeriod = "30 Seconds" }
                10 { $PassivePollPeriod = "Every Minute" }
                default { $PassivePollPeriod = $chkPOLL }
            }
            $StaleThreshold = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('StaleThreshold') 
            $WebTimeout = $($WinReg_HKLM.OpenSubKey("SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")).GetValue('WebTimeout')
            $hostARRY = @()
            $hostARRAY = Select-String -Path "\\$Computer\C$\Windows\System32\drivers\etc\hosts" -Pattern "(msftncsi.com|131.107.255.255|dns.msftncsi.com)" -ErrorAction SilentlyContinue
            if($hostARRAY) {
                $CDMHosts = $($hostARRAY | & {$ofs=';';"$hostARRAY"})
            } else {
                $CDMHosts = "No"
            }
        } catch { continue }
        $outSTR = "$Computer$EnableActiveProbing$ActiveWebProbeHost$ActiveWebProbePath$ActiveWebProbeContent$ActiveDnsProbeContent$ActiveDnsProbeHost$PassivePollPeriod$StaleThreshold$WebTimeout$CDMHosts"
        if($outSTR -notcontains $outARRAY) {
            $OutputString = [string]""
            $OutputString += ($Computer.ToUpper()).Trim() + "," + $EnableActiveProbing + "," + $ActiveWebProbeHost + "," + $ActiveWebProbePath + "," + $ActiveWebProbeContent + "," + $ActiveDnsProbeContent + "," + $ActiveDnsProbeHost + "," + $PassivePollPeriod + "," + $StaleThreshold + "," + $WebTimeout + "," + $CDMHosts
            $Obj += $OutputString
            [array]$outARRAY = $outSTR
        }
    }
    $Obj
}
