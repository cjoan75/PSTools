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
