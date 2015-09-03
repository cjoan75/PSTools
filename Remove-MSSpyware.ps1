[cmdletbinding()]
param(
$computername = $env:computername
)            
[array]$hotfixes = Get-WmiObject -ComputerName $computername -Class Win32_QuickFixEngineering | select hotfixid            
$hotfixIDs = @("3068708","3022345","3075249","3080149")
foreach($HotfixID in $hotfixes) {
if($HotfixID -contains $hotfixIDs) {
    Write-host "Found the hotfix KB" + $HotfixID
    Write-Host "Uninstalling the hotfix"
    $UninstallString = "cmd.exe /c wusa.exe /uninstall /KB:$HotfixID /quiet /norestart"
    ([WMICLASS]"\\$computername\ROOT\CIMV2:win32_process").Create($UninstallString) | out-null            

    while (@(Get-Process wusa -computername $computername -ErrorAction SilentlyContinue).Count -ne 0) {
        Start-Sleep 3
        Write-Host "Waiting for update removal to finish ..."
    }
	write-host "Completed the uninstallation of $hotfixID"
} else {            
	write-host "Given hotfix($hotfixID) not found"
}
}
