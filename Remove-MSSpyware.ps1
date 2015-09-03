[cmdletbinding()]
param(
$computername = $env:computername
)            
$hotfixes = Get-WmiObject -ComputerName $computername -Class Win32_QuickFixEngineering | select hotfixid            
$hotfixIDs = @("3068708","3022345","3075249","3080149")
foreach($HotfixID in $hotfixes) {
	Write-Verbose $HotfixID
}
