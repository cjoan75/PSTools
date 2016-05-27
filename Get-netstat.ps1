#remote netstat with parameter support
function netstat
{
param(
[Parameter(Position=0)]
[Alias(“CN”,”Computer”)]
[String[]]$ComputerName = $env:COMPUTERNAME,
[Parameter(Position=1)]
[Alias(“Arguments”)]
$argument)

write-host “Gathering information…”
invoke-command -ComputerName $ComputerName -ScriptBlock { param ($argument) & ‘netstat’ -$argument } -ArgumentList “$argument” | out-gridview
}
