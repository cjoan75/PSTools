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

param( 
    [Parameter(Position=0,Mandatory=$false)]
    [ValidateNotNullorEmpty()]
    [Alias('cn')][String[]]$ComputerName=$Env:COMPUTERNAME,
    [switch]$Local, 
    [switch]$GPO 
)
if (!($Local) -and !($Gpo)) { $Local = $true }
$Obj = @()
foreach($Computer in $ComputerName) {
$RegistryKeys = @() 
if ($Local) { $RegistryKeys += 'Registry::HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' } 
if ($GPO) { $RegistryKeys += 'Registry::HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules' } 
    Foreach ($Key in $RegistryKeys) { 
        if (Test-Path -Path $Key) { 
            (Get-ItemProperty -Path $Key).PSObject.Members | 
            Where-Object {(@('PSPath','PSParentPath','PSChildName') -notcontains $_.Name) -and ($_.MemberType -eq 'NoteProperty') -and ($_.TypeNameOfValue -eq 'System.String')} | 
            ForEach-Object { 
                $HashProps = @{ 
                    NameOfRule = $_.Name 
                    RuleVersion = ($_.Value -split '\|')[0] 
                    Action = $null 
                    Active = $null 
                    Dir = $null 
                    Protocol = $null 
                    LPort = $null 
                    App = $null 
                    Name = $null 
                    Desc = $null 
                    EmbedCtxt = $null 
                    Profile = $null 
                    RA4 = $null 
                    RA6 = $null 
                    Svc = $null 
                    RPort = $null 
                    ICMP6 = $null 
                    Edge = $null 
                    LA4 = $null 
                    LA6 = $null 
                    ICMP4 = $null 
                    LPort2_10 = $null 
                    RPort2_10 = $null 
                } 
                if ($Key -match 'HKLM\\System\\CurrentControlSet') { $HashProps.RuleType = 'Local' } else { $HashProps.RuleType = 'GPO' } 
                ForEach ($FireWallRule in ($_.Value -split '\|')) { 
                    switch (($FireWallRule -split '=')[0]) { 
                        'Action' {$HashProps.Action = ($FireWallRule -split '=')[1]} 
                        'Active' {$HashProps.Active = ($FireWallRule -split '=')[1]} 
                        'Dir' {$HashProps.Dir = ($FireWallRule -split '=')[1]} 
                        'Protocol' {$HashProps.Protocol = ($FireWallRule -split '=')[1]} 
                        'LPort' {$HashProps.LPort = ($FireWallRule -split '=')[1]} 
                        'App' {$HashProps.App = ($FireWallRule -split '=')[1]} 
                        'Name' {$HashProps.Name = ($FireWallRule -split '=')[1]} 
                        'Desc' {$HashProps.Desc = ($FireWallRule -split '=')[1]} 
                        'EmbedCtxt' {$HashProps.EmbedCtxt = ($FireWallRule -split '=')[1]} 
                        'Profile' {$HashProps.Profile = ($FireWallRule -split '=')[1]} 
                        'RA4' {$HashProps.RA4 = ($FireWallRule -split '=')[1]} 
                        'RA6' {$HashProps.RA6 = ($FireWallRule -split '=')[1]} 
                        'Svc' {$HashProps.Svc = ($FireWallRule -split '=')[1]} 
                        'RPort' {$HashProps.RPort = ($FireWallRule -split '=')[1]} 
                        'ICMP6' {$HashProps.ICMP6 = ($FireWallRule -split '=')[1]} 
                        'Edge' {$HashProps.Edge = ($FireWallRule -split '=')[1]} 
                        'LA4' {$HashProps.LA4 = ($FireWallRule -split '=')[1]} 
                        'LA6' {$HashProps.LA6 = ($FireWallRule -split '=')[1]} 
                        'ICMP4' {$HashProps.ICMP4 = ($FireWallRule -split '=')[1]} 
                        'LPort2_10' {$HashProps.LPort2_10 = ($FireWallRule -split '=')[1]} 
                        'RPort2_10' {$HashProps.RPort2_10 = ($FireWallRule -split '=')[1]} 
                        Default {} 
                    } 
                }
                $outSTR = $Computer + "" + $HashProps.Action + "" + $HashProps.Active + "" + $HashProps.Dir + "" + $HashProps.Protocol + "" + $HashProps.LPort + "" + $HashProps.App + "" + $HashProps.Name + "" + $HashProps.Desc
                if($outSTR -notcontains $outARRAY) {
                    $OutputString = [string]""
                    $OutputString += ($Computer.ToUpper()).Trim() + "," + $HashProps.Action + "," + $HashProps.Active + "," + $HashProps.Dir 
                    $OutputString += $HashProps.Protocol + "," + $HashProps.LPort + "," + $HashProps.App + "," + $HashProps.Name
                    $OutputString += $HashProps.Desc + "," + $HashProps.EmbedCtxt + "," + [array]$HashProps.RA4 + "," + [array]$HashProps.RA6
                    $OutputString += $HashProps.Svc + "," + $HashProps.RPort + "," + $HashProps.ICMP6 + "," + $HashProps.Edge
                    $OutputString += [array]$HashProps.LA4 + "," + [array]$HashProps.LA6 + "," + $HashProps.ICMP4 + "," + $HashProps.LPort2_10
                    $OutputString += $HashProps.RPort2_10
                    $Obj += $OutputString
                    [array]$outARRAY = $outSTR
                }
            } 
        } 
    }
    $Obj
}
