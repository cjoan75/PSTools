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

[cmdletbinding()]
param(
    [switch]$v,
    [switch]$vv,
    [string]$path,
    [string]$workstations,
    [string]$rptname
)
if($path -ne $true) { $global:path = "$env:TEMP\Temp" }
if($workstations -ne $true) { $workstations = "workstations.csv" }
if($rptname -ne $true) { $rptname = "T*_*.xlsm" }
$Heatmaps = "$env:TEMP\Heatmaps"
$lastdate = $true
##> Previously Processed Stores
if($lastdate -eq $true) {
    [array]$processedSID = ((gci -Path $env:TEMP\Heatmaps -Filter $rptname).Name | %{ $sp = $_.ToString().split("REG"); Write-Output $sp[0] } | Sort -Unique)
    Write-Host "Previously Processed: " -NoNewline 
    Write-Host ($processedSID).Count
    #Write-Output "Processed"
    #Write-Output $processedSID
}
#
##> All of the Stores in Splunk
#if($vv -eq $true) { Write-Host "Processing workstations..." }
[array]$wrkstnids = (gc "$global:path\$workstations" | %{ $sp = $_.ToString().split("REG"); if($sp[0] -notmatch "(workstation)") { Write-Output $sp[0] }} | Sort -Unique)
    Write-Host "Number of Stores: " -NoNewline 
    Write-Host ($wrkstnids).Count
#Write-Output "Current"
#Write-Output $wrkstnids
#
##> Get the Diff
if($lastdate -eq $true) {
    #Compare-Object $processedSID $wrkstnids -PassThru
    [array]$tobeSID = Compare-Object $processedSID $wrkstnids -PassThru
} else {
    $tobeSID = $wrkstnids
}
    Write-Host "New Stores: " -NoNewline 
    Write-Host ($tobeSID).Count
##> All of the workstations Fullname in Splunk
[array]$reg = (gc "$global:path\$workstations" | ?{$_ -notmatch "^(workstation)"}| Sort -Unique)
    Write-Host "Number of workstations: " -NoNewline 
    Write-Host ($reg).Count
# Column F (6)
$col = 6
foreach($rg in $reg) {
    if($tobeSID -contains ($rg | %{ $sp = $_.ToString().split('REG'); Write-Output $sp[0]})) {
        [array]$tobeadded += $rg
    }
}
Write-Host ($tobeadded).Count
if((Test-Path $env:TEMP\Temp\42.csv) -eq $true) { [array]$42Array = (gc $env:TEMP\Temp\42.csv|?{$_ -notmatch "^workstation"}) }
    Write-Host "Test Criteria 42: " -NoNewline 
    Write-Host ($42Array).Count
if((Test-Path $env:TEMP\Temp\44.csv) -eq $true) { [array]$44Array = (gc $env:TEMP\Temp\44.csv|?{$_ -notmatch "^workstation"}) }
    Write-Host "Test Criteria 44: " -NoNewline 
    Write-Host ($44Array).Count
if((Test-Path $env:TEMP\Temp\45.csv) -eq $true) { [array]$45Array = (gc $env:TEMP\Temp\45.csv|?{$_ -notmatch "^workstation"}) }
    Write-Host "Test Criteria 45: " -NoNewline 
    Write-Host ($45Array).Count
if((Test-Path $env:TEMP\Temp\53.csv) -eq $true) { [array]$53Array = (gc $env:TEMP\Temp\53.csv|?{$_ -notmatch "^workstation"}) }
    Write-Host "Test Criteria 53: " -NoNewline 
    Write-Host ($53Array).Count
if((Test-Path $env:TEMP\Temp\54.csv) -eq $true) { [array]$54Array = (gc $env:TEMP\Temp\54.csv|?{$_ -notmatch "^workstation"}) }
    Write-Host "Test Criteria 54: " -NoNewline 
    Write-Host ($54Array).Count
if((Test-Path $env:TEMP\Temp\56.csv) -eq $true) { [array]$56Array = (gc $env:TEMP\Temp\56.csv|?{$_ -notmatch "^workstation"}) }
    Write-Host "Test Criteria 56: " -NoNewline 
    Write-Host ($56Array).Count
if((Test-Path $env:TEMP\Temp\57.csv) -eq $true) { [array]$57Array = (gc $env:TEMP\Temp\57.csv|?{$_ -notmatch "^workstation"}) }
    Write-Host "Test Criteria 57: " -NoNewline 
    Write-Host ($57Array).Count

function ForEach-Parallel {
    param(
        [Parameter(Mandatory=$true,position=0)]
        [System.Management.Automation.ScriptBlock] $ScriptBlock,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [PSObject]$InputObject,
        [Parameter(Mandatory=$false)]
        [int]$MaxThreads=5
    )
    BEGIN {
        $iss = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $pool = [Runspacefactory]::CreateRunspacePool(1, $maxthreads, $iss, $host)
        $pool.open()
        $threads = @()
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param(`$_)`r`n" + $Scriptblock.ToString())
    }
    PROCESS {
        $powershell = [powershell]::Create().addscript($scriptblock).addargument($InputObject)
        $powershell.runspacepool=$pool
        $threads+= @{
            instance = $powershell
            handle = $powershell.begininvoke()
        }
    }
    END {
        $notdone = $true
        while ($notdone) {
            $notdone = $false
            for ($i=0; $i -lt $threads.count; $i++) {
                $thread = $threads[$i]
                if ($thread) {
                    if ($thread.handle.iscompleted) {
                        $thread.instance.endinvoke($thread.handle)
                        $thread.instance.dispose()
                        $threads[$i] = $null
                    }
                    else {
                        $notdone = $true
                    }
                }
            }
        }
    }
}

#
#####> Individual workstation reports
#
# Purpose: This will creates a spreadsheet of each workstation and reports on what test criteria it passed or failed
# 
[array]$AryProperties = "Title" 
$ttreg = ($reg).Count
$regcnt = 1
($tobeadded).Count

foreach($fn in $tobeadded) {
$global:path = "$env:TEMP\Temp"
    #if($tobeSID -contains ($fn | %{ $sp = $_.ToString().split('REG'); Write-Output $sp[0]})) {
    #if([bool]($tobeSID | Select-String -Pattern $fn) -eq $true) {
    $DestinationFN = "$global:path\$fn" + "Security Readiness Test Plan v2 8.xlsm"
    $tobepath = "$global:path\Security Readiness Test Plan v2 8.xlsm"
    #Write-Output "Checking if $DestinationFN already exists"
        if((Test-Path -Path $DestinationFN) -ne $true) {
            Write-Output "`nProcessing $DestinationFN in $global:path"
            $cp= [decimal]::round(($regcnt/$ttreg)*100)
            Write-Progress -id 1 -Activity "Processing $fn" -PercentComplete $cp -CurrentOperation "$cp% complete" -Status "Please wait."
            copy-item -Path $tobepath -Destination $DestinationFN -Force
            $Excel = New-Object -Com Excel.Application
            $Excel.Visible = $false
            $binding = "System.Reflection.BindingFlags" -as [type]
            $wb = $Excel.Workbooks.Open($DestinationFN)
            $BuiltinProperties = $wb.BuiltInDocumentProperties 
            $builtinPropertiesType = $builtinProperties.GetType()
            try {
                $BuiltInProperty = $builtinPropertiesType.invokemember("item",$binding::GetProperty,$null,$BuiltinProperties,$AryProperties) 
                $BuiltInPropertyType = $BuiltInProperty.GetType()
                $BuiltInPropertyType.invokemember("value",$binding::SetProperty,$null,$BuiltInProperty,$DestinationFN)
            } catch { 
                Write-Host "Unable to set value for $AryProperties"
            }
            $ws = $wb.Sheets.Item(2)
            $rowArr = @()
            if($42Array -contains $fn) { $rowArr += 44 }
            if($44Array -contains $fn) { $rowArr += 46 }
            if($45Array -contains $fn) { $rowArr += 47 }
            if($53Array -contains $fn) { $rowArr += 55 }
            if($54Array -contains $fn) { $rowArr += 56 }
            if($56Array -contains $fn) { $rowArr += 58 }
            if($57Array -contains $fn) { $rowArr += 59 }
            if( (($rowArr | Measure-Object).Count) -gt 0 ) {
                foreach($row in $rowArr) {
                    if($vv -eq $true) { Write-Host $fn
                                        Write-Host $ws.Name -NoNewline
                                        Write-Host " Row - $row | Col - $col"
                                      }
            
                    $cell = $ws.Cells.Item($row,$col)

                    if($vv -eq $true) { Write-Host "Before - " -NoNewLine
                                        Write-Host $cell.Value() 
                                      }
            
                    $cell.Value() = "Fail"
        
                    if($vv -eq $true) { Write-Host "After - " -NoNewLine
                                        Write-Host $cell.Value() 
                                      }
                }
            }
            if($wb.Saved -eq $false) { $wb.Save() }
            #$wb.Close()
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($BuiltinProperties) | Out-Null
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($wb) | Out-Null
            Remove-Variable -Name wb, BuiltinProperties
            $Excel.quit()
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Excel) | Out-Null
            Remove-Variable -Name Excel
            [gc]::collect()
            [gc]::WaitForPendingFinalizers()
        }
    #}
    $regcnt++
}    

#
#####> Top Right Quadrant Report
#
# Purpose: This will creates a version of the previous individal spreadsheets and produces a summarized report on what test criteria each workstation passed or failed on
# 
foreach($regs in $reg) {
[string]$regs = $regs
$outOBJ = New-Object -TypeName PSobject
$outOBJ | Add-Member -MemberType NoteProperty -Name workstation -Value $regs.ToString()

#Write-Output $regs
    if($42Array -contains $regs) {
        $outOBJ | Add-Member -MemberType NoteProperty -Name T42 -Value "X"
    }
    if($44Array -contains $regs) {
        $outOBJ | Add-Member -MemberType NoteProperty -Name T44 -Value "X"
    }
    if($45Array -contains $regs) {
        $outOBJ | Add-Member -MemberType NoteProperty -Name T45 -Value "X"
    }
    if($53Array -contains $regs) {
        $outOBJ | Add-Member -MemberType NoteProperty -Name T53 -Value "X"
    }
    if($54Array -contains $regs) {
        $outOBJ | Add-Member -MemberType NoteProperty -Name T54 -Value "X"
    }
    if($56Array -contains $regs) {
        $outOBJ | Add-Member -MemberType NoteProperty -Name T56 -Value "X"
    }
    if($57Array -contains $regs) {
        $outOBJ | Add-Member -MemberType NoteProperty -Name T57 -Value "X"
    }
$outOBJ | Select-Object workstation,T42,T44,T45,T53,T54,T56,T57 | Export-Csv -Path "$global:path\alerts\TopRightQuadrant.csv" -Force -NoTypeInformation -Append -NoClobber
}
$UpperRight = "$env:TEMP\Temp\alerts\TopRightQuadrant.csv"
Copy-Item -Path $UpperRight -Destination '\\lab.domain.com\sites\lab\Security Engineering\opsec\production validation\Results' -Force
#
#####> Copy and Move the Heatmaps
#
# This copies the heatmaps to the file share, then moves it into local folder
#
#$folderReference = "\\lab.domain.com\sites\lab\HeatMap"
#$folderDifference = "$env:TEMP\Temp"

#$FolderReferenceContents = Get-ChildItem $folderReference -Filter "T*.xlsm" | where-object {-not $_.PSIsContainer}
#$FolderDifferenceContents = Get-ChildItem $folderDifference -Filter "T*.xlsm" | where-object {-not $_.PSIsContainer}
<#%
# Only copy/move the
$ItemstoCopy = (Compare-Object -ReferenceObject $FolderReferenceContents -DifferenceObject $FolderDifferenceContents -Property ('Name', 'Length') -PassThru | where-object { $_.SideIndicator -eq '=>'}).FullName
$i = $ItemstoCopy.Count
$a = 1

$ItemstoCopy | ForEach-Parallel -MaxThreads 100 {
    $folderReference = "\\lab.domain.com\sites\lab\HeatMap"
    $folderDifference = "$env:TEMP\Temp"
    $folderHeatmaps = "$env:TEMP\Heatmaps"

    #Write-Output "-Path $file -Destination $folderReference"
    Copy-Item -Path "$folderDifference\$_" -Destination $folderReference -Force 
    Move-Item -Path "$folderDifference\$_" -Destination $folderHeatmaps -Force

}
%#>


Get-Variable | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue } 
