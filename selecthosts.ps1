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
    [string]$rptname,
    [switch]$lastdate,
    [string]$ldate
)
$vv = $true
if($path -ne $true) { $path = "$env:TEMP\Temp" }
if($workstations -ne $true) { $workstations = "workstations.csv" }
if($rptname -ne $true) { $rptname = "T*_*.xlsm" }
$lastdate = $true
$ldate = "8192016"
$Heatmaps = "$env:TEMP\Heatmaps"
#
#####> StoreIDS
#
# Export the following Splunk query to a file named "workstations.csv"
#
##> index=poshw fieldset=Evital workstation | table workstation | dedup workstation
#
##> Previously Processed Stores
if($lastdate -eq $true) {
    [array]$processedSID = ((gci -Path "$Heatmaps\$rptname").Name | %{ $sp = $_.ToString().split("REG"); if($sp[0] -notmatch "(workstation)") { Write-Output $sp[0] }} | Sort -Unique)
    #Write-Output "Processed"
    #Write-Output $processedSID
}
#
##> All of the Stores in Splunk
#if($vv -eq $true) { Write-Host "Processing workstations..." }
[array]$wrkstnids = (gc "$path\$workstations" | %{ $sp = $_.ToString().split("REG"); if($sp[0] -notmatch "(workstation)") { Write-Output $sp[0] }} | Sort -Unique)
#Write-Output "Current"
#Write-Output $wrkstnids
#
##> Get the Diff
if($lastdate -eq $true) {
    [array]$tobeSID = Compare-Object $processedSID $wrkstnids -PassThru
} else {
    $tobeSID = $wrkstnids
}
#
#####> Last Scheduled Scan
#
if($lastdate -eq $true) {
    if((Test-Path -Path "$env:TEMP\Temp\domains_*_T*.txt") -eq $true) {
        $f = ([datetime]::ParseExact((((gci -Path $path "domains_*_T*.txt").Name | %{ $sp = $_.ToString().split("_"); Write-Output $sp[1] } | measure -Maximum).Maximum),"MMddyyyy",$null))
        Write-Output $f | Out-File "$env:TEMP\Temp\lastdate.txt"
    } else {
        if((Test-Path -Path "$env:TEMP\Temp\lastdate.txt") -eq $true) {
            $f = gc "$env:TEMP\Temp\lastdate.txt"
        } else {
            if($ldate) {
                $f = [datetime]::ParseExact($ldate,"MMddyyyy",$null)
            } else {    
                $f = [datetime]::ParseExact("8182016","MMddyyyy",$null)
            }
        }
    }
} else {
    if($ldate) {
        $f = [datetime]::ParseExact($ldate,"MMddyyyy",$null)
    } else {    
        $f = Get-Date
    }
}
Write-Output $f
#####> Define workstations
#
# Based on the naming convention of the workstations name put them into types
#
if($vv -eq $true) { Write-Host "Organizing the workstations into types..." }
[array]$nosales = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0{2}(1{1}|2{1})"
$nosales = $nosales + (gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0{2}(3(1|2|3|4|5|6|7|8|9))")
$nosales = $nosales + (gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG01(81|9{1})")
[array]$bakery = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0{1,2}(4(0|1)))"
[array]$deli = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0{1,2}(4(2|3)))"
[array]$mobileshopper = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0{1,2}(4(4|5)))"
[array]$optical = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0{1,2}(4(6|7)))"
[array]$health = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0{1,2}(4(8|9)))"
[array]$mobilePOS = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0{1,2}(5{1,2}|6(0|1|2|3|4|5|6|7)))"
[array]$photofin = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0{1,2}(6(8|9)))"
$photostudio = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0070"
[array]$lanes = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0{1,2}(7(1|2|3|4|5|6|7|8|9)|8{1,2}|9{1,2}))"
$lanes = $lanes + (gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG010(1|2|3)")
$lanes = $lanes + (gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(13(4|5|6|7|8|9)|14{1}|150)")
[array]$jewelry = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(0(10(4|5|6)))"
[array]$pharmacy = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(10(7|8|9)|110)"
[array]$electronics = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(11(1|2|3|4)|12(0|1))"
[array]$c9shop = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(11(5|6))"
[array]$liquor = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(11(7|8))"
$tgtdommobile = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0119"
[array]$servicedesk = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(12(2|3|4|5|6|7|8)|18(2|3|4|5|6|7))" 
$openregs = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0129"
[array]$jamba = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(13(0|1))"
[array]$coldstone = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(13(2|3))"
[array]$foodave = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(15(1|2|3|4|5|6))"
[array]$starbucks = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(15(7|8|9))"
[array]$specvnt = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(16{1})"
[array]$selfco = gc "$path\$workstations" | Select-String -Pattern "T(\d){4}REG0(17{1}|180)"
#
#####> House Cleaning
#
if($vv -eq $true) { Write-Host "Cleaning house..." }
foreach($wrkstnid in $tobeSID) {
    if(Test-Path "$path\domains_$wrkstnid.txt") { Remove-Item -Force "$path\domains_$wrkstnid.txt" }
}
Move-Item -Path "$path\$rptname" -Destination $Heatmaps -Force
#
#####> Randomly select
#
# Randomly select 1 out of each workstation lane type
#
if($vv -eq $true) { Write-Host "Randomly selecting workstations to be scanned..." }
foreach($wrkstnid in $tobeSID) {
    if($wrkstnid) {
        $nosales | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $bakery | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $deli | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $mobileshopper | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $optical | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $health | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $mobilePOS | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $photofin | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $photostudio | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $lanes | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $jewelry | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $pharmacy | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $electronics | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $c9shop | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $liquor | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $tgtdommobile | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $servicedesk | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $openregs | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $jamba | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $coldstone | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $foodave | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $starbucks | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $specvnt | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
        $selfco | Select-String -Pattern "$wrkstnid" -AllMatches | Get-Random -Count 1 | Out-File "$path\domains_$wrkstnid.txt" -Append
    }
}
#
#####> House Cleaning
#
# Remove any blank lines in each of the files
#
if($vv -eq $true) { Write-Host "Cleaning house..." }
foreach($wrkstnid in $tobeSID) {
    (gc "$path\domains_$wrkstnid.txt") | ? {$_.trim() -ne "" } | set-content "$path\domains_$wrkstnid.txt"
}
#
#####> Set the schedule
#
if($vv -eq $true) { Write-Host "Setting up the schedule of when the workstations will be scannnd..." }
#
##> Set Parameters
#
$l = (( Get-ChildItem $path -Filter domains_T*.txt -Recurse | Where-Object {!$_.PSIsContainer} | Measure-Object ).Count) - 1
[array]$filename = Get-ChildItem $path -Filter domains_T* | Where-Object {!$_.PSIsContainer}
#
##> Create an array of dates from $f
#
$td = @()
for($i=0;$i -le ($l * 2);$i++){
    $s = [int](Get-Date (Get-Date $f).AddDays($i)).DayOfWeek
    if($s -notmatch "(0|6)") {
        $t = (Get-Date (Get-Date $f).AddDays($i))
        [array]$td += (Get-Date $t -Format 'Mdyyyy')
    }
}
#
##> Remove Holidays
#
[System.Collections.ArrayList]$dateArray = $td
$dateArray.Remove("732015")   # July 4th
$dateArray.Remove("972015")   # Labor Day
$dateArray.Remove("11262015") # Thannksgiving
$dateArray.Remove("11272015") # Thannksgiving
$dateArray.Remove("12242015") # Christmas Eve
$dateArray.Remove("12252015") # Christmas
$dateArray.Remove("12312015") # New Years Eve
$dateArray.Remove("112016")   # New Years Day
$dateArray.Remove("1182016")  # MLK
$dateArray.Remove("2152016")  # President's Day
$dateArray.Remove("3282016")  # Easter
$dateArray.Remove("5302016")  # Memorial Day
$dateArray.Remove("742016")   # July 4th
$dateArray.Remove("952016")   # Labor Day
$dateArray.Remove("11242016") # Thannksgiving
$dateArray.Remove("11252016") # Thannksgiving
$dateArray.Remove("12242016") # Christmas Eve
$dateArray.Remove("12252016") # Christmas
$dateArray.Remove("12312016") # New Years Eve
$dateArray.Remove("112016")   # New Years Day
#
##> Rename files
#
for($i=0;$i -le $l;$i++){
    $oldname = $filename[$i].FullName
    $a = $filename[$i].FullName.Split('_')
    $newname = $a[0] + "_" + $dateArray[$i] + "_" + $a[1]
    if((Test-Path -Path $newname) -ne $true) {
        Write-Host "$i | Rename $oldname to $newname"
        try {
            Rename-Item -Path $oldname -NewName $newname -force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Couldn't rename $oldname to $newname"
        }
    }
}
#
#####> Done
#
Get-Variable | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue } 
if($vv -eq $true) { Write-Host "Done!" }
