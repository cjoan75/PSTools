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
    [Alias('cn')][String[]]$ComputerName=$Env:COMPUTERNAME,
    [String]$CopyTo
)
$Obj = @()
$i = 1
foreach($Computer in $ComputerName) {
    if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $Computer -Quiet) {
        $dmpstatus = $false
        $DumpFolder = $null
        $LD = @("LocalDumps","LocalDump")
        foreach($LocalDump in $LD) { 
            $chkLD = "SOFTWARE\Microsoft\Windows\Windows Error Reporting\" + $LocalDump + "\POS.exe"
            try {
                if(([bool][Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer).OpenSubKey($chkLD)) = $true) {
                    if(([bool][Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer).OpenSubKey($chkLD).GetValue('DumpFolder')) = $true) {  
                        $RegistryKey = "Enabled"
                        $DumpFolder = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer).OpenSubKey($chkLD).GetValue('DumpFolder')
                        if($DumpFolder -imatch "(windir)") { $tmpdir = "Windows\" + ($DumpFolder -replace "[%WINDIR%[\\]", "") } else { $tmpdir = $DumpFolder }
                        if(([bool](gci -Path \\$Computer\C$\$tmpdir -Filter *.dmp)) -eq $true) {
                            $DumpFilename = (gci -Path \\$Computer\C$\$tmpdir -Filter *.dmp).Name
                            if($CopyTO) {
                                $destFilename = $CopyTo + "\" + ($Computer.ToUpper()).Trim() + "_" + $DumpFilename
                                Copy-Item -Path \\$Computer\C$\$tmpdir\$DumpFilename -Destination $destFilename
                            }
                            $cclookup = Select-String -Path \\$Computer\C$\$tmpdir\$DumpFilename -Pattern "^((4|5)(\d){15}|5(1|2|3|4)(\d){14}|(34|35|36|37|38)(\d){13}|30(0|1|2|3|4|5)(\d){13}|60(11|65)(\d){12}|(2131|1800)(\d){12})$" -AllMatches| %{$_.Matches}| %{$_.Value}
                            if(([bool]($cclookup)) -eq $true) {
                                $NAPExposed = "Yes"
                            } else {
                                $NAPExposed = "No"
                            } 
                        } else {
                            $DumpFilename = "Not Found"
                            $NAPExposed = "No"
                        }
                    } else {
                        $DumpFolder = "Not Found"
                        $NAPExposed = "No"
                    }
                } else {
                    $RegistryKey = "Unk"
                    $DumpFolder = "Unk"
                    $DumpFilename = "Unk"
                    $NAPExposed = "Unk"
                }
            } catch {
                continue
            }
        }
        $outSTR = "$Computer$RegistryKey$DumpFolder$DumpFilename$NAPExposed"
        if($outSTR -notcontains $outARRAY) {
            $OutputString = [string]""
            $OutputString += ($Computer.ToUpper()).Trim() + "," + $RegistryKey + "," + $DumpFolder + "," + $DumpFilename + "," + $NAPExposed
            $Obj += $OutputString
            [array]$outARRAY = $outSTR
        }
    }
    $Obj
}
