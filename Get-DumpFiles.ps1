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
    [array]$Stores,
    [string]$Dest
)
function checkWMI ([string]$srv){  
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
$sw = [Diagnostics.Stopwatch]::StartNew()
foreach($StoreID in $Stores) {
    for($i=1; $i -le 200; $i++){ 
        $workstation = $StoreID + "REG" + ($i).ToString().PadLeft(4,'0')
        Write-Verbose "Checking $workstation"
        if((checkWMI $workstation) -eq $true) {
            Write-Verbose "Checking $workstation for dump files in Windows\Temp "  
            if(([bool](gci -Path \\$workstation\C$\Windows\Temp -Filter *.*dmp)) -eq $true) {
                Write-Verbose "Found one or more dump files in \\$workstation\C$\Windows\Temp"
                Write-Verbose "Making a copy of the dump file to $Dest"
                [array]$dmpfiles = (gci -Path \\$workstation\C$\Windows\Temp -Filter *.*dmp).Name
                foreach($dmpfile in $dmpfiles) {
                    $dmptime = ((gci -Path \\$workstation\C$\Windows\Temp -Filter $dmpfile).LastWriteTime).ToString("MMddyyyy")
                    $dmpfound = $Dest + "\" + $workstation + "_" + $dmptime + "_" + $dmpfile
                    Write-Verbose "Making a copy of $dmpfile to $dmpfound"
                    Copy-Item -Path \\$workstation\C$\Windows\Temp\$dmpfile -Destination $dmpfound
                }
            }
            $dmpstatus = $false
            $DumpFolder = $null
            $LD = @("LocalDumps","LocalDump")
            foreach($LocalDump in $LD) { 
                $chkLD = "SOFTWARE\Microsoft\Windows\Windows Error Reporting\" + $LocalDump + "\POS.exe"
                try {
                    if(([bool][Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$workstation).OpenSubKey($chkLD)) = $true) {
                        Write-Verbose "Found $chkLD registry setting on $workstation"
                        if(([bool][Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$workstation).OpenSubKey($chkLD).GetValue('DumpFolder')) = $true) {  
                            
                            $DumpFolder = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$workstation).OpenSubKey($chkLD).GetValue('DumpFolder')
                            Write-Verbose "The dump folder on $workstation is set to $DumpFolder"
                            if($DumpFolder -imatch "(windir)") { $tmpdir = "Windows\" + ($DumpFolder -replace "[%WINDIR%[\\]", "") } else { $tmpdir = $DumpFolder }
                            Write-Verbose "Checking in $tmpdir for Dump files"
                            if(([bool](gci -Path \\$workstation\C$\$tmpdir -Filter *.*dmp)) -eq $true) {
                                Write-Verbose "Found one or more dump files in $tmpdir"
                                [array]$dmpfiles = (gci -Path \\$workstation\C$\$tmpdir -Filter *.*dmp).Name
                                foreach($dmpfile in $dmpfiles) {
                                    $dmptime = ((gci -Path \\$workstation\C$\$tmpdir -Filter $dmpfile).LastWriteTime).ToString("MMddyyyy")
                                    $dmpfound = $Dest + "\" + $workstation + "_" + $dmptime + "_" + $dmpfile
                                    Write-Verbose "Making a copy of $dmpfile to $dmpfound"
                                    Copy-Item -Path \\$workstation\C$\$tmpdir\$dmpfile -Destination $dmpfound
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
            Write-Verbose "Checking $workstation for dump files in ProgramData\NCR\Log "
            if(([bool](gci -Path \\$workstation\C$\ProgramData\NCR\Log -Filter *.*dmp)) -eq $true) {
                Write-Verbose "Found one or more dump files in \\$workstation\C$\ProgramData\NCR\Log"
                Write-Verbose "Making a copy of the dump file to $Dest"
                [array]$dmpfiles = (gci -Path \\$workstation\C$\ProgramData\NCR\Log -Filter *.*dmp).Name
                foreach($dmpfile in $dmpfiles) {
                    $dmptime = ((gci -Path \\$workstation\C$\ProgramData\NCR\Log -Filter $dmpfile).LastWriteTime).ToString("MMddyyyy")
                    $dmpfound = $Dest + "\" + $workstation + "_" + $dmptime + "_" + $dmpfile
                    Write-Verbose "Making a copy of $dmpfile to $dmpfound"
                    Copy-Item -Path \\$workstation\C$\ProgramData\NCR\Log\$dmpfile -Destination $dmpfound
                }
            }
            Write-Verbose "Checking $workstation for dump files in ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Install\Logs "
            if(([bool](gci -Path "\\$workstation\C$\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Install\Logs" -Filter *.*dmp)) -eq $true) {
                Write-Verbose "Found one or more dump files in \\$workstation\C$\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Install\Logs"
                Write-Verbose "Making a copy of the dump file to $Dest"
                [array]$dmpfiles = (gci -Path "\\$workstation\C$\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Install\Logs" -Filter *.*dmp).Name
                foreach($dmpfile in $dmpfiles) {
                    $dmptime = ((gci -Path "\\$workstation\C$\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Install\Logs" -Filter $dmpfile).LastWriteTime).ToString("MMddyyyy")
                    $dmpfound = $Dest + "\" + $workstation + "_" + $dmptime + "_" + $dmpfile
                    Write-Verbose "Making a copy of $dmpfile to $dmpfound"
                    Copy-Item -Path "\\$workstation\C$\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Install\Logs\$dmpfile" -Destination $dmpfound
                }
            }
            $Watsons = @("ProgramData\Microsoft\Windows\WER\ReportArchive","ProgramData\Microsoft\Windows\WER\ReportQueue","Users\UserProfileName\AppData\Local\Microsoft\Windows\WER\ReportArchive","Users\UserProfileName\AppData\Local\Microsoft\Windows\WER\ReportQueue")
            Write-Verbose "Checking $workstation for dump files in Watson defined directories "
            foreach($Watson in $Watsons) {
                if(([bool](gci -Path "\\$workstation\C$\$Watson" -Filter *.*dmp)) -eq $true) {
                    Write-Verbose "Found one or more dump files in \\$workstation\C$\$Watson"
                    Write-Verbose "Making a copy of the dump file to $Dest"
                    [array]$dmpfiles = (gci -Path "\\$workstation\C$\$Watson" -Filter *.*dmp).Name
                    foreach($dmpfile in $dmpfiles) {
                        $dmptime = ((gci -Path "\\$workstation\C$\$Watson" -Filter $dmpfile).LastWriteTime).ToString("MMddyyyy")
                        $dmpfound = $Dest + "\" + $workstation + "_" + $dmptime + "_" + $dmpfile
                        Write-Verbose "Making a copy of $dmpfile to $dmpfound"
                        Copy-Item -Path "\\$workstation\C$\$Watson\$dmpfile" -Destination $dmpfound
                    }
                }
            }
            if(([bool](gci -Path "\\$workstation\C$\" -Filter *.*dmp)) -eq $true) {
                Write-Verbose "Found one or more dump files in \\$workstation\C$\"
                Write-Verbose "Making a copy of the dump file to $Dest"
                [array]$dmpfiles = (gci -Path "\\$workstation\C$\" -Filter *.*dmp).FullName
                foreach($dmpfile in $dmpfiles) {
                    $dmptime = ((gci -Path $dmpfile -Filter ($dmpfile).Name).LastWriteTime).ToString("MMddyyyy")
                    $dmpfound = $Dest + "\" + $workstation + "_" + $dmptime + "_" + ($dmpfile).Name
                    Write-Verbose "Making a copy of " + ($dmpfile).Name + " to $dmpfound"
                    Copy-Item -Path $dmpfile -Destination $dmpfound
                }
            }
        }
    }
}

$sw.Stop()
$ms = $sw.Elapsed.Milliseconds
$sec = $sw.Elapsed.Seconds
$min = $sw.Elapsed.Minutes
$hrs = $sw.Elapsed.Hours
$to = "$hrs`:$min`:$sec`:$ms"

Write-Verbose "Processed " -NoNewLine
Write-Verbose $RegisterName.Count -NoNewline
Write-Verbose " In $to"
