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
$AuditFN = $Dest + "\DumpRegValidate_" + (Get-Date).ToString("MMddyyyy") + ".csv"
Write-Verbose "Output will be written into $AuditFN"
foreach($Store in $Stores) {
    if($Store -notcontains $ArrayID) {
        if($Store -imatch "(T(\d){4}REG(\d){4})") { 
            $StoreID = ($Store.ToString() -split "REG")[0] 
        } else {
            $StoreID = $Store
        }
        for($i=1; $i -le 200; $i++){
            $workstation = $StoreID + "REG" + ($i).ToString().PadLeft(4,'0')
            Write-Verbose "Checking $StoreID -> $workstation"
            $outOBJ = New-Object -TypeName PSobject -ErrorAction SilentlyContinue
            $outOBJ | Add-Member -MemberType NoteProperty -Name StoreID -Value $StoreID   
            $outOBJ | Add-Member -MemberType NoteProperty -Name workstation -Value $workstation
            if((Test-Connection -BufferSize 32 -Count 1 -ComputerName $workstation -Quiet) -eq $true) {
                if((checkWMI $workstation) -eq $true) {
                    Write-Verbose "Access to $workstation's registry is allowed"
                    $chkSK = "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
                    $chkLD = "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\POS.exe"
                    if(([bool][Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$workstation).OpenSubKey($chkSK)) = $true) {  
                        Write-Verbose "Registry setting Enabled"
                        $dmpfolder = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$workstation).OpenSubKey($chkLD).GetValue('DumpFolder')
                        Write-Verbose "Dump Folder is set to $dmpfolder"
                        $outOBJ | Add-Member -MemberType NoteProperty -Name RegKeyStatus -Value "Enabled"
                        $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFolder -Value $dmpfolder
                        if(([bool](gci -Path \\$workstation\C$\Windows\Temp -Filter *.dmp)) -eq $true) {
                            [array]$dmpfndir = (gci -Path \\$workstation\C$\Windows\Temp -Filter *.dmp).Name
                            Write-Verbose "Dump files found: $dmpfndir"
                            $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFilename -Value $dmpfndir.ToString()
                        } else {
                            Write-Verbose "No Dump files were found: $dmpfndir"
                            $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFilename -Value "Not Found"
                        }
                    } else {
                        Write-Verbose "Registry not set for POS.exe dump files"
                        $outOBJ | Add-Member -MemberType NoteProperty -Name RegKeyStatus -Value "Not Enabled"
                        $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFolder -Value "NA"
                        $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFilename -Value "NA"
                    }  
                }
            } else {
                Write-Verbose "$workstation is not active."
                $outOBJ | Add-Member -MemberType NoteProperty -Name RegKeyStatus -Value "Not Active"
                $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFolder -Value "NA"
                $outOBJ | Add-Member -MemberType NoteProperty -Name DumpFilename -Value "NA"
            }
            $outOBJ | Select-Object StoreID,workstation,RegKeyStatus,DumpFolder,DumpFileName | Export-Csv -Path $AuditFN -Force -NoTypeInformation -Append -NoClobber
        }
        [array]$ArrayID = $Store
    }
}

$sw.Stop()
$ms = $sw.Elapsed.Milliseconds
$sec = $sw.Elapsed.Seconds
$min = $sw.Elapsed.Minutes
$hrs = $sw.Elapsed.Hours
$to = "$hrs`:$min`:$sec`:$ms"

Write-Verbose "Processed "
Write-Verbose $RegisterName.Count
Write-Verbose "In $to"
