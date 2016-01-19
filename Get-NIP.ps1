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

.DESCRIPTION

This is the example of a stand alone script designed to audit the workstations.

If the logic is triggered the output is sent to a MS Excel compatible CSV 
file.

And the results are sent to an email account.

.PARAMETERS ComputerName

The workstation to audit

.PARAMETERS email

The email address to sent the results to

.PARAMETERS outFN

The directory and filename to write the results into

.EXAMPLE

To send an email with the results 

gc $env:TEMP\workstations | %{ .\example.ps1 -ComputerName $_ -email rvance@ngosecurity.com }

OR

To only write the results

gc $env:TEMP\workstations | %{ .\example.ps1 -ComputerName $_ -outFN $env:TEMP\panpinaudit.csv }

OR

To send an email with the results with the filename and output whats happening to the screen

gc $env:TEMP\workstations | %{ .\example.ps1 -ComputerName $_ -email rvance@ngosecurity.com -outFN $env:TEMP\panpinaudit.csv -Verbose }

#>
[cmdletbinding()]
param(
    [string]$ComputerName,
    [string]$email,
    [string]$outFN
)
Write-Verbose "A message will be sent to $email"
Write-Verbose "The output file is set to $outFN"
foreach($Computer in $ComputerName) {
    # Check if the name is either the hostname or FQDN
    switch($Computer) {
        # if FQDN (i.e., hostname.domain.com)
        { $_ -match "." -and $_ -match "com" } { $logfn = "log" + ((($Computer.split("."))[0]).ToUpper() | %{ ($_.split("REG"))[3] }) + ".txt" }
        # if hostname (i.e., hostname)
        default { $logfn = "log" + (($_.ToUpper()).split("REG"))[3] + ".txt" }
    }
    # Check to see if the host is active
    if((Test-Connection -BufferSize 32 -Count 1 -ComputerName $Computer -Quiet) -eq $true) {
    Write-Verbose "$Computer is Active"
        # Check if log file exists
        if((Test-Path \\$Computer\C$\Logs\$logfn -ErrorAction SilentlyContinue) -eq $true) {
        Write-Verbose "$logfn exists on $Computer"
            # Capture the log file where the field 9F34 exists 
            foreach($line in (Select-String -Path \\$Computer\C$\Logs\$logfn -Pattern "(\b(9F34[-](\d){6})\b)" -AllMatches)) {
            Write-Verbose $line
                # Replace [1c] with pipes "|" for each matching lines
                $a = ($line.ToString() -replace "\[1C\]","|").TrimEnd("]").Split("|") | Where-Object {$_ -ne " "}
                # Parse out the line
                foreach($b in $a) {
                    # Instead of a bunch of if/then
                    switch($b) {
                        # Capture each field based on match
                        # Ad - Transaction Date
                        {$_ -match "Ad(\d){14}" } { $Ad = ($_.ToString().Split("Ad"))[2] }
                        # Ah - Transaction Number
                        {$_ -match "Ah" } { $Ah = ($_.ToString().Split("Ah"))[2] }
                        # Bf - Entry Type - Swipe or EMV
                        {$_ -match "Bf(E|S)" } { $Bf = ($_.ToString().Split("Bf"))[2] }
                        # Bq - Card Type - Visa
                        {$_ -match "Bq" } { $Bq = ($_.ToString().Split("Bq"))[2] }
                        # Ic - ADEVICE Serial Number
                        {$_ -match "Ic(\d){3}[-](\d){3}[-](\d){3}" } { $Ic = ($_.ToString().Split("Ic"))[2] }
                        # Ig - Did the ADEVICE do its job with the NAP (Ig4)
                        {$_ -match "Ig" } { $Ig = $_.ToString() }
                        # Field that is 20 characters long with a number followed by a letter, etc.
                        {$_ -match "((\d)[1}[A-Z](\d){11}[A-Z](\d){3,5})" } { $VSN = $_.ToString() }
                        # 9F34 - the 2nd Byte of 3 - Is the NIP do its jobed
                        {$_ -match "(9F34)" } { $NIP = (($_.Split("-",2,[System.StringSplitOptions]::RemoveEmptyEntries))[1]).SubString(2,2) }
                    }
                }
                    # Create a string
                    $chkSTR = "$Computer$Ad$Ah$Bf$Bq$Ic$Ig$VSN$NIP"
                    # Check if the array $outARRAY does not contain the $chkSTR
                    # If true then set the custom objects
                    if($chkSTR -notcontains $outARRAY) {
                        Write-Host $chkSTR -ForegroundColor Green
                        # Create a custom object
                        $outOBJ = New-Object -TypeName PSobject -ErrorAction SilentlyContinue 
                        $outOBJ | Add-Member -MemberType NoteProperty -Name workstation -Value $Computer
                        $outOBJ | Add-Member -MemberType NoteProperty -Name TDate -Value $Ad
                        $outOBJ | Add-Member -MemberType NoteProperty -Name TNumb -Value $Ah
                        $outOBJ | Add-Member -MemberType NoteProperty -Name EType -Value $Bf
                        $outOBJ | Add-Member -MemberType NoteProperty -Name CType -Value $Bq
                        $outOBJ | Add-Member -MemberType NoteProperty -Name ADEVICESN -Value $Ic
                        $outOBJ | Add-Member -MemberType NoteProperty -Name DidItNAP -Value $Ig
                        $outOBJ | Add-Member -MemberType NoteProperty -Name VSN -Value $VSN
                        $outOBJ | Add-Member -MemberType NoteProperty -Name DoItNIP -Value $NIP
                        $outOBJ | Add-Member -MemberType NoteProperty -Name Raw -Value $line
                        [array]$outARRAY = $chkSTR
                    } else {
                        # String was already seen
                        Write-Host "Duplicate - $chkSTR" -ForegroundColor DarkRed
                    }
                    # If object isn't empty            
                    if($outOBJ) {
                        if($NIP) {
                            # Pipe object with the following fields into a CSV formatted file
                            $outOBJ | Select-Object workstation,TDate,TNumb,EType,CType,ADEVICESN,DidItNAP,VSN,DoItNIP,Raw | Export-Csv -Path $outFN -Force -NoTypeInformation -Append -NoClobber
                            # Check if the output file exists
                            if((Test-Path $outFN -ErrorAction SilentlyContinue) -eq $true) { Write-Verbose "Wrote the following $outOBJ to $outFN" }
                        }
                    }
            }
        }
    }
}
# If email parameter is defined
if($sendto) {
    Write-Verbose "Sending an email to email"
    # And the a file exists
    if((Test-Path $outFN -ErrorAction SilentlyContinue) -eq $true) {
        $From = "rvance@ngosecurity.com"
        $To = email
        $Attachment = $outFN
        $Subject = "Results of Audit"
        $Body = "Attached is the results of an audit completed on " + (get-date)
        $SMTPServer = "smtp.domain.com"
        $SMTPPort = "25"
        # Send an email
        Write-Verbose "Sending and email -From $From -to $To -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -Attachments $Attachment"
        Send-MailMessage -From $From -to $To -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -Attachments $Attachment -ErrorAction Stop
    }
}
