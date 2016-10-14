<#
.SYNOPSIS

Keylight API
version 1.0
Author: Rob Vance (http://www.ngosecurity.com)

	The MIT License
	-----------------------------------------------------------------------
	Copyright (c) 2016 NGO Security Solutions
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

TODO:

Fix up event log

#>
[cmdletbinding()]
param(
    [switch]$m,
    [switch]$s,
    [switch]$a,
    [switch]$c,
    [switch]$d,
    [switch]$e,
    [string]$f,
    [switch]$p,
    [switch]$ftp,
    [switch]$ftps,
    [switch]$v,
    [Parameter(ParameterSetName="Help")]
    [switch]$h,
    [Parameter(ParameterSetName="Help")]
    [switch]$help
)
switch ($PSCmdlet.ParameterSetName) {
  Help { Write-Host "Requesting assistance, one moment please..." -ForegroundColor Yellow }
}
#
####> Init Functions
#
# For use in the USAGE function
$global:scriptname = $MyInvocation.MyCommand.Name
#
function usage() { 
$helpfile = "

.SYNOPSIS
    Executes supported Keylight API v.4.4 Calls

    Script name: $scriptname
    Version    : 1.0
    Author     : Rob Vance (http://www.ngosecurity.com)

.DESCRIPTION
    The script generates the results to be sent to either ReportOne or ReportTwo

.SYNTAX

    .\$scriptname [[-ms|-ReportTwo] <CommonParameters>] [-filename <name>.<ext>]

    Parameter + Argument        ID
    ========================    ========================

    -m (required [or -s])       Run ReportOne Report
    -s (required [or -m])       Run ReportTwo Report
    -a (required [or -d|-p])    Send report as an Attachment via email
    -c (required)               Cleanup temp files (exclude to troubleshoot)
    -d (required [or -a|-p])    Secure copy to Destiniation
    -e (optional)               Eventlog
    -f <filename>               Final results Filename
    -p (required [or -a|-d])    Copy and Paste to Share folder
    -ftp                        Use FTP to transfer file
    -ftps                       Use FTP through SSL to transfer file
    -v (optional)               Verbose mode. Send everything to the Eventlog

    -h | help                   This display

.EXAMPLE
Create a report for (-m)reportone (or (-s)reporttwo) called (-f)ilename, (-c)lear 
any miscellaneous  logs, log it into the application (-e)vent log (-v)erbosely, and secure 
copy the filename to a predetermined (-d)estination. 

.\$scriptname -m -c -d -e -v -f ReportOne.xml

Create a report for (-m)reportone (or (-s)reporttwo) called (-f)ilename, (-c)lear 
any miscellaneous  logs, log it into the application (-e)vent log (-v)erbosely, than copy 
and (-p)aste the filename to a predetermined destination.

.\$scriptname -s -c -p -e -v -f ReportTwo.csv 

"
Write-Host $helpfile
exit
}
#
####> Call usage if asked
#
if($h -eq $true -or $help -eq $true) { usage }
if(($f.Length -lt 1) -or ([string]::IsNullOrWhiteSpace($f))) { usage }
#
function Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value;
    if($Invocation.PSScriptRoot) {
        return $Invocation.PSScriptRoot;
    } elseif($Invocation.MyCommand.Path) {
        return Split-Path $Invocation.MyCommand.Path
    } else {
        return $Invocation.InvocationName.Substring(0,$Invocation.InvocationName.LastIndexOf("\"));
    }
}
#
function scrubPWD($scrub) {
    if([regex]::matches($scrub,'\\').count -ge 2) {
        return ($scrub -replace '\\\\','\')
    }
}
$pwd = Get-ScriptDirectory
$tpwd = $pwd + "\Temp" 
if((Test-Path -PathType Container -Path $tpwd) -eq $false) {
    New-Item -ItemType Directory -Force -Path $tpwd | Out-Null
}
#
function cleanup($ignoreFile) {
    $excARR = [System.Collections.ArrayList]@("AES.key", "klextractor.ps1", "klparser.ps1", "Password.txt")
    if($excARR) { [void]$excARR.Add($ignoreFile) }
    Get-ChildItem $tpwd -Exclude $excARR | Where{ -not $_.PsIsContainer } | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Randomize-List {
   Param(
     [array]$InputList
   )
   return $InputList | Get-Random -Count $InputList.Count;
}
#
####> Add script to System's Application Event Logs
#
try {
    if([system.diagnostics.eventlog]::SourceExists($scriptname) -ne $true) { 
        [system.diagnostics.EventLog]::CreateEventSource($scriptname, “Application”) 
    }
} catch {
    $e = $false
    $v = $false
}
if($m) { $group = "ReportOne" }
if($s) { $group = "Sreporttwo" }
#
###########################> Presets <###########################
#
####> vvvvvvvvvvv Make changes as required here vvvvvvvvvvvvvvvvv
#
if($d) {
    if($m) {
        $SSHSever = "10.0.0.1"
        $SSHPort = "22"
        $SSHDest = "" 
        $SSHUser = "" 
        $SSHPass = ""  
        $SSHKey = ""
        $SSHFinger = ""
    }
    if($s) {
        $SSHSever = "10.0.0.2"
        $SSHPort = "22"
        $SSHDest = "" 
        $SSHUser = "" 
        $SSHPass = "" # Not required if public key is being used
        $SSHKey = ""
        $SSHFinger = ""
    }
}
if($ftp -or $ftps) {
    if($m) {
        $FTPSever = "IPADDR"
        $FTPDest = "/path/to/" 
        $FTPUser = "user" 
        $FTPPass = "Pass" 
    }
    if($s) {
        $FTPSever = "IPADDR"
        $FTPDest = "/path/to/" 
        $FTPUser = "user" 
        $FTPPass = "Pass" 
    }
}
#
# Supplier Inventory
$API_CID = "1"
#
$From = "keylight@targetco.com"
if($m) {
    $To = "ReportOnesupport@targetco.com"
}
if($s) {
    $To = "thiagarajan.natchiappan@targetco.com"
}
#
$Cc = "tgt.user1@targetco.com","tgt.user2@targetco.com"
#$Attachment = $rptNAME
$Subject = "Daily $f File"
$Body = "Please see the following attachment ($f) for the $group group."
# Can't seem to resolve to smtp.relay.com with is round robin of SMTP relays (of two).  But can access can access either via
# the IP Address.
$RNDRobin = "10.0.0.3","10.0.0.4","10.0.0.5","10.0.0.6"
$SMTPServer = (Randomize-List -InputList $RNDRobin)[0]
$SMTPPort = "25"
#
####> ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#
####> Paths and Temporary Files
#
$rptNAME = scrubPWD($tpwd + "\" + $f)
#
$xmltmp = scrubPWD($tpwd + "\tmp_" + $f)
#
$GDRSO = scrubPWD($tpwd + "\GetDetailRecordsOutput.xml")
#
$outTMP = scrubPWD($tpwd + "\outTMP.csv")
$outCSV = scrubPWD($tpwd + "\outCSV.csv")
$outCSV2 = scrubPWD($tpwd + "\outCSV2.csv")
$outCSV3 = scrubPWD($tpwd + "\outCSV3.csv")
#
$tmpReportTwo = scrubPWD($tpwd + "\tmpReportTwo.csv")
#
# NOTE: The ColName can be anything, but the KLID must match whatever the Id's of the fields of interest
if($m) { 
    $published = $true
    $fields = [ordered]@{ ColName1 = KLID1;
                 ColName2 = KLID2 }
}
if($s) {
    $published = $false
    $fields = [ordered]@{ ColName1 = KLID1;
                 ColName2 = KLID2 }
}
#
####> Remove old files
#
if($c) { cleanup }
#
###########################> Functions <###########################
#
#
####> Create an array of fields to keep in the final report
#
[System.Collections.ArrayList]$keepFLDS = $fields.Keys | % ToString
$keepFLDS.Remove('WorkflowStage')
#
####> Header - Convert $fields to a string 
#
$selectobj = ""
foreach($item in ($fields.GetEnumerator())) {
    $selectobj = $selectobj + $item.Name + ","
}
# rm comma at the end
$selectobj = $selectobj -replace ",$"
#
####> Covert CSV to XML
#
function New-Xml {
param($RootTag='Assessments',$ItemTag=”Assessment”, $ChildItems, $Attributes=$Null)
    Begin {
        $xml = “<$RootTag>`n”
    }
    Process {
        $xml += ” <$ItemTag”
        if ($Attributes) {
            foreach ($attr in $_ | Get-Member -type *Property $attributes){ 
                $name = $attr.Name
                $xml += ” $Name=`”$($_.$Name)`””
            }
        }
        $xml += “>`n”
        foreach ($child in $_ | Get-Member -Type *Property $childItems){
            $Name = $child.Name
            if (($Name -match 'CriticalOpenItems') -or ($Name -match 'HighOpenItem')) {
                if ($_.$Name -lt 1) {
                    $xml += ” <$Name><![CDATA[0]]></$Name>`n”
                } else {
                    $xml += ” <$Name><![CDATA[" + $($_.$Name) + "]]></$Name>`n”
                }
            } else {
                $xml += ” <$Name><![CDATA[" + $($_.$Name) + "]]></$Name>`n”
            }
        }
        $xml += ” </$ItemTag>`n”
    }
    End {
        $xml += “</$RootTag>`n”
        $xml
    }
}
#
####> Tidy up the XML file
#
function Format-XML ([xml]$xml, $Indent=2) { 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $xmlWriter.Formatting = “Indented” 
    $xmlWriter.Indentation = $Indent 
    $xml.WriteContentTo($XmlWriter) 
    $XmlWriter.Flush() 
    $StringWriter.Flush() 
    Write-Output $StringWriter.ToString() 
}
#
####> Extracts the values from XML based on $fields
#
function add-OBJ($varName, $id, $varKey) {
    return (($XmlDocument.ArrayOfDynamicRecordItem.DynamicRecordItem | ?{ $_.id -eq $id }).FieldValues).KeyValuePair | ?{ $_.key -eq $varKey } | %{ $_.value.DisplayName }
}
#
####> Extracts the values from either value or DisplayName
#     and save the details into one CSV file i.e., $outCSV2
#
function subXML($ids) {
    # Orignial Record
    $GDRSO = scrubPWD($tpwd + "\GetRecord_" + $ids + "_Output.xml")
    # Scrubbed Record
    $GDRSO2 = scrubPWD($tpwd + "\GR_" + $ids + "_Output.xml")
    #
    $outOBJ2 = New-Object PSObject
    # Remove Attributes
    $lookupTable = @{
        "xmlns:a=`"http://www.w3.org/2001/XMLSchema`"" = ""
        " i:type=`"a:string`"" = ""
        " i:type=`"a:boolean`"" = ""
        " i:type=`"a:dateTime`"" = ""
        " i:type=`"a:decimal`"" = ""
        " i:nil=`"true`"" = ""
        " i:type=`"DynamicRecordList`"" = ""
        " i:type=`"DynamicRecordItem`"" = ""
    }
    Get-Content -Path $GDRSO | ForEach-Object { 
        $line = $_
        $lookupTable.GetEnumerator() | ForEach-Object {
            if ($line -match $_.Key) {
                $line = $line -replace $_.Key, $_.Value
            }
        }
       $line
    } | Set-Content -Path $GDRSO2
    # Get clean XML file
    [xml]$xmlObject = Get-Content $GDRSO2
    $xmldata = $xmlObject.DynamicRecordItem.FieldValues
    # comb through XML
    foreach($item in ($fields.GetEnumerator() | sort -Property value)) {
        $name = $item.Key
        switch -Regex ($item.Value) {
        '(1)' { $results = $xmldata.KeyValuePair | ?{ $_.key -eq $item.Value } | %{ $_.value } }              # fields labeled as value
        '(2)' { $results = "https://keylight.targetco.com/Custom/ViewRecord.aspx?tableId=$API_CID&id=$ids" }  # fields that are not define
        '(3)' { $results = $xmldata.KeyValuePair | ?{ $_.key -eq $item.Value } | %{ if($m) { ($_.value -split 'T').GetValue(0) } else { %{ $_.value } } } } # fields that have data time stamps          
        default { $results = $xmldata.KeyValuePair | ?{ $_.key -eq $item.Value } | %{ $_.value.DisplayName } } # fields labeled as DisplayName
        }
        Write-Verbose "Name $name Results $results"
        $outOBJ2 | Add-Member -MemberType NoteProperty -Name $name -Value $results
    }
    $outOBJ2 | Select-Object -PipelineVariable $selectobj | Export-Csv -Path $outCSV2 -Force -NoTypeInformation -Append -NoClobber
}
#
####> Logic starts here
#
try {
    .\klapiscript.ps1 -g GetDetailRecords -c $API_CID
    if($e -and $v) {
        $ErrMsg = "Request to the API server was successful.  Executed a GetDetailRecords for Compontent Id $API_CID"
        Write-EventLog -LogName Application -EntryType Information -EventId 1 -Source $scriptname -Message $ErrMsg
    }
} catch {
    if($e) {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        $ErrMsg = "$ErrorMessage `n`n $FailedItem `n`n Could not access the API server.  Possible failures due to: `n Credentials `n API Listener"
        Write-EventLog -LogName Application -EntryType Error -EventId 1 -Source $scriptname -Message $ErrMsg
    }
}
#
[xml]$XmlDocument = Get-Content -Path $GDRSO
$xmldata = $XmlDocument.ArrayOfDynamicRecordItem.DynamicRecordItem
#
####> Parse XML for elements as defined by $fields and save as CSV
#
foreach($id in $xmldata.Id) {
$outOBJ = New-Object PSObject
$outOBJ | Add-Member -MemberType NoteProperty -Name "Id" -Value $id
    foreach($item in ($fields.GetEnumerator() | sort -Property value)) {  
        $outOBJ | Add-Member -MemberType NoteProperty -Name $item.Key -Value (add-OBJ $item.Key $id $item.Value)
    }
    $outOBJ | Select-Object -PipelineVariable $selectobj | Export-Csv -Path $outCSV -Force -NoTypeInformation -Append -NoClobber
}
#
####> Get all records where the WorkflowStage is identified as Published
# 
if($published) {
    Import-Csv -Path $outCSV | Where { $_.WorkflowStage -cmatch "Published" } | Sort-Object -Property Id -Unique | Export-Csv -Path $outTMP -Force -NoTypeInformation -Append -NoClobber
} else {
    Import-Csv -Path $outCSV | Sort-Object -Property Id -Unique | Export-Csv -Path $outTMP -Force -NoTypeInformation -Append -NoClobber
}
#
# TEMP - Ignore record Id 40 : Where { $_.Id -notmatch '40'}
# Renew - Import-Csv $outTMP | Select -ExpandProperty Id 
#
####> Parse through the each file created for each record from the previous steps
#
$idtmp = @()
$idtmp = Import-Csv $outTMP | Select -ExpandProperty Id
#$idtmp = (Import-Csv $outTMP | Where { $_.Id -notmatch '40'} | Select -ExpandProperty Id )
#
foreach($ids in $idtmp) {
    .\klapiscript.ps1 -g GetRecord -c $API_CID -r $ids -o $ids
    subXML $ids
}
#
####> Create reports accordings to requirements
#
if($m) {
    #
    ####> Remove entire column from CSV file
    #
    Import-CSV $outCSV2 | Select-Object $keepFLDS | Export-CSV $outCSV3 -NoTypeInformation
    #
    ####> Convert CSV to XML
    #
    Write-Output '<?xml version="1.0" encoding="UTF-8"?>' | Out-File $xmltmp
    $TxtAfter1 = '<Assessments xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="Schema.xsd">'
    Import-Csv -Path $outCSV3 | New-XML -RootTag 'Assessments' -ItemTag Assessment -ChildItems ($selectobj -split ',') | out-file $xmltmp -append
    Format-XML ([xml](cat $xmltmp)) -Indent 4 | Out-File $rptNAME
    #
    ####> Insert XSD in ROOTITEM
    #
    $tmpxml = gc $rptNAME
    # Set to Row 2 (starting from zero)
    $tmpxml[1] = $TxtAfter1 
    $tmpxml | sc $rptNAME
}
if($s) {
    #
    ####> Top of Page
    #
    "$f - " + (Get-ChildItem $outCSV2).CreationTime | Set-Content $tmpReportTwo
    Get-Content $outCSV2 | Add-Content $tmpReportTwo
    #
    ####> Bottom of Page
    #
    "Total Records: " + $idtmp.Count | Add-Content $tmpReportTwo
    #
    ####> Transform delimiters from comma to pipe
    #
    (Get-Content -Path $tmpReportTwo) -replace ',','|' | Set-Content $rptNAME
    #
}
#
####> Secure Copy
#
if($d) {
    try {
        # Refer to https://winscp.net/eng/docs/script_upload_file_list
        # Load WinSCP .NET assembly
        Add-Type -Path "C:\Program Files (x86)\WinSCP\WinSCPnet.dll"
        # Set up session options
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
            Protocol = [WinSCP.Protocol]::Scp
            HostName = $SSHSever
            UserName = $SSHUser
            SshHostKeyFingerprint = $SSHFinger
            SshPrivateKeyPath = $SSHKey
            TimeoutInMilliseconds = 600000
        }
        $sessionOptions.AddRawSettings("AgentFwd", "1")
        $sessionOptions.AddRawSettings("AuthKI", "0")
        $sessionOptions.AddRawSettings("Ssh2DES", "1")
        $sessionOptions.AddRawSettings("Cipher", "aes,blowfish,3des,chacha20,arcfour,des,WARN")
        $sessionOptions.AddRawSettings("KEX", "ecdh,dh-gex-sha1,dh-group14-sha1,dh-group1-sha1,rsa,WARN")
        $sessionOptions.AddRawSettings("AddressFamily", "1")
        $sessionOptions.AddRawSettings("RekeyBytes", "0")
        $sessionOptions.AddRawSettings("RekeyTime", "0")
        $sessionOptions.AddRawSettings("Shell", "/bin/ksh")
        $sessionOptions.AddRawSettings("ClearAliases", "0")
        $sessionOptions.AddRawSettings("UnsetNationalVars", "0")
        $sessionOptions.AddRawSettings("SCPLsFullTime", "1")
        $sessionOptions.AddRawSettings("LookupUserGroups2", "1")
        $sessionOptions.AddRawSettings("SftpServer", $SSHDest)
        $session = New-Object WinSCP.Session
        try {
            # Connect
            $session.Open($sessionOptions)
            # Upload files
            $transferOptions = New-Object WinSCP.TransferOptions
            $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
            Write-Debug "Transfering $rptNAME to $SSHDest..."
            $transferResult = $session.PutFiles($rptNAME, $SSHDest, $False, $transferOptions)
            if($transferResult.IsSuccess -and $e -and $v) {
                Write-Debug "File $rptNAME transfered to $SSHDest"
                $ErrMsg = "The $scriptname successfully transfered $f via FTP to $sourceuri"
                Write-EventLog -LogName Application -EntryType Information -EventId 2 -Source $scriptname -Message $ErrMsg
            } 
        } catch {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            $ErrMsg = "$ErrorMessage `n`n $FailedItem `n`n Could not send $rptNAME via Secure Copy."
            Write-EventLog -LogName Application -EntryType Error -EventId 2 -Source $scriptname -Message $ErrMsg
        } finally {
            $session.Dispose()
        }
    } catch {
        if($e) {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            $ErrMsg = "$ErrorMessage `n`n $FailedItem `n`n Could not access $SSHSever on port $SSHPort."
            Write-EventLog -LogName Application -EntryType Error -EventId 2 -Source $scriptname -Message $ErrMsg
        }
    }
}
#
####> Copy and Paste
#
if($p) {
    try {
        Copy-Item -Path $rptNAME -Destination $pasteDST
        if($e -and $v) {
            $ErrMsg = "The $scriptname successfully copied $f to $pasteDST"
            Write-EventLog -LogName Application -EntryType Information -EventId 3 -Source $scriptname -Message $ErrMsg
        }
    } catch {
        if($e) {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            $ErrMsg = "$ErrorMessage `n`n $FailedItem `n`n Could not copy $rptNAME to $pasteDST."
            Write-EventLog -LogName Application -EntryType Error -EventId 3 -Source $scriptname -Message $ErrMsg
        }
    }
}
#
####> Email
#
if($a) {
    try {
        Send-MailMessage -From $From -to $To -Cc $Cc -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -Attachments $rptNAME
        if($e -and $v) {
            $ErrMsg = "The $scriptname successfully sent $f via email to $To and $Cc"
            Write-EventLog -LogName Application -EntryType Information -EventId 4 -Source $scriptname -Message $ErrMsg
        }
    } catch {
        if($e) {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            $ErrMsg = "$ErrorMessage `n`n $FailedItem `n`n Could not send $f via email."
            Write-EventLog -LogName Application -EntryType Error -EventId 4 -Source $scriptname -Message $ErrMsg
        }
    }
}
#
####> FTP/FTPS
#
if($ftp -or $ftps) {
    try {
        if($ftp) {
            $webclient = New-Object System.Net.WebClient 
            $webclient.Credentials = New-Object System.Net.NetworkCredential($FTPUser,$FTPPass) 
            $uri = New-Object System.Uri($FTPServer+$f) 
            $webclient.UploadFile($uri, $rptNAME) 
            if($e -and $v) {
                $ErrMsg = "The $scriptname successfully transfered $f via FTP to $sourceuri"
                Write-EventLog -LogName Application -EntryType Information -EventId 5 -Source $scriptname -Message $ErrMsg
            }
        }
        if($ftps) {
            try {
                # Refer to http://winscp.net
                # Load WinSCP .NET assembly
                Add-Type -Path "C:\Program Files (x86)\WinSCP\WinSCPnet.dll"
                # Set up session options
                $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
                    Protocol = [WinSCP.Protocol]::Scp
                    HostName = $SSHSever
                    UserName = $SSHUser
                    SshHostKeyFingerprint = $SSHFinger
                    SshPrivateKeyPath = $SSHKey
                    TimeoutInMilliseconds = 600000
                }
                $sessionOptions.AddRawSettings("AgentFwd", "1")
                $sessionOptions.AddRawSettings("AuthKI", "0")
                $sessionOptions.AddRawSettings("Ssh2DES", "1")
                $sessionOptions.AddRawSettings("Cipher", "aes,blowfish,3des,chacha20,arcfour,des,WARN")
                $sessionOptions.AddRawSettings("KEX", "ecdh,dh-gex-sha1,dh-group14-sha1,dh-group1-sha1,rsa,WARN")
                $sessionOptions.AddRawSettings("AddressFamily", "1")
                $sessionOptions.AddRawSettings("RekeyBytes", "0")
                $sessionOptions.AddRawSettings("RekeyTime", "0")
                $sessionOptions.AddRawSettings("Shell", "/bin/ksh")
                $sessionOptions.AddRawSettings("ClearAliases", "0")
                $sessionOptions.AddRawSettings("UnsetNationalVars", "0")
                $sessionOptions.AddRawSettings("SCPLsFullTime", "1")
                $sessionOptions.AddRawSettings("LookupUserGroups2", "1")
                $sessionOptions.AddRawSettings("SftpServer", $SSHDest)
                $session = New-Object WinSCP.Session
                try {
                    # Connect
                    $session.Open($sessionOptions)
                    # Upload files
                    $transferOptions = New-Object WinSCP.TransferOptions
                    $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
                    Write-Debug "Transfering $rptNAME to $SSHDest..."
                    $transferResult = $session.PutFiles($rptNAME, $SSHDest, $False, $transferOptions)
                    if($transferResult.IsSuccess -and $e -and $v) {
                        Write-Debug "File $rptNAME transfered to $SSHDest"
                        $ErrMsg = "The $scriptname successfully transfered $f via FTP to $sourceuri"
                        Write-EventLog -LogName Application -EntryType Information -EventId 2 -Source $scriptname -Message $ErrMsg
                    } 
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    $FailedItem = $_.Exception.ItemName
                    $ErrMsg = "$ErrorMessage `n`n $FailedItem `n`n Could not send $rptNAME via Secure Copy."
                    Write-EventLog -LogName Application -EntryType Error -EventId 2 -Source $scriptname -Message $ErrMsg
                } finally {
                    $session.Dispose()
                }
            } catch {
                if($e) {
                    $ErrorMessage = $_.Exception.Message
                    $FailedItem = $_.Exception.ItemName
                    $ErrMsg = "$ErrorMessage `n`n $FailedItem `n`n Could not access $SSHSever on port $SSHPort."
                    Write-EventLog -LogName Application -EntryType Error -EventId 2 -Source $scriptname -Message $ErrMsg
                }
            }
        }
    } catch {
        if($e) {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            $ErrMsg = "$ErrorMessage `n`n $FailedItem `n`n Could not FTP $rptNAME to $sourceuri."
            Write-EventLog -LogName Application -EntryType Error -EventId 5 -Source $scriptname -Message $ErrMsg
        }
    }
}
#
####> Cleanup
#
if($c) { cleanup $f }
#
####> Fin
