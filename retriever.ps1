<#
.SYNOPSIS
    Executes supported Keylight API v.4.4 Calls

    Script name: $scriptname
    Version    : 1.0-4.4
    Author     : Rob Vance (http://www.ngosecurity.com)

.DESCRIPTION
    This script executes the various capabilities available through the Keylight API. The script
    is based on what was available in v4.4 of the guide. (Refer to the guide for details on how to 
    utilize the API for your specific needs.) 

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

#>
[cmdletbinding()]
param(
    [Parameter(Mandatory, ParameterSetName="RunFunction")]
    [ValidateSet('GetComponentList',
                 'GetComponent',
                 'GetComponentByAlias',
                 'GetFieldList',
                 'GetField',
                 'GetRecord', 
                 'GetDetailRecord',
                 'GetLookupReportColumnsFields',
                 'GetRecordAttachment',
                 'GetRecordAttachments',
                 'GetRecordCount',
                 'GetRecords',
                 'DeleteRecord',
                 'CreateRecord',
                 'UpdateRecord',
                 'GetDetailRecords',
                 'UpdateRecordAttachments',
                 'DeleteRecordAttachments')]
    [string]$g,
    [ValidateLength(1,1000)]
    [ValidatePattern("\d*")]
    [string]$c,
    [ValidateLength(1,1000)]
    [ValidatePattern("\d*")]
    [string]$f,
    [ValidateLength(1,1000)]
    [ValidatePattern("\d*")]
    [string]$p,
    [ValidateLength(1,1000)]
    [ValidatePattern("\d*")]
    [string]$a,
    [ValidateLength(1,1000)]
    [ValidatePattern("\d*")]
    [string]$r,
    [ValidateLength(1,1000)]
    [ValidatePattern("\d*")]
    [string]$o,
    [string]$d,
    [Parameter(ParameterSetName="Help")]
    [switch]$h,
    [Parameter(ParameterSetName="Help")]
    [switch]$help
)
switch ($PSCmdlet.ParameterSetName) {
  RunFunction { }
  Help { Write-Host "Requesting assistance, one moment please..." -ForegroundColor Yellow }
}
#
####> Init Functions
#
# For use in the USAGE function
$global:scriptname = $MyInvocation.MyCommand.Name
if([system.diagnostics.eventlog]::SourceExists($scriptname) -ne $true) { 
    [system.diagnostics.EventLog]::CreateEventSource($scriptname, “Application”) 
}
#
function usage() { 
$helpfile = "

.SYNOPSIS
    Executes supported Keylight API v.4.4 Calls

    Script name: $scriptname
    Version    : 1.0
    Author     : Rob Vance (http://www.ngosecurity.com)

.DESCRIPTION
    The script executes the various call available in v.4.4 of the Keylight API. (Refer to the guide for 
    details on how to utilize the API for your specific needs.) 

.SYNTAX

    .\$scriptname [[-g] <Call>] [<CommonParameters>]

    -g <function name>          Required. Select the API Call to run

    Parameter + Argument        ID
    ========================    ========================

    -c <Component ID>           Component ID
    -f <Field ID>               Field ID
    -p <Field Path ID>          Field Path ID
    -a <Alias ID>               Alias ID
    -r <Record ID>              Record ID
    -d <Document ID>            Document ID
    -o <Output filename>       Output Filename

    -v                          Verbose (Display results to screen)
    -h                          This display

.PARAMETER GetFieldList
    Returns a complete list of all Keylight components available to the user based on account permissions.
    No input elements are used. The list will be ordered in ascending alphabetical order of the component
    name.

    PS H:\> .\$scriptname -g GetComponentList

    Retrieves a component specified by its ID. A component is a user-defined data object such as a custom
    content table. The component ID may be found by using GetComponentList.

    PS H:\> .\$scriptname -g GetComponent -c 1

.PARAMETER GetFieldList
    Retrieves a component specified by its Alias. A component is a user-defined data object such as a
    custom content table. The component Alias may be found by using GetComponentList (ShortName).

    PS H:\> .\$scriptname -g GetComponentByAlias -a Vendors

.PARAMETER GetFieldList
    Retrieves detail field listing for a component specified by its ID. The component ID may be found by
    using GetComponentList. Documents or Assessments field types will not be visible in this list.

    PS H:\> .\$scriptname -g GetFieldList -c 1

.PARAMETER GetField
    Retrieves details for a field specified by its ID. The field ID may be found by using GetFieldList.

    PS H:\> .\$scriptname -g GetFieldList -f 1414

.PARAMETER GetRecordCount
    Return the number of records in a given component.  
    
    Prerequisite: GetRecordCountInput.xml

    PS H:\> .\$scriptname -g GetRecordCount

.PARAMETER GetRecord
    Returns the complete set of fields for a given record within a component.

    PS H:\> .\$scriptname -g GetRecord -c 1 -r 12

.PARAMETER GetRecords
    Return the title/default field for a set of records within a chosen component. Filters may be applied to
    return only the records meeting selected criteria.

    Prerequisite: GetRecordsInput.xml

    PS H:\> .\$scriptname -g GetRecords

.PARAMETER GetDetailRecord
    Retrieves record information based on the provided component ID and record ID, with lookup field
    report details.

    PS H:\> .\$scriptname -g GetDetailRecord -c 1 -r 12

.PARAMETER GetDetailRecords
    GetDetailRecords provides the ability to run a search with filters and paging (GetRecords) while
    returning a high level of detail for each record (GetRecord). 

    Prerequisite: GetDetailRecordsInput.xml

    PS H:\> .\$scriptname -g GetDetailRecords

.PARAMETER GetLookupReportColumnFields
    Gets the field information of each field in a field path that corresponds to a lookup report column.
     
    The lookupFieldId corresponds to a lookup field with a report definition on it and the fieldPathId 
    corresponds to the field path to retrieve fields from, which is obtained from GetDetailRecord.
    GetLookupReportColumnFields compliments GetRecordDetail by adding additional details about the
    lookup report columns returned from GetRecordDetail.

    PS H:\> .\$scriptname -g GetLookupReportColumnFields -f 1234 -p 1

.PARAMETER GetRecordAttachment
    Gets a single attachment associated with the provided component ID, record ID, documents field ID,
    and document ID. The file contents are returned as a Base64 string.

    PS H:\> .\$scriptname -g GetRecordAttachment -c 1 -r 12 -f 1234 -d 1

.PARAMETER GetRecordAttachments
    Gets information for all attachments associated with the provided component ID, record ID, and
    Documents field id. No file data is returned, only file name, field ID, and document ID information.

    PS H:\> .\$scriptname -g GetRecordAttachment -c 1 -r 12 -f 1234

.PARAMETER CreateRecord
    Create a new record within the specified component of the Keylight application.

    Prerequisite: CreateRecordInput.xml

    PS H:\> .\$scriptname -g CreateRecord

.PARAMETER UpdateRecord
    Update fields in a specified record.

    Prerequisite: UpdateRecordInput.xml

    PS H:\> .\$scriptname -g UpdateRecord

.PARAMETER DeleteRecord
    Delete a selected record from within a chosen component.

    Prerequisite: DeleteRecordInput.xml

    PS H:\> .\$scriptname -g DeleteRecord

.PARAMETER DeleteRecordAttachments
    Deletes the specified attachments from the provided document fields on a specific record.

    Prerequisite: DeleteRecordAttachmentsInput.xml

    PS H:\> .\$scriptname -g DeleteRecordAttachments

.EXAMPLE
    PS H:\> .\$scriptname -g GetComponentList

"
Write-Host $helpfile
exit
}
#
####> Call usage if asked
#
if($h -eq $true -or $help -eq $true) { usage }

if(($g.Length -lt 1) -or ([string]::IsNullOrWhiteSpace($g))) { usage }

#
####> Grab the current path
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
####> Preset Defaults
#
# Paths
$pwd = Get-ScriptDirectory
$tpwd = $pwd + "\Temp" 
if((Test-Path -PathType Container -Path $tpwd) -eq $false) {
    New-Item -ItemType Directory -Force -Path $tpwd | Out-Null
}
if($pwd.Split("\").count -eq 2) { $pwd = $pwd -replace "\\","\" }
$API_XML = $pwd + "\" + $g + "Input.xml"
if($API_XML.Split("\").count -eq 2) { $API_XML = $API_XML -replace "\\","\" }

$OUTFILE = $tpwd + "\" + $g + "Output.xml"
if($OUTFILE.Split("\").count -eq 2) { $OUTFILE = $OUTFILE -replace "\\","\" }

$PasswordFile = $pwd + "\Password.txt"
if($PasswordFile.Split("\").count -eq 2) { $PasswordFile = $PasswordFile -replace "\\","\" }
$KeyFile = $pwd + "\AES.key"
if($KeyFile.Split("\").count -eq 2) { $KeyFile = $KeyFile -replace "\\","\" }

if($o) {
    $xmlfile = $tpwd + "\" + $g + "_" + $o + "_Output.xml" 
    if($xmlfile.Split("\").count -eq 2) { $xmlfile = $xmlfile -replace "\\","\" }
} else {
    $xmlfile = $tpwd + "\" + $g + "Output.xml" 
    if($xmlfile.Split("\").count -eq 2) { $xmlfile = $xmlfile -replace "\\","\" }
}
#
# Change as required
$API_HOST = "keylight.targetco.com"
$API_SCHEME = "https"
$API_PORT = "4443"
#
$API_ENDPOINT = "$API_SCHEME`://$API_HOST`:$API_PORT"
$API_LOGIN = "$API_ENDPOINT/SecurityService/Login"
$API_LOGOUT = "$API_ENDPOINT/SecurityService/Logout"
$API_CS = "$API_ENDPOINT/ComponentService"
$API_CALL = "$API_CS/$g"
#
####> API Account
#
$API_ACCT = "apiacct"
#
####> Add Arguments
#
switch -regex ($g) {
        '\bGetComponentList\b' { $ARG="" }
        '\bGetComponent\b' { 
            if(($PSBoundParameters.Keys -eq "c") -and ($PSBoundParameters.Values)) {
                $ARG="?id=" + $c.ToString()
                $OUTFILE = $pwd + "\" + $g + "Output$c.xml"
                if($OUTFILE.Split("\").count -eq 2) { $OUTFILE = $OUTFILE -replace "\\","\" }
            }
            if($PSBoundParameters.Keys -cnotcontains "c") {
                Write-Host "Component ID (-c) is missing"
                usage
            }   
        }
        '\bGetComponentByAlias\b' { 
            if(($PSBoundParameters.Keys -eq "a") -and ($PSBoundParameters.Values)) {
                $ARG="?alias=$a"
            }
            if($PSBoundParameters.Keys -cnotcontains "a") {
                Write-Host "Alias ID (-a) is missing"
                usage
            }          
        }        
        '\bGetField\b' {
            if(($PSBoundParameters.Keys -eq "f") -and ($PSBoundParameters.Values)) {
                $ARG="?id=$f"
            }
            if($PSBoundParameters.Keys -cnotcontains "f") {
                Write-Host "Field ID (-f) is missing"
                usage
            }          
        } 
        '\bGetFieldList\b' {
            if(($PSBoundParameters.Keys -eq "c") -and ($PSBoundParameters.Values)) {
                $ARG="?componentId=$c"
            }
            if($PSBoundParameters.Keys -cnotcontains "c") {
                Write-Host "Component ID (-c) is missing"
                usage
            }      
        } 
        '\bGetRecord\b' { 
            if((($PSBoundParameters.Keys -eq "c") -and ($PSBoundParameters.Values)) -and (($PSBoundParameters.Keys -eq "r") -and ($PSBoundParameters.Values))) {
                $ARG="?componentId=$c&recordId=$r"
            } 
            if(($PSBoundParameters.Keys -cnotcontains "c") -or ($PSBoundParameters.Keys -cnotcontains "r")) {
                if($PSBoundParameters.Keys -cnotcontains "c") { Write-Host "Component ID (-c) is missing" }
                if($PSBoundParameters.Keys -cnotcontains "r") { Write-Host "Record ID (-r) is missing" }
                usage
            }
        } 
        '\bGetDetailRecord\b' { 
            if((($PSBoundParameters.Keys -eq "c") -and ($PSBoundParameters.Values)) -and (($PSBoundParameters.Keys -eq "r") -and ($PSBoundParameters.Values))) {
                $ARG="?componentId=$c&recordId=$r"
            } 
            if(($PSBoundParameters.Keys -cnotcontains "c") -or ($PSBoundParameters.Keys -cnotcontains "r")) {
                if($PSBoundParameters.Keys -cnotcontains "c") { Write-Host "Component ID (-c) is missing" }
                if($PSBoundParameters.Keys -cnotcontains "r") { Write-Host "Record ID (-r) is missing" }
                usage
            }
        }         
        '\bGetLookupReportColumnsFields\b' {
            if((($PSBoundParameters.Keys -eq "f") -and ($PSBoundParameters.Values)) -and (($PSBoundParameters.Keys -eq "p") -and ($PSBoundParameters.Values))) {
                $ARG="?lookupField=$f&fieldPathId=$p"
            } 
            if(($PSBoundParameters.Keys -cnotcontains "f") -or ($PSBoundParameters.Keys -cnotcontains "p")) {
                if($PSBoundParameters.Keys -cnotcontains "f") { Write-Host "Field ID (-f) is missing" }
                if($PSBoundParameters.Keys -cnotcontains "p") { Write-Host "Field Path ID (-p) is missing" }
                usage
            }
        } 
        '\bGetRecordAttachment\b' { 
            if((($PSBoundParameters.Keys -eq "c") -and ($PSBoundParameters.Values)) -and (($PSBoundParameters.Keys -eq "f") -and ($PSBoundParameters.Values)) -and (($PSBoundParameters.Keys -eq "d") -and ($PSBoundParameters.Values))) {
                $ARG="?componentId=$c&recordId=$r&fieldId=$f&documentId=$d"
            } 
            if(($PSBoundParameters.Keys -cnotcontains "c") -or ($PSBoundParameters.Keys -cnotcontains "r") -or ($PSBoundParameters.Keys -cnotcontains "p")) {
                if($PSBoundParameters.Keys -cnotcontains "c") { Write-Host "Component ID (-c) is missing" }
                if($PSBoundParameters.Keys -cnotcontains "r") { Write-Host "Record ID (-f) is missing" }
                if($PSBoundParameters.Keys -cnotcontains "d") { Write-Host "Document ID (-d) is missing" }
                usage
            }
        }
        '\bGetRecordAttachments\b' {
            if((($PSBoundParameters.Keys -eq "c") -and ($PSBoundParameters.Values)) -and (($PSBoundParameters.Keys -eq "r") -and ($PSBoundParameters.Values)) -and (($PSBoundParameters.Keys -eq "f") -and ($PSBoundParameters.Values))) {
                $ARG="?componentId=$c&recordId=$r&fieldId=$f"
            } 
            if(($PSBoundParameters.Keys -cnotcontains "c") -or ($PSBoundParameters.Keys -cnotcontains "r") -or ($PSBoundParameters.Keys -cnotcontains "f")) {
                if($PSBoundParameters.Keys -cnotcontains "c") { Write-Host "Component ID (-c) is missing" }
                if($PSBoundParameters.Keys -cnotcontains "r") { Write-Host "Record ID (-f) is missing" }
                if($PSBoundParameters.Keys -cnotcontains "f") { Write-Host "Field ID (-d) is missing" }
                usage
            }
        }
}
#
####> XML Input Files
#
$XMLQuery = @('GetRecordCount',
              'GetRecords',
              'DeleteRecord',
              'CreateRecord',
              'UpdateRecord',
              'GetDetailRecords',
              'UpdateRecordAttachments',
              'DeleteRecordAttachments')
#
####> Tidy up the XML file
#
function Format-XML ([xml]$xml, $indent=2) { 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $xmlWriter.Formatting = “indented” 
    $xmlWriter.Indentation = $Indent 
    $xml.WriteContentTo($XmlWriter) 
    $XmlWriter.Flush() 
    $StringWriter.Flush() 
    $StringWriter.ToString() | Out-File $xmlfile
}
#
####> Main
#
# Making sure we're running on a compatible PowerShell version (>3)
if(($PSVersionTable.PSVersion).Major -ge 3) {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #ignore ssl warning
    # Login
    $key = Get-Content $KeyFile
    $MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $API_ACCT, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MyCredential.Password)
    #
    $contenttype = "application/xml"
    $charset = "utf-8"
    $header = @{"charset"= $charset; }; 
    $body = "<Login><username>" + $MyCredential.UserName + "</username><password>" + [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) + "</password></Login>"
    $listatus = Invoke-WebRequest -Uri $API_LOGIN -Headers $header -ContentType $contenttype -SessionVariable s -Method Post -Body $body -ErrorAction SilentlyContinue
    # Query

    if($XMLQuery -contains $g) {

        if($g -cmatch "DeleteRecord") { $Method = "Delete" } else { $Method = "Post" }

        # If an XML input file is required execute this type of call
        if(Test-Path $API_XML) {
            (Invoke-WebRequest -Uri $API_CALL -Headers $header -ContentType $contenttype -Method $Method -Body (Get-Content $API_XML) -WebSession $s).Content | Out-File $OUTFILE
        } else {
            Write-Warning "Cannot execute $API_CALL without the $API_XML file.  Create the $API_XML according to the 'Keylight Platform API Guide v4.4' and try again."
        }
    } else {
        # If arguments are used, execute this call
        $API_CALL = $API_CALL + $ARG
        (Invoke-WebRequest -Uri $API_CALL -WebSession $s).Content | Out-File $OUTFILE
    }

    Format-XML ([xml](cat $OUTFILE)) -indent 4

    $diff=((ls $xmlfile).LastWriteTime - (get-date)).totalseconds
    if($diff -gt -5) { 
        if($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { Get-Content $xmlfile }
        #Write-Debug "Finished. " -foreground DarkGreen -NoNewline
        #Write-Debug "The request for $g has been completed. Go to $xmlfile to view the results."
    }

    # Logout
    try {
        $lo = Invoke-WebRequest -Uri $API_LOGOUT -WebSession $s -ErrorAction SilentlyContinue
    } catch {

    }

} else {
    Write-Warning "PowerShell must be at version 3.0 or greater to execute this $scriptname.  Its currently at $psver."
    exit;
}