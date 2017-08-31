<#
.SYNOPSIS

Convert CSV to XML
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

#>
[cmdletbinding()]
param(
    [array]$c,
    [array]$x,
    [switch]$help
)
#
####> Init Functions
#
# For use in the USAGE function
$global:scriptname = $MyInvocation.MyCommand.Name

function usage() { 
$helpfile = "
Convert CSV to XML
version 1.0
Author: Rob Vance (http://www.ngosecurity.com)

.SYNOPSIS

Converts the CSV file into XML then copies it to file share

.PARAMETER csv

Defines the name of the csv file

.PARAMETER xml

Defines the name of the xml file to export

.EXAMPLE

PS H:\> .\$scriptname -csv file.csv -xml file.xml

"
Write-Host $helpfile
exit
}
#
####> Call usage if asked
#
if($h -eq $true -or $help -eq $true) { usage }
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
if($pwd.Split("\").count -eq 2) { $pwd = $pwd -replace "\\","\" }
$csvfile = $pwd + "\$c"
if($csvfile.Split("\").count -eq 2) { $csvfile = $csvfile -replace "\\","\" }
$xmlfile = $pwd + "\$x"
if($xmlfile.Split("\").count -eq 2) { $xmlfile = $xmlfile -replace "\\","\" }
$xmltmp = $pwd + "\tmp_" + $x
if($xmltmp.Split("\").count -eq 2) { $xmltmp = $xmltmp -replace "\\","\" }
#
####> Network Share
#
# <<<<<<<<<<<< Change according to requirement >>>>>>>>>>>>>>>>
#
$mspath = "\\<SERVER>\path\to\file\share>"
#
####> Notication Email
#
# <<<<<<<<<<<< Change according to requirement >>>>>>>>>>>>>>>>
#
$dom = $env:userdomain
$usr = $env:username
$user = ([adsi]"WinNT://$dom/$usr,user").fullname
$datetime = Get-Date
$to = "ravance@ngosecurity.com"
$subject = "Metricstream Task Completed at $datetime"
$body = "$usr | $user | $xmlfile | $datetime"
#
####> Covert CSV to XML
#
function New-Xml {
param($RootTag='Assessments',$ItemTag=”Assessment”, $ChildItems=”*”, $Attributes=$Null)
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
function Format-XML ([xml]$xml, $indent=2) { 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $xmlWriter.Formatting = “indented” 
    $xmlWriter.Indentation = $Indent 
    $xml.WriteContentTo($XmlWriter) 
    $XmlWriter.Flush() 
    $StringWriter.Flush() 
    Write-Output $StringWriter.ToString() 
}
#
####> Covert CSV to XML
#
Write-Output '<?xml version="1.0" encoding="UTF-8"?>' | Out-File $xmltmp
$TxtAfter1 = '<Assessments xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="Support_Central_Schema.xsd">'
Import-Csv -Path $csvfile | New-XML -RootTag 'Assessments' -ItemTag Assessment -ChildItems RiskTier,OverallAssessmentStatus,OverallAssessmentScore,AssessmentID,AssessmentDate,ControlAreaFindingSummaryDocument,LinkToOverallAssessmentDocument,OverallAssessmentRatingHistoryLinkToFolder,CriticalOpenItems,HighOpenItems,ProfileIdentifier | out-file $xmltmp -append
Format-XML ([xml](cat $xmltmp)) -indent 4 | Out-File $xmlfile
#
####> Insert XSD in ROOTITEM
#
$tmpxml = gc $xmlfile
# Set to Row 2 (starting from zero)
$tmpxml[1] = $TxtAfter1 
$tmpxml | sc $xmlfile
#
####> Cleanup
#
if (Test-Path $xmltmp) {
    remove-item $xmltmp -Force -Recurse -ErrorAction SilentlyContinue
}
#
####> Copy XML to Shared Folder
#
#Copy-Item -Path $csvfile -Destination $mspath\$xml -Force -ErrorAction SilentlyContinue
#
####> Notify that tasks was completed
#
$Outlook = New-Object -ComObject Outlook.Application
$Mail = $Outlook.CreateItem(0)
$Mail.To = $to
$Mail.Subject = $subject
$Mail.Body = $body
$Mail.Send()
