<#
.SYNOPSIS

Convert CSV to XML
version 1.0
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
    [array]$csv,
    [array]$xml,
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

Converts the CSV file exported from Keylight Metricstream report into XML then copies the file to the Metricstream file share

.PARAMETER csv

Defines the name of the csv file, typically Metricstream

.PARAMETER xml

Defines the name of the xml file to export

.EXAMPLE

PS H:\> .\$scriptname -csv metricstream.csv -xml metricstream.csv

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
$csvfile = $pwd + "\$csv"
if($csvfile.Split("\").count -eq 2) { $csvfile = $csvfile -replace "\\","\" }
$xmlfile = $pwd + "\$xml"
if($xmlfile.Split("\").count -eq 2) { $xmlfile = $xmlfile -replace "\\","\" }
#
####> Network Share
#
$mspath = "\\<SERVER>\path\to\metricstream\file\share>"
#
####> Covert CSV to XML
#
function New-Xml {
param($RootTag=”ROOT”,$ItemTag=”ITEM”, $ChildItems=”*”, $Attributes=$Null)
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
            $xml += ” <$Name>$($_.$Name)</$Name>`n”
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
Write-Output "<?xml version='1.0' encoding='UTF-8'?>" | Out-File $xmlfile
Import-Csv -Path $csvfile | New-XML -RootTag Assessments -ItemTag Assessment -ChildItems RiskTier,OverallAssessmentStatus,OverallAssessmentScore,AssessmentID,AssessmentDate,ControlAreaFindingSummaryDocument,LinkToOverallAssessmentDocument,OverallAssessmentRatingHistoryLinkToFolder,CriticalOpenItems,HighOpenItems,ProfileIdentifier | Out-File $xmlfile -Append
Format-XML ([xml](cat $xmlfile)) -indent 4 | Out-File $xmlfile
#
####> Copy XML into Metricstream Shared Folder
#
#Copy-Item -Path $csvfile -Destination $xmlfile -Force -ErrorAction SilentlyContinue