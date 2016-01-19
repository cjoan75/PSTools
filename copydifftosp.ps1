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

Get-Variable | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue } 

$folderReference = "$env:TEMP\Heatmaps"
$folderDifference = "$env:TEMP\Temp"
$folderHeatmaps = "$env:TEMP\Heatmaps"

$FolderReferenceContents = Get-ChildItem $folderReference -Filter "T*.xlsm" | where-object {-not $_.PSIsContainer}
$FolderDifferenceContents = Get-ChildItem $folderDifference -Filter "T*.xlsm" | where-object {-not $_.PSIsContainer}

$ItemstoCopy = (Compare-Object -ReferenceObject $FolderReferenceContents -DifferenceObject $FolderDifferenceContents -Property ('Name', 'Length') -PassThru | where-object { $_.SideIndicator -eq '=>'}).FullName

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

$ItemstoCopy | ForEach-Parallel -MaxThreads 100 {

$folderReference = "$env:TEMP\Heatmaps"
$folderDifference = "$env:TEMP\Temp"
$folderHeatmaps = "$env:TEMP\Heatmaps"
  
    Write-Output "-Path $_ -Destination $folderReference"
    #Copy-Item -Path $_ -Destination $folderReference -Force 
    Move-Item -Path $_ -Destination $folderHeatmaps -Force

}

Get-Variable | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue } 
