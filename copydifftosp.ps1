Get-Variable | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue } 

$folderReference = "H:\Heatmaps"
$folderDifference = "H:\Temp"
$folderHeatmaps = "H:\Heatmaps"

$FolderReferenceContents = Get-ChildItem $folderReference -Filter "T*.xlsm" | where-object {-not $_.PSIsContainer}
$FolderDifferenceContents = Get-ChildItem $folderDifference -Filter "T*.xlsm" | where-object {-not $_.PSIsContainer}

$ItemstoCopy = (Compare-Object -ReferenceObject $FolderReferenceContents -DifferenceObject $FolderDifferenceContents -Property ('Name', 'Length') -PassThru | where-object { $_.SideIndicator -eq '=>'}).FullName

functionForEach-Parallel {
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

$folderReference = "H:\Heatmaps"
$folderDifference = "H:\Temp"
$folderHeatmaps = "H:\Heatmaps"
  
    Write-Output "-Path $_ -Destination $folderReference"
    #Copy-Item -Path $_ -Destination $folderReference -Force 
    Move-Item -Path $_ -Destination $folderHeatmaps -Force

}

Get-Variable | % { Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue } 
