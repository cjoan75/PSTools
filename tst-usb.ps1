$n = $false

function ListUSB () {
    gwmi Win32_USBControllerDevice | %{ [wmi]($_.Dependent) } | Where-Object { $_.DeviceID -Like "*USB*" } | Select-Object -Property DeviceID, Service, Description | ForEach-Object -Process { $_.DeviceID = $_.DeviceID -replace '\&','' | % { $_.Split('\\',3)[2] }; $_ }
}

function createList () {
    if(Test-Path test.csv) { Remove-Item test.csv }
    (ListUSB).GetEnumerator() | Export-Csv test.csv -NoClobber -NoTypeInformation
}

function addtoList($chkUSB) {
    $chkUSB.DeviceID, 
    $chkUSB.Service
    $chkUSB.Description
    CreateList
}

function incident($varID) {
    if($varID = "776838E102") {
        Write-Host "Shut it Down!"
        Stop-Computer
    }
}

if((-not (Test-Path test.csv)) -or $n){
    createList   
}
Unregister-Event -SourceIdentifier deviceChange
Register-WmiEvent -Class win32_DeviceChangeEvent -SourceIdentifier deviceChange
write-host (get-date -format s) " Beginning script..."
do{
    $newEvent = Wait-Event -SourceIdentifier deviceChange
    $eventType = $newEvent.SourceEventArgs.NewEvent.EventType
    $eventTypeName = switch($eventType) {
        1 {"Configuration changed"}
        2 {"Device arrival"}
        3 {"Device removal"}
        4 {"docking"}
    }
    write-host (get-date -format s) " Event detected = " $eventTypeName
    if($eventTypeName) {
        $whiteList = Get-Content test.csv | ConvertFrom-Csv -Delimiter "`," | Select DeviceID
        $scanUSB = (ListUSB).GetEnumerator() | Select DeviceID, Service, Description
        $chkUSB = Compare-Object -ReferenceObject($whiteList) -DifferenceObject($scanUSB) -Property DeviceID -PassThru #| Select * -ExcludeProperty SideIndicator
        if($chkUSB) {
            switch($chkUSB.SideIndicator) {
                '=>' { Write-Host "Net New: "; addtoList($chkUSB); break }
                '<=' { Write-Host "Missing: "; incident($chkUSB.DeviceID); break }
            }
        }

        if (($eventType -eq 2) -and ((Get-CimInstance Win32_LogicalDisk).DriveType) -eq 2) { # Add check if its a flashdrive
            $driveLetter = $newEvent.SourceEventArgs.NewEvent.DriveName
            $driveLabel = ([wmi]"Win32_LogicalDisk='$driveLetter'").VolumeName
            write-host (get-date -format s) " Drive name = " $driveLetter
            write-host (get-date -format s) " Drive label = " $driveLabel       
        }
    }
Remove-Event -SourceIdentifier deviceChange
} while (1-eq1) #Loop until next event
Unregister-Event -SourceIdentifier deviceChange

$chkUSB = ""
$whiteList = ""
$scanUSB = ""
