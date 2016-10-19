$n = $false
#
####> Function Alley
#
##> Discover what USB Devices is present on the system
#
function ListUSB () {
# Scan for anything identified as a USB Device
    gwmi Win32_USBControllerDevice | %{ [wmi]($_.Dependent) } | Where-Object { $_.DeviceID -Like "*USB*" } | Select-Object -Property DeviceID, Service, Description | ForEach-Object -Process { $_.DeviceID = $_.DeviceID -replace '\&','' | % { $_.Split('\\',3)[2] }; $_ }
}
#
##> Create list of currently installed USB Devices into the whitelist
#
function createList () {
    if(Test-Path test.csv) { Remove-Item test.csv }
    (ListUSB).GetEnumerator() | Export-Csv test.csv -NoClobber -NoTypeInformation
}
#
##> Prompt user
#
function yesanswer($msg) {
    $defaultValue = 'Y'
    $prompt = Read-Host "$msg [$($defaultValue)]"
    $prompt = ($defaultValue,$prompt)[[bool]$prompt]
    return $prompt
}
#
##> Define the primary key
#
function createKey($keyID) {
    if(Test-Path key.txt) { Remove-Item key.txt }
    $keyID | Out-File key.txt
}
#
##> Add new devices to the whitelist
#
function addtoList($chkUSB) {
    Write-Host "DeviceID: " $chkUSB.DeviceID
    $prompt1 = yesanswer "Do you want to add it to the list?"
    if($prompt1 -eq 'Y') {
        Write-Host "Adding " $chkUSB.Description " to the whitelist of trusted devices."
        $chkUSB | Export-Csv -Append test.csv
        $prompt2 = yesanswer "Should this USB Device be used as the key?"
        if($prompt2 -eq 'Y') {
            createKey $chkUSB.DeviceID
        } else {
            break
        }
    } else {
        Write-Host $chkUSB.Description " will not be added to whitelist."
        break
    }
}
#
##> If the primary key is removed perform CYA actions
#
function incident($ckID, $eID) {
    [string]$kID = gc key.txt
    [string]$cID = $ckID.DeviceID
    if(($kID -match $cID) -and ($eID -eq 3)) {
        Write-Host "The $cID key is not present, shutting down now!"
        exit
        #shutdown /p
    } else {
        break 
    }
}
#
####> Main
#
##> Check to be sure the whitelist file exist, if not create one
#
if((-not (Test-Path test.csv)) -or $n) {
    $promptCreate = yesanswer "All of the following USB Devices will be whitelisted. Do you want to proceed?"
    ListUSB
    if($promptCreate -eq 'Y') {
        createList
    } else {
        Write-Host "Remove all of the USB Devices that you don't want to be whitelisted and re-run $scriptname again."
        exit
    }   
}
#
##> Check the status of the USB Ports
#
Unregister-Event -SourceIdentifier deviceChange -ErrorAction SilentlyContinue
Register-WmiEvent -Class win32_DeviceChangeEvent -SourceIdentifier deviceChange -ErrorAction SilentlyContinue
write-host (get-date -format s) "Beginning script..."
do{
    $newEvent = Wait-Event -SourceIdentifier deviceChange
    $eventType = $newEvent.SourceEventArgs.NewEvent.EventType
    $eventTypeName = switch($eventType) {
        1 { "Configuration changed"; }
        2 { "Device arrival"; }
        3 { "Device removal"; }
        4 { "docking"; }
    }
    $ts = (get-date -format s)
    Write-Host "$ts Event detected = $eventTypeName"
    if($eventTypeName) {
        $whiteList = Get-Content test.csv | ConvertFrom-Csv -Delimiter "`," | Select DeviceID
        $scanUSB = (ListUSB).GetEnumerator() | Select DeviceID, Service, Description
        $chkUSB = Compare-Object -ReferenceObject($whiteList) -DifferenceObject($scanUSB) -Property DeviceID -PassThru
        if($chkUSB) {
            switch($chkUSB.SideIndicator) {
                 '=>' { Write-Host "Net New: " $chkUSB.Description; addtoList($chkUSB); break }
                '<=' { Write-Host "Missing: " $chkUSB.Description; incident $chkUSB $eventType; break }
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
#
####> Clear variables
#
#$chkUSB = ""
#$whiteList = ""
#$scanUSB = ""
$prompt1 = ""
$prompt2 = ""
