# https://github.com/hephaest0s/usbkill

function List-UsbDevices(){
    return gwmi Win32_USBControllerDevice |%{[wmi]($_.Dependent)};
}

function Print-USBDevices(){
    List-UsbDevices|Select Description, DeviceID;
}

$vchg = Register-WmiEvent -Class win32_DeviceChangeEvent -SourceIdentifier deviceChange
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
    
    if (($eventType -eq 2) -and ((Get-CimInstance Win32_LogicalDisk).DriveType) -eq 2) { # Add check if its a flashdrive
        $driveLetter = $newEvent.SourceEventArgs.NewEvent.DriveName
        $driveLabel = ([wmi]"Win32_LogicalDisk='$driveLetter'").VolumeName
        write-host (get-date -format s) " Drive name = " $driveLetter
        write-host (get-date -format s) " Drive label = " $driveLabel       
    }
Remove-Event -SourceIdentifier deviceChange
} while (1-eq1) #Loop until next event
Unregister-Event -SourceIdentifier deviceChange
