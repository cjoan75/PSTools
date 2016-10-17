function ListUSB () {
    gwmi Win32_USBControllerDevice | %{ [wmi]($_.Dependent) } | Where-Object { $_.DeviceID -Like "*USB*" } | Select-Object -Property DeviceID, Service, Description | ForEach-Object -Process { $_.DeviceID = $_.DeviceID -replace '\&','' | % { $_.Split('\\',3)[2] }; $_ }
}

if(Test-Path test.csv) {
    ListUSB
}else{
    (ListUSB).GetEnumerator() | Export-Csv test.csv -NoClobber -NoTypeInformation
}

$whiteList = Get-Content test.csv | ConvertFrom-Csv -Delimiter "`," | Select DeviceID

$scanUSB = (ListUSB).GetEnumerator() | Select DeviceID, Service, Description

$chkUSB = Compare-Object -ReferenceObject($whiteList) -DifferenceObject($scanUSB) -Property DeviceID -PassThru

$chkUSB

$chkUSB = ""
