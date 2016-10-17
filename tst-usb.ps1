$n = $false

function ListUSB () {
    gwmi Win32_USBControllerDevice | %{ [wmi]($_.Dependent) } | Where-Object { $_.DeviceID -Like "*USB*" } | Select-Object -Property DeviceID, Service, Description | ForEach-Object -Process { $_.DeviceID = $_.DeviceID -replace '\&','' | % { $_.Split('\\',3)[2] }; $_ }
}

function createList () {
    if(Test-Path test.csv) { Remove-Item test.csv }
    (ListUSB).GetEnumerator() | Export-Csv test.csv -NoClobber -NoTypeInformation
}

if((-not (Test-Path test.csv)) -or $n){
    createList   
}

$whiteList = Get-Content test.csv | ConvertFrom-Csv -Delimiter "`," | Select DeviceID

$scanUSB = (ListUSB).GetEnumerator() | Select DeviceID, Service, Description

$chkUSB = Compare-Object -ReferenceObject($whiteList) -DifferenceObject($scanUSB) -Property DeviceID -PassThru #| Select * -ExcludeProperty SideIndicator

if($chkUSB) {
    switch($chkUSB.SideIndicator) {
    '=>' { Write-Host "Net New: " $chkUSB.DeviceID; break }
    '<=' { Write-Host "Missing: "; $chkUSB.DeviceID; break }
    }
}

$chkUSB = ""
$whiteList = ""
$scanUSB = ""
