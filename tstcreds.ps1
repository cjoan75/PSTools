## Construct the header
$PlainPassword = "P@ssw0rd2013"

$SecurePwd = ConvertTo-SecureString -AsPlainText $PlainPassword -Force  | ConvertFrom-SecureString

Write-Host "1. SecurePwd - $SecurePwd"

# Base64 Encode
$b64Encode = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($SecurePwd))

Write-Host "2. Base64 Encoded - $b64Encode"

# Base64 Decode
$b64Decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64Encode))

Write-Host "3. Base64 Decoded - $b64Decode"

if ($SecurePwd -eq $b64Decode) {
    Write-Host "4. SecureString Matched"
} else { 
    Write-Host "4. SecureString Don't Matched"
}

$UnsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString $b64Decode) ))

if ($PlainPassword -eq $UnsecurePassword) {
    Write-Host "5. $PlainPassword & $UnsecurePassword are the same"
} else {
    Write-Host "5. $PlainPassword & $UnsecurePassword don't match"
}

$SecureString = ConvertTo-SecureString -AsPlainText $UnsecurePassword -Force
$Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'tstad\tstusr',$SecureString

Invoke-Command -ComputerName $SecHopName -ScriptBlock { Get-ChildItem C:\ } -Credential $Credentials

Remove-Variable UnsecurePassword,SecurePwd,b64Encode,b64Decode
