$PlainPassword = "P@s5w0rD" 

$SecurePassword = ConvertTo-SecureString -AsPlainText $PlainPassword -Force | ConvertFrom-SecureString

#### Method 1 - Cannot be used with Base64

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)

Write-Host "BSTR - $BSTR"

$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

Write-Host "Method 1 - $UnsecurePassword"

Remove-Variable UnsecurePassword,BSTR

Write-Host "`n"

#### Method 2 - Cannot be used with Base64
$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($SecurePassword)

Write-Host "PTR - $Ptr"

$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
Write-Host "Method 2 - $UnsecurePassword"

Remove-Variable UnsecurePassword,Ptr

Write-Host "`n"

#### Method 3
$SecurePwd = ConvertTo-SecureString -AsPlainText $PlainPassword -Force  | ConvertFrom-SecureString

Write-Host "Method 3 SecurePwd - $SecurePwd"

$UnsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString $SecurePwd) ))

Write-Host "Method 3 - $UnsecurePassword"

Remove-Variable UnsecurePassword,SecurePwd

#### Method 4 - Method 3 Works with Base64
Write-Host "`nMethod 3 Encrypt and Base64"

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

Remove-Variable UnsecurePassword,SecurePwd,b64Encode,b64Decode
