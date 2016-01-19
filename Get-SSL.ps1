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

Param
(
    [Parameter(Position=0,Mandatory=$false)]
    [ValidateNotNullorEmpty()]
    [Alias('cn')][String[]]$ComputerName=$Env:COMPUTERNAME,
    [Array[]]$portList= @(443,8010,8011,8012,8015,8089)
)
function testport($Computer,$port) {
    $Test = New-Object Net.Sockets.TcpClient
    $Test.BeginConnect( $Computer, $port, $Null, $Null ) | Out-Null
    $Timeout = ( Get-Date ).AddMilliseconds( 1000 )
    While( -not $Test.Connected -and ( Get-Date ) -lt $Timeout ){ Sleep -Milliseconds 50 }
    $results = $Test.Connected
    if($results -eq $true) { return $results }
    $Test.Close()
}
function stripcomma([string]$tempstring) { return $tempstring.replace(',',';') }
function convertoid([string]$oid) {
    $oidstr = $oid.replace("1.2.840.113549.1.","")
    $firstval = $oidstr.substring(0,$oidstr.indexof('.'))
    $sub = $oidstr.substring(2)
    if ($sub.indexof('.') -gt 0) { $sub = $sub.substring(0,$sub.indexof('.')) }
    if ($firstval -eq "1") {
        $format = "PKCS-1"
        switch ($sub) {
        "1" { return ($format + " RSA Encryption") }
        "2" { return ($format + " MD2 with RSA") }
        "3" { return ($format + " rsadsi md4 with RSA")}
        "4" { return ($format + " MD5 with RSA") }
        "5" { return ($format + " SHA-1 with RSA") }
        "6" { return ($format + " rsaOAEPEncryptionSet")}
        "11" { return ($format + " sha256 with RSA") }
        }
    } elseif ($firstval -eq "5") {
        $format = "RSA PKCS5"
        switch ($sub) {
        "1" { return ($format + " rsadsi pbe with MD2 DES-CBC")}
        "3" { return ($format + " rsadsi pbe with MD5 DES-CBC")}
        "4" { return ($format + " pbe with MD2 and RC2_CBC")}
        "6" { return ($format + " pbe with MD5 and RC2_CBC")}
        "9" { return ($format + " pbe with MD5 and XOR")}
        "10" { return ($format + " pbe with SHA1 and DES-CBC")}
        "11" { return ($format + " pbe with SHA1 and RC2_CBC")}
        "12" { return ($format + " id-PBKDF2 key derivation function")}
        "13" { return ($format + " id-PBES2  PBES2 do its jobion")}
        "14" { return ($format + " id-PBMAC1 message auth scheme")}
        }
    } elseif ($firstval -eq "7" ) {
        $format = "PKCS-7"
        switch ($sub) {
            "1" { return ($format + " data")}
            "2" { return ($format + " signed data")}
            "3" { return ($format + " enveloped data")}
            "4" { return ($format + " signed and enveloped data")}
            "5" { return ($format + " digested data")}
            "6" { return ($format + " do its jobed data")}
        }
    } elseif ($firstval -eq "12") {
        return ("PKCS-12")
    } elseif ($firstval -eq "15") {
        return ("PKCS-15") 
    } else {
        return $oid 
    }
}
$Obj = @()
foreach($Computer in $ComputerName) {
    $outOBJ = New-Object -TypeName PSobject
    if(Test-Connection -BufferSize 32 -Count 1 -ComputerName $Computer -Quiet) {
        $IPAddress = ([System.Net.DNS]::GetHostEntry($Computer).AddressList[0].IPAddressToString)
        $i = 0
        $csvport = @()
        do {
            $tstport = testport $Computer $([string]$portList[$i])
            if($tstport -eq $true) { $csvport += $([string]$portList[$i]) }
            $i++
        } until ($i -eq 20)
        $ports = [string]$csvport -replace " ", ";"
        foreach($port in $ports) {
           
                $client = New-Object System.Net.Sockets.TcpClient -ErrorAction SilentlyContinue 
                $client.Connect($Computer, $port)
                $sslStream = New-Object System.Net.Security.SslStream($client.GetStream()) -ErrorAction SilentlyContinue 
            try{
                $sslStream.AuthenticateAsClient($Computer)
                $Cert = $sslStream.Get_RemoteCertificate()
                $Cert2 = New-Object system.security.cryptography.x509certificates.x509certificate2($Cert) -ErrorAction SilentlyContinue 
                $ValidTo = [datetime]::Parse($Cert.GetExpirationDatestring())
                $Validfrom = [datetime]::Parse($Cert.GetEffectiveDatestring())
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain -ErrorAction SilentlyContinue 
                $RevocationFlag = $chain.ChainPolicy.RevocationFlag
                $RevocationMode = $chain.ChainPolicy.RevocationMode
                $VerificationFlags = $chain.ChainPolicy.VerificationFlags
                $Client.Close()
                if([string]::IsNullOrEmpty($RevocationFlag) -or [string]::IsNullOrWhiteSpace($RevocationFlag)) { $RevocationFlag = "NA" }
                if([string]::IsNullOrEmpty($RevocationMode) -or [string]::IsNullOrWhiteSpace($RevocationMode)) { $RevocationMode = "NA" }
                if([string]::IsNullOrEmpty($VerificationFlags) -or [string]::IsNullOrWhiteSpace($VerificationFlags)) { $VerificationFlags = "NA" }
                foreach ($objItem in $sslStream) {
                    $SslProtocol               = $objItem.SslProtocol
                    $CheckCertRevocationStatus = $objItem.CheckCertRevocationStatus
                    $CipherAlgorithm           = $objItem.CipherAlgorithm
                    $CipherStrength            = $objItem.CipherStrength 
                    $HashAlgorithm             = $objItem.HashAlgorithm
                    $HashStrength              = $objItem.HashStrength
                    $KeyExchangeAlgorithm      = $objItem.KeyExchangeAlgorithm
                    $KeyExchangeStrength       = $objItem.KeyExchangeStrength
                }
                if([string]::IsNullOrEmpty($SslProtocol) -or [string]::IsNullOrWhiteSpace($SslProtocol)) { $SslProtocol = "NA" }
                if([string]::IsNullOrEmpty($CheckCertRevocationStatus) -or [string]::IsNullOrWhiteSpace($CheckCertRevocationStatus)) { $CheckCertRevocationStatus = "NA" }
                if([string]::IsNullOrEmpty($CipherAlgorithm) -or [string]::IsNullOrWhiteSpace($CipherAlgorithm)) { $CipherAlgorithm = "NA" }
                if([string]::IsNullOrEmpty($CipherStrength) -or [string]::IsNullOrWhiteSpace($CipherStrength)) { $CipherStrength = "NA" }
                if([string]::IsNullOrEmpty($HashAlgorithm) -or [string]::IsNullOrWhiteSpace($HashAlgorithm)) { $HashAlgorithm = "NA" }
                if([string]::IsNullOrEmpty($HashStrength) -or [string]::IsNullOrWhiteSpace($HashStrength)) { $HashStrength = "NA" }
                if([string]::IsNullOrEmpty($KeyExchangeAlgorithm) -or [string]::IsNullOrWhiteSpace($KeyExchangeAlgorithm)) { $KeyExchangeAlgorithm = "NA" }
                if([string]::IsNullOrEmpty($KeyExchangeStrength) -or [string]::IsNullOrWhiteSpace($KeyExchangeStrength)) { $KeyExchangeStrength = "NA" }
                if([string]::IsNullOrEmpty($ValidTo) -or [string]::IsNullOrWhiteSpace($ValidTo)) { $ValidTo = [datetime]::Parse($Cert.GetExpirationDatestring()) }
                if([string]::IsNullOrEmpty($Validfrom) -or [string]::IsNullOrWhiteSpace($Validfrom)) { $Validfrom = [datetime]::Parse($Cert.GetEffectiveDatestring()) }
                $CertFormat                = $cert.getformat()
                $CertExpiration            = $Validto
                $CertIssueDate             = $Validfrom
                $CertIssuer                = stripcomma $cert.get_issuer()
                $SerialNumber              = $cert.getserialnumberstring()
                $CertSubject               = stripcomma $cert.get_subject()
                $CertSubject               = $CertSubject.Replace("`" "," ")
                $CertType                  = convertoid $cert.getkeyalgorithm()
                $CertKeySize               = $cert2.PublicKey.key.KeySize
                if([string]::IsNullOrEmpty($CertFormat) -or [string]::IsNullOrWhiteSpace($CertFormat)) { $CertFormat = "NA" }
                if([string]::IsNullOrEmpty($CertExpirationl) -or [string]::IsNullOrWhiteSpace($CertExpiration)) { $CertExpiration = "NA" }
                if([string]::IsNullOrEmpty($CertIssueDate) -or [string]::IsNullOrWhiteSpace($CertIssueDate)) { $CertIssueDate = "NA" }
                if([string]::IsNullOrEmpty($CertIssuer) -or [string]::IsNullOrWhiteSpace($CertIssuer)) { $CertIssuer = "NA" }
                if([string]::IsNullOrEmpty($SerialNumber) -or [string]::IsNullOrWhiteSpace($SerialNumber)) { $SerialNumber = "NA" }
                if([string]::IsNullOrEmpty($CertSubject) -or [string]::IsNullOrWhiteSpace($CertSubject)) { $CertSubject = "NA" }
                if([string]::IsNullOrEmpty($CertType) -or [string]::IsNullOrWhiteSpace($CertType)) { $CertType = "NA" }
                if([string]::IsNullOrEmpty($CertKeySize) -or [string]::IsNullOrWhiteSpace($CertKeySize)) { $CertKeySize = "NA" }
                $ValidDays = $($ValidTo - [datetime]::Now).Days
                if($ValidDays -lt 0) { $ValidDays = 0 }
                $ObjSSL = @()
                ([System.Security.Authentication.SslProtocols] | gm -static -MemberType Property | ?{$_.Name -notin @("Default","None")} | %{$_.Name}) | %{
                $ProtocolName = $_
                $Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                $Socket.Connect($ComputerName, $Port)
                    try {
                        $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
                        $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
                        $SslStream.AuthenticateAsClient($ComputerName, $null, $ProtocolName, $false )
                        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
                        $KeyLength = $RemoteCertificate.PublicKey.Key.KeySize
                        $SignatureAlgorithm = $RemoteCertificate.PublicKey.Key.SignatureAlgorithm.Split("#")[1]
                        $SslProtocolName = [string]""
                        $SslProtocolName += $ProtocolName + ";"
                        $ObjSSL += $SslProtocolName
                    } catch  {
                        #$ProtocolStatus.Add($ProtocolName, $false)
                    } finally {
                        $SslStream.Close()
                    }
                }

            } Catch [System.Management.Automation.ActionPreferenceStopException] {
                continue
            }
        }
        $outSTR = "$Computer$port$SslProtocol$CheckCertRevocationStatus$CipherAlgorithm$CipherStrength$HashAlgorithm$HashStrength$KeyExchangeAlgorithm$KeyExchangeStrength$CertFormat$CertExpiration$CertIssueDate$CertIssuer$SerialNumber$CertSubject$CertSubject$CertType$CertKeySize$ValidDays"
        if($outSTR -notcontains $outARRAY) {
            $OutputString = [string]""
            $OutputString += ($Computer.ToUpper()).Trim() + "," + $port + "," + $SslProtocol + "," + $CheckCertRevocationStatus + "," + $CipherAlgorithm + "," + $CipherStrength + "," + $HashAlgorithm + "," + $HashStrength + "," + $KeyExchangeAlgorithm + "," + $KeyExchangeStrength+ "," + $CertFormat + "," + $CertExpiration + "," + $CertIssueDate + "," + $CertIssuer + "," + $SerialNumber + "," + $CertSubject + "," + $CertSubject + "," + $CertType + "," + $CertKeySize + "," + $ValidDays + "," + $ObjSSL + "," + $KeyLength + "," + $SignatureAlgorithm
            $Obj += $OutputString
            [array]$outARRAY = $outSTR
        }
    }
    $Obj
}
