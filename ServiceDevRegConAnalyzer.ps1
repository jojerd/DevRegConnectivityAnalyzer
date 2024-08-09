# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
<#
MIT License

Copyright (c) 2024 Josh Jerdon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

.NOTES
	Name: DevRegConnectAnalyzer.ps1
	Requires: PowerShell 5.1
    Major Release History:
        8/2/2024- 1.0 Initial Release
        8/9/2024- 1.01 Added error handling for connection attempts.

.SYNOPSIS
Automates the process for checking device registration and Windows Hello for Business connectivity to Entra. Its a best effort attempt to check everything from IP
addresses resolved per hostname, and attempts to connect to each hostname IP returned over port 443 and will also attempt to provide the TLS version and connection information.
This information is useful to help troubleshoot connectivity to various Microsoft Entra endpoints.

.DESCRIPTION
This utility will check connectivity and TLS encryption to the required endpoints to help provide insight into connectivity related issues with Device Registration
and Windows Hello for Business issues.


.EXAMPLE
PowerShell as an Administrator: .\DevRegConnectAnalyzer.ps1

#>
$IPHashtable = @{}
$JsonFile = Get-Content .\IPs.json
$PSObject = $JsonFile | ConvertFrom-Json
$PSObject.PSObject.Properties | ForEach-Object {
    $IPHashtable[$_.Name] = $_.Value
}

$Portsclosed = @{}

$Logname = 'SYSTEM-DevRegConAnalyzer.log'
# Special thanks to EE Matt Byrd for the Write-Log function
function Write-Log {
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$String,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$OutHost,

        [switch]$OpenLog

    )

    begin {
        # Get our log file path
        $Path = Get-Location
        $LogFile = Join-Path $Path $Name
        if ($OpenLog) {
            Notepad.exe $LogFile
            exit
        }
    }
    process {

        # Get the current date
        [string]$date = Get-Date -Format G

        # Build output string
        [string]$logstring = ( "[" + $date + "] - " + $string)

        # Write everything to our log file and the screen
        $logstring | Out-File -FilePath $LogFile -Append -Confirm:$false
        if ($OutHost) { Write-Host $logstring }
        else { Write-Verbose  $logstring }
    }
}
$WhoCheck = whoami.exe
Write-Log -String "$($WhoCheck) account is running this script" -Name $Logname -OutHost

function Test-Connectivity {
    # Specify protocols we are going to use to test with to confirm TLS is not being interfered with (Only testing with TLS 1.2 and TLS 1.3).
    $Protocols = [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
    $ProtocolArray = $Protocols -split ","
    [int]$Port = 443
    # Specify Timeout to wait for connection in milliseconds.
    $Timeout = 500
    # Itinerate through the Hashtable for each endpoint IP address to check if Port is open or closed.
    foreach ($HashEndpoint in $IPHashtable.Keys) {
        Write-Log -String "Checking connectivity for Endpoint: $HashEndpoint" -Name $Logname -OutHost
        foreach ($IPaddress in $IPHashtable[$HashEndpoint]) {
            Write-Log -String " " -Name $Logname -OutHost
            Write-Log -String "Checking IP Address: $IPaddress" -Name $Logname -OutHost
            # Build the TCP Client to make the connection to IP and Port.
            try {
                $TCPClient = New-Object System.Net.Sockets.TcpClient
                $Portcheck = $TCPClient.ConnectAsync($IPaddress, $Port).Wait($Timeout)
            }
            catch {
                Write-Log -String "$($_.Exception.Message)" -Name $Logname -OutHost
            }

            # If connection is successful create a new variable with the port status and log it.
            if ($Portcheck -eq 'True') {
                $PortStatus = "Open"
                $TcpClient.Close()
                Write-Log -String "Port 443 for $HashEndpoint IP Address $IPaddress is $PortStatus" -Name $Logname -OutHost
            }
            else {
                # If connection failed log the endpoint name and IP Address.
                $PortStatus = "Closed"
                Write-Log -String "Connection Timeout for $HashEndpoint IP Address: $IPaddress" -Name $Logname -OutHost
                $TCPClient.Close()
            }
            # If Port 443 is open test connectivity and obtain connection details.
            if ($PortStatus -eq 'Open') {
                foreach ($Protocol in $ProtocolArray) {
                    # Build a new client to check TLS connectivity.
                    try {
                        $SocketClient = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                        $SocketClient.Connect($IPAddress, $Port)
                    }
                    catch {
                        Write-Log -String "$($_.Exception.Message)" -Name $Logname -OutHost
                    }

                    try {
                        # Retrieve connection details to be able to log them (Remote Certificate, Cipher used, Protocol connected etc.)
                        $Stream = New-Object System.Net.Sockets.NetworkStream($SocketClient, $true)
                        $SecureChannel = New-Object System.Net.Security.SslStream($Stream, $true)
                        $SecureChannel.AuthenticateAsClient($HashEndpoint, $null, $Protocol, $false)
                        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SecureChannel.RemoteCertificate
                        $ConnectedCipher = [System.Security.Authentication.CipherAlgorithmType]$SecureChannel.CipherAlgorithm
                        $ProtocolStatus = "True"
                        Write-Host ""
                        Write-Host "SUCCESS!" -ForegroundColor Green
                        Write-Host "Connected to $HashEndpoint with IP: $IPaddress using TLS Version $Protocol" -ForegroundColor Green
                        # Save connection details to a PS Custom Object to be written to the log file.
                        $ConnectedReport = [PSCustomObject]@{
                            Hostname             = $HashEndpoint
                            IPAddress            = $IPAddress
                            PortChecked          = $Port
                            Certificate          = $Certificate.Subject
                            Thumbprint           = $Certificate.Thumbprint
                            Issuer               = $Certificate.Issuer
                            CertIssueDate        = $Certificate.NotBefore
                            CertExpires          = $Certificate.NotAfter
                            KeyLength            = $Certificate.PublicKey.Key.KeySize
                            CertificateSignature = $Certificate.SignatureAlgorithm.FriendlyName
                            CipherUsed           = $ConnectedCipher
                            ProtocolVersion      = $Protocol
                            ProtocolSupported    = $ProtocolStatus
                        
                        }
                        # Iterate through the PS Custom Object and write details retrieved from TLS Connection above to log file.
                        foreach ($object in $ConnectedReport) {
                            Write-Log -String "+++++++++++++++++++++++++++++++++++ CERTIFICATE DETAILS +++++++++++++++++++++++++++++++++++++++++++++" -Name $Logname -OutHost
                            foreach ($i in $object.PSObject.Properties) {
                                Write-log -String "$($i.Name), $($i.Value)" -Name $Logname -OutHost
                            }
                            Write-Log -String "+++++++++++++++++++++++++++++++++++ CERTIFICATE DETAILS +++++++++++++++++++++++++++++++++++++++++++++" -Name $Logname -OutHost
                        }
                          
                    }
        
                    catch {
                        # If Connection fails write to the log the hostname, IP address, Port and protocol used.
                        $ProtocolStatus = "False"
                        Write-Host ""
                        Write-Host "FAILURE!" -ForegroundColor Red
                        Write-Host "Unable to connect to $HashEndpoint IP Address of $IPAddress over port 443 with TLS version $Protocol" -ForegroundColor Red -ErrorAction Continue
                        
                        $UnableConnectReport = [PSCustomObject]@{
                            Hostname          = $HashEndpoint
                            IPAddress         = $IPaddress
                            PortChecked       = $Port
                            ProtocolVersion   = $Protocol
                            ProtocolSupported = $ProtocolStatus
                        }
                        # Itinerate through the PS Custom Object and write details retrieved from TLS connection failure details above to log file.
                        foreach ($object in $UnableConnectReport) {
                            Write-Log -String "+++++++++++++++++++++++++++++++++++ TLS FAILURE DETAILS +++++++++++++++++++++++++++++++++++++++++++++" -Name $Logname -OutHost
                            foreach ($i in $object.PSObject.Properties) {
                                Write-Log -String "$($i.Name), $($i.Value)" -Name $Logname -OutHost
                            }
                            Write-Log -String "+++++++++++++++++++++++++++++++++++ TLS FAILURE DETAILS +++++++++++++++++++++++++++++++++++++++++++++" -Name $Logname -OutHost
                        }
                    }
                    # Close the current connection.
                    $SocketClient.Dispose()
                    $SecureChannel.Dispose()
                }

            }
            else {
                # If port is closed log it and detail which endpoint and IP Address script was unable to connect to.
                Write-Log -String "Skipping diagnostics for $IPAddress as destination port is closed or unreachable" -Name $Logname -OutHost
                Write-Host ""
                Write-Host "Unable to connect to $IPaddress for $HashEndpoint over port 443 as it is either being blocked by a firewall / proxy or is unreachable" -ForegroundColor Red
                $TCPClient.Close()
                if ($Portsclosed.Contains($HashEndpoint -eq $false)) {
                    $Portsclosed.$HashEndpoint = @()
                    $Portsclosed.Add($HashEndpoint, "$IPaddress,")
                }
                else {
                    $Portsclosed.$HashEndpoint += "$IPaddress,"
                }             

            }
        }
    }
    # Notify that script has completed.
    Write-Log -String "Script completed testing connectivity under SYSTEM Context" -Name $Logname -OutHost
    Write-Host ""
    Write-Host "Script Completed and details logged" -ForegroundColor Yellow
    Write-Host ""
    # Log IPs that were unreachable over port 443 for easier review.
    foreach ($item in $Portsclosed.Keys) {
        Write-Log -String "$item IP's Port 443 detected closed:" -Name $Logname -OutHost
        foreach ($obj in $Portsclosed[$item].trimend(",").split(",")) {
            Write-log -String "IP: $obj" -Name $Logname -OutHost
        }
    }
   
}
Test-Connectivity