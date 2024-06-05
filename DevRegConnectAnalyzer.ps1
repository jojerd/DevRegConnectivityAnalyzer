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
        To Be Announced - Initial Release

.SYNOPSIS
Automates the process for checking device registration and Windows Hello for Business connectivity to Entra. Its a best effort attempt to check everything from IP
addresses resolved per hostname, and attempts to connect to each hostname IP returned over port 443 and will also attempt to provide the TLS version and connection information.
This information is useful to help troubleshoot connectivity to various endpoints.

.DESCRIPTION
This utility will check connectivity and TLS encryption to the required endpoints to help provide insight into connectivity related issues with Device Registration
and Windows Hello for Business issues.


.EXAMPLE
Fill in later after script is completed.

#>
#Requires -Version 5.1
$Global:ProgressPreference = 'SilentlyContinue'
#Log filename
$Logname = 'DevRegConnectivity.log'

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
# Retrieve device registration status information. 
Write-log -String "Retrieving DSRegcmd /status information and logging to a separate log file" -Name $Logname
$DSReg = dsregcmd.exe /Status
$DSReg | Out-File .\dsregcmd.log

# Endpoints used for Device Registration and Windows Hello for Business (commercial tenants)
$CommercialEndpoints = 'login.microsoftonline.com', 'device.login.microsoftonline.com', 'enterpriseregistration.windows.net'
$WindowsHelloEndpoints = 'account.live.com', 'aadcdn.msftauth.net', 'aadcdn.msauth.net'

# Endpoints used for Device Registration and Windows Hello for Business (Gov tenants)
$GovEndpoints = 'login.microsoftonline.us', 'device.login.microsoftonline.us', 'enterpriseregistration.microsoftonline.us'
$GovWindowsHelloEndpoints = 'fp-afd.azurefd.us', 'account.live.com', 'acctcdn.msauth.net', 'aadcdn.msauthimages.us'

# Hashtable used to store endpoints and retrieved IP addresses.
$IPHashtable = @{}

#Get Environmental data about the host system, user and domain.
Write-Log -String "Checking if machine is on-prem domain joined" -Name $Logname -OutHost
try {
    $Domainjoined = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
}
catch {
    Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname -OutHost
}
Write-Log -String "Retrieving system environmental details" -Name $Logname -OutHost
$User = $env:USERNAME
$Tenantdomain = $env:USERDNSDOMAIN
$UserUPN = "$env:USERNAME@$env:USERDNSDOMAIN"
Write-Log -String "User UPN: $UserUPN" -Name $Logname -OutHost
Write-Log -String "User who executed script: $User" -Name $Logname -OutHost
Write-Log -String "Tenant domain: $TenantDomain" -Name $Logname -OutHost
if ($null -ne $Domainjoined) { $Joined = $true } else { $Joined = $false }
Write-Log -String "Client is Domain joined: $Joined" -Name $Logname -OutHost
$DomainName = $Domainjoined.Name
Write-Log -String "Host joined Domain Name: $DomainName" -Name $Logname -OutHost
$Hostname = ([System.Net.Dns]::GetHostByName(($env:COMPUTERNAME))).Hostname
Write-Log -String "Client hostname: $Hostname" -Name $Logname -OutHost
Write-Log -string "Retrieving Host details..." -Name $Logname -OutHost
$OS = Get-WmiObject win32_operatingsystem | Select-Object Caption, OSArchitecture, Version, BuildNumber
$ConnectionInfo = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" }
$Interface = $ConnectionInfo.InterfaceAlias
$LocalIP = $ConnectionInfo.IPv4Address.IPAddress
$DefaultGateway = $ConnectionInfo.IPv4DefaultGateway.NextHop
$DNSServer = $ConnectionInfo.DNSServer.ServerAddresses
#Get possible WAN IP Address (VPN or VPN with split tunnel, and or multiple WANs could provide false positive results)
$WAN = Invoke-RestMethod -Method Get "https://checkip.azurewebsites.net"
$WANIP = $WAN.html.body -split ":"


Write-Log -String "Host Operating System: $($OS.caption)" -Name $Logname -OutHost
Write-Log -string "Host Operating System Architecture: $($OS.OSArchitecture)" -Name $Logname -OutHost
Write-Log -String "Host Operating System Version: $($OS.Version)" -Name $Logname -OutHost
Write-Log -String "Host Operating System Build Number: $($OS.BuildNumber)" -Name $Logname -OutHost
Write-Log -string "Host connected interface: $Interface" -Name $Logname -OutHost
Write-Log -String "Host IP Address: $LocalIP" -Name $Logname -OutHost
Write-Log -String "Host Default Gateway IP: $DefaultGateway" -Name $Logname -OutHost
Write-Log -String "Host Configured DNS server(s) $DNSServer" -Name $Logname -OutHost
Write-Log -String "Host WAN IP:$($WANIP[1])" -Name $Logname -OutHost

#Get local Firewall configuration information
$PublicFirewall = Get-NetFirewallProfile -Name Public
$PrivateFirewall = Get-NetFirewallProfile -Name Private
$DomainFirewall = Get-NetFirewallProfile -Name Domain

Write-Log -String "Public Firewall Enabled: $($PublicFirewall.Enabled)" -Name $Logname -OutHost
Write-Log -String "Pirvate Firewall Enabled: $($PrivateFirewall.Enabled)" -Name $Logname -OutHost
Write-Log -String "Domain Firewall Enabled: $($DomainFirewall.Enabled)" -Name $Logname -OutHost

# Retrieve USGov endpoint DNS records.
function Get-USGov {
    $USGovTenantUrl = "https://login.microsoftonline.us/getuserrealm.srf?json=1&login=$TenantDomain"
    $USGovHRD = Invoke-RestMethod -Method Get -Uri $USGovTenantUrl
    $USGovDomain = $USGovHRD.NameSpaceType
    $USGovIDP = $USGovHRD.AuthURL
    Write-Log -String "USGov Domain: $USGovDomain" -Name $Logname -OutHost
    Write-Log -String "USGov IDP Url: $USGovIDP" -Name $Logname -OutHost

    foreach ($Endpoint in $GovEndpoints) {

        try {
            # Log successful retrieval of USGov Endpoint IP's.
            $DNS = Resolve-DnsName -Name $Endpoint | Select-Object IPAddress | Where-Object { $null -ne $_.IPAddress }
            Write-Host ""
            Write-Host "$Endpoint resolved successfully" -ForegroundColor Green
            Write-Log -String "$Endpoint resolved successfully" -Name $Logname
            Write-Log -String "$(($DNS.IPAddress).count) IP(s) returned for $Endpoint" -Name $Logname -OutHost
            Write-Log -String "$($DNS.IPAddress)" -Name $Logname -OutHost
            $IPHashtable.Add($Endpoint, $DNS.IPAddress)        
        }
        catch {
            # Log failures and stop script because if we cannot retrieve the DNS records no point to continuing.
            Write-Log -String "Unable to resolve DNS for $Endpoint" -Name $Logname -OutHost
            Write-Host "Unable to resolve hostname $Endpoint, check DNS to confirm it is working correctly" -ForegroundColor Red
            Write-Host "Unable to continue to analyze connectivity, please resolve DNS resolution issue" -ErrorAction Stop
        }       
    }
    Write-Log -String "Checking DNS resolution for US Government Windows Hello for Business endpoints" -Name $Logname -OutHost
    foreach ($WHGEndpoint in $GovWindowsHelloEndpoints) {
        try {
            # Log successful retrieval of USGov Windows Hello for Business endpoints.
            $WHGDNS = Resolve-DnsName -Name $WHGEndpoint | Select-Object IPAddress | Where-Object { $null -ne $_.IPAddress }
            Write-Host ""
            Write-Host "$Endpoint resolved successfully" -ForegroundColor Green
            Write-Log -String "$WHGEndpoint resolved successfully" -Name $Logname -OutHost
            Write-Log -String "$(($WHGDNS.IPAddress).count) IP(s) returned for $WHGEndpoint" -Name $Logname -OutHost
            $IPHashtable.Add($WHGEndpoint, $WHGDNS.IPAddress)
            Write-Host ""
            Write-Host "$WHGEndpoint resolved successfully" -ForegroundColor Green             
        }
        catch {
            # Log failures and silently continue as Windows Hello for Business may not always be used in a USGov tenant.
            Write-Log -String "Unable to resolve DNS for $WHGEndpoint" -Name $Logname -OutHost
            Write-Host ""
            Write-Host "Unable to resolve hostname $WHGEndpoint, check DNS to confirm it is working correctly" -ForegroundColor Red
            Write-Host "Unable to continue to analyze connectivity, please resolve DNS resolution issue" -ErrorAction SilentlyContinue
        }

    }
    # Write each endpoint and each IP Address resolved for that endpoint to the log.
    foreach ($HashEndpoint in $IPHashtable.Keys) {
        Write-Log -String "Endpoint: $HashEndpoint" -Name $Logname -OutHost
        foreach ($IPaddress in $IPHashtable[$HashEndpoint]) {
            Write-Log -String "IP: $IPaddress" -Name $Logname -OutHost
        }
    }
    # Write to log that the function completed and inform which function is next.
    Write-Log -String "Completed function Get-USGov, calling next fuction to test Connectivity" -Name $Logname; Test-Connectivity -OutHost
}
    
# Function to retrieve Commercial endpoint DNS records.
function Get-Commercial {

    foreach ($Endpoint in $CommercialEndpoints) {

        try {
            # Log successful retrieval of Commercial Endpoint IP's.
            $DNS = Resolve-DnsName -Name $Endpoint | Select-Object IPAddress | Where-Object { $null -ne $_.IPAddress }
            Write-Host ""
            Write-Host "$Endpoint resolved successfully" -ForegroundColor Green 
            Write-Log -String "$Endpoint resolved successfully" -Name $Logname
            Write-Log -String "$(($DNS.IPAddress).count) IP(s) returned for $Endpoint" -Name $Logname -OutHost
            $IPHashtable.Add($Endpoint, $DNS.IPAddress)
                
        }
        catch {
            # Log failures and stop script because if we cannot retrieve the DNS records no point to continuing.
            Write-Host ""
            Write-Log -String "Unable to resolve DNS for $Endpoint" -Name $Logname -OutHost
            Write-Host "Unable to resolve hostname $Endpoint, check DNS to confirm it is working correctly" -ForegroundColor Red
            Write-Host "Unable to continue to analyze connectivity, please resolve DNS resolution issue" -ErrorAction Stop
        }
    }
    # Check Windows Hello for Business Endpoints for DNS resolution.
    Write-Log -String "Checking DNS resolution for Commercial Windows Hello for Business endpoints" -Name $Logname -OutHost
    foreach ($WHCEndpoint in $WindowsHelloEndpoints) {
        try {
            $WHDNS = Resolve-DnsName -Name $WHCEndpoint | Select-Object IPAddress | Where-Object { $null -ne $_.IPAddress }
            Write-Host ""
            Write-Host "$WHCEndpoint resolved successfully" -ForegroundColor Green  
            Write-Log -String "$WHCEndpoint resolved successfully" -Name $Logname
            Write-Log -String "$(($WHDNS.IPAddress).count) IP(s) returned for $WHCEndpoint" -Name $Logname -OutHost
            $IPHashtable.Add($WHCEndpoint, $WHDNS.IPAddress)   
        }
        catch {
            # Log failures and silently continue as Windows Hello for Business may not always be used in a Commercial tenant.
            Write-Host ""
            Write-Log -String "Unable to resolve DNS for $WHCEndpoint" -Name $Logname -OutHost
            Write-Host "Unable to resolve hostname $WHCEndpoint, check DNS to confirm it is working correctly" -ForegroundColor Red
            Write-Host "Unable to continue to analyze connectivity, please resolve DNS resolution issue" -ErrorAction SilentlyContinue
        }

    }
    # Write each endpoint and each IP Address resolved for that endpoint to the log.
    foreach ($HashEndpoint in $IPHashtable.Keys) {
        Write-Log -String "Endpoint: $HashEndpoint" -Name $Logname -OutHost
        foreach ($IPaddress in $IPHashtable[$HashEndpoint]) {
            Write-Log -String "IP: $IPaddress" -Name $Logname -OutHost
        }
    }
    # Write to log that the function completed and inform which function is next.
    Write-Log -String "Completed function Get-Commercial, calling next fuction to test Connectivity" -Name $Logname; Test-Connectivity
}

# Function to retrieve tenant details
# Special Thanks to Rosalio Diera for the base code and idea.
function Get-TenantInfo {
    # Temporary Array used for storing Tenant specific endpoints to add them for DNS lookup later.
    $TempArray = @()

    Write-Log -String "Retrieving Tenant Information..." -Name $Logname -OutHost
    # Checking the openid-configuration to pull information from.
    $url = "https://login.windows.net/$TenantDomain/.well-known/openid-configuration"
    $TenantInfo = Invoke-RestMethod -Method Get -Uri $url
    $TenantIDInfo = ($TenantInfo.authorization_endpoint).split("/")
    $TenantID = $TenantIDInfo[3]
    $CloudInstance = $TenantInfo.cloud_instance_name
    $TenantCloud = $TenantInfo.tenant_region_scope
    Write-Log -String "Tenant ID: $TenantID" -Name $Logname -OutHost
    Write-Log -String "Cloud Instance: $CloudInstance" -Name $Logname -OutHost
    Write-Log -String "Tenant Cloud: $TenantCloud" -Name $Logname -OutHost
    #===========================================================================================
    # Checking the get user realm endpoint to get home realm related information. 
    $HRDUrl = "https://login.microsoftonline.com/getuserrealm.srf?json=1&login=$TenantDomain"
    $HomeRealmDiscoveryInfo = Invoke-RestMethod -Method Get -Uri $HRDUrl
    $DomainAuth = $HomeRealmDiscoveryInfo.NameSpaceType
    $IDP = $HomeRealmDiscoveryInfo.AuthURL
    Write-Log -String "Domain Authentication Type: $DomainAuth" -Name $Logname -OutHost
    Write-Log -String "Tenant IDP URL: $IDP" -Name $Logname -OutHost
    #===========================================================================================
    # Retrieve Tenant Specific Endpoints to be included in connectivity testing.
    Write-Log -String "Retrieving Tenant Specific endpoints to test connectivity against" -Name $Logname -OutHost
    foreach ($Property in $TenantInfo.PSObject.Properties) {
        $PropertyName = $Property.Name
        $PropertValue = $Property.Value

        if (($PropertyName -match "endpoint") -or ($PropertyName -match "issuer") -or ($PropertyName -match "rbac")) {
            $TenantEndpointObjects = $PropertValue -split "/"
            $TempArray += $TenantEndpointObjects[2]
        } 
    }
    # Switch to determine which tenant to add the tenant specific endpoints to. Regex pattern used to filter hostnames from other data.
    Write-Log -String "Adding retrieve tenant specific endpoints to pre-defined endpoints" -Name $Logname -OutHost
    switch ($TenantCloud) {
        "USG" {
            $AdditionalEndpoints = $TempArray | Select-String -Pattern "^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$"
            $GovEndpointAdd = $AdditionalEndpoints | Select-Object -Unique
            $GovEndpoints += $GovEndpointAdd 
        }
        "USGov" {
            $AdditionalEndpoints = $TempArray | Select-String -Pattern "^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$"
            $GovEndpointAdd = $AdditionalEndpoints | Select-Object -Unique
            $GovEndpoints += $GovEndpointAdd 
        }
        default {
            $AdditionalEndpoints = $TempArray | Select-String -Pattern "^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$"
            $ComEndpointAdd = $AdditionalEndpoints | Select-Object -Unique
            $CommercialEndpoints += $ComEndpointAdd 
        }
    }
     
    # Switch to determine which function to call after tenant information has been retrieved.
    Switch ($TenantCloud) {
        "USG" { Write-Log -String "Tenant is in (USG) FairFax, calling Get-USGov function" -Name $Logname -OutHost; Get-USGov }
        "USGov" { Write-Log -String "Tenant is in (USGov) Arlington, calling Get-USGov function" -Name $Logname -OutHost; Get-USGov } 
        default { Write-Log -String "Tenant is in Commercial Cloud, calling Get-Commercial function" -Name $Logname -OutHost; Get-Commercial }
     
    }    
    
}

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
            $TCPClient = New-Object System.Net.Sockets.TcpClient
            $Portcheck = $TCPClient.ConnectAsync($IPaddress, $Port).Wait($Timeout)
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
                    $SocketClient = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                    $SocketClient.Connect($IPAddress, $Port)
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
                        # Itinerate through the PS Custom Object and write details retrieved from TLS Connection above to log file.
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
                    # Close the current connection to create a new one.
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

            }
        }
    }
    # Notify that script has completed.
    Write-Log -String "Script completed testing connectivity" -Name $Logname
    Write-Host ""
    Write-Host "Script Completed and details logged" -ForegroundColor Yellow
    Write-Host ""
   
}
Get-TenantInfo