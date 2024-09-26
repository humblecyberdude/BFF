<#

                                                                      ██████╗     ███████╗    ███████╗
                                                                      ██╔══██╗    ██╔════╝    ██╔════╝
                                                                      ██████╔╝    █████╗      █████╗  
                                                                      ██╔══██╗    ██╔══╝      ██╔══╝  
                                                                      ██████╔╝    ██║         ██║     
                                                                      ╚═════╝     ╚═╝         ╚═╝     
                                                                                                                                          
                                   ██╗    ███╗   ██╗    ███████╗    ████████╗     █████╗     ██╗         ██╗         ███████╗    ██████╗  
                                   ██║    ████╗  ██║    ██╔════╝    ╚══██╔══╝    ██╔══██╗    ██║         ██║         ██╔════╝    ██╔══██╗ 
                                   ██║    ██╔██╗ ██║    ███████╗       ██║       ███████║    ██║         ██║         █████╗      ██████╔╝ 
                                   ██║    ██║╚██╗██║    ╚════██║       ██║       ██╔══██║    ██║         ██║         ██╔══╝      ██╔══██╗ 
                                   ██║    ██║ ╚████║    ███████║       ██║       ██║  ██║    ███████╗    ███████╗    ███████╗    ██║  ██║ 
                                   ╚═╝    ╚═╝  ╚═══╝    ╚══════╝       ╚═╝       ╚═╝  ╚═╝    ╚══════╝    ╚══════╝    ╚══════╝    ╚═╝  ╚═╝ 
                                                                                                                                          
                                           ██████╗      █████╗     ██╗   ██╗    ██╗          ██████╗      █████╗     ██████╗              
                                           ██╔══██╗    ██╔══██╗    ╚██╗ ██╔╝    ██║         ██╔═══██╗    ██╔══██╗    ██╔══██╗             
                                           ██████╔╝    ███████║     ╚████╔╝     ██║         ██║   ██║    ███████║    ██║  ██║             
                                           ██╔═══╝     ██╔══██║      ╚██╔╝      ██║         ██║   ██║    ██╔══██║    ██║  ██║     
                                           ██║         ██║  ██║       ██║       ███████╗    ╚██████╔╝    ██║  ██║    ██████╔╝             
                                           ╚═╝         ╚═╝  ╚═╝       ╚═╝       ╚══════╝     ╚═════╝     ╚═╝  ╚═╝    ╚═════╝              
                                                                                                                                                 
                                                                << DECRYPTED INSTALLER PAYLOAD FOR BFF >>
                                                                                                                                                                            

    .NOTES
    Project:                Backstop Flexibility Framework (BFF)
    Public GitHub Repo:     https://github.com/humblecyberdude/BFF
    Copyright:              HumbleCyberDude@gmail.com
    License:                MIT (https://opensource.org/license/mit)
    Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
    Major Release Name:     Tender Lovin' Snare
    █ Last Updated By:      HumbleCyberDude
    █ Release Stage:        ALPHA
    █ Version:              0.1
    █ Last Update:          9-August-2024

#>




##############################################################################################################################################################################
#region   SCRIPT INFO   ######################################################################################################################################################
##############################################################################################################################################################################

    # Script Version
    [System.Version]$runningScriptVer = "1.1.0"
    
    # Breakout the Version info for easier parsing
    $runningScriptVerMajor = ($runningScriptVer).Major
    $runningScriptVerMinor = ($runningScriptVer).Minor
    $runningScriptVerBuild = ($runningScriptVer).Build
    
    # Ensure that this script version gets passed to ClientCore Functions
    $Global:runningScriptVerString = "$runningScriptVerMajor.$runningScriptVerMinor.$runningScriptVerBuild"

#endregion SCRIPT INFO 




##############################################################################################################################################################################
#region   VARIABLES   ########################################################################################################################################################
##############################################################################################################################################################################

    # Supress progress bars to reduce odd artifacts when running in console mode.
    $Global:ProgressPreference = 'SilentlyContinue'

    # Define the Backstop C2 Server hostname
    $Global:backstopServerName = 'YOUR_FQDN_HERE'

    # Determine if Backstop API Server is reachable
    $backstopApiServerReachable = (Test-NetConnection -ComputerName "$backstopServerName" -Port "443").TcpTestSucceeded

    # Define the valid certificate thumbprint that to match against to ensure that it's your signed code running.
    $validBackstopCodeSigningThumbprint = "YOUR_THUMBPRINT_HERE"

    # Define the valid thumbprints. We want to create an array so we can add additional ones later. The certificate thumbpint isn't contained within the cert but instead,
    # is the SHA256 hash of the entire cert, allowing anyone to more easiliy compare the cert.
    $validBackstopAPICertThumbprints = @('YOUR_THUMBPRINT_HERE')

    # Define the custom local log path for this script
    $Global:CustomLocalLogPath = "C:\Windows\Temp\$env:COMPUTERNAME-bff\$env:COMPUTERNAME-bff.log"

    # Define PowerShell version string
    $Global:psVerString = (Get-Host).version.ToString()

    # See if Backstop is installed or not
    $backstopInstalled = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE" -Name Installed -ErrorAction SilentlyContinue

    # Define the Splunk HEC Classification Level
    $Global:classificationLevel = "C3"

#endregion VARIABLES




##############################################################################################################################################################################
#region   DEPENDANCIES   #####################################################################################################################################################
##############################################################################################################################################################################

    function Invoke-GeneralDependancies
    {
        Write-Host "Checking dependencies..."

        # Create temp directory for Backstop
        if(-not(Test-Path "C:\Windows\Temp\$env:COMPUTERNAME-bff"))
        {
            New-Item -ItemType Directory -Path "C:\Windows\Temp\$env:COMPUTERNAME-bff" -Force | Out-Null
        }

        # Ensure that we're running in at least PowerShell 7
        $psVersion = (get-host).version.Major
        if($psVersion -lt 7)
        {
            $message = "Exit Error: Must be running at least PowerShell 7. Download the latest version at: https://github.com/PowerShell/PowerShell/releases/latest."

            # Write Local Log File
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

            Write-Host $message -ForegroundColor Red

            # Exit
            Exit
        }

        # Ensure that Powershell is running as the SYSTEM account. Else, install will fail after directory lockdowns.
        $whoami = whoami

        # Exit if not running as SYSTEM. No thanks to non-standard system images, have to account for things like "nt-autorität\system".
        if($whoami -notmatch "nt.+\\system")
        {
            $message = "Exit Error: This PowerShell process must run as SYSTEM. Try: psexec.exe /s /i `"C:\Program Files\PowerShell\7\pwsh.exe`""
                
            # Write Local Log File
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

            Write-Host $message -ForegroundColor Red

            # Exit
            Exit
        }


        # Exit if Backstop API Server or Splunk HEC Unreachable (Required)
        if(-not($backstopApiServerReachable))
        {
            $message = "Exit Error: Unable to reach the Backstop server. Additional Info: backstopApiServerReachable=$backstopApiServerReachable"
                
            # Write Local Log File
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

            Write-Host $message -ForegroundColor Red

            # Exit
            Exit
        }

        # Lockdown the directory even though we'll delete it anyway. Important to do this *after* the above. Else it can't log anything if not running as SYSTEM.
        # Here, lockdown means only "NT AUTHORITY\SYSTEM" user has any access (Full Access) and we mark it as both a System directory + hidden
        & "C:\Windows\System32\icacls.exe" "C:\Windows\Temp\$env:COMPUTERNAME-bff" /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /inheritance:r | out-null
        & "C:\Windows\System32\attrib.exe" +S +H +I "C:\Windows\Temp\$env:COMPUTERNAME-bff"

        # Ensure that the asset trusts the Internal Root CA else TLS will break. This would be true for base images, assets not yet on the domain, DMZ servers, M&A assets or other one-off's like test VM's.
        if(-not(Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -eq "YOUR_THUMBPRINT_HERE"}))
        {
            # Create the cert (doesn't change and less dependencies on fetching it elsewhere)
            Add-Content "C:\Windows\Temp\$env:COMPUTERNAME-bff\YourRootCA.pem" "-----BEGIN CERTIFICATE-----"
            Add-Content "C:\Windows\Temp\$env:COMPUTERNAME-bff\YourRootCA.pem" "...BASE64 STRINGS..."
            Add-Content "C:\Windows\Temp\$env:COMPUTERNAME-bff\YourRootCA.pem" "-----END CERTIFICATE-----"

            # Import Cert to Root Trust Store
            Import-Certificate -FilePath "C:\Windows\Temp\$env:COMPUTERNAME-bff\YourRootCA.pem" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

            # Cleanup the cert
            Remove-Item -Path "C:\Windows\Temp\$env:COMPUTERNAME-bff\YourRootCA.pem" -Force

            # Verify
            if(-not(Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -eq "YOUR_THUMBPRINT_HERE"}))
            {
                # Log the failure but continue with local copy (if available)
                $message = "Exit Error: The Internal root CA wasn't installed to begin with and still isn't installed after trying to automatically install it. Manually check what's going on here."

                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=warn message=$message"

                Write-Host $message -ForegroundColor Red

                # Exit
                Exit
            }
        }


        # This is needed to ensure that the public backstop API cert is fully trusted. Ensure that the asset trusts the UserTrust Root CA else TLS will break.
        # Now, as this is a well-known public CA, it "should" already be trusted... except that party pooper Randy Reality, Edge McCase and our good friends
        # Technical Debt and Captain Incompetence love to break up the party. Remember, "Enterprise Grade" truly stands for "I can't believe it works with so 
        # much duct tape". Sorry for the rant but it's true...
        if(-not(Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -eq "YOUR_THUMBPRINT_HERE"}))
        {
            # Create the cert (doesn't change and less dependencies on fetching it elsewhere)
            Add-Content "C:\Windows\Temp\$env:COMPUTERNAME-bff\UserTrustRootCA.pem" "-----BEGIN CERTIFICATE-----"
            Add-Content "C:\Windows\Temp\$env:COMPUTERNAME-bff\UserTrustRootCA.pem" "...BASE64 STRINGS..."
            Add-Content "C:\Windows\Temp\$env:COMPUTERNAME-bff\UserTrustRootCA.pem" "-----END CERTIFICATE-----"

            # Import Cert to Root Trust Store
            Import-Certificate -FilePath "C:\Windows\Temp\$env:COMPUTERNAME-bff\UserTrustRootCA.pem" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

            # Cleanup the cert
            Remove-Item -Path "C:\Windows\Temp\$env:COMPUTERNAME-bff\UserTrustRootCA.pem" -Force

            # Verify
            if(-not(Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -eq "YOUR_THUMBPRINT_HERE"}))
            {
                # Log the failure but continue with local copy (if available)
                $message = "Exit Error: The UserTrust root CA wasn't installed to begin with and still isn't installed after trying to automatically install it. Manually check what's going on here."

                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=warn message=$message"

                Write-Host $message -ForegroundColor Red

                # Exit
                Exit
            }
        }

    }

    function Invoke-InstallDependancies
    {
        # Check if Backstop is already installed
        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -ErrorAction SilentlyContinue).Installed -eq "1")
        {
            Write-Host "Exit Error: Backstop already appears to be installed. Please uninstall it first: .\Install-BFF.ps1 -Remove..." -ForegroundColor Red

            # Exit
            Exit
        }
    }

    function Invoke-RemovalDependancies
    {
        # Check if Backstop is already installed
        if($RemovalToken -notmatch "[a-fA-F0-9]{64}")
        {
            Write-Host "Exit Error: Check the format of the removal token. It must be 64 hexadecimal characters." -ForegroundColor Red

            # Exit
            Exit
        }
    }

#endregion DEPENDANCIES




##############################################################################################################################################################################
#region   CERTIFICATE PINNING CHECK   ########################################################################################################################################
##############################################################################################################################################################################

    # We need to ensure that we're not getting MiTM'd. Therefore, we need to check the certificate thumbprint to ensure that it's ours.

    function Confirm-Certificate
    {
        if($backstopApiServerReachable)
        {
            # Get the cert so we can compare it. 
            # CREDIT: This is thanks to Faris Malaeb (CertifcateScanner: https://www.powershellcenter.com/2021/12/23/sslexpirationcheck/)
            $socket = New-Object Net.Sockets.TcpClient($backstopServerName, 443)
            $stream = $socket.GetStream()
            $sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))
            $ProtocolVersion = 'Tls12'
            $sslStream.AuthenticateAsClient($backstopServerName,$null,[System.Security.Authentication.SslProtocols]$ProtocolVersion,$false)
            $cert = $sslStream.RemoteCertificate
            $serverThumbprint = $cert.Thumbprint

            # Fail if the validBackstopAPICertThumbprints array doesn't contain a valid thumbprint
            if($validBackstopAPICertThumbprints -notcontains $serverThumbprint)
            {
                $subject = $cert.Subject
                $issuer = $cert.Issuer
                $validFrom = $cert.NotBefore
                $validTo = $cert.NotAfter

                # Write Local Log File
                $message = "EXIT ERROR: Certificiate pinning check failed so script exited. Traffic interception may have been performed. Bad Cert Info: subject=$subject issuer=$issuer invalidServerThumbprint=$serverThumbprint validFrom=$validFrom validTo=$validTo"
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"
                Write-Host $message -ForegroundColor Red

                # EJECT! EJECT!
                Exit
            }
        }
    }

#endregion CERTIFICATE PINNING CHECK




##############################################################################################################################################################################
#region   SET API KEYS   #####################################################################################################################################################
##############################################################################################################################################################################

    function Set-ApiKeys
    {
        # If installing for the first time, generate the correct registration API key so the server will accept initial requests prior to getting our permanent API key.
        if($Install)
        {
            # Define API server registration key. This is the key used to register or uninstall the endpoint
            $registrationHMACSecret = "$env:COMPUTERNAME|YOUR_REGISTRATION_SECRET_HERE"

            # If Backstop is not yet installed, we need to use an initial API key to get our new API key from the server that we can use going forward for subsequent requests. 
            # However, we can't have all clients using a universal API key and at the same time, we also don't want an API key that's based only on the hostname of the asset 
            # (just in case that's burned as well). Therefore, we're going to submit the salt along with the hostname of this asset to have the server, with its separate 
            # private key, create a per-install API key. Below, we simply create a random string of letters and numbers for the salt.
            $Global:clientSalt = (-join ((0x30..0x39)+(0x41..0x5A)+(0x61..0x7A) | Get-Random -Count 16 | ForEach-Object {[char]$_}))

            # Do an HMAC function to create the registration API key from the HMAC secret and the registration key. $RegistrationKey is created with "-RegistrationKey [KEY_HERE]" at command line during install.
            $hmacSHA256 = New-Object System.Security.Cryptography.HMACSHA256
            $hmacSHA256.key = [Text.Encoding]::ASCII.GetBytes($registrationHMACSecret)
            $apiKey = $hmacSHA256.ComputeHash([Text.Encoding]::ASCII.GetBytes($RegistrationKey))
            $Global:registrationApiKey = [Convert]::ToBase64String($apiKey)
        }

        # If attempting to remove Backstop and it's already installed, obtain the correct removal API key so we can authenticate to see where Backstop is installed so we can then remove it.
        if(($Remove)   -and   ($backstopInstalled))
        {
            # Define API server uninstall key. This is the key used to register or uninstall the endpoint
            $uninstallHMACSecret = "$env:COMPUTERNAME|YOUR_UNINSTALL_SECRET_HERE"

            # Get the salt value which will be needed for the API call to get where BFF is installed
            $Global:clientSalt = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE").SLT

            # Do an HMAC function to create the API key from the HMAC secret and the registration key (RK)
            $hmacSHA256 = New-Object System.Security.Cryptography.HMACSHA256
            $hmacSHA256.key = [Text.Encoding]::ASCII.GetBytes($uninstallHMACSecret)
            $apiKey = $hmacSHA256.ComputeHash([Text.Encoding]::ASCII.GetBytes($clientSalt))
            $Global:uninstallApiKey = [Convert]::ToBase64String($apiKey)
        }
    }

#endregion SET API KEYS




##############################################################################################################################################################################
#region   REGISTER ENDPOINT   ################################################################################################################################################
##############################################################################################################################################################################

    function Register-Endpoint
    {
        # Register with the API server and get our random directory and task scheduler names so they're different on each host + get our go-forward API key
        try {
            
            $registrationData = Invoke-RestMethod -Method GET -Uri "https://$backstopServerName/backstop/registerEndpoint/v1" -Headers @{apiKey = "$registrationApiKey"; clientHostname = $env:COMPUTERNAME; clientSalt = "$clientSalt"; clientState = "installing"} -UserAgent "Backstop ($scriptName/$runningScriptVerString) (PowerShell/$psVerString)" -ErrorVariable webRequestError

        } catch {

            # Parse out just the status code text for the specific error
            $webRequestError = $webRequestError.InnerException.Response.StatusCode

            # Write Local Log File
            $message = "Exit Error: Unable to get random installation names. Additional Info: webRequestError=$webRequestError"
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"
            Write-Host $message -ForegroundColor Red

            # Exit
            Exit
        }

        # Define the random names give back from the API server. The API server will give both in the response we captured in the variable $registrationData.
        $Global:directoryName = $registrationData.directoryName
        $Global:taskPathName = $registrationData.taskPathName
        $Global:newApiKey = $registrationData.newClientApiKey

        # Set the splunkHECRelayApiKey with the same as the new Backstop API key. There's two ways to send via Splunk HEC: Direct and Relayed via Backstop. If this
        # is an M&A computer, it likely will not have connectivity to Splunk HEC directly so we need to ensure that we give the Write-Log functions in the ClientCore
        # functions module the API key to relay to Splunk HEC via Backstop. 
        $Global:splunkHECRelayApiKey = $newApiKey

        # Ensure that we have the random names before proceeding. If not, exit.
        if((-not($directoryName))   -or   (-not($taskPathName))   -or   (-not($newApiKey)))
        {
            # Write Local Log File
            $message = "Exit Error: Secondary failure getting the random directory and task path names. Additional Info: webRequestError=$webRequestError directoryName=$directoryName taskPathName=$taskPathName apiKey=$apiKey"
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"
            Write-Host $message -ForegroundColor Red

            # Exit
            Exit
        }
    }

#endregion REGISTER ENDPOINT




##############################################################################################################################################################################
#region   IMPORT CLIENTCORE FUNCTION MODULE   ################################################################################################################################
##############################################################################################################################################################################

    function Import-ClientCore
    {
        # Download the latest version of ClientCore if Backstop API Server is reachable (which is should be by this point). This module gives us the ability to send data back to Splunk and easily test signatures.
        try
        {
            Invoke-RestMethod -Method GET -Uri "https://$backstopServerName/backstop/getFiles/v1" -Headers @{apiKey = "$newApiKey"; clientHostname = $env:COMPUTERNAME; fileName = "ClientCore.psm1"} -OutFile "C:\Windows\Temp\$env:COMPUTERNAME-bff\ClientCore.psm1" -UserAgent "Backstop ($scriptName/$runningScriptVerString) (PowerShell/$psVerString)" -ErrorVariable webRequestError

        } catch {

            # Parse out just the status code text for the specific error
            $webRequestError = $webRequestError.InnerException.Response.StatusCode

            # Log the failure but continue with local copy (if available)
            $message = "Exit Error: The Backstop API Server was reachable but we're unable to download ClientCore.psm1. Additional Info: backstopApiServerReachable=$backstopApiServerReachable webRequestError=$webRequestError"

            # Write Local Log File
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=warn message=$message"

            Write-Host $message -ForegroundColor Red
        }

        # If the file exists, check its signature and run if signature is valid. Note that it will still execute even if the Backstop API Server is unreachable so long as it's correctly signed. Again, this is by design.
        if(Test-Path -Path "C:\Windows\Temp\$env:COMPUTERNAME-bff\ClientCore.psm1")
        {
            # Get the file signature status for each file
            $scriptSignatureStatus = (Get-AuthenticodeSignature -FilePath "C:\Windows\Temp\$env:COMPUTERNAME-bff\ClientCore.psm1").Status.ToString()
            $scriptSignatureThumbprint = ((Get-AuthenticodeSignature -FilePath "C:\Windows\Temp\$env:COMPUTERNAME-bff\ClientCore.psm1").SignerCertificate).Thumbprint

            # Execute pspm.ps1 only if it is correctly signed and signed by the Backstop code signing certificate
            if(($scriptSignatureStatus -eq "Valid")   -and   ($scriptSignatureThumbprint -eq "$validBackstopCodeSigningThumbprint"))
            {
                Import-Module "C:\Windows\Temp\$env:COMPUTERNAME-bff\ClientCore.psm1" -Force

            } Else {

                $message = "Exit Error: Found missing or incorrect Backstop cert thumbprint for ClientCore.psm1. Additional Info: validBackstopCodeSigningThumbprint=$validBackstopCodeSigningThumbprint scriptSignatureThumbprint=$scriptSignatureThumbprint scriptSignatureStatus=$scriptSignatureStatus."
                
                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

                Write-Host $message -ForegroundColor Red

                # Exit Script
                Exit
            }

        } Else {

            # Only exit if using the -Install switch and the file is missing via this else statement
            if($Install)
            {
                $message = "Exit Error: The ClientCore.psm1 file is missing locally and script was unable to download a copy. Script will exit now since we can't verify code integrity. Additional Info: connectedToInternalNetwork=$connectedToInternalNetwork webRequestError=$webRequestError"

                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

                Write-Host $message -ForegroundColor Red

                # Exit Script
                Exit
            }
        }

        # Beacon back to Splunk that the installer was launched and registration was successful (would have exited out at this point if it wasn't)
        Write-Log -eventTag "Beacon" -eventSubTag "-" -severityLevel "info" -messages "Backstop installer executed. Registration appears to have been successful." -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
    }

#endregion IMPORT CLIENTCORE FUNCTION MODULE




##############################################################################################################################################################################
#region   BUILD RANDOM INSTALL LOCATION   ####################################################################################################################################
##############################################################################################################################################################################

    function Install-Directories
    {
        Write-Host "Beginning install process..."

        # Create Chaff array to store the other decoy (clutter) directories
        $chaffArray = @()

        # Create chaff/clutter directory names (at most, make it somewhat less appealing to go through them all) but vary their names and number
        # Usually we'd do something like 1..100 (do something 100 times for each number 1 through 100) but for the latter, we'll make that a random number.
        $randomNumberofGuids = Get-Random -Minimum 10 -Maximum 50
        1..$randomNumberofGuids | Foreach-Object {

            $randomGuid = [guid]::NewGuid().Guid
            $chaffArray += $randomGuid
        }

        # Pick specific GUID for the real working directory under the one above (we'll have many decoys so it's important we know which is the right one)
        $realDirectory = [guid]::NewGuid().Guid

        # Define the full "root path" to the install directory which will contain all our other needed directories
        $Global:fullRealDirectoryPath = "C:\ProgramData\$directoryName\$realDirectory"

        # Create directory structures
        New-Item -ItemType Directory "$fullRealDirectoryPath" -Force | out-null

        # Lockdown the new directory. Here, lockdown means only the "NT AUTHORITY\SYSTEM" account has Full Access and we mark it as both a System directory & hidden
        # This is the same technique that Sysmon uses for its deleted items directory if configured. I may decide against doing this later because it's a balance of 
        # sticking out (clearly being hidden) or blending in. For now, chosing to hide as best I can since it's too easy to miss if hidden and not paying attention.
        # Simply put, this is to keep curious people out. Remember, if you're an admin, you can elevate to SYSTEM and from there, do a string search or file name
        # search regardless to find it. I could randomize all the filenames and compress the code (more complexity) but finding which scheduled task(s) call 
        # something in the ProgramData directory isn't hard either. Balancing staying hiden vs. supportability. 
        & "C:\Windows\System32\icacls.exe" "C:\ProgramData\$directoryName" /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /inheritance:r | out-null
        & "C:\Windows\System32\attrib.exe" +S +H +I "C:\ProgramData\$directoryName"

        # Create chaff/clutter directories which will, at most, make it less interesting to look through if only casually glancing at it.
        foreach($randomChaffDirectoryName in $chaffArray)
        {
            New-Item -ItemType Directory "C:\ProgramData\$directoryName\$randomChaffDirectoryName" -Force | out-null
        }

        # Populate the standard directories we need
        New-Item -ItemType Directory "$fullRealDirectoryPath\bin" -Force | out-null
        New-Item -ItemType Directory "$fullRealDirectoryPath\etc" -Force | out-null
        New-Item -ItemType Directory "$fullRealDirectoryPath\logs" -Force | out-null
        New-Item -ItemType Directory "$fullRealDirectoryPath\modules" -Force | out-null
        New-Item -ItemType Directory "$fullRealDirectoryPath\scripts" -Force | out-null
        New-Item -ItemType Directory "$fullRealDirectoryPath\temp" -Force | out-null

        # Move ClientCore to the modules directory
        Move-Item -Path "C:\Windows\Temp\$env:COMPUTERNAME-bff\ClientCore.psm1" -Destination "$fullRealDirectoryPath\modules" -Force


        # Make a simple DPAPI-based vault for the SYSTEM account and specific to this machine only. This "vault" will be used to store API keys and any other sensitive information.
        # Again, since this is secured via the DPAPI key pairs, the vault can only be accessed from the SYSTEM account on only this machine. It's not portable unless you exported the 
        # DPAPI key pairs - I can't worry about everything but hey, at least I don't have to worry about domain backup DPAPI keys since it's kinda local.

        # Create the Vault
        try {

            # Create the initial JSON vault so we can add the needed secret(s)
            New-SimpleVault -VaultPath "$fullRealDirectoryPath\etc\vault.json" -Force

        } catch {

            # Log and Exit
            Write-Log -eventTag "Build Random Install Location" -eventSubTag "NewVault" -severityLevel "error" -messages "Exit Error: Unable to create the JSON vault. BFF can't be installed on this endpoint. Additional Info: Error=$($Error[0])" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost

            Exit
        }

        # Open the Vault
        try {
            # Open the JSON vault so we can get the needed secrets
            Open-SimpleVault -VaultPath "$fullRealDirectoryPath\etc\vault.json" -ErrorVariable openVaultError

        } catch {

            # Log and Exit
            Write-Log -eventTag "Build Random Install Location" -eventSubTag "OpenVault" -severityLevel "error" -messages "Exit Error: Unable to open the JSON vault. BFF can't be installed on this endpoint. Additional Info: Error=$($Error[0])" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost
        
            Exit
        }

        # Add Secrets(s)
        try {

            # Get the secrets we need so we can authenticate to the Backstop API, etc. 
            # NOTE: Any extracted secrets will populate a variable called [Name]_vaultSecret. Example if the name was "foo" then it's secret you use is foo_vaultSecret
            Add-SimpleVaultSecret -Name backstopGeneralApiKey -Secret $newApiKey -Force -Quiet -ErrorVariable addVaultSecretError

        } catch {

            # Log and Exit
            Write-Log -eventTag "Build Random Install Location" -eventSubTag "AddSecrets" -severityLevel "error" -messages "Exit Error: Unable to add a secret to the JSON vault. BFF can't be installed on this endpoint. Additional Info: Error=$($Error[0])" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost

            Exit
        }       

        # Get Invoke-BFF.ps1 and place in the scripts directory. This is the main/core file that will be executed every ~15min
        try {

            Invoke-RestMethod -Method GET -Uri "https://$backstopServerName/backstop/getFiles/v1" -Headers @{apiKey = "$newApiKey"; clientHostname = $env:COMPUTERNAME; fileName = "Invoke-BFF.ps1"} -OutFile "$fullRealDirectoryPath\scripts\Invoke-BFF.ps1" -UserAgent "Backstop ($scriptName/$runningScriptVerString) (PowerShell/$psVerString)" -ErrorVariable webRequestError

        } catch {

            # Parse out just the status code text for the specific error
            $webRequestError = $webRequestError.InnerException.Response.StatusCode

            # Log Event
            Write-Log -eventTag "Register Endpoint" -eventSubTag "-" -severityLevel "error" -messages "Exit Error: Unable to download Invoke-BFF.ps1. Additional Info: webRequestError=$webRequestError" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost

            # Exit
            Exit
        }

        # Generate a set of chaff decoy keys to note if Backstop was installed or not. This will be used to key off of later. Originally this code was going to be used to burry 
        # the install location which Backstop and the uninstaller could use to dynamically determine where it was installed. However, I decided to move this functionality 
        # to the API server instead for better security. Normally I'd just burry a simple key but since I already wrote these commands, might as well use them.
        # Feel free to change this and burry it wherever you want.
        New-Item -Path "HKLM:\SOFTWARE\Microsoft" -Name "YOUR_HIDDEN_LOCATION_HERE" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE" -Name "Description" -Force | Out-Null        
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE" -Name "{C9622FA9-0CDF-440E-BFE3-05FC794312EE}" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\{C9622FA9-0CDF-440E-BFE3-05FC794312EE}" -Name "Mappings" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\{C9622FA9-0CDF-440E-BFE3-05FC794312EE}\Mappings" -Name "uuid:efb3622c-1a47-4135-b498-173f05d34500" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\{C9622FA9-0CDF-440E-BFE3-05FC794312EE}\Mappings\uuid:efb3622c-1a47-4135-b498-173f05d34500\" -Name "(Default)" -Value "uuid:b872f8b1-d925-4794-a2fb-9e706a43b25c" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\{C9622FA9-0CDF-440E-BFE3-05FC794312EE}\Mappings\uuid:efb3622c-1a47-4135-b498-173f05d34500" -Name "Settings" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "DWord" -Name "AllowUntrustedCode" -Value "0" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "DWord" -Name "EnableDynamicUPNPDiscover" -Value "1" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "DWord" -Name "Version" -Value "4" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "DWord" -Name "Recognizer Capability Flags" -Value "396734" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "String" -Name "Languages" -Value "en-US,en-PH,en-LR" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "String" -Name "Vendor Name" -Value "Microsoft Corporation" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "DWord" -Name "EnableTracing" -Value "0" -Force | Out-Null

        # Declare if Backstop is installed or not. This is the key that will be used during install (to tell you to manually uninstall it first) and during uninstall to ensure it was installed in the first place.
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "DWord" -Name "Installed" -Value "1" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE\" -PropertyType "String" -Name "SLT" -Value "$clientSalt" -Force | Out-Null

        # Define the directories and files to iterate through below for timestamp changes (includes chaff)
        $directories = Get-ChildItem "C:\ProgramData\$directoryName" -Recurse -Force

        # Iterate through our directory to change the timestamps to something in the past. Make it look like it's been there for a year+.
        foreach ($directory in $directories)
        {
            # Create a random year of install. If you try and randomly mess with the days and convert to a datetime stamp, good luck. They won't line up to reality. Can't 
            # have something like "Wednesday, September 22, 2017 6:35:32 AM" because September 22, 2017 wasn't a Wednesday. Therefore, the year is good enough. 
            $randomYear = Get-Random -Minimum 1 -Maximum 5

            # Craft the timestamp string that will be needed for the foreach loop below
            [DateTime]$newTimestamp = (Get-Date).AddYears(-$randomYear)

            # Set some random month/day amount within reason. We want to ensure that directories DO NOT appear to be created/modified at the same time - again some minor blending in
            # This will iterate through and keep adding to the date so it will progressively increase
            $randomMonth = Get-Random -Minimum 0 -Maximum 2
            $randomDay = Get-Random -Minimum 0 -Maximum 30
            $randomHour = Get-Random -Minimum 0 -Maximum 24
            $randomMinute = Get-Random -Minimum 0 -Maximum 60
        
            # Randomize Timestamps
            [DateTime]$newTimestamp = $newTimestamp.AddMonths($randomMonth)
            [DateTime]$newTimestamp = $newTimestamp.AddDays($randomDay)
            [DateTime]$newTimestamp = $newTimestamp.AddHours($randomHour)
            [DateTime]$newTimestamp = $newTimestamp.AddMinutes($randomMinute)

            # Update timestamps
            (Get-Item -Path "$directory" -Force).CreationTime=($newTimestamp)
            (Get-Item -Path "$directory" -Force).LastAccessTime=($newTimestamp)
            (Get-Item -Path "$directory" -Force).LastWriteTime=($newTimestamp)
        }

        # Confirm signature on Invoke-BFF.ps1. Note that, assuming it's valid, the ClientCore module will populate variable 'signatureVerified' to $True (see usage below for spot check)
        Confirm-Authenticode -FilePath "$fullRealDirectoryPath\scripts\Invoke-BFF.ps1" -Thumbprint $validBackstopCodeSigningThumbprint

        # Get variables for spot check
        $filedirectoryCount = (Get-ChildItem -Recurse "$fullRealDirectoryPath").count
        $directoryModifiedDate = (Get-ChildItem "$fullRealDirectoryPath").CreationTime
        $vaultCreatedSuccessfully = ((Get-Content -Path "$fullRealDirectoryPath\etc\vault.json" | ConvertFrom-Json).secrets.backstopGeneralApiKey).length -gt 600
        $currentDate = Get-Date
        $installedMarkerPresent = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE" -Name Installed -ErrorAction SilentlyContinue
        $clientSaltPresent = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE" -Name SLT -ErrorAction SilentlyContinue
        
        # General Spot Check + Ensure that Invoke-BFF.ps1 is correctly signed: NEVER trust the server!
        if(((Test-Path -Path "$fullRealDirectoryPath\scripts\Invoke-BFF.ps1")   -and   ($signatureVerified))   -and   ($filedirectoryCount -ge 6)   -and   ($directoryModifiedDate -le $currentDate)   -and   ($installedMarkerPresent -eq 1)   -and   ($clientSaltPresent -eq "$clientSalt")   -and   ($vaultCreatedSuccessfully -eq $True))
        {
            # Log Event
            Write-Log -eventTag "Build Random Install Location" -eventSubTag "Spot Check" -severityLevel "info" -messages "All spot checks passed" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel

            # Create overall check variable
            $Global:InstallRandomDirectories = "pass"

        } Else {

            # Log Event
            Write-Log -eventTag "Build Random Install Location" -eventSubTag "Spot Check" -severityLevel "error" -messages "Exit Error: Spot check failed for either the Invoke-BFF.ps1 signature, directory count or other condition. Additional Info: signatureVerified=$signatureVerified filedirectoryCount=$filedirectoryCount directoryModifiedDate=$directoryModifiedDate installedMarkerPresent=$installedMarkerPresent saltPresent=$clientSaltPresent vaultCreatedSuccessfully=$vaultCreatedSuccessfully" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost

            # Exit
            Exit
        }
    }

#endregion BUILD RANDOM INSTALL LOCATION




##############################################################################################################################################################################
#region   BUILD RANDOM SCHEDULED TASK   ######################################################################################################################################
##############################################################################################################################################################################
    
    function Install-ScheduledTask
    {
        # Pick a GUID for the scheduled task name (random and other tasks do it as well). However... keep it looking sort of like a GUID but make it slightly invalid so a 
        # standard search for it via a normal regex GUID pattern won't work. Here we 
        $taskName = [guid]::NewGuid().Guid

        # Put it in brackets like other GUID task names I've seen. Probably doesn't matter but whatever.
        $Script:taskName = "{$taskName}"

        # Set a random year date in the past
        $randomYear = Get-Random -Minimum 0 -Maximum 5

        # Specify that the task should have started two years ago from current date. Make it look like it's old and certainly don't set it for the future else it won't run yet.
        $scheduledAt = (Get-Date).AddYears(-$randomYear)

        # Define the timespan for what the max amount of random time Task Scheduler will pick. Random delay will also help spread the load on the API server.
        $randomDelayInMinutes = New-TimeSpan -Minutes 7

        # This is how often the task will run but keep in mind the randomized time above.
        $runInterval = New-TimeSpan -Minutes 25

        # Create the trigger for the scheduled task. Even though it's "once", no worries. As long as it's in the past and it's enabled, it will run every $runInterval.
        $scheduledTaskTrigger = New-ScheduledTaskTrigger -Once -At $scheduledAt -RepetitionInterval $runInterval -RandomDelay $randomDelayInMinutes 

        # Define the full path to Invoke-BFF.ps1
        $backstopFullPath = "$fullRealDirectoryPath\scripts\Invoke-BFF.ps1"

        # Create the action for the scheduled task
        $scheduledTaskAction = New-ScheduledTaskAction -Execute "C:\Program Files\PowerShell\7\pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$backstopFullPath`""

        # Pick which account this needs to run under. Here, we choose the local SYSTEM account
        $scheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

        # Specify additional scheduled task settings
        $scheduledTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew -Compatibility Win8

        # Finally, register the task
        Register-ScheduledTask -Action $scheduledTaskAction -Trigger $scheduledTaskTrigger -Principal $scheduledTaskPrincipal -TaskPath "\Microsoft\Windows\$taskPathName" -TaskName $taskName -Settings $scheduledTaskSettings -Force | out-null

        # Get variables for spot check
        $scheduledTaskState = (Get-ScheduledTask -TaskName $taskName).State
        $scheduledTaskArguments = (Get-ScheduledTask -TaskName $taskName).actions.Arguments
        $scheduledTaskInterval = (Get-ScheduledTask -TaskName $taskName).triggers.repetition.interval

        # General Spot Check
        if(($scheduledTaskState -eq "Ready")   -and   ($scheduledTaskArguments -eq "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$fullRealDirectoryPath\scripts\Invoke-BFF.ps1`"")   -and   ($scheduledTaskInterval -eq "PT25M"))
        {
            # Log Event
            Write-Log -eventTag "Build Random Scheduled Task" -eventSubTag "Spot Check" -severityLevel "info" -messages "All spot checks passed" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel

            # Create overall check variable
            $Global:InstallRandomScheduledTask = "pass"

            # Start the task
            Start-ScheduledTask -TaskPath "\Microsoft\Windows\$taskPathName\" -TaskName $taskName

            # Wait a tiny bit to ensure it's still running (didn't just start, exit and fail right away)
            Start-Sleep 1

            # Get the current task state
            $taskState = (Get-ScheduledTask -TaskPath "\Microsoft\Windows\$taskPathName\" -TaskName $taskName).State

            if($taskState -eq "Running")
            {
                # Create overall check variable
                $Global:taskRemainedRunning = "pass"

            } Else {

                $scheduledTaskState = (Get-ScheduledTask -TaskName $taskName).State

                # Get the last run time result code and translate that into a hex value (lookup tables are in hex)
                $lastTaskResultDecimal = (Get-ScheduledTaskInfo -TaskPath "\Microsoft\Windows\$taskPathName\" -TaskName "$taskName").LastTaskResult
                $lastTaskResultCode = '{0:x}' -f $lastTaskResultDecimal
                $lastTaskResultCode = "0x$lastTaskResultCode"

                $messages = @{
                    messageText = "Tried to start the scheduled task but it died to quickly - probably an issue. Take a look at the last task result code in this message and look it up at https://en.wikipedia.org/wiki/Windows_Task_Scheduler"
                    scheduledTaskState = $scheduledTaskState
                    lastTaskResultCode = $lastTaskResultCode
                    scheduledTaskArguments = $scheduledTaskArguments
                    scheduledTaskInterval = $scheduledTaskInterval
                }

                # Log Event
                Write-Log -eventTag "Build Random Scheduled Task" -eventSubTag "Spot Check" -severityLevel "warn" -messages $messages -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
            }

        } Else {

            # Log Event
            Write-Log -eventTag "Build Random Scheduled Task" -eventSubTag "Spot Check" -severityLevel "error" -messages "Exit Error: Spot check failed for either the Invoke-BFF.ps1 signature, directory count or other condition. Additional Info: scheduledTaskState=$scheduledTaskState scheduledTaskArguments=$scheduledTaskArguments scheduledTaskInterval=$scheduledTaskInterval" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost

            # Exit
            Exit
        }
    }

#endregion BUILD RANDOM SCHEDULED TASK




##############################################################################################################################################################################
#region   INSTALL CLEANUP AND BEACON   #######################################################################################################################################
##############################################################################################################################################################################

    function Invoke-CleanupAndBeacon
    {
        Write-Host "Starting cleanup process..."

        # Remove temp directory to tidy up (no longer needed)
        Remove-Item -Path "C:\Windows\Temp\$env:COMPUTERNAME-bff" -Recurse -Force

        # Spot Check
        if(-Not(Test-Path "C:\Windows\Temp\$env:COMPUTERNAME-bff"))
        {
            # Create overall check variable
            $InstallCleanupAndBeacon = "pass"

        } Else {

            # Create overall check variable
            $InstallCleanupAndBeacon = "fail"

            # Log Event
            Write-Log -eventTag "Install Cleanup and Beacon" -eventSubTag "Spot Check" -severityLevel "error" -messages "Unable to delete `"C:\Windows\Temp\$env:COMPUTERNAME-bff`"" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost -DoNotLogToLocalFile
        }

        # Send confirmation beacon back to Splunk that the install was successful. No sense having another else statement to log a failure here since it should have already 
        # exited and provided feeback by this point. 
        if(($InstallRandomDirectories -eq "pass")   -and   ($InstallRandomScheduledTask -eq "pass")   -and   ($InstallCleanupAndBeacon -eq "pass")   -and   ($taskRemainedRunning -eq "pass"))
        {
            $messages = @{
                finalStatus = "Install Successful"
                InstallRandomDirectories = $InstallRandomDirectories
                InstallRandomScheduledTask = $InstallRandomScheduledTask
                InstallCleanupAndBeacon = $InstallCleanupAndBeacon
                taskRemainedRunning = $taskRemainedRunning
            }

        # Confirm registration with the API server. Move from pending state to registered state.
        try
        {
            Invoke-RestMethod -Method GET -Uri "https://$backstopServerName/backstop/registerEndpoint/v1" -Headers @{apiKey = "$registrationApiKey"; clientHostname = $env:COMPUTERNAME; clientState = "installed"} -UserAgent "Backstop ($scriptName/$runningScriptVerString) (PowerShell/$psVerString)" -ErrorVariable webRequestError

        } catch {

            # Parse out just the status code text for the specific error
            $webRequestError = $webRequestError.InnerException.Response.StatusCode

            # Log Event
            Write-Log -eventTag "Install Cleanup and Beacon" -eventSubTag "Spot Check" -severityLevel "error" -messages "Unable to delete `"C:\Windows\Temp\$env:COMPUTERNAME-bff`"" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -WriteHost -DoNotLogToLocalFile
        }
            # Log Event
            Write-Log -eventTag "Install Cleanup and Beacon" -eventSubTag "Final Check" -severityLevel "info" -messages $messages -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel -DoNotLogToLocalFile

            Write-Host "[IMPLANT INSTALLED]`n" -ForegroundColor Green
        }
    }

    function Remove-Script
    {
        # Remove script so long as the -KeepScript parameter wasn't selected
        if(-not($KeepScript))
        {
            # If PSCommandPath (i.e. the path the script is running from) doesn't match these locations, delete the script.
            if(($fullScriptPath -notlike "*dev*")   -and   ($fullScriptPath -notlike "*ccmcache*")   -and   ($fullScriptPath -notlike "*backstop*"))
            { 
                # Dynamically determine script location and delete it.
                Remove-Item -Path $fullScriptPath -Force

                # Verify if cleanup was successful or not
                if(Test-Path $fullScriptPath)
                {
                    # Log Event
                    Write-Log -eventTag "Install Cleanup and Beacon" -eventSubTag "Remove-Script" -severityLevel "error" -messages "Unable to delete the installer script. Fix this!" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
                }
            }
        }
    }

#endregion INSTALL CLEANUP AND BEACON




##############################################################################################################################################################################
#region   REMOVE BACKSTOP   ##################################################################################################################################################
##############################################################################################################################################################################

    function Invoke-RemovalDependancyChecks
    {
        # If Backstop doesn't exist, exit because there should be nothing to uninstall anyway
        if(-Not($backstopInstalled))
        {
            Write-Error "Exit Error: Backstop doesn't appear to be installed."

            # Exit
            Exit
        }

        # Now, request where Backstop is installed for this host
        try
        {
            # Make rest call to find out what the directory and task path names are. Once we have them, we can see if they're present on the machine and if so, call to uninstall it.
            $names = Invoke-RestMethod -Method GET -Uri "https://$backstopServerName/backstop/removeEndpoint/v1" -Headers @{apiKey = "$uninstallApiKey"; removalToken = "$removalToken"; clientHostname = $env:COMPUTERNAME; clientSalt = $clientSalt; reason = "$RemovalReason"; clientState = "uninstalling"} -UserAgent "Backstop ($scriptName/$runningScriptVerString) (PowerShell/$psVerString)" -ErrorVariable webRequestError

            # Since we don't have the general API key yet to download and import the ClientCore support module, we'll just import it from the local install. The last two items 
            # in the IF statement are for deception responses from the API server (encryptedDirectoryName and "No mapping found") if they try with an invalid reason.
            if(($names)   -and   (-not($names.encryptedDirectoryName)   -and   (-not($names.directoryName -eq "No mapping found"))))
            {
                # Define the random names give back from the API server. The API server will give both in the response we captured in the variable $names.
                $Global:directoryName = $names.directoryName
                $Global:taskPathName = $names.taskPathName

                # Find the module directory so we can import the ClientCore support module without having to make an API call (we don't have the common key with this script for uninstalling)
                $moduleDirectory = (Get-ChildItem -Recurse -Path "C:\ProgramData\$directoryName" -Include ClientCore.psm1).DirectoryName

                # Import the module
                Import-Module "$moduleDirectory\ClientCore.psm1" -Force

            }

        } catch {

            # Parse out just the status code text for the specific error
            $webRequestError = $webRequestError.InnerException.Response.StatusCode

            Write-host "Unable to aquire the random directory and task path names needed to find and remove Backstop. Additional Info: backstopApiServerReachable=$backstopApiServerReachable webRequestError=$webRequestError"

            # Exit
            Exit
        }

        # Decieve the person if reason code is wrong. Look, I get it. If they see this code here and look at it closely, they'll know but never assume an attacker is always 100% competent, hard working and/or had a cup of coffee.
        # If there's a better option, I'm open to suggestion.
        If($names.encryptedDirectoryName)
        {
            # Signal to the person trying to remove it that it was successfully uninstalled. Also, sleep at intervals which would make it feel more realistic (somewhat mimics the real thing). Will vary between machines anyway.
            $randomSleepInterval = Get-Random -Minimum 2 -Maximum 5
            Start-Sleep -Seconds $randomSleepInterval
            Write-Host "Scheduler was found and successfully removed"

            $randomSleepInterval = Get-Random -Minimum 1 -Maximum 3
            Start-Sleep -Seconds $randomSleepInterval
            Write-Host "Directory was found and successfully removed"
            Start-Sleep -Seconds $randomSleepInterval
            Write-Host "Registry keys were found and successfully removed"

            $randomSleepInterval = Get-Random -Minimum 1 -Maximum 3
            Start-Sleep -Seconds $randomSleepInterval
            Write-Host "`n[IMPLANT REMOVED]`n"

            # Exit
            Exit
        }

        # Exit if the API server can't find the name
        If($directoryName -eq "No mapping found")
        {
            Write-Error "Exit Error: The API server was unable to find the random directory and task path names needed to find and remove Backstop."

            # Exit
            Exit
        }

        # Ensure that we have the random names before proceeding. If not, exit.
        if((-not($directoryName))   -or   (-not($taskPathName)))
        {
            # Log Event
            Write-Error "Exit Error: Secondary failure getting the random directory and task path names. Additional Info: directoryName=$directoryName taskPathName=$taskPathName webRequestError=$webRequestError"

            # Exit
            Exit
        }
    }

    function Remove-ScheduledTask
    {
        # If scheduled task is present (should be), remove it.
        if(Get-ScheduledTask -TaskPath "\Microsoft\Windows\$taskPathName\")
        {
            # Get the task name
            $taskName = (Get-ScheduledTask -TaskPath "\Microsoft\Windows\$taskPathName\").TaskName

            # Stop scheduled Task if Running
            Stop-ScheduledTask -TaskPath "\Microsoft\Windows\$taskPathName\" -TaskName "$taskName" -ErrorAction SilentlyContinue

            # Initiate Sleep (Give Time to Stop)
            Start-Sleep 3

            # Remove Scheduled Task Job
            Unregister-ScheduledTask -TaskName "$taskName" -Confirm:$false

            # Verify $taskPathName is populated. We want to be SUPER careful not to blow away all Windows scheduled tasks.
            if($taskPathName -match "[a-zA-Z0-9]")
            {
                # Remove the scheduled task Path (the directory in Task Scheduler)
                Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\$taskPathName\" -Force -Recurse
            }

            # Spot Check Test
            if(-Not(Get-ScheduledTask -TaskPath "\Microsoft\Windows\$taskPathName\" -TaskName "$taskName" -ErrorAction SilentlyContinue))
            {
                # Log Event
                Write-Log -eventTag "Remove Backstop" -eventSubTag "Scheduled Task" -severityLevel "info" -messages "Scheduler was found and successfully removed" -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel

                # Set spot check variable
                $Global:scheduledTaskCleanup = "pass"

            } Else {

                # Log Event
                Write-Log -eventTag "Remove Backstop" -eventSubTag "Scheduled Task" -severityLevel "error" -messages "Scheduled task still found on system and may still try and run. Additional Info: taskPathName=$taskPathName taskName=$taskName" -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel

                # Set spot check variable
                $Global:scheduledTaskCleanup = "fail"
            }
        }
    }

    function Remove-Directories
    {
        # Ensure the directory and task path exists. Also be REALLY careful and double check that $directoryName fully contains at least something. If still blank somehow, this could delete the ProgramData directory.
        If((Test-Path -Path "C:\ProgramData\$directoryName")   -and   ($directoryName -match "[a-zA-Z0-9]"))
        {
            # Blow it all away
            Remove-Item -Path "C:\ProgramData\$directoryName" -Recurse -Force

        }

        # Spot Check Test
        if(-Not(Test-Path -Path "C:\ProgramData\$directoryName"))
        {
            # Log Event
            Write-Log -eventTag "Remove Backstop" -eventSubTag "Remove Directories" -severityLevel "info" -messages "Directory was found and successfully removed" -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel

            # Set spot check variable
            $Global:directoryCleanup = "pass"

        } Else {

            # Log Event
            Write-Log -eventTag "Remove Backstop" -eventSubTag "Remove Directories" -severityLevel "error" -messages "The root directory for Backstop is still present and must be manually removed." -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel

            # Set spot check variable
            $Global:directoryCleanup = "fail"
        }
    }

    function Remove-RegKeys
    {
        # Remove the registry keys
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE" -Recurse -Force

        # Spot Check Test
        if((-Not(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\YOUR_HIDDEN_LOCATION_HERE")))
        {
            # Log Event
            Write-Log -eventTag "Remove Backstop" -eventSubTag "Remove Registry Keys" -severityLevel "info" -messages "Registry keys were found and successfully removed" -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel

            # Set spot check variable
            $Global:regkeyCleanup = "pass"

        } Else {

            # Log Event
            Write-Log -eventTag "Remove Backstop" -eventSubTag "Remove Registry Keys" -severityLevel "error" -messages "Unable to remove the registry keys for Backstop. Check your code!" -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel

            # Set spot check variable
            $Global:regkeyCleanup = "fail"
        }
    }

    function Invoke-FinalRemoveBeacon
    {
        if(($scheduledTaskCleanup -eq "pass")   -and   ($directoryCleanup -eq "pass")   -and   ($regkeyCleanup -eq "pass"))
        {
            try
            {
                # Beacon back to the server to confirm that the uninstall was fully successful. State should then be unregistered on the server side.
                Invoke-RestMethod -Method GET -Uri "https://$backstopServerName/backstop/removeEndpoint/v1" -Headers @{apiKey = "$uninstallApiKey"; removalToken = "$removalToken"; clientHostname = $env:COMPUTERNAME; reason = "$RemovalReason"; clientState = "uninstalled"} -UserAgent "Backstop ($scriptName/$runningScriptVerString) (PowerShell/$psVerString)" -ErrorVariable webRequestError

            } Catch {

                # Parse out just the status code text for the specific error
                $webRequestError = $webRequestError.InnerException.Response.StatusCode

                Write-host "Unable to beacon back. Additional Info: backstopApiServerReachable=$backstopApiServerReachable webRequestError=$webRequestError"

                # Exit
                Exit
            }

            # Log Event
            Write-Log -eventTag "Remove Backstop" -eventSubTag "Final Beacon" -severityLevel "info" -messages "Backstop was successfully removed and removal verified" -CustomLocalLogPath "$CustomLocalLogPath" -ClassificationLevel $classificationLevel
            Write-Host "`n[IMPLANT REMOVED]`n" -ForegroundColor Green

            # Remove temp directory to tidy up (no longer needed)
            Remove-Item -Path "C:\Windows\Temp\$env:COMPUTERNAME-bff" -Recurse -Force -ErrorAction SilentlyContinue

        } Else {

            # Log Event
            Write-Log -eventTag "Remove Backstop" -eventSubTag "Final Beacon" -severityLevel "error" -messages "Backstop removal failed. Additional Info: scheduledTaskCleanup=$scheduledTaskCleanup directoryCleanup=$directoryCleanup regkeyCleanup=$regkeyCleanup" -CustomLocalLogPath "$CustomLocalLogPath" -WriteHost -ClassificationLevel $classificationLevel
        }
    }

#endregion REMOVE BACKSTOP
