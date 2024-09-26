<#
    .SYNOPSIS
    This script builds the Backstop manifest file. The Backstop manifest file contains a collection of not only which 
    modules Backstop should run but also a list of important file hashes to tell Backstop if it needs to update any files 
    on the local system (i.e. new versions of binaries in the bin directory, new modules in the modules directory or new 
    scripts in the scripts directory). Without this, Backstop would have to download the files each time even if the 
    local copy is the same on the server which is needless API/server load. Backstop downloads the manifest file first, 
    understands which modules to run and does a self-check against the manifest comparing the server file hashes against 
    those on disk locally. If a file is missing or there's a hash mismatch, Backstop downloads the file and if the 
    signature is valid, will overwrite the existing local file.

    While the reason for grabbing the file hash below is obvious (so we can compare them), we also need to help the client
    understand where the files are to check locally. The client will automatically understand it's hidden install directory 
    via the rootPath variable but we need to tell it where to check the files locally (i.e. check filename example.ps1 in  
    the scripts directory or check this module in the modules directory, etc.). Additionally, we also provide the download
    path for the client as well to make things easier.


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


    .PARAMETER Environment
    This specifies which environment you'd like to build for. This helps to keep the test code separate from the prod code.
    If prod is specified, new files will be placed in "C:\Code\Backstop\ToServer\prod" and if test then in test (same place).


    .PARAMETER UpdateType
    This specifies which type of update you want. 'ClientFiles' updates the files the clients download from the Backstop 
    server whereas 'Installer' updates the installer by taking the Installer-Plaintext.ps1 text, encrypting it and then
    inserting that into the correct location into the outer shell or "wrapper" for the installer: Installer-Wrapper.ps1


    .PARAMETER NoArchive
    Skips the Backstop archive process


    .EXAMPLE
    .\Update-Backstop.ps1 -Environment Test -UpdateType ClientFiles

#>


# Define script parameters (arguments to the script)
Param
(
    # Specify the environment to build for
    [parameter(Mandatory=$True)]
    [ValidateSet('Prod', 'Test')]
    [String]
    $Environment,

    # Specify the type of update
    [parameter(Mandatory=$True)]
    [ValidateSet('ClientFiles', 'Installer')]
    [String]
    $UpdateType,

    # Use this if you do not want to create a backup archive
    [parameter(Mandatory=$False)]
    [Switch]
    $SkipArchive
)




##############################################################################################################################################################################
#region   SCRIPT INFO   ######################################################################################################################################################
##############################################################################################################################################################################

    # Script Version
    [System.Version]$runningScriptVer = "1.1.0"

    # Breakout the Version info for easier parsing
    $runningScriptVerMajor = ($runningScriptVer).Major
    $runningScriptVerMinor = ($runningScriptVer).Minor
    $runningScriptVerBuild = ($runningScriptVer).Build

    # Ensure that this script version gets passed to ClientCore functions
    $Global:runningScriptVerString = "$runningScriptVerMajor.$runningScriptVerMinor.$runningScriptVerBuild"

    # Define script name and hash
    $scriptPath = $MyInvocation.MyCommand.Source
    $scriptName = Split-Path $scriptPath -leaf

    # Get file hash of the calling script
    $Global:scriptFileHashSHA256 = (Get-FileHash $scriptPath -Algorithm SHA256).hash

#endregion SCRIPT INFO




##############################################################################################################################################################################
#region   VARIABLES   ########################################################################################################################################################
##############################################################################################################################################################################

    # Define the custom path of where the backstop files are located. Will standardize this later but setting it in one place to make it easy to move later
    $customPath = "C:\Code\Backstop"

    # Define the archive path
    $archivePath = "C:\Code\Archive\Backstop"

    # Define how large the archive needs to be in order to be generally considered valid
    $validArchiveSizeInKB = 512

    # Define the valid Backstop High-Trust Thumbprint so we can verify the correct signatures on files
    $validHighTrustThumbprint = 'YOUR_THUMBPRINT_HERE'

    # Define the custom local log path for this script
    $Global:CustomLocalLogPath = "C:\Windows\Temp\$scriptName.log"

    # Define the ClientCore module location
    $ClientCoreFilePath = "C:\Code\Backstop\SourceFiles\prod\modules\ClientCore.psm1"

#endregion VARIABLES




##############################################################################################################################################################################
#region   IMPORT CLIENTCORE FUNCTIONS MODULE   ###############################################################################################################################
##############################################################################################################################################################################

    if(Test-Path $ClientCoreFilePath)
    {
        # Get the file signature status for ClientCore
        $scriptSignatureStatus = (Get-AuthenticodeSignature -FilePath "$ClientCoreFilePath").Status.ToString()
        $scriptSignatureThumbprint = ((Get-AuthenticodeSignature -FilePath "$ClientCoreFilePath").SignerCertificate).Thumbprint

        # Import ClientCoreFilePath only if it is correctly signed and signed by the Backstop high-trust code signing certificate
        if(($scriptSignatureStatus -eq "Valid")   -and   ($scriptSignatureThumbprint -eq "$validHighTrustThumbprint"))
        {
            # Import the local module
            try
            {
                Import-Module "$ClientCoreFilePath" -Force -ErrorVariable moduleImportError -ErrorAction SilentlyContinue

            } catch {

                # Log the failure and Exit
                $message = "Exit Error: Unable to import the ClientCore module and therefore unable to build Backstop. Additional Info: Error=$($moduleImportError.Exception.Message)"

                # Write Local Log File
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
                Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

                Write-Error $message

                Exit
            }

        } Else {

            # Log the failure and Exit
            $message = "Exit Error: Found missing or incorrect Backstop cert thumbprint for ClientCore.psm1. Additional Info: validBackstopCodeSigningThumbprint=$validHighTrustThumbprint scriptSignatureThumbprint=$scriptSignatureThumbprint scriptSignatureStatus=$scriptSignatureStatus."
            
            # Write Local Log File
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
            Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

            Write-Error $message

            Exit
        }

    }  Else {

        # Log the failure and Exit
        $message = "Exit Error: File path to the ClientCore module isn't valid. Unable to build Backstop. Additional Info: Error=$($moduleImportError.Exception.Message)"

        # Write Local Log File
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K:"
        Add-Content -Path "$CustomLocalLogPath" -Value "$timestamp scriptName=$scriptName severity=error message=$message"

        Write-Error $message

        Exit
    }

#endregion IMPORT CLIENTCORE FUNCTIONS MODULE




##############################################################################################################################################################################
#region   ARCHIVE BACKSTOP   #################################################################################################################################################
##############################################################################################################################################################################

    if(-not($SkipArchive))
    {
        Write-Host "Creating an archive backup of the $Environment environment to $archivePath\$Environment..."

        # Make a timestamp
        $timeStamp = Get-Date -AsUTC -Format "yyyy-MM-dd HH-mm-ss"

        # Backup the files... just in case something goes oopsie... because IT WILL!
        Compress-Archive -Path "$customPath" -DestinationPath "$archivePath\archive-backstop-$Environment-$timeStamp.zip"

        # Archive File Size
        $archiveFileSize = [math]::Round((Get-ChildItem $archivePath\archive-backstop-$Environment-$timeStamp.zip).Length / 1024, 2)

        # Ensure that the archive was created (it exists) AND that it's greater than N number of KB's so we know it's not blank for some reason.
        if((Test-Path -Path "$archivePath\archive-backstop-$Environment-$timeStamp.zip")   -and   ($archiveFileSize -gt $validArchiveSizeInKB))
        {
            Write-Host "Successfully created archive $archivePath\archive-backstop-$Environment-$timeStamp.zip. NOTE: Local archives held for 90 days."

        } Else {

            Write-Warning "Something went wrong generating the archive: $archivePath\archive-backstop-$Environment-$timeStamp.zip. Check for errors but size may also have been <$validArchiveSizeInKB KB's"

            $answer = Read-Host -Prompt "`nDo you want to proceed? Type either `"yes`" or `"no`". Unless you know what you're doing, type `"no`"."

            if($answer -notmatch "yes|no")
            {
                Write-Host "That was not a valid answer. Perhaps a typing class should be in your future huh? Script exiting..."

                Exit
            }

            if($answer -eq "no")
            {
                Exit
            }
        }

        # Remove archives more than 90 days old
        Get-ChildItem -Path $archivePath -File -Recurse | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-90) } | Remove-Item -Force
    }

#endregion ARCHIVE BACKSTOP




##############################################################################################################################################################################
#region   UPDATE BACKSTOP CLIENT FILES   #####################################################################################################################################
##############################################################################################################################################################################

    if($UpdateType -eq 'ClientFiles')
    {
        # Import the previous environments manifest file and warn if it's not there. We need to do this so we can compare files that changed from last time to now. If the files
        # haven't changed, we just re-hash them without re-signing them (which would change their hash value). If the hash values don't change, they won't be downloaded which is 
        # what we want in order to reduce load on the server. We just want files to be downloaded only when they're changed. The files we're talking about here are the ones in 
        # the bin, modules and scripts directories.
        if((Test-Path -Path "$customPath\ToServer\$Environment\etc\manifest.ps1xml"))
        {
            # Import the current manifest file in the build directory. This is used to help understand what's already been signed
            $previousManifest = Import-Clixml -Path "$customPath\ToServer\$Environment\etc\manifest.ps1xml"

        } Else {

            Write-Warning -Message "No manifest file found in $customPath\ToServer\$Environment\etc\. Will assume all files are new and build from scratch. WARNING: This means that clients will re-download all files again!"
        }

        # Create initial manifest object
        $newManifest = [ordered]@{
            hashList = @{}
        }

        # Define the names of the items to process.
        $directoryNames = @('bin','modules','scripts')

        # Remove any items (old or not) from the directory
        Remove-Item -Path "$customPath\ToServer\$Environment\*" -Recurse -Force

        foreach ($directoryName in $directoryNames)
        {
            # Recreate the needed directory
            New-Item -ItemType Directory "$customPath\ToServer\$Environment\$directoryName" -Force | Out-Null

            # Copy fresh files over from Backstop build environment to this directory
            Copy-Item -Path "$customPath\SourceFiles\$Environment\$directoryName\*" -Recurse -Destination "$customPath\ToServer\$Environment\$directoryName" -Force

            # Capture all the files we may want to hash in this directory IF they have changed since last time.
            $directoryItems = Get-ChildItem -Force -Path "$customPath\ToServer\$Environment\$directoryName" -File

            foreach ($file in $directoryItems)
            {
                # Get the specific name of the file with the name attribute. Something like example.txt.
                $fileName = $file.Name

                # Get the local file hash of the file and, if possible, the previous hash of the same file in the old manifest file
                $localSHA256FileHash = (Get-FileHash -Path "$customPath\ToServer\$Environment\$directoryName\$fileName" -Algorithm SHA256).Hash
                $previousSHA256FileHash = ($previousManifest.hashList.Values | Where-Object {$_.localDirectoryName -eq "$directoryName"   -and   $_.fileName -eq "$fileName"}).remoteSHA256FileHash

                # If we have the previous manifest file but the file wasn't listed, then it's missing and we just need to add it.
                if(($previousManifest)   -and   (-not($previousSHA256FileHash)))
                {
                    $updateReason = "fileMissing"
                }

                # IF we have the previous hash but it does not equal the new hash, we need to update it
                if(($previousSHA256FileHash)   -and   ($localSHA256FileHash)   -and   ($previousSHA256FileHash -ne $localSHA256FileHash))
                {
                    $updateReason = "hashMismatch"
                }

                # Update everything if the manifest is missing
                if(-not($previousManifest))
                {
                    $updateReason = "manifestMissing"
                }

                # If file doesn't exist in the previous manifest file (we assume it's new in such a case), sign the file and add the file + hash to the new manifest file
                if($updateReason)
                {
                    Write-host "NEW/CHANGED FILE: Adding $fileName to the new manifest file and signing it. Reason: $updateReason" -ForegroundColor Green

                    # Sign files
                    Set-FileSignature -File "$customPath\ToServer\$Environment\$directoryName\$fileName" -TrustLevel High -CertStoreLocation CurrentUser -QuietMode

                    # Define the variables needed for the itemProperties object
                    $localDirectoryName = "$directoryName"

                    # Update the local hash value again, now that it should be signed
                    $localSHA256FileHash = (Get-FileHash -Path "$customPath\ToServer\$Environment\$directoryName\$fileName" -Algorithm SHA256).Hash

                    # Create the object to be added to the object
                    # Remember, even though we're calling the "local" file hash here, we're prepping the manifest file the clients will download from the server. 
                    $newManifest.hashList.$fileName = [PSCustomObject]@{fileName=$fileName; localDirectoryName=$localDirectoryName; remoteSHA256FileHash=$localSHA256FileHash}

                    # Flush the variable so it's not picked up again on subsequent passes
                    Remove-Variable updateReason

                } Else {

                    Write-host "EXISTING/UNCHANGED FILE: Adding $fileName to the new manifest file without updating its signature" -ForegroundColor Cyan

                    # Define the variables needed for the itemProperties object
                    $localDirectoryName = "$directoryName"

                    # Create the object to be added to the object
                    # Remember, even though we're calling the "local" file hash here, we're prepping the manifest file the clients will download from the server. 
                    $newManifest.hashList.$fileName = [PSCustomObject]@{fileName=$fileName; localDirectoryName=$localDirectoryName; remoteSHA256FileHash=$localSHA256FileHash}
                }
            }
        }

        # Create the etc directory
        New-Item -ItemType Directory "$customPath\ToServer\$Environment\etc" -Force | Out-Null

        # Take the new manifest object in memory and output that to a file
        $newManifest | Export-Clixml -Path "$customPath\ToServer\$Environment\etc\manifest.ps1xml"

        # Sign the new manifest file
        Set-FileSignature -File "$customPath\ToServer\$Environment\etc\manifest.ps1xml" -TrustLevel High -CertStoreLocation CurrentUser -QuietMode

        # Sync back the changes to the SourceFiles directory
        Remove-Item -Path "$customPath\SourceFiles\$Environment\*" -Recurse -Force
        Copy-Item -Path "$customPath\ToServer\$Environment\*" -Recurse -Destination "$customPath\SourceFiles\$Environment" -Force
    }

#endregion UPDATE BACKSTOP CLIENT FILES




##############################################################################################################################################################################
#region   UPDATE BACKSTOP INSTALLER   ########################################################################################################################################
##############################################################################################################################################################################

    if($UpdateType -eq "Installer")
    {
        <#
            Even though the installer will be one single file, we want to ensure that the most important parts (i.e. what it does and the registration keys) are encrypted. 
            Therefore, we split the installer into two files initially and merge them into a single file for simplicity. The two parts are:

            OUTER PORTION:  This is the Installer-Wrapper.ps1 file and acts are the outer portion which is always in plaintext. This provides the bare functions to decrypt 
                            the inner functions. What we do here is place the encrypted portions of the inner file (below) as a variable called $encryptedPayload which we 
                            can then decrypt and use.

            INNER PORTION:  This is (initially) the Installer-Plaintext.ps1 file. This portion is the "business end" that does the actual installing. Because this contains
                            some initial API registration keys, we want to keep this portion encrypted. No, it's not fool-proof but it helps by ensuring that there's no 
                            unencrypted copies just left lying around plus it just adds another hurtle in trying to decipher what it's doing. This also supports functionality
                            of removing BFF from the endpoint.
        #>


        # Capture the raw content of the installer wrapper file (again, the outer portion of the installer)
        $installerWrapperRawContent = Get-Content -Path "$customPath\Build\Installer-Wrapper.ps1" -Raw

        # Do the same as the above for the installer payload portion (the inner portion that does the install or removal)
        $installerPlaintextPayloadRawContent = Get-Content -Path "$customPath\Build\Installer-Plaintext.ps1" -Raw

        # Encrypt the installer payload so we can insert that encrypted payload into the install wrapper
        $installerEncryptedPayload = Invoke-AESEncryption -Mode Encrypt -Key "YOUR_KEY_HERE" -Text $installerPlaintextPayloadRawContent

        # Insert the encrypted payload into the installer wrapper. Here, we find the text 'replacementKeyword' and replace that with the encrypted payload so we can place 
        # the payload at the correct location in the wrapper script.
        $finalInstaller = $installerWrapperRawContent.Replace("replacementKeyword","`$encryptedPayload = `"$installerEncryptedPayload`"")

        # Finally, finish by outputting the finished installer as Install-BFF.ps1
        $finalInstaller | Out-File "$customPath\Build\Install-BFF.ps1" -Force

        # Sign the new manifest file
        Set-FileSignature -File "$customPath\Build\Install-BFF.ps1" -TrustLevel High -CertStoreLocation CurrentUser -QuietMode

        Write-Host "Done: Files merged into Install-BFF.ps1" -ForegroundColor Green
    }

#endregion UPDATE BACKSTOP INSTALLER




##############################################################################################################################################################################
#region   SIGNATURE BLOCK   ##################################################################################################################################################
##############################################################################################################################################################################



