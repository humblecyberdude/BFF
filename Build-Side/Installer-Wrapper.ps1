<#
                                                                                                                                                                            
                                         ██████╗      █████╗      ██████╗    ██╗  ██╗    ███████╗    ████████╗     ██████╗     ██████╗                                      
                                         ██╔══██╗    ██╔══██╗    ██╔════╝    ██║ ██╔╝    ██╔════╝    ╚══██╔══╝    ██╔═══██╗    ██╔══██╗                                     
                                         ██████╔╝    ███████║    ██║         █████╔╝     ███████╗       ██║       ██║   ██║    ██████╔╝                                     
                                         ██╔══██╗    ██╔══██║    ██║         ██╔═██╗     ╚════██║       ██║       ██║   ██║    ██╔═══╝                                      
                                         ██████╔╝    ██║  ██║    ╚██████╗    ██║  ██╗    ███████║       ██║       ╚██████╔╝    ██║                                          
                                         ╚═════╝     ╚═╝  ╚═╝     ╚═════╝    ╚═╝  ╚═╝    ╚══════╝       ╚═╝        ╚═════╝     ╚═╝                                          
                                                                                                                                                                            
                            ███████╗    ██╗         ███████╗    ██╗  ██╗    ██╗       ██████╗     ██╗    ██╗         ██╗    ████████╗    ██╗   ██╗                          
                            ██╔════╝    ██║         ██╔════╝    ╚██╗██╔╝    ██║       ██╔══██╗    ██║    ██║         ██║    ╚══██╔══╝    ╚██╗ ██╔╝                          
                            █████╗      ██║         █████╗       ╚███╔╝     ██║       ██████╔╝    ██║    ██║         ██║       ██║        ╚████╔╝                           
                            ██╔══╝      ██║         ██╔══╝       ██╔██╗     ██║       ██╔══██╗    ██║    ██║         ██║       ██║         ╚██╔╝                            
                            ██║         ███████╗    ███████╗    ██╔╝ ██╗    ██║       ██████╔╝    ██║    ███████╗    ██║       ██║          ██║                             
                            ╚═╝         ╚══════╝    ╚══════╝    ╚═╝  ╚═╝    ╚═╝       ╚═════╝     ╚═╝    ╚══════╝    ╚═╝       ╚═╝          ╚═╝                             
                                                                                                                                                                            
                               ███████╗    ██████╗      █████╗     ███╗   ███╗    ███████╗    ██╗    ██╗     ██████╗     ██████╗     ██╗  ██╗                              
                               ██╔════╝    ██╔══██╗    ██╔══██╗    ████╗ ████║    ██╔════╝    ██║    ██║    ██╔═══██╗    ██╔══██╗    ██║ ██╔╝                              
                               █████╗      ██████╔╝    ███████║    ██╔████╔██║    █████╗      ██║ █╗ ██║    ██║   ██║    ██████╔╝    █████╔╝                               
                               ██╔══╝      ██╔══██╗    ██╔══██║    ██║╚██╔╝██║    ██╔══╝      ██║███╗██║    ██║   ██║    ██╔══██╗    ██╔═██╗                               
                               ██║         ██║  ██║    ██║  ██║    ██║ ╚═╝ ██║    ███████╗    ╚███╔███╔╝    ╚██████╔╝    ██║  ██║    ██║  ██╗                              
                               ╚═╝         ╚═╝  ╚═╝    ╚═╝  ╚═╝    ╚═╝     ╚═╝    ╚══════╝     ╚══╝╚══╝      ╚═════╝     ╚═╝  ╚═╝    ╚═╝  ╚═╝                              


    .SYNOPSIS
        Installs or removes the Backstop Flexibility Framework on an endpoint


    .PARAMETER Install
        Installs Backstop Flexibility Framework


    .PARAMETER Remove
        Removes Backstop Flexibility Framework


    .PARAMETER RemovalReason
        A string value for the reason of why Backstop is being uninstalled


    .PARAMETER DecryptionKey
        A string value for the decrpytion key used to decrypt the payload


    .PARAMETER RegistrationKey
        A string value for the registration key used to register Backstop
    
    
    .PARAMETER RemovalToken
        A string value for the removal token to remove backstop


    .PARAMETER KeepScript
        Do not delete the script after it installs


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


    .EXAMPLE
    .\Install-BFF.ps1 -Install -RegistrationKey [KEY] -DecryptionKey [KEY]
    .\Install-BFF.ps1 -Remove -RemovalReason [REASON] -RemovalToken [TOKEN] -DecryptionKey [KEY]

#>




##############################################################################################################################################################################
#region   PARAMETERS   #######################################################################################################################################################
##############################################################################################################################################################################

    # Define the switch parameters
    Param(
        [Parameter(Mandatory=$False,Position=0)]
            [Switch]$Install,
        [Parameter(Mandatory=$False,Position=1)]
            [switch]$Remove,
        [Parameter(Mandatory=$False,Position=2)]
            [string]$RemovalReason,
        [Parameter(Mandatory=$True,Position=3)]
            [string]$DecryptionKey,
        [Parameter(Mandatory=$False,Position=4)]
            [string]$RegistrationKey,
        [Parameter(Mandatory=$False,Position=5)]
            [string]$RemovalToken,
        [Parameter(Mandatory=$False,Position=6)]
            [switch]$KeepScript
    )

    # Error if no switch was defined
    if((-not($Install -or $Remove))   -or   (($Install -and $Remove)))
    {
        Write-Host "You have to specify either -Install or -Remove. Naturally, you also can't specify both at the same time." -ForegroundColor DarkYellow

        # Exit Script
        Exit
    }

    # Error if -Remove was used without specifing -RemovalReason
    if(($Remove)   -and   (-not($RemovalReason) -and (-not($RemovalToken))))
    {
        Write-Host "You have to specify both the -RemovalReason and -RemovalToken in order to remove Backstop." -ForegroundColor DarkYellow

        # Exit Script
        Exit
    }

    # Error if -Install was used without specifing -RegistrationKey
    if(($Install)   -and   (-not($RegistrationKey)))
    {
        Write-Host "You have to specify the -RegistrationKey parameter in order to install Backstop." -ForegroundColor DarkYellow

        # Exit Script
        Exit
    }

#endregion PARAMETERS




##############################################################################################################################################################################
#region   VARIABLES   ########################################################################################################################################################
##############################################################################################################################################################################

    # Define the full script path. We must do that due to the fact that Invoke-Expression can't use $PSCommandPath when read in after decryption. This is used to dynamically
    # determine where the script is so we can remove it.
    $fullScriptPath =  $PSCommandPath

#endregion VARIABLES




##############################################################################################################################################################################
#region   FUNCTIONS   ########################################################################################################################################################
##############################################################################################################################################################################

    function Invoke-AESEncryption
    {
        <#
        .SYNOPSIS
            CREDIT: Credit for this goes to David Retzer (DR Tools)
            Reference: https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1
            Encrypts or Decrypts Strings or Byte-Arrays with AES


        .DESCRIPTION
            Takes a String or File and a Key and encrypts or decrypts it with AES256 (CBC)


        .PARAMETER Mode
            Encryption or Decryption Mode


        .PARAMETER Key
            Key used to encrypt or decrypt


        .PARAMETER Text
            String value to encrypt or decrypt


        .PARAMETER Path
            Filepath for file to encrypt or decrypt


        .EXAMPLE
            Invoke-AESEncryption -Mode Encrypt -Key [PASSWORD] -Text "Secret Text"
            
            Description
            -----------
            Encrypts the string "Secret Test" and outputs a Base64 encoded cipher text.


        .EXAMPLE
            Invoke-AESEncryption -Mode Decrypt -Key [PASSWORD] -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
            
            Description
            -----------
            Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.


        .EXAMPLE
            Invoke-AESEncryption -Mode Encrypt -Key [PASSWORD] -Path file.bin
            
            Description
            -----------
            Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"


        .EXAMPLE
            Invoke-AESEncryption -Mode Encrypt -Key [PASSWORD] -Path file.bin.aes
            
            Description
            -----------
            Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
        #>

        [CmdletBinding()]
        [OutputType([string])]
        Param
        (
            [Parameter(Mandatory = $true)]
            [ValidateSet('Encrypt', 'Decrypt')]
            [String]$Mode,

            [Parameter(Mandatory = $true)]
            [String]$Key,

            [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
            [String]$Text,

            [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
            [String]$Path
        )

        Begin {
            $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
            $aesManaged = New-Object System.Security.Cryptography.AesManaged
            $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
            #$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126
            $aesManaged.BlockSize = 128
            $aesManaged.KeySize = 256
        }

        Process {
            $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

            switch ($Mode) {
                'Encrypt' {
                    if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                    
                    if ($Path) {
                        $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                        if (!$File.FullName) {
                            Write-Error -Message "File not found!"
                            break
                        }
                        $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                        $outPath = $File.FullName + ".aes"
                    }

                    $encryptor = $aesManaged.CreateEncryptor()
                    $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                    $encryptedBytes = $aesManaged.IV + $encryptedBytes
                    $aesManaged.Dispose()

                    if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                    
                    if ($Path) {
                        [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                        (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                        return "File encrypted to $outPath"
                    }
                }

                'Decrypt' {
                    if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                    
                    if ($Path) {
                        $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                        if (!$File.FullName) {
                            Write-Error -Message "File not found!"
                            break
                        }
                        $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                        $outPath = $File.FullName -replace ".aes"
                    }

                    $aesManaged.IV = $cipherBytes[0..15]
                    $decryptor = $aesManaged.CreateDecryptor()
                    $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                    $aesManaged.Dispose()

                    if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                    
                    if ($Path) {
                        [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                        (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                        return "File decrypted to $outPath"
                    }
                }
            }
        }

        End {
            $shaManaged.Dispose()
            $aesManaged.Dispose()
        }
    }

#endregion FUNCTIONS




##############################################################################################################################################################################
#region   ENCRPYTED PYALOAD   ################################################################################################################################################
##############################################################################################################################################################################

replacementKeyword

#endregion ENCRPYTED PYALOAD




##############################################################################################################################################################################
#region   DECRYPT AND EXECUTE   ##############################################################################################################################################
##############################################################################################################################################################################

    try
    {
        # Try to decrypt the text with the given key 
        $decryptedPayload = Invoke-AESEncryption -Mode Decrypt -Key "$DecryptionKey" -Text $encryptedPayload
    
    } Catch {

        Write-Host "Decryption key was invalid. Insert coins to continue." -ForegroundColor Red

        # Exit
        Exit
    }

    # Check for syntax errors. Just because it decrypted successfully doesn't mean it's not a hot 'n spicy soup of corium code. Errors here will be sent to $syntaxErrors.
    $syntaxErrors = @()
    [void][System.Management.Automation.Language.Parser]::ParseInput($decryptedPayload,[ref]$null,[ref]$syntaxErrors)

    # If there are no syntax errors (errors equal to 0), run the decrypted payload. Else, error out and exit. Since we do trust this code, we're using Invoke-Expression.
    if($syntaxErrors.Count -eq 0)
    {
        # Execute code         
        Invoke-Expression -Command $decryptedPayload

    } Else {

        Write-Host "Syntax error(s) detected in decrypted payload. Insert coins to continue." -ForegroundColor Red

        # Exit
        Exit
    }

#endregion DECRYPT AND EXECUTE




##############################################################################################################################################################################
#region   SWITCH ACTIONS   ###################################################################################################################################################
##############################################################################################################################################################################

    # Call the following functions in order if the -Install switch was used
    if($Install)
    {
        Invoke-GeneralDependancies
        Invoke-InstallDependancies
        Confirm-Certificate
        Set-ApiKeys
        Register-Endpoint
        Import-SecOpsFunctions
        Install-Directories
        Install-ScheduledTask
        Invoke-CleanupAndBeacon
        Remove-Script
    }

    # Call the following functions in order if the -Remove switch was used
    if($Remove)
    {
        Invoke-GeneralDependancies
        Invoke-RemovalDependancies
        Confirm-Certificate
        Set-ApiKeys
        Invoke-RemovalDependancyChecks
        Remove-ScheduledTask
        Remove-Directories
        Remove-RegKeys
        Invoke-FinalRemoveBeacon
        Remove-Script
    }

#endregion SWITCH ACTIONS

