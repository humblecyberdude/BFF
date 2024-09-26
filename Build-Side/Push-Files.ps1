<#
    .SYNOPSIS
    Tool to push code to the Backstop S3 bucket


    .DESCRIPTION
    Pushed Files to the Backstop S3 bucket


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
    █ Last Update:          7-Nov-2023


.EXAMPLE
    .\Push-Files.ps1

#>




############################################################################################################################################
#region SWITCH PARAMETERS   ################################################################################################################
############################################################################################################################################

    # Define the switch parameters
    Param(

        # Specify the S3 bucket name
        [parameter(Mandatory=$True)]
        [ValidateSet('YOUR_BUCKET_NAME_HERE')]
        [String]
        $BucketName,

        # Specify the source path
        [parameter(Mandatory=$True)]
        [String]
        $SourcePath,
        
        # Specify the destination directory
        [parameter(Mandatory=$True)]
        [ValidateSet('scripts')]
        [String]
        $DestinationDirectory,

        # Specify if you want to recursively transfer multiple files
        [parameter(Mandatory=$False)]
        [Switch]
        $Recursive
    )

#endregion SWITCH PARAMETERS




############################################################################################################################################
#region   VARIABLES   ######################################################################################################################
############################################################################################################################################

    $fileName = $SourcePath | Split-Path -Leaf

#endregion VARIABLES




############################################################################################################################################
#region   DEPENDENCY CHECKS   ##############################################################################################################
############################################################################################################################################

    # Ensure that we have AWS installed. 
    if(-not(Test-Path -Path "C:\Program Files\Amazon\AWSCLI\bin\aws.exe"))
    {
        Write-Error -Message "It doesn't appear that you have AWS CLI installed. Please download it from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"

        Exit
    }

    # Ensure that we have AWS installed. Moving creds to secure vault now...
    if((-not(Test-Path -Path C:$ENV:HOMEPATH\.aws\credentials))   -and   (-not($env:AWS_ACCESS_KEY_ID -and $env:AWS_SECRET_ACCESS_KEY)))
    {
        Write-Error -Message "Missing AWS config/creds. Please run 'aws configure' to create it"

        Exit
    }

    # Ensure that we can list S3 buckets. This will test access to S3.
    try {

        aws s3 ls | out-null

    } Catch {

        Write-Error -Message "Unable to run the 'aws s3 ls' command."

        Exit
    }

#endregion DEPENDENCY CHECKS




############################################################################################################################################
#region   PUSH TO AWS S3   #################################################################################################################
############################################################################################################################################

    # Single File: Push files based on the arguments supplied where a wildcard is not used at the end
    if(-not($Recursive))
    {
        & "C:\Program Files\Amazon\AWSCLI\bin\aws.exe" s3 cp "$SourcePath" "s3://$BucketName/$DestinationDirectory/$fileName"
    }

    # Multiple Files: Push files based on the arguments supplied where a wildcard is not used at the end
    if($Recursive)
    {
        & "C:\Program Files\Amazon\AWSCLI\bin\aws.exe" s3 cp "$SourcePath\" "s3://$BucketName/$DestinationDirectory/" --recursive
    }

#endregion PUSH TO AWS S3


