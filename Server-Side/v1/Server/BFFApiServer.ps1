<#
                ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗ ██████╗ 
                ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
                ██████╔╝███████║██║     █████╔╝ ███████╗   ██║   ██║   ██║██████╔╝
                ██╔══██╗██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██║   ██║██╔═══╝ 
                ██████╔╝██║  ██║╚██████╗██║  ██╗███████║   ██║   ╚██████╔╝██║     
                ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝     
                                                        
             █████╗ ██████╗ ██╗    ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗            
            ██╔══██╗██╔══██╗██║    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗           
            ███████║██████╔╝██║    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝           
            ██╔══██║██╔═══╝ ██║    ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗           
            ██║  ██║██║     ██║    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║           
            ╚═╝  ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝           

    .SYNOPSIS
    This is the API server for the Backstop Flexibility Framework


    .DESCRIPTION
    This API server should be positioned behind a reverse proxy which filters any requests that: do not have 
    the correct user-agent, do not have the correct hostname in the header and/or requests incorrect endpoints.
    After being filtered by the reverse-proxy, this API server authenticates, rate-limits and ensures that the 
    inputs specified are also inspected and are correct for the client request.

    This server is comprised of two primary components: The ServerCore functions module and the BFFEndpoints module.
    
    ↪ ServerCore Functions Module
      ---------------------------
      The ServerCore module, located in the ..\Server\Modules directory, contains the primary working functions
      for the API server itself such as receiving requests, how to respond back to API requests, logging, authentication
      rate-limiting, input sanitization, etc.


    ↪ BFFEndpoints Module
      -------------------
      This module contains all the individual endpoints in the form of functions which are called via this API server.



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
    █ Last Update:          20-July-2024

#>




##############################################################################################################################################################################
#region   INITIALIZE API SERVER   ############################################################################################################################################
##############################################################################################################################################################################

    #region INITIAL VARIABLES ################################################################################################################################################
        
        # Specify the servers root path (i.e. where it's located) minus the version number
        $Global:rootPath = "D:\Apps\Backstop\v1"

        # Suppress errors to help ensure that information isn't leaked back to the client
#$ErrorActionPreference = "SilentlyContinue"

    #endregion INITIAL VARIABLES


    #region SETUP LOGGING ####################################################################################################################################################

        # Set the logging level for this module. Options are:
        # "Problems"   Notice or Above (Any warnings, errors or problems)
        # "Info"       Info and Above (Normal operational or transactional logs + above)
        # "Debug"      Debug and Above (Verbose logs for troubleshooting + all of above)
        $DefaultLogLevel = "Info"

        # Set the local logging paths
        $accessLogPath = "$rootPath\Server\Logs\access.log"
        $consoleLogPath = "$rootPath\Server\Logs\console.log"

    #endregion SETUP LOGGING


    #region IMPORT CORE MODULES ##############################################################################################################################################

        # Define the shortname of the modules to import
        $modules = ('PSSQLite','ServerCore','BFFEndpoints')

        # Import each of the modules
        foreach ($moduleName in $modules)
        {
            # Pull the modules from the neede directories
            if ($moduleName -eq "PSSQLite")
            {
                $modulePath = "$rootPath\Server\modules\PSSQLite\1.1.0\"

            } Else {

                $modulePath = "$rootPath\Server\Modules"
            }

            # Import the modules we need so we can get things running
            Import-Module "$modulePath\$moduleName.psm1" -Force

            # Ensure that the API core functions module was imported correctly
            if(-Not(Get-Module -Name $moduleName))
            {
                # Refresh Timestamp
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MMM-dd HH:mm:ss.ffff UTC")

                # Create the log line in field="value" format.
                $logLine = "$timestamp eventTag=`"IMPORT CORE MODULES`" severityLevel=`"CRITICAL`" Comments=`"Unable to load module $moduleName. Exiting!`""

                # Write log to disk
                Add-Content -Path $consoleLogPath -Value "$logLine"

                # Eject! Eject!
                Break
            }
        }

    #endregion IMPORT CORE MODULES


    #region CONNECT TO DATABASE ##############################################################################################################################################

        # Open the database connection for the endpoints to use
        $backstopDBFile = "$rootPath\Server\db\backstop.db"
        $Global:dbConnection = New-SQLiteConnection -DataSource $backstopDBFile

    #endregion CONNECT TO DATABASE


    #region IMPORT SECRETS ###################################################################################################################################################

        # Import Secrets and open the vault in memory. This will aquire the variable $Vault.
        Open-SimpleVault -VaultPath "$rootPath\Server\etc\secrets.json"

        # If the vault was able to be opened, aquire the secrets and cache them.
        if($Vault)
        {
            # Aquire the secrets from the vault using DPAPI to decrypt them
            Get-SimpleVaultSecret -Name hmacSecretCommon
            Get-SimpleVaultSecret -Name hmacSecretRegistration
            Get-SimpleVaultSecret -Name hmacSecretRemoval
            Get-SimpleVaultSecret -Name hmacSecretUpdate
            Get-SimpleVaultSecret -Name canaryApiKey

            # Ensure they're in cache so we don't have to repeat the process
            $Global:hmacSecretGeneral = $hmacSecretGeneral_vaultSecret
            $Global:hmacSecretRegistration = $hmacSecretRegistration_vaultSecret
            $Global:hmacSecretRemoval = $hmacSecretRemoval_vaultSecret
            $Global:hmacSecretUpdate = $hmacSecretUpdate_vaultSecret
            $Global:canaryApiKey = $canaryApiKey_vaultSecret

            # Set a general variable that the secrets were already aquired
            $Global:vaultSecretsAlreadyAquired = $True

        } Else {

            Write-ApiLog -LogType Console -SeverityLevel Error -eventTag "Get Vault Secrets" -Comments "Unable to open vault!"

            # Break since we can't authenticate anyway
            Break
        }

    #endregion IMPORT SECRETS

#endregion INITIALIZE API SERVER




##############################################################################################################################################################################
#region   START API SERVER   #################################################################################################################################################
##############################################################################################################################################################################

    #region START LISTENER ###################################################################################################################################################

        # Using HTTP.SYS, start our HTTP listener on the loopback IP on TCP port 
        $Global:listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add('http://127.0.0.1:9999/') 
        $listener.Start()

    #endregion START LISTENER


    #region SERVICE REQUESTS #################################################################################################################################################

        # Start the API server listener and apply a loop label to it so we can call it for terminating requests. The reason for the label is to ensure that we always 
        # return to this specific point if we want to terminate a request such as when using Send-APIResponse for example. If we just used "continue" it only breaks 
        # out of the inner-most loop and may not be enough to fully terminate the request so we generically call ApiServerLoop so it's "set and forget".
        :ApiServerLoop while ($true)
        {
            # Capture the initial request so we can parse it and get ready to respond if it's valid
            Receive-Request

            # TEST: Remove for prod
            if(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/stop"))
            {
                $listener.Stop()
                Break
            }

            # Validate inputs for the given request (headers, values, etc.) to ensure they're what's expected
            Confirm-Inputs

            if($uriPath -like "/common/*") 
            {
                # Authenticate via normal API keys
                Confirm-Authentication -EndpointType Common


            } Elseif(($method -eq "Get")   -and   ($uriPath -eq "/management/backstop/v1/endpoints")){



            }











            # Process incoming API requests in order of the most hit first. Elseif statements will of course process as a first-match-wins to reduce processing time
            # for non-matching rules.
            if(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/manifest"))
            {
                $someTextWhatever = "sample test text"

                Send-APIResponse -StatusCode 200 -GeneralContentType Text -Body $someTextWhatever

            } elseif(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/test")){
                
                $someTextWhatever = "sample test text"

                Send-APIResponse -StatusCode 200 -GeneralContentType Text -Body $someTextWhatever
            
            } elseif(($method -eq "Post")   -and   ($uriPath -eq "/common/backstop/v1/test")){
                
                Send-APIResponse -StatusCode 200 -GeneralContentType JSON -Body $requestBody

            } elseif(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/request")){

                Send-APIResponse -StatusCode 200 -GeneralContentType JSON -Body $request

            } elseif(($method -eq "POST")   -and   ($uriPath -eq "/common/backstop/v1/request")){

                Send-APIResponse -StatusCode 200 -GeneralContentType JSON -Body "posted"

            } elseif(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/context")){

                Send-APIResponse -StatusCode 200 -GeneralContentType JSON -Body $context

            } elseif(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/requestHeaders")){

                Send-APIResponse -StatusCode 200 -GeneralContentType JSON -Body $requestHeaders

            } elseif(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/getDBentry")){

                Get-DBEntry

            } elseif(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/files")){

                Confirm-Authentication -EndpointType General
                #Limit-Requests -Type Endpoint -TimeIntervalInMin 60 -MaxRequests 32
                Send-File -FileName $FileName

            } elseif(($method -eq "POST")   -and   ($uriPath -eq "/common/backstop/v1/uploadBinary")){

                Send-APIResponse -StatusCode 200 -GeneralContentType JSON -Body "posted" -Headers $headersOfShame

            } Else {

                Send-APIResponse -StatusCode 400 -GeneralContentType TEXT -Body "API: Bad Request" -LogComments "FIX THIS! Client passed checks but requested an unroutable endpoint. This rule should never be hit - fix this in Confirm-Inputs function!"
            }
        }

    #endregion SERVICE REQUESTS
#endregion START API SERVER



##############################################################################################################################################################################
#region   SIGNATURE   ########################################################################################################################################################
##############################################################################################################################################################################


