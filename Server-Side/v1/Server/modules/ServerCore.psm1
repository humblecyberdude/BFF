<#
                    ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗ ██████╗      ██████╗ ██████╗ ██████╗ ███████╗            
                    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗    ██╔════╝██╔═══██╗██╔══██╗██╔════╝            
                    ██████╔╝███████║██║     █████╔╝ ███████╗   ██║   ██║   ██║██████╔╝    ██║     ██║   ██║██████╔╝█████╗              
                    ██╔══██╗██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██║   ██║██╔═══╝     ██║     ██║   ██║██╔══██╗██╔══╝              
                    ██████╔╝██║  ██║╚██████╗██║  ██╗███████║   ██║   ╚██████╔╝██║         ╚██████╗╚██████╔╝██║  ██║███████╗            
                    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝          ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝            
                                                                                                                                    
    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗    ███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗██╗     ███████╗
    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝    ████╗ ████║██╔═══██╗██╔══██╗██║   ██║██║     ██╔════╝
    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗    ██╔████╔██║██║   ██║██║  ██║██║   ██║██║     █████╗  
    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║    ██║╚██╔╝██║██║   ██║██║  ██║██║   ██║██║     ██╔══╝  
    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║███████║    ██║ ╚═╝ ██║╚██████╔╝██████╔╝╚██████╔╝███████╗███████╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
                                                                                                                                   

    .SYNOPSIS
    This is the core functionality module for the API server.


    .DESCRIPTION
    Separate from the endpoints module, this module contains all the needed elements to run the server itself including how to handle 
    HTTP requests, logging, authentication and rate-limiting among others. See the documentation for each function for further details.


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
    █ Last Update:          30-July-2024

#>




Function Write-ApiLog
{
    <#
        .SYNOPSIS
        Logs operational console logs for the API server itself or access logs for client requests.


        .DESCRIPTION
        Writes two separate logs to disk in a standardized field="value" format for easy ingestion into SIEM's.


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
        █ Last Update:          6-July-2024


        .PARAMETER LogType
        Specifies one of the two log types below. The logging fields are different for each.
        ↪ ACCESS:   Use this for any API requests from any clients accessing any resources
        ↪ INTERNAL: Use this for any internal logs that are NOT related to clients accessing resources


        .PARAMETER EventTag
        A logical tag to better categorize the event


        .PARAMETER SeverityLevel
        A roughly standard list of severity levels


        .PARAMETER LogComments
        This should be the "plain-english" wording of what really happened so that even the new guy can get an idea of at least what happened


        .PARAMETER AccessLogPath
        The path to the access log for client requests for visibility and troubleshooting


        .PARAMETER InternalLogPath
        The path to the internal API log for visibility and troubleshooting


        .EXAMPLE
        Write-ApiLog -LogType Console -eventTag "Get Vault Secrets" -SeverityLevel Error -LogComments "Unable to open vault... Exiting"
        ↪ Writes a console log specific to the operation of the API server itself, separate from client requests.
        ↪ Tags it with w/e tag you want to organize your events - usuall based on function or region of code.
        ↪ Simple severity level of the event. NOTE: Check variable DefaultLogLevel if your logs aren't being written. Set DefaultLogLevel to either Debug and Info as needed.
        ↪ Human comments that actually state what's actually going on

        Write-ApiLog -LogType Access -eventTag "Endpoint Name Here" -SeverityLevel Info -LogComments "Example: Client requested X and it was successfully served"
        ↪ Same as above, just an access log for a client request

    #>




    ##########################################################################################################################################################################
    #region   PARAMETERS   ###################################################################################################################################################
    ##########################################################################################################################################################################

        Param
        (
            # Access is the access log which includes more details about the specific request whereas Console is more for operational logs for the API server
            [parameter(Mandatory=$true)]
            [ValidateSet('Access', 'Internal')]
            [String]$LogType,

            # A general tag for the function, section of code or module name
            [parameter(Mandatory=$false)]
            [String]$EventTag,

            # Specifies the severity of the message            
            [parameter(Mandatory=$true)]
            [ValidateSet('DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERROR', 'CRITICAL')]
            [String]$SeverityLevel,

            # Allows you to put in plain-english comments for the log line
            [parameter(Mandatory=$false)]
            [String]$LogComments,

            # Specify the path for the access log
            [parameter(Mandatory=$false)]
            [String]$AccessLogPath,

            # Specify the path for the console log
            [parameter(Mandatory=$false)]
            [String]$InternalLogPath
        )

    #endregion PARAMETERS




    ######################################################################################################################################################################
    #region   VARIABLES   ################################################################################################################################################
    ######################################################################################################################################################################

        # Set the default logging level if it's not already defined
        if(-Not($DefaultLogLevel))
        {
            # Set to info as a balanced setting if not specified elsewhere
            $DefaultLogLevel = "Info"
        }

        # Set the default log paths if not already set (rootPath is pulled from Initialize-APIServer on the API server script itself)
        if(($LogType -eq "Console")   -and   (-Not($InternalLogPath)))
        {
            $InternalLogPath = "$rootPath\server\Logs\console.log"
        }
    
        if(($LogType -eq "Access")   -and   (-Not($AccessLogPath)))
        {
            $AccessLogPath = "$rootPath\server\Logs\access.log"
        }
    
        # Set the tags to unspecified if not set
        if(-Not($EventTag))
        {
            $EventTag = "unspecified"
        }

        # Each function should have its own name defined as a variable. If not, log this as the value
        if(-Not($FunctionName))
        {
            $FunctionName = "UNKNOWN_FIX_ME!"
        }

    #endregion VARIABLES




    ######################################################################################################################################################################
    #region   LOG TO FILE   ##############################################################################################################################################
    ######################################################################################################################################################################

        # Honor the DefaultLogLevel set on the API server. For clarity: 
        # ↪ Problems = Notice or Above      (Any warnings, errors or problems)
        # ↪ Info = Info and Above           (Normal operational or transactional logs + Above)
        # ↪ Debug = Debug and Above         (Verbose logs for troubleshooting + all of above)
        if(($DefaultLogLevel -eq "Debug")   -or   ($DefaultLogLevel -eq "Info" -and $severityLevel -ne "debug")   -or   ($DefaultLogLevel -eq "Problems" -and $severityLevel -notmatch "debug|info"))
        {
            # Set default log paths based on LogType
            if($LogType -eq "Access")
            {
                # Set the log path set originally in API Server > INITIALIZE API SERVER > SETUP LOGGING
                $LogPath = $AccessLogPath

                # Grab the response code so we can log it
                $statusCode = $response.StatusCode
    
                # Define the Client IP address to compare against the Proxy subnets. Note that this is what's in the XFF header from the reverse proxy.
                [System.Net.IPAddress]$clientIP = $clientIP
    
                # Define Proxy subnets to check the IP address against
                $proxySubnetsSubnets = @{
                    # EXAMPLE: "1.2.3.0" = "255.255.255.0"
                    #REPLACE_ME!
                }
    
                # Define RFC1918 subnets
                $rfc1918Subnets = @{
                    "10.0.0.0" = "255.0.0.0"
                    "172.16.0.0" = "255.240.0.0"
                    "192.168.0.0" = "255.255.0.0"
                }
    
                # On Proxy or Internet Check
                foreach ($item in $proxySubnetsSubnets.GetEnumerator())
                {
                    # Define the subnets (basically each line in the hash table one at a time)
                    [System.Net.IPAddress]$ProxySubnet = $($item.Name)
                    [System.Net.IPAddress]$ProxySubnetMask = $($item.Value)
    
                    # If there's a match (the IP is within one of the Proxy subnets), mark isLocalIP=true. Else isLocalIP=false.
                    if($ProxySubnet.Address -eq ($clientIP.Address -band $ProxySubnetMask.Address))
                    {
                        $clientZone = "proxySubnet"
    
                        # Break out of the loop or else we'll almost certainly hit the else statement below and variable will be wrong.
                        break

                    } Else {

                        $clientZone = "Internet"
                    }
                }

                # RFC1918 Check
                foreach ($item in $rfc1918Subnets.GetEnumerator())
                {
                    # Define the subnets (basically each line in the hash table one at a time)
                    [System.Net.IPAddress]$rfc1918Subnet = $($item.Name)
                    [System.Net.IPAddress]$rfc1918SubnetMask = $($item.Value)
    
                    # If there's a match (the clientIP is within one of the RFC1918 subnets), mark isLocalIP=true. Else isLocalIP=false.
                    If($rfc1918Subnet.Address -eq ($clientIP.Address -band $rfc1918SubnetMask.Address))
                    {
                        $clientZone = "Intranet"
                    }
                }

                # Verify if UserAgent is correct by checking for the presents of either at the start of the agent string
                if($userAgent -match "^(Backstop|Metrics)")
                {
                    $userAgentStatus = "Valid"

                } Else {

                    $userAgentStatus = "Invalid"
                }

                # Modify logging specific to the getZone API
                if($url -eq "/metrics/getZone/v1")
                {
                    $authenticationVerified = "no-auth-api"
                }

                # Refresh Timestamp
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MMM-dd HH:mm:ss.ffff UTC")

                # Create the log line in field="value" format.
                $logLine = "$timestamp FunctionName=`"$FunctionName`" eventTag=`"$eventTag`" severityLevel=`"$severityLevel`" clientIP=`"$clientIP`" clientHostname=`"$clientHostname`" method=`"$method`" uriPath=`"$uriPath`" statusCode=`"$statusCode`" LogComments=`"$LogComments`" inputChecksVerified=`"$inputChecksVerified`" authenticationVerified=`"$authenticationVerified`" rateLimitVerified=`"$rateLimitVerified`" fileName=`"$fileName`" clientZone=`"$clientZone`" serverHost=`"$serverHost`" userAgentStatus=`"$userAgentStatus`" GeneralContentType=`"$GeneralContentType`" userAgent=`"$userAgent`""

                # Write log to disk
                Add-Content -Path $LogPath -Value "$logLine"

            } elseif ($LogType -eq "Console") {

                # Again, set the log path set originally in API Server > INITIALIZE API SERVER > SETUP LOGGING
                $LogPath = $InternalLogPath

                # Refresh Timestamp
                $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MMM-dd HH:mm:ss.ffff UTC")

                # Create the log line in field="value" format.
                $logLine = "$timestamp FunctionName=`"$FunctionName`" eventTag=`"$eventTag`" severityLevel=`"$severityLevel`" LogComments=`"$LogComments`""

                # Write log to disk
                Add-Content -Path $LogPath -Value "$logLine"
            }
        }

    #endregion LOG TO FILE
}




function Receive-Request
{
    <#
        .SYNOPSIS
        Captures the initial requests and sets up the variables we need so we can respond back to the request.


        .DESCRIPTION
        The function operates by listening for HTTP requests on the address above. When an HTTP request is received, this function captures
        the details of the request and sets up the right variables to respond back.


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
        █ Last Update:          6-July-2024

    #>


    # Dynamically get the function name for logging
    $functionName = (Get-PSCallStack)[0].FunctionName

    # Get the context of the entire HTTP request
    $Global:context = $listener.GetContext() 

    # Capture all the details about the request such as headers, URL, user-agents, etc. that we can key off of later
    $Global:request = $context.Request

    # Read the request headers to capture them in the variable $requestHeaders
    $Global:requestHeaders = @{}
    $request.Headers.AllKeys | ForEach-Object {
        $Global:requestHeaders[$_] = $request.Headers.Get($_)
    }

    # Extract critical variables for our other functions to utilize
    $Global:serverHost = ($requestHeaders).Host
    $Global:userAgent = ($requestHeaders)."User-Agent"
    $Global:clientIP = ($requestHeaders)."X-Forwarded-For"
    $Global:method = ($request).HttpMethod
    $Global:clientSubmittedApiKey = $requestHeaders.apiKey
    $Global:clientHostname = $requestHeaders.clientHostname
    $Global:scriptFileHashSHA256 = $requestHeaders.scriptFileHashSHA256
    $Global:clientSalt = $requestHeaders.clientSalt
    $Global:fileName = $requestHeaders.fileName
    $Global:contentType = $requestHeaders['Content-Type']
    $Global:acceptEncoding = $requestHeaders['Accept-Encoding']
    $Global:memo = $requestHeaders.memo
    $Global:kind = $requestHeaders.kind

    # Read the body of the request
    $streamReader = New-Object IO.StreamReader($request.InputStream)
    $Global:requestBody = $streamReader.ReadToEnd()
    $streamReader.Close()

    # Extract portions of the URL
    $Global:fullUrl = $request.Url
    $Global:queryString = [System.Uri]::new($fullUrl).Query
    $Global:uriPath = [System.Uri]::new($fullUrl).AbsolutePath

    # Capture the client details from the DB if they exist
    $Global:clientRegData = Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query "SELECT * FROM registrations WHERE clientHostname = `"$clientHostname`"" -ErrorAction SilentlyContinue

    # Setup a place to deliver a response
    $Global:response = $context.Response
}




function Send-APIResponse
{
    <#
        .SYNOPSIS
        An easy-to-use function to send HTTP responses back to the client and logs the request


        .DESCRIPTION
        Packages the pedantic fiddly bits of sending an API response into an easy-to-use function


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
        █ Last Update:          6-July-2024


        .PARAMETER StatusCode
        The HTTP status code you want to send back to the client. Maybe there should be a validation set but just forcing it to an Int32 for now.


        .PARAMETER Body
        The payload, as part of the body, to send back to the client. Usually this is a JSON response.


        .PARAMETER GeneralContentType
        Simplified content-type with specific, pre-formatted parameters


        .PARAMETER Headers
        Specify any headers you desire as a hash table prior to passing to this function. 


        .PARAMETER SendFilePath
        Specify the full file path of the file to send to the client


        .PARAMETER LogComments
        Specify any comments for the access log


        .EXAMPLE
        Standard JSON: Send-APIResponse -StatusCode 200 -Body $ObjectYouWantToSend -GeneralContentType JSON
        Standard JSON + Headers: Send-APIResponse -StatusCode 200 -Body $ObjectYouWantToSend -GeneralContentType JSON -Headers $responseHeaders

    #>

    Param
    (
        [parameter(Mandatory=$true)]
        [Int32]$StatusCode,

        [parameter(Mandatory=$false)]
        $Body,

        [parameter(Mandatory=$true)]
        [ValidateSet('JSON', 'Binary', 'Text')]
        [String]$GeneralContentType,

        [parameter(Mandatory=$false)]
        $SendFilePath,

        [parameter(Mandatory=$false)]
        [String]$LogComments,

        [parameter(Mandatory=$false)]
        [String]$LogEventTag,

        [parameter(Mandatory=$false)]
        [Hashtable]$ResponseHeaders,

        [parameter(Mandatory=$false)]
        [ValidateSet('DEBUG,','INFO', 'NOTICE', 'WARN', 'ERROR', 'CRITICAL')]
        [String]$SeverityLevelOverride
    )

    # Set the HTTP status code to give back to the client. Note that $response has already been setup for us in function Receive-Request
    $response.StatusCode = $StatusCode

    # Set the formatting and content-type of the HTTP response in order of what's used the most for slightly better performance
    if ($GeneralContentType -eq 'JSON') {

        # Convert the response body into JSON and set the HTTP content type to JSON
        $body = $body | ConvertTo-Json 
        $response.ContentType = 'application/json'

    } elseif ($GeneralContentType -eq 'Binary') {

        # Set the conte-nt type to application/octet-stream for binary data
        $response.ContentType = 'application/octet-stream'

    } elseif ($GeneralContentType -eq 'Text') {

        # Set the content of the body to a string and set the content type to text/plain
        [string]$body = $body
        $response.ContentType = 'text/plain'
    }

    # Add the headers to the HTTP response if they were passed to this function with the -Headers parameter
    if($responseHeaders)
    {
        foreach ($key in $responseHeaders.Keys)
        {
            $response.Headers.Add($key, $responseHeaders[$key])
        }
    }

    # If sending a file, populate the buffer with it's binary contents regardless of file format (always convert to binary for simplicity)
    if ($SendFilePath)
    {
        # Read the file into a byte array - specifically the file path specified in the -SendFilePath
        $buffer = [System.IO.File]::ReadAllBytes($SendFilePath)

    } Else {

        # Convert the body of the response to UTF8 bytes
        [byte[]]$buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
    }

    # Set length of response
    $response.ContentLength64 = $buffer.length
    
    # Send HTTP response and close the connection
    $output = $response.OutputStream
    $output.Write($buffer, 0, $buffer.length)
    $output.Close()

    # Honor the override set for severity level if it exists. Otherwise, automatically set it based on the status code in order of which get hit the most.
    if($SeverityLevelOverride)
    {
        $SeverityLevel = $SeverityLevelOverride

    } Else {

        if ($StatusCode -match "^2\d{2}")
        {
            $SeverityLevel = "INFO"
    
        } elseif ($StatusCode -match "^4\d{2}") {
    
            $SeverityLevel = "NOTICE"
    
        } elseif ($StatusCode -match "^3\d{2}"){
    
            $SeverityLevel = "INFO"
    
        } elseif ($StatusCode -match "^5\d{2}"){
    
            $SeverityLevel = "ERROR"
    
        } Else {
    
            $SeverityLevel = "CRITICAL"
        }
    }

    # Log the request
    Write-ApiLog -LogType Access -SeverityLevel $SeverityLevel -eventTag $eventTag -LogComments "$LogComments"

    # Generically stop processing any further and return to the API server loop regardless of any other loop. It is
    # critical to stop processing anything else after the API response is sent back to the client. 
    Continue ApiServerLoop
}




function Confirm-Inputs
{
    <#
        .SYNOPSIS
        Validates input for requests to ensure that they contain the correct headers and that the values are in line with what is expected. 


        .DESCRIPTION
        This function validates the input for requests to ensure that they not only contain the required fields but also that the values for 
        those fields are what's expected. For example, if a value for a given field should be a SHA256 hash, then ensure it matches a 
        fixed-length HEX string. This ensures that the requests are validated and if anything is incorrect, the request will be denied. This
        function has two main parts: 

        COMMON INPUT VALIDATION 
        ↪ Validation for any incoming request (i.e. what's common to all)

        ENDPOINT SPECIFIC INPUT VALIDATION
        ↪ Validation custom to that specific endpoints unique needs


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




    ##########################################################################################################################################################################
    #region   VARIABLES   ####################################################################################################################################################
    ##########################################################################################################################################################################

        # Dynamically get the function name for logging
        $Global:functionName = (Get-PSCallStack)[0].FunctionName

    #endregion VARIABLES




    ##########################################################################################################################################################################
    #region   GENERAL INPUT VALIDATION   ######################################################################################################################################
    ##########################################################################################################################################################################

        # This is the general input validation globally for all requests.

        # Define the only valid headers allowed and check each header to ensure they're on the valid headers list
        $validCommonHeaders = ('host', 'Accept-Encoding', 'User-Agent', 'Connection', 'X-ARR-SSL', 'Max-Forwards', 'X-Forwarded-For', 'X-ARR-LOG-ID', 'X-Original-URL', 'apikey', 'clientSalt', 'clientHostname', 'scriptHash', 'acceptEncoding', 'fileName', 'kind', 'memo', 'hashedUsername', 'clientState', 'removalToken', 'clientSalt', 'reason', 'contentType', 'updateType')

        # Capture all headers in client request as an array
        $requestHeaderNames = $requestHeaders.Keys

        # Itterate through each client-supplied header to ensure that each one is a valid header name as defined in $validHeaders
        foreach($requestHeaderName in $requestHeaderNames)
        {
            if ($validCommonHeaders -notcontains $requestHeaderName)
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client provided headerName `"$requestHeaderName`" which is not allowed"
            }
        }

        # Ensure there are no query string parameters in the URI path. If so, deny the request. Nothing against them but here we just use and prefer headers instead for now.
        if($queryString)
        {
            Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client provided a query string of `'$queryString`' in the URI path which is not allowed. IIS should have filtered this out based on regex patterns so look into this!"
        }

        # For valid headers, if they exist, ensure that they match what should be expected. The first part of the regex (prior to the middle '|') is for standard API key's while the second half is for the 
        # removalApiKey which is a different format.
        if((-Not($requestHeaders.apikey))   -or   ($requestHeaders.apikey -notmatch "(^([\+]|[\/]|[a-zA-Z0-9]){43}\=$)|(^[a-fA-F0-9]{64}$)"))
        {
            Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the apiKey header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.apikey""
        }

        # Ensure that the clientHostname matches the correct format
        if((-Not($requestHeaders.clientHostname))   -or   ($requestHeaders.clientHostname -notmatch "^[a-zA-Z0-9\-]{1,30}$"))
        {
            Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the clientHostname header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.clientHostname""
        }

        # Ensure that the scriptHash matches the correct format
        if((-Not($requestHeaders.scriptHash))   -or   ($requestHeaders.scriptHash -notmatch "^[a-fA-F0-9]{64}$"))
        {
            Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the scriptHash header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.scriptHash""
        }

        # Ensure that the scriptHash matches the correct format
        if($acceptEncoding -notmatch "gzip")
        {
            Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "For header acceptEncoding, client provided bad format. Value for header was "$requestHeaders.acceptEncoding" which is not valid - must be gzip."
        }

        # Ensure that there's no body in get request
        if(($method -eq "Get")   -and   ($requestBody))
        {
            Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client provided data in the body of a GET request."
        }

    #endregion GENERAL INPUT VALIDATION




    ##########################################################################################################################################################################
    #region   ENDPOINT SPECIFIC INPUT VALIDATION   ###########################################################################################################################
    ##########################################################################################################################################################################

        # Start input validation on a per-endpoint basis starting with the most requested items first (first match wins with elseif). Not that most of these checks will check
        # if the header is missing or if it's present, is the values for the data in the correct format.

        if(($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/ping"))
        {

            # TO BE DONE



        # REMOVE: TEST INPUT VALIDATION RULE
        } elseif ($userAgent -eq "test"){

            # Do nothing

        # Input validation for client file downloads
        } elseif (($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/files")){

            if((-Not($requestHeaders.fileName))   -or   ($requestHeaders.fileName -notmatch "^[a-zA-Z0-9-_.]{1,50}$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the fileName header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.filename""
            }

        # Input validation for Splunk HEC relay
        } elseif (($method -eq "Post")   -and   ($uriPath -eq "/common/backstop/v1/hecrelay")){

            if((-Not($requestBody))   -or   (-Not($requestBody | Test-Json)))
            {
                 Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the fileName header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.filename""
            }

        # Input validation for aquiring Canary tokens
        } elseif (($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/tokens")){

            if((-Not($requestHeaders.kind))   -or   ($requestHeaders.kind -notmatch "(active\-directory\-login)|(autoreg\-google\-docs)|(autoreg\-google\-sheets)|(aws\-id)|(aws\-s3)|(azure\-id)|(cloned\-web)|(dns)|(doc\-msexcel)|(doc\-msword)|(fast\-redirect)|(gmail)|(google\-docs)|(google\-sheets)|(googledocs\_factorydoc)|(googlesheets\_factorydoc)|(http)|(msexcel\-macro)|(msword\-macro)|(office365mail)|(pdf\-acrobat\-reader)|(qr\-code)|(sensitive\-cmd)|(signed\-exe)|(slack\-api)|(slow\-redirect)|(web\-image)|(windows\-dir)|(wireguard)"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the kind header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.kind""
            }

            if((-Not($requestHeaders.memo))   -or   ($requestHeaders.memo -notmatch "^Host\=[a-zA-Z0-9\-_]{1,30}\sUser\=[a-zA-Z0-9\-\._\\]{1,30}\sDIR\=[a-zA-Z0-9\:\-\.\s\\_]{1,120}\sNOTES\=[a-zA-Z0-9\-_\.\s]{1,160}$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the memo header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.memo""
            }

        # Input validation for clients finding out what the persona of a system is
        } elseif (($method -eq "Get")   -and   ($uriPath -eq "/common/backstop/v1/persona")){

            if((-Not($requestHeaders.hashedUsername))   -or   ($requestHeaders.hashedUsername -notmatch "^([a-zA-Z]|\d|\+|\/|\=){88}$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the hashedUsername header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.hashedUsername""
            }

        # Input validation for installing and registering endpoints
        } elseif (($method -eq "Post")   -and   ($uriPath -eq "/backstop/v1/endpoints")){

            if((-Not($requestHeaders.clientState))   -or   ($requestHeaders.clientState -notmatch "(installing)|(installed)"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the clientState header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.clientState""
            }

            if(($requestHeaders.clientState -eq "installing")   -and   (-Not($clientSalt)))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client said that it's installing but is missing clientSalt"
            }

        # Input validation for uninstalling and unregistering endpoints
        } elseif (($method -eq "Delete")   -and   ($uriPath -eq "/backstop/v1/endpoints")){

            if((-Not($requestHeaders.removalToken))   -or   ($requestHeaders.removalToken -notmatch "^[a-fA-F0-9]{64}$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the removalToken header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.removalToken""
            }

            if((-Not($requestHeaders.clientState))   -or   ($requestHeaders.clientState -notmatch "(uninstalling)|(uninstalled)"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the clientState header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.clientState""
            }

            # Ensure that the clientSalt matches the correct format
            if((-Not($requestHeaders.clientSalt))   -or   ($requestHeaders.clientSalt -notmatch "^[a-zA-Z0-9]{16}$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the clientSalt header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.clientSalt""
            }

            if((-Not($requestHeaders.reason))   -or   ($requestHeaders.reason -notmatch "^[a-zA-Z0-9\s]{1,50}$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the reason header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.reason""
            }

            # Ensure removal key exists in the Backstop DB
            if(-not($clientRegData.removalToken))
            { 
                Send-APIResponse -StatusCode 404 -GeneralContentType Text -Body "API: Not Found" -LogComments "Unable to find the removal token in the DB for the client"
            }

        # Input validation for updating the Backstop API server
        } elseif (($method -eq "Post")   -and   ($uriPath -eq "/backstop/v1/update")){

            if((-Not($requestHeaders.contentType))   -or   ($requestHeaders.contentType -notmatch "^application\/octet-stream$"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the contentType header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.contentType""
            }

            if((-Not($requestHeaders.updateType))   -or   ($requestHeaders.updateType -notmatch "(^database$)|(^code$)"))
            {
                Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client either did not provide the updateType header and/or the value in that header was not in the correct format. If it exists, the value of the header was: "$requestHeaders.updateType""
            }

        # Catch-all response for clients making naughty requests
        } Else {

            Send-APIResponse -StatusCode 400 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Hit catch-all rule for bad requests."
        }

        # If the request ran the guantlet above and survived, we assume it's valid. Therefore, set inputChecksVerified to true.
        $Global:inputChecksVerified = $true

    #endregion ENDPOINT SPECIFIC INPUT VALIDATION
}




function Confirm-Authentication
{
    <#
        .SYNOPSIS
        Like it basically says on the tin, this function authenticates client requests.


        .DESCRIPTION
        Based on the type of the request, authenticate the request to ensure that the client has the correct API key for
        the correct type of authentication request


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


        .PARAMETER EndpointType
        Specifies the type of the endpoint request. For Security, there are different private keys per endpoint. Each endpoint type is described below:
        ↪ COMMON:   Any general endpoint request post registration. For example, beaconing back, downloading files, etc.
        ↪ REGISTER: Initial registration request when installing the endpoint. For example, doing a POST request to the ../endpoints (clients) API endpoint.
        ↪ REMOVE:   Removal request to uninstall the endpoint. For example, doing a DELETE request to the ../endpoints (clients) API endpoint.
        ↪ UPDATE:   Requests to update the Backstop API server. For example, doing a POST request to the ../update API endpoint.

    #>


    Param
    (
        # Specifies the type of the request
        [parameter(Mandatory=$true)]
        [ValidateSet('Common', 'Register', 'Remove', 'Update')]
        [String]$EndpointType
    )

    # Dynamically get the function name for logging
    $functionName = (Get-PSCallStack)[0].FunctionName




    ##########################################################################################################################################################################
    #region   GENERAL CHECKS   ###############################################################################################################################################
    ##########################################################################################################################################################################

        # Ensure that the clientAuthenticated and authenticationStatus variable is flushed for added freshness (paranoid)
        Remove-Variable authenticationVerified -Force -ErrorAction SilentlyContinue

        # Check and see if there's a match in the key revocation table
        $keyRevoked = Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query "SELECT * FROM revokedApiKeys WHERE key = `"$clientSubmittedApiKey`"" -ErrorAction SilentlyContinue

        # Check the API key against the revocation list. If found, fail the authentication attempt.
        if($keyRevoked)
        {
            # Set authenticationVerified to Failed
            $Global:authenticationVerified = $false

            # Flush the variable
            Remove-Variable keyRevoked

            # Send an HTTP 401 (unauthorized) back to the client
            Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client `"$clientHostname`"used revoked API key"
        }

    #endregion GENERAL CHECKS




    ##########################################################################################################################################################################
    #region   AUTHENTICATE REQUEST   #########################################################################################################################################
    ##########################################################################################################################################################################

        # Authenticate typical API requests from endpoints
        if($EndpointType -eq "Common")
        {
            # Reject the request if their is no clientRegData OR if the state is not 'installed'. Otherwise, update the clientLastPhoneHome time
            # We check this here vs. Confirm-Inputs so we can write the code once here vs. on every general endpoint.
            if(-Not($clientRegData)   -or   ($clientRegData.clientState -ne 'installed'))
            {
                # Send an HTTP 404 (not found) back to the client
                Send-APIResponse -StatusCode 404 -GeneralContentType Text -Body "API: Bad Request" -LogComments "Client `"$clientHostname`" either not in the DB or has a state other than 'installed'"

            } Else {

                $dateTimeInUTC = Get-Date -AsUTC -Format "yyyy-MM-dd HH:mm:ss K"
                Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query "UPDATE registrations SET clientLastPhoneHome =  `"$dateTimeInUTC`" WHERE clientHostname = `"$clientHostname`""
            }

            # Get the clientSalclientRegDatat value from the DB for the endpoint
            $clientSalt = $clientRegData.clientSalt

            # Specify the common API request HMAC secret where the clients hostname is used as the public portion
#$hmacSecret = $hmacSecretCommon_vaultSecret
            $hmacSecret = "EXAMPLE"
            $inputData = "$clientSalt|$clientHostname"

        } Elseif($EndpointType -eq "Register"){

            # Use separate HMAC key for registration
            $hmacSecret = "$clientHostname|$hmacSecretRegistration_vaultSecret"

            # Specify the commandline rollout key used during install. 
            $inputData = $cache:registrationKey

        } Elseif($EndpointType -eq "Remove"){

                # Check that the removal key matches what's in the database. If not, stop immediately as we don't want to give back any installation details without it being correct.
                if($requestHeaders.removalToken -ne $clientRegData.removalToken)
                {                   
                    # Capture the response for logging variables; send response back to client; log event
                    Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Unauthorized" -LogComments "The removal token was incorrect"
                }

                # Use separate HMAC key for removal. This is separate from the Removal Token which is an added layer of security. The below just sets the secrets to interact with the API at all.
                $hmacSecret = "$clientHostname|$hmacSecretRemoval_vaultSecret"

                # Specify the commandline rollout key used during install. 
                $inputData = $clientSalt

        } Elseif($EndpointType -eq "Update"){

                # Specify the upload API request HMAC secret
                $hmacSecret = $cache:hmacSecretUpdate
                $inputData = "$clientSalt|$clientHostname"
        }

        # Create HMAC signature to verify the API key submitted
        $hmacSHA256 = New-Object System.Security.Cryptography.HMACSHA256
        $hmacSHA256.key = [Text.Encoding]::ASCII.GetBytes($hmacSecret)
        $computedApiKey = $hmacSHA256.ComputeHash([Text.Encoding]::ASCII.GetBytes($inputData))
        $computedApiKey = [Convert]::ToBase64String($computedApiKey)

        # Check if the API key the client gave matches the correct key
        if($clientSubmittedApiKey -eq "$computedApiKey")
        {
            $Global:authenticationVerified = $true

        } Else {

            $Global:authenticationVerified = $false
#Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Unauthorized" -LogComments "Authentication failed as API keys did not match"
            Send-APIResponse -StatusCode 401 -GeneralContentType Text -Body "API: Unauthorized" -LogComments "clientSubmittedApiKey=$clientSubmittedApiKey computedApiKey=$computedApiKey clientSalt=$clientSalt clientHostname=$clientHostname"
        }

    #endregion AUTHENTICATE REQUEST
}




function Limit-Requests
{
    <#
        
    
    
    
    
    
    
    
        DO NOT USE YET - TO BE CONVERTED FROM POWERSHELL UNIVERSAL/RE-WRITTEN
    
    
    
    
    
    
    
    
    
    
        .SYNOPSIS
        A simple, sliding-window rate limiter for requests to the API server.


        .DESCRIPTION
        This is a sliding window rate limiter. Basically, a more granular version of fixed window rate limiter which adjusts the limits over a
        sliding window of time. When clients make a request, they go into a bucket for the last rolling X number of minutes. If you exceed the
        threshold of Y requests in that rolling X period of minutes, your requests will be denied.


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


        .PARAMETER EndpointType
        Specifies the type of the endpoint request. For Security, there are different private keys per endpoint. Each endpoint type is described below:
        ↪ COMMON:   Any general endpoint request post registration. For example, beaconing back, downloading files, etc.
        ↪ REGISTER: Initial registration request when installing the endpoint. For example, doing a POST request to the ../endpoints (clients) API endpoint.
        ↪ REMOVE:   Removal request to uninstall the endpoint. For example, doing a DELETE request to the ../endpoints (clients) API endpoint.
        ↪ UPDATE:   Requests to update the Backstop API server. For example, doing a POST request to the ../update API endpoint.


        .PARAMETER TimespanInMin
        Specifies the period of time, in minutes, which the rate limit cover. For example, if you only want the endpoint hit
        no more than 30 times in a 60 minute period, specify the TimespanInMin as 60 and the MaxRequests as 30.


        .PARAMETER MaxRequests
        Specifies the maximum number of requests allowed during the given timespan.


        .EXAMPLE
        Limit-Requests -EndpointType General -TimespanInMin 60 -MaxRequests 30

    #>


    Param
    (
        # Specifies the type of the request
        [parameter(Mandatory=$true)]
        [ValidateSet('General', 'Register', 'Remove', 'Update')]
        [String]$EndpointType,

        # A general tag for the function, section of code or module name
        [parameter(Mandatory=$true)]
        [Int32]$TimespanInMin,

        # Specifies the severity of the message            
        [parameter(Mandatory=$true)]
        [Int32]$MaxRequests
    )


    ##########################################################################################################################################################################
    #region   ENFORCE RATE LIMIT   ###########################################################################################################################################
    ##########################################################################################################################################################################

        # Dynamically get the function name for logging
        $functionName = (Get-PSCallStack)[0].FunctionName

        # Set how many tokens are allowed during what time interval. For example: Only allow 10 requests (tokens) per 1 minute
        # Restrict registration requests
        if($urlDefinition -eq "/registerEndpoint/v1")
        {
            $allowedRequestsPerInterval = 2
            $timeIntervalInMinutes = 60
        }

        # Restrict removal requests
        if($urlDefinition -eq "/removeEndpoint/v1")
        {
            $allowedRequestsPerInterval = 2
            $timeIntervalInMinutes = 60
        }

        # For general API requests (anything else)
        if(($urlDefinition -ne "/registerEndpoint/v1")   -and   ($urlDefinition -ne "/removeEndpoint/v1"))
        {
            $allowedRequestsPerInterval = 60
            $timeIntervalInMinutes = 15
        }
        
        # Get the cache
        [system.array]$rateLimitStateTable = Get-PSUCache -Key "rateLimitStateTable"

        if(-not([system.array]$cache:rateLimitStateTable))
        {
            # Create table if this is the first time the server is starting. 
            Set-PSUCache -Key "rateLimitStateTable" -Value ""

            # Grab the variable just created as a new array variable so we can search it, add new objects to it and modify it.
            [system.array]$cache:rateLimitStateTable = $cache:rateLimitStateTable
        }

        # Grab the object once from memory
        $clientRateLimitValues = ($cache:rateLimitStateTable | Where-Object {$_.clientHostname -eq "$clientHostname"})

        if($clientRateLimitValues)
        {
            # Define current time
            $currentDateTime = Get-Date

            # See if we're in the same minute. If so, just see if there are tokens available and if so, just add to the counter. Else, deny the request.
            [datetime]$usedDateTime = ($clientRateLimitValues).usedDateTime

            # Compare the two times
            $timeDelta = ($currentDateTime - $usedDateTime).TotalMinutes

            # Check if we're within the internval or not
            if($timeDelta -lt $timeIntervalInMinutes)
            {
                # Check if there are tokens available to service the request
                if($clientRateLimitValues.used -lt $clientRateLimitValues.allowedRequestsPerInterval)
                {
                    # Update the counter
                    ($cache:rateLimitStateTable | Where-Object {$_.clientHostname -eq "$clientHostname"}).used += 1

                } Else {

                    # Reply back that the client is over the limit
                    $Global:response = New-PSUApiResponse -StatusCode 401 -Body "Rate limit exceeded"; $response
                    Write-EndpointLog -SeverityLevel Error -LogType Access -LogComments "Rate limit exceeded"
                    Break
                }

            } Else {

                # Reset Counter to 1 and make the usedDateTime stamp the current time
                ($cache:rateLimitStateTable | Where-Object {$_.clientHostname -eq "$clientHostname"}).used = 1
                ($cache:rateLimitStateTable | Where-Object {$_.clientHostname -eq "$clientHostname"}).usedDateTime = get-date
            }

        } Else {

            # Define current time
            $currentDateTime = Get-Date

            # No rate limit info exists so just create one and add to array
            $clientRateLimitState = [pscustomobject]@{clientHostname="$clientHostname";allowedRequestsPerInterval="$allowedRequestsPerInterval";used = 1; usedDateTime="$currentDateTime"}
            [system.array]$cache:rateLimitStateTable += $clientRateLimitState
        }

    #endregion ENFORCE RATE LIMIT
}




function New-SimpleVault
{
    <#
        .SYNOPSIS
        Creates a simple JSON secrets vault if you don't already have one. When you invoke this, it will create the vault
        on disk (or warn if a file already exists there). Note that you'll need to use the Open-Vault to read it into memory 
        and once in memory, use the other functions below to manipulate the vault such as adding or removing named secrets. 
        The vault is mainly for local, non-domain accounts.


        .DESCRIPTION
        This is a simple user/machine-specific "vault" for service accounts in a simple key/value JSON format store. The
        JSON vault is easily readable and keys are easily retrievable based on a friendly key name. You can store as many
        keys in the vault as you want BUT there is a trade-off which is generally ok for smaller applications. Since we 
        are using the DPAPI functionality (which takes care of the complexities of key management for us), you need to be 
        logged in as the user (typically a service account) on the same machine which are you going to use the secrets. 
        For example, you want to ensure that you're NOT stupidly putting API keys into a scripts since they'd be plaintext
        and, depending on the DACL/access, could be easily compromised. You need to run-as pwsh as the service account which
        will be running this code.

        Simple Vault is meant for local user (non-domain) service accounts on the same machine. It's purpose is to secure secrets
        via DPAPI. Instead of putting secrets (i.e. API keys, passwords, etc.) directly and stupidly in your scripts in plaintext,
        these functions allow you to easily and with a fair amount of security, store your secrets in an easy to manipulate JSON
        "Vault" file. To have your scripts get the secrets they need (after creating the vault), you simply have the script open
        the vault with the Open-SimpleVault cmdlet and then get the secret by a friendly name with Get-SimpleVaultSecret command.
        If you have no idea what you're doing, start with New-SimpleVault first to create it. 


        .NOTES
        Project:                Backstop Flexibility Framework (BFF)
        Public GitHub Repo:     https://github.com/humblecyberdude/BFF
        Copyright:              HumbleCyberDude@gmail.com
        License:                MIT (https://opensource.org/license/mit)
        Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
        Major Release Name:     Tender Lovin' Snare
        █ Last Updated By:      HumbleCyberDude
        █ Release Stage:        BETA
        █ Version:              0.2
        █ Last Update:          20-July-2024


        RELEASE NOTES
        -------------
        - 1.0 Initial release


        .PARAMETER Path
        Path to the vault which you want to create

        .PARAMETER Force
        Just do it without any acknowledgement (more for programmatic functions)

        .EXAMPLE
        PS> New-SimpleVault -Path "C:\Path\to\your\vault.json"

    #>


    param(
        [Parameter(Mandatory=$True)]
        [string]$VaultPath,
        [Switch]$Force
    )

    if(-Not($Force))
    {
        # Advise the admin that they need to be running as the user which intends to use the creds
        Write-Host "
        NOTICE, UNDERSTAND AND ACKNOWLEDGE:
        -----------------------------------
        
        1.  You are currently logged in as "$env:USERDOMAIN\$env:USERNAME". In order to add decryptable secrets to the 
            vault, you must be logged in as the user/service account which will be using them. If this is not the case
            then simply open another pwsh shell as the service account and run this command again.

        2.  You should only use domain accounts as the service account IF AND ONLY IF you need access to domain resources.
            If you fully trust AD, you are a fool and probably just don't know it. Use local accounts wherever possible or
            if you must use a domain account, at least try to use a GMSA (auto-rotates password for you). There are more 
            security risks to using domain accounts as the DPAPI keys can/are backed up in AD and can be recovered if the 
            domain is compromised.
        
        3.  If you force-reset a password (Example: Computer Management > Users > Right Click > Set Password) for an account
            that uses this vault, then all your secrets will become undecryptable. When rotating a password, do the normal 
            reset process and login as that user, reset their password that way. Basically, if you have to enter your old 
            password to rotate to a new one, you're good. If you force reset it in any manner without entering the old password
            then you're screwed.

        4.  For local accounts, this vault is non-portable. It must be used with the same credentials on the same machine which
            is generally ok for smaller applications. This function seeks to only be `"good enough`".

        5.  Ensure you have a backup of your secrets in a secure password manager. DO NOT be a shining example of apathetic 
            incompetence by not backing up your secrets or, unforgivably worse, storing your secrets in other non-encrypted 
            formats like text files or spreadsheets.
        
        " -ForegroundColor Yellow

        $acknowledgment = Read-Host -Prompt "If you've read and understood the above, type `"UNDERSTOOD`""
    }

    # Warn if path exists already
    if((Test-Path -Path $VaultPath)   -and   (-not($Force)))
    {
        $userFeedback = Read-Host -Prompt "WARNING: The path you specified already exists. Type 'OVERWRITE' to overwrite it. Else CTRL+C to quit."
    }

    # If userFeedback doesn't exist (no existing file) or they typed "OVERWRITE" AND they answered 'UNDERSTOOD', create the vault. If they just forced it, just do it.
    if(((-Not($userFeedback))   -or   ($userFeedback -eq "OVERWRITE"))   -and   ($acknowledgment -eq "UNDERSTOOD")   -or   ($Force))
    {
        # Create the Metadata hash table which will help us determine when it was created, on which machine and for which user
        $Metadata = @{
            "CreationDateInUTC" = "$((get-date -AsUTC).ToString())"
            "Description" = "This vault uses DPAPI and it will only work with the user on the machine specified below. If you need to move the vault to another machine, you'll need to re-create it again. Also, if you see [Domain]\COMPUTERNAME$ it indicates that the SYSTEM account was used."
            "ForMachineName" = "$env:COMPUTERNAME"
            "ForUser" = "$env:USERDOMAIN\$env:USERNAME"
        }

        # Create an initial blank secrets hash table
        $Secrets = @{}

        # Create the parent hash table
        $Vault = [Ordered]@{
            "Metadata" = $Metadata
            "Secrets" = $Secrets
        }

        # Export the vault to disk. Note that it will be blank until the Save-SimpleVault function is used.
        $Vault | ConvertTo-Json | Out-File "$VaultPath"

    } Else {

        Write-Host "Maybe try typing that again? Insert coins to continue."; Break
    }
}




function Open-SimpleVault
{
    <#
        .SYNOPSIS
        Opens the vault in for use or to manipulate.        


        .DESCRIPTION
        This is used to open the vault in memory in order to add or remove objects


        .NOTES
        Project:                Backstop Flexibility Framework (BFF)
        Public GitHub Repo:     https://github.com/humblecyberdude/BFF
        Copyright:              HumbleCyberDude@gmail.com
        License:                MIT (https://opensource.org/license/mit)
        Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
        Major Release Name:     Tender Lovin' Snare
        █ Last Updated By:      HumbleCyberDude
        █ Release Stage:        BETA
        █ Version:              0.2
        █ Last Update:          20-July-2024


        .PARAMETER Path
        Path to the vault which you want to open


        .EXAMPLE
        PS> Open-SimpleVault -Path "C:\Path\to\your\vault.json"
        
    #>


    param(
        [Parameter(Mandatory=$True)]
        [string]$VaultPath
    )

    # Do some basic verifications when opening the vault
    if((Test-Path $VaultPath)   -and   (Get-Content $VaultPath -Raw | Test-Json))
    {
        # Convert the hashtable to JSON and save it to a file
        $Global:Vault = Get-Content -Path $VaultPath | ConvertFrom-Json
        $Global:VaultPath = $VaultPath

        # Gather important details to determine if you're even able to get the keys
        $currentRunningUser = "$env:USERDOMAIN\$env:USERNAME"
        $vaultForUser = $vault.Metadata.ForUser
        $vaultForMachine = $vault.Metadata.ForMachineName

        # Error if you aren't running with the right user on the right machine
        if(($currentRunningUser -ne $vaultForUser)   -or   ($env:COMPUTERNAME -ne $vaultForMachine))
        {
            Write-Error "Vault requires you to be running from the context of user $vaultForUser on endpoint $vaultForMachine.
                However, you're running as $currentRunningUser on machine $env:COMPUTERNAME. Please run from correct user and machine."

            #Break
        }

    } Else {

        Write-Error "The file path specified doesn't exist or it's not a valid JSON file. To create a new vault use New-SimpleVault."
    }
}




function Add-SimpleVaultSecret
{
    <#
        .SYNOPSIS
        Function to add a secret to the vault


        .DESCRIPTION
        Add secrets by name to the vault and saves the vault file on disk


        .NOTES
        Project:                Backstop Flexibility Framework (BFF)
        Public GitHub Repo:     https://github.com/humblecyberdude/BFF
        Copyright:              HumbleCyberDude@gmail.com
        License:                MIT (https://opensource.org/license/mit)
        Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
        Major Release Name:     Tender Lovin' Snare
        █ Last Updated By:      HumbleCyberDude
        █ Release Stage:        BETA
        █ Version:              0.2
        █ Last Update:          20-July-2024


        .PARAMETER Name
        Specify the friendly name of the secret.


        .PARAMETER NoAutoSave
        Use this if you want to add items in memory but not save it to disk. If you want to save it to disk
        afterwards, simply use the Save-SimpleVault command.


        .PARAMETER Secret
        Specify the secret manually. You should ONLY do this if you already have it captured as an initial
        variable anyway and there's no way around it. Remember that this could be captured vis PowerShell 
        logging.


        .PARAMETER Force
        Forces the ability to write a small secret


        .PARAMETER Update
        Replaces the secret for the given name


        .PARAMETER Quiet
        Supresses certain nagging messages


        .EXAMPLE
        PS> Add-SimpleVaultSecret -Name "FriendlyKeyName"

    #>


    param(
        [Parameter(Mandatory=$True)]
        [string]$Name,
        
        [Parameter(Mandatory=$False)]
        [string]$Secret,

        [Parameter(Mandatory=$False)]
        [Switch]$Force,
        
        [Parameter(Mandatory=$False)]
        [Switch]$Update,
        
        [Parameter(Mandatory=$False)]
        [Switch]$NoAutoSave,
        
        [Parameter(Mandatory=$False)]
        [Switch]$Quiet
    )

    if($Vault)
    {
        # Ensure the key name isn't already in use or if -Update is used, overwrite it of it does.
        if(($vault.Secrets.PSObject.Properties.Name -notcontains $Name)   -or   ($Update))
        {
            if($Secret)
            {
                if(-Not($Quiet))
                {
                    Write-Host "NOTICE: Per the documentation, only use the -Secret option if there's no other way. Remember PowerShell logging! It's added now anyway."
                }
                
                $secureString = $Secret | ConvertTo-SecureString -AsPlainText -Force

            } Else {

                # Use Read-Host so ensure that the plaintext secret isn't recorded in PowerShell logging
                $secureString = Read-Host -Prompt "Type the secret you want to protect for $name" -AsSecureString
            }

            # See how long the secret is (clearly not a complexity check)
            $secretLength = $secureString.Length

            if($secretLength -eq 0)
            {
                Write-Error "Either you type something for a secret or our relationship status is going to change to `"It's Complicated`""
                Break
            }

            # Warn and break if secret is between 8 and 11 characters unless -Force is used
            if(($secretLength -ge 8   -and   $secretLength -lt 12)   -and   (-not($Force)))
            {
                Write-Warning "Not accepting the secret unless -Force is used. The length of your secret is $secretLength so if this is a password then you REALLY need to up it past at least 16 characters or more."
                Break
            }

            # Berate and break if secret is <8 characters unless -Force is used
            if(($secretLength -gt 0 -and $secretLength -lt 8)   -and   (-not($Force)))
            {
                Write-Host "JUST STOP: The length of your secret is $secretLength characters. *IF* this is a password (use -Force if not) then you have totally failed. Seriously, when you woke up today to work at Apathy International, did you ask yourself `"How can I fail even more than I did yesterday? How can I be the weakest link in the chain or how can I achieve the next level of stupidity?`" Perhaps we can help you find a better job..." -ForegroundColor Red
                
                # Help the admin find a better job
                Start-Process "https://jobs.mchire.com"
                Break
            }

            # Convert the secureString in memory an encrypted Secure-String that we can write to the vault
            $encryptedSecureString = $secureString | ConvertFrom-SecureString

            # Immediately flush the plaintext data from memory (no longer needed) and also flush the length as well
            Remove-Variable secureString -Force
            Remove-Variable secretLength -Force

            # Ensure that the encryptedSecureString is > 292 bytes long
            if($encryptedSecureString.Length -lt 256)
            {
                Write-Error "The encrypted form of the secret is somehow less than the minimum byte length of 256. Somehow, something went wrong and may be in plaintext. Stopping prior to writing to modifying the vault or writing to disk."
                Break
            }

            # Add secret to the vault or update it if -Update was called
            $vault.Secrets | Add-Member -MemberType NoteProperty -Name "$name" -Value "$encryptedSecureString"

            # Save to disk unless -NoAutoSave was specified
            if(-Not($NoAutoSave))
            {
                $Vault | ConvertTo-Json | Out-File -Path "$VaultPath"
            }

        } Else {

            Write-Error "Name is already in the vault. Please pick a different name, use -Update with this command or just use Remove-SimpleVaultSecret -Name $Name"
        }

    } Else {

        Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
    }

}




function Remove-SimpleVaultSecret
{
    <#
        .SYNOPSIS
        Function to remove a secret from the vault


        .DESCRIPTION
        Removes a secret from the vault by the friendly name specified in -Name. Also, it saves the vault file on disk


        .NOTES
        Project:                Backstop Flexibility Framework (BFF)
        Public GitHub Repo:     https://github.com/humblecyberdude/BFF
        Copyright:              HumbleCyberDude@gmail.com
        License:                MIT (https://opensource.org/license/mit)
        Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
        Major Release Name:     Tender Lovin' Snare
        █ Last Updated By:      HumbleCyberDude
        █ Release Stage:        BETA
        █ Version:              0.2
        █ Last Update:          20-July-2024


        .PARAMETER Name
        Specify the friendly name of the secret you want to remove from the vault.


        .EXAMPLE
        PS> Remove-SimpleVaultSecret -Name "FriendlyKeyName"

    #>


    param(
        [Parameter(Mandatory=$True)]    
        [string]$Name,
        [Switch]$NoAutoSave
    )

    if($Vault)
    {
        # Annoyingly, there's no Remove-Member so need to do it this way
        $vault.Secrets.PSObject.Properties.Remove($Name)

        # Save to disk unless -NoAutoSave was specified
        if(-Not($NoAutoSave))
        {
            $Vault | ConvertTo-Json | Out-File -Path "$VaultPath"
        }

    } Else {

        Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
    }
}




function Get-SimpleVaultNames
{
    <#
        .SYNOPSIS
        Just gets the friendly names of the secrets in the vault


        .NOTES
        Project:                Backstop Flexibility Framework (BFF)
        Public GitHub Repo:     https://github.com/humblecyberdude/BFF
        Copyright:              HumbleCyberDude@gmail.com
        License:                MIT (https://opensource.org/license/mit)
        Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
        Major Release Name:     Tender Lovin' Snare
        █ Last Updated By:      HumbleCyberDude
        █ Release Stage:        BETA
        █ Version:              0.2
        █ Last Update:          20-July-2024


        .PARAMETER Name
        Specify the friendly name of the secret you want to remove from the vault.


        .EXAMPLE
        PS> Get-SimpleVaultNames -Name "FriendlyKeyName"

    #>


    if($Vault)
    {
        $Vault.Secrets.PSObject.Properties.Name

    } Else {

        Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
    }
}




function Get-SimpleVaultDetails
{
    <#
        .SYNOPSIS
        Retrieves the vault details in the metadata


        .NOTES
        Project:                Backstop Flexibility Framework (BFF)
        Public GitHub Repo:     https://github.com/humblecyberdude/BFF
        Copyright:              HumbleCyberDude@gmail.com
        License:                MIT (https://opensource.org/license/mit)
        Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
        Major Release Name:     Tender Lovin' Snare
        █ Last Updated By:      HumbleCyberDude
        █ Release Stage:        BETA
        █ Version:              0.2
        █ Last Update:          20-July-2024


        .EXAMPLE
        PS> Get-SimpleVaultDetails

    #>

    if($Vault)
    {
        $Vault.Metadata

    } Else {

        Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
    }
}




function Get-SimpleVaultSecret
{
    <#
        .SYNOPSIS
        Retrieves the plaintext secret from the vault to use in scripts, etc.


        .NOTES
        Project:                Backstop Flexibility Framework (BFF)
        Public GitHub Repo:     https://github.com/humblecyberdude/BFF
        Copyright:              HumbleCyberDude@gmail.com
        License:                MIT (https://opensource.org/license/mit)
        Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
        Major Release Name:     Tender Lovin' Snare
        █ Last Updated By:      HumbleCyberDude
        █ Release Stage:        BETA
        █ Version:              0.2
        █ Last Update:          20-July-2024


        .PARAMETER Name
        Specify the friendly name of the secret. 


        .PARAMETER Scope
        Specify the varaiable scope for the plaintext password:
        - Script: Constrain the variable just to the script you're running (DEFAULT)
        - Global: Means that you can use this outside of the script your running but within the single session you're in


        .EXAMPLE
        PS> Get-SimpleVaultSecret -Name "FriendlyKeyName"

    #>


    param(
        [Parameter(Mandatory=$True)]    
        [string]$Name
    )


    if($Vault)
    {
        # Gather important details to determine if you're even able to get the keys
        # NOTE: The SYSTEM user isn't listed as "NT AUTHORITY\SYSTEM" as you may expect. It's [DOMAIN/WORKGROUP]\[COMPUTERNAME]$.
        $currentRunningUser = "$env:USERDOMAIN\$env:USERNAME"
        $vaultForUser = $vault.Metadata.ForUser
        $vaultForMachine = $vault.Metadata.ForMachineName

        # Error if you aren't running with the right user on the right machine (can't even decrypt the string anyway)
        if(($currentRunningUser -ne $vaultForUser)   -or   ($env:COMPUTERNAME -ne $vaultForMachine))
        {
            Write-Error "Vault requires you to be running from the context of user $vaultForUser on endpoint $vaultForMachine.
                However, you're running as $currentRunningUser on machine $env:COMPUTERNAME. Please run from correct user and machine."

#Break
        }

        # If the specified name exists, get the secret
        if(($Vault.Secrets.PSObject.Properties | Where-Object {$_.Name -eq $Name}))
        {
            # Get the encrypted value of the Secure-String
            $encryptedSecureString = ($Vault.Secrets.PSObject.Properties | Where-Object {$_.Name -eq $Name}).Value

            # Convert that to a binary in-memory securestring
            $encryptedSecureString = $encryptedSecureString | ConvertTo-SecureString

            # Convert the encryptedSecureString variable back into plaintext via DPAPI
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedSecureString)
            $plaintextSecureString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

            # Refresh variables if they exist
            if(Get-Variable -Name ($name + "_vaultSecret") -ErrorAction SilentlyContinue)
            {
                Remove-Variable -Name ($name + "_vaultSecret") -Scope Global
            }

            # Output the plainext as the variable [$Name_vaultSecret]
            New-Variable -Name ($name + "_vaultSecret") -Value $plaintextSecureString -Scope Global

            # Just define the variable name for verbose output
            $varName = (Get-Variable ($name + "_vaultSecret")).Name

            # Ensure that we have something for the secret. Not really a good way to verify it other than it exists since it's arbitrary.
            if((Get-Variable ($name + "_vaultSecret")).Value)
            {
                Write-Verbose "Plaintext is in memory for this PowerShell session context. Variable name is $varName"

            } Else {

                Write-Error "Enable to decrypt secret"
            }

        } Else {

            Write-Error "The name of the key $name doesn't appear in the vault. Maybe you typed something wrong?"

            Break
        }

    } Else {

        Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet?"
    }
}




function Save-SimpleVault
{
    <#
        .SYNOPSIS
        Saves the vault to the file on disk. This is only really used if you specified -NoAutoSave.


        .NOTES
        Project:                Backstop Flexibility Framework (BFF)
        Public GitHub Repo:     https://github.com/humblecyberdude/BFF
        Copyright:              HumbleCyberDude@gmail.com
        License:                MIT (https://opensource.org/license/mit)
        Credit:                 Team Humble Cyber Dudes (Any 3rd party code credited separately in-line)
        Major Release Name:     Tender Lovin' Snare
        █ Last Updated By:      HumbleCyberDude
        █ Release Stage:        BETA
        █ Version:              0.2
        █ Last Update:          20-July-2024


        .EXAMPLE
        PS> Save-SimpleVault

    #>


    if($Vault   -and   $VaultPath)
    {
        # Save the contents to disk
        $Vault | ConvertTo-Json | Out-File "$VaultPath"

    } Else {

        Write-Error "Unable to find/parse the vault. Did you use Open-SimpleVault yet? Also, ensure that `$VaultPath` variable is present and correct"
    }
}





##############################################################################################################################################################################
#region   SIGNATURE   ########################################################################################################################################################
##############################################################################################################################################################################

