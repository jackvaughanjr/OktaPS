### DELETE IN PROD, USED FOR TESTING ###
. ./OktaConfig.ps1

Function Format-OktaHeaderLink {
    param(
        [Parameter(Mandatory=$true)]$linkHeader
    )
    If ($linkHeader -is [System.String[]]) { $links = $linkHeader }
    ElseIf ($linkHeader -is [System.String]) { $links = $linkHeader.Split(",") }

    $outLinks = @{}

    ForEach ($link in $links) {
        If ($link.Trim() -match '^<(https://.+)>; rel="(\w+)"$') {
            $outLinks[$Matches[2].Trim()] = $Matches[1].Trim()
        }
    }

    Return $outLinks
}

Function New-OktaUserAgent {
    If ($Global:defaultUserAgent) {
        Return $Global:defaultUserAgent
    }
    $userAgentArray = $PSVersionTable | Select-Object -Property OS,Platform,PSVersion
    If (!$userAgentArray.OS) { $userAgentArray.OS = "UnknownOS" }
    If (!$userAgentArray.Platform) { $userAgentArray.Platform = "UnknownPlatform" }
    If (!$userAgentArray.PSVersion) { $userAgentArray.PSVersion = "UnknownPSVersion" }

    $agentString = "Okta-PSModule/$((Get-Module -Name Okta).Version.ToString())"
    ForEach ($property in $userAgentArray.PSObject.Properties) {
        $agentString += " $($property.Value)"
    }
    Write-Verbose -Message "Created UserAgent: $agentString"

    $Global:defaultUserAgent = $agentString
    Return $agentString
}

Function Test-OktaOrgConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]$org
    )
    If ($oktaOrgs[$org]) {
        Return $true
    }
    Else {
        $errorString = "The Org $org is not defined in the OktaConfig.ps1 file!"
        Throw $errorString
    }
}

function Format-OktaDateFields {
[CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $oktaEntity
    )
    begin {
        $dateFields = ('created','activated','statusChanged','lastLogin','lastUpdated','passwordChanged','lastSync')
    }
    process {
        ForEach ($field in $dateFields) {
            If ($oktaEntity.$field) {
                $user.$field = Get-Date $user.$field
            }
        }
    }
    end {
        Return $oktaEntity
    }
}

Function Convert-OktaRateLimitTimeRemaining {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [long]$seconds
    )
    Begin {
        $utcTime = $(Get-Date -Date "1970-01-01 00:00:00Z").ToUniversalTime()
    }
    Process {
        $resetTime = $utcTime.AddSeconds($seconds)
        $timeToReset = New-TimeSpan -Start (Get-Date).ToUniversalTime() -End $resetTime
    }
    
    End {
        Return $timeToReset.TotalSeconds
    }
}

Function New-OktaUriQuery {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [UriBuilder]$uri,
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$addParams
    )
    ForEach ($property in $addParams.PSObject.Properties) {
        $paramToAdd = "$($property.Name)=$($property.Value)"
        If (!$uri.Query) { $uri.Query = "$paramToAdd" }
        Else { $uri.Query += "&$paramToAdd"}
    }
    Return $uri
}

Function New-OktaUri {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resource,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$params
    )
    Begin {
        Write-Verbose -Message "Start: $resource"
        $uriArgs = @{
            "Scheme" = "https"
            "Host" = "hostplaceholder"
            "Port" = 443
            "Path" = $resource
        }
        $uri = New-Object -TypeName System.UriBuilder -Property $uriArgs
    }
    Process {
        $uri = New-OktaUriQuery -uri $uri -addParams $params
        $rawResource = ($uri.Path + $uri.Query)
        Write-Verbose -Message "Before: $rawResource"
        $newResource = [System.Web.HttpUtility]::UrlPathEncode($rawResource)
        Write-Verbose -Message "After Encoding: $newResource"
    }
    End {
        Return $newResource
    }
}

Function Invoke-OktaApiNextRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][ValidateSet("Get","Head","Post","Put","Delete")][string]$method,
        [Parameter(Mandatory=$true)][string]$uri,
        [Parameter(Mandatory=$true)][PSCustomObject]$headers,
        [Parameter(Mandatory=$false)][PSCustomObject]$body,
        [Parameter(Mandatory=$false)][string]$userAgent,
        [Parameter(Mandatory=$false)][string]$contentType = "application/json"
    )
    Begin {
        If (!$userAgent) { $userAgent = New-OktaUserAgent }
    }
    Process {
        $restArguments = @{
            "Method" = $method
            "Uri" = $uri
            "UserAgent" = $userAgent
            "Headers" = $headers
            "ContentType" = $contentType
            "ErrorVariable" = "evar"
            "ResponseHeadersVariable" = "responseHeaders"
        }
        If ($body) {
            $bodyJson = ConvertTo-Json $body -Depth 10 
            Write-Verbose -Message "Body:"
            Write-Verbose -Message $bodyJson
            $restArguments.Body = $bodyJson
        }
        $response = Invoke-RestMethod @restArguments
        
        ### Process response headers ###
        If ($responseHeaders.Link) { 
            $links = Format-OktaHeaderLink -linkHeader $responseHeaders.Link
            If ($links.next) { $next = $links.next }
            Else { $next = $false }
            Remove-Variable -Name links -Force
        }
        Else {
            $next = $false
        }

        $resOutput = @{
            response = $response
            resheaders = $responseHeaders
            next = $next
        }
    }
    End {
        Return $resOutput
    }
}

Function Invoke-OktaApiRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][ValidateScript({Test-OktaOrgConfig -org $_})][String]$OktaOrg,
        [Parameter(Mandatory=$true)][ValidateSet('Get','Head','Post','Put','Delete')][String]$Method,
        [Parameter(Mandatory=$true)][String]$Resource,
        [Parameter(Mandatory=$false)][PSCustomObject]$Body = @{},
        [Parameter(Mandatory=$false)][Boolean]$EnablePagination = $OktaOrgs[$OktaOrg].enablePagination,
        [Parameter(Mandatory=$false)][PSCustomObject]$AltHeaders,
        [Parameter(Mandatory=$false)][ValidateRange(1,10000)][Int]$Limit,
        [Parameter(Mandatory=$false)][Boolean]$Untrusted = $false,
        [Parameter(Mandatory=$false)][String]$ContentType = 'application/json'
    )
    Begin {
        $headers = @{
            'Accept-Charset' = 'ISO-8859-1,utf-8'
            'Accept-Language' = 'en-US'
            'Accept-Encoding' = 'deflate,gzip'
        }
        ##Convert Encoded Token to usable string if provided
        If (!$Untrusted) {
            If ($OktaOrgs[$OktaOrg].encToken) {
                $apiToken = [System.Net.NetworkCredential]::new('dummy', $OktaOrgs[$OktaOrg].encToken).Password
            }
            Else {
                $apiToken = $OktaOrgs[$OktaOrg].secToken.ToString()
            }
            $headers.Authorization = "SSWS $apiToken"
        }
        ##Build Resource Uri
        If ($Resource -like 'https://*') { [String]$uri = $Resource }
        Else { [string]$uri = ($OktaOrgs[$OktaOrg].baseUrl.ToString()) + $Resource }
        ##Use Alternate UserAgent string if exists
        If ($AltHeaders.UserAgent) {
            $userAgent = $AltHeaders.UserAgent
            $AltHeaders.PSObject.Properties.Remove('UserAgent')
        }
        ##Merge any remaining AltHeaders into Headers
        ForEach ($property in $AltHeaders.PSObject.Properties) {
            $headers.$($property.Name) = $property.Value
        }
    }
    Process {
        $getPages = $true
        $Global:nextNext = $false
        $next = $false
        $results = @()
        $pageCount = 1

        While ($getPages) {
            $apiArgs = @{
                "Method" = $Method
                "Uri" = $uri
                "Headers" = $headers
                "Body" = $Body
                "UserAgent" = $userAgent
                "ContentType" = $ContentType
                "Verbose" = $false
            }
            $response = Invoke-OktaApiNextRequest @apiArgs

            If ($response.response) {
                $results += $response.response
                $next = $response.next
                $responseCount = $response.response.Count
            }
            Else {
                $responseCount = 0
                $next = $false
            }
            Clear-Variable -Name response -Force

            $resultCount = $results.Count
            Write-Verbose "[$(Get-Date -format G)] Page $($pageCount): $responseCount results returned. $resultCount total results."

            If ($responseCount = 0) {
                Write-Verbose "[$(Get-Date -format G)] 0 results returned - skipping next page"
                $getPages = $false
                If ($next) { $Global:nextNext = $next }
                Else { $Global:nextNext = $uri }
            }

            If ($Limit) {
                If ($responseCount -lt $Limit) {
                    $getPages = $false
                    If ($next) { $Global:nextNext = $next }
                    Else { $Global:nextNext = $uri }
                }
            }

            If (!$EnablePagination) {
                $getPages = $false
            }

            If ($next) {
                If ($getPages) { 
                    Write-Verbose "[$(Get-Date -format G)] Fetching next link: $next"
                    $uri = $next 
                }
                Else { 
                    Write-Verbose "[$(Get-Date -format G)] Not fetching next link: $next"
                }
            }
            Else {
                Write-Verbose "[$(Get-Date -format G)] No next link found or it's invalid: $($next.ToString())"
                $getPages = $false
            }
            $pageCount++
        } # End While
    }
    End {
        Return $results
    }
}

Function Get-OktaUserById {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)][ValidateScript({Test-OktaOrgConfig -org $_})][String]$OktaOrg = $oktaDefOrg,
        [Parameter(Mandatory=$true)][ValidateLength(1,100)][String]$UserName
    )
    Begin {
        $method = "Get"
        $resource = "/api/v1/users/$UserName"
    }
    Process {
        $request = Invoke-OktaApiRequest -Method $method -Resource $resource -OktaOrg $oktaOrg
    }
    End {
        Return $request
    }
}

Function Get-OktaApps {
    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [Parameter(Mandatory=$false,ParameterSetName='Status')][ValidateSet('ACTIVE','INACTIVE')][String]$Status,
        [Parameter(Mandatory=$false,ParameterSetName='GroupId')][String]$GroupID,
        [Parameter(Mandatory=$false,ParameterSetName='UserId')][String]$UserID,
        [Parameter(Mandatory=$false)][Int]$Limit = 200,
        [Parameter(Mandatory=$false,ParameterSetName='GroupId')]
        [Parameter(Mandatory=$false,ParameterSetName='UserId')][Switch]$Expand
    )
    Begin {
        $method = "Get"
        $resource = "/api/v1/apps?limit=$Limit"
        If ($Status) {
            $addFilter = $true
            $filter = "status eq ""$Status"""
        }
        If ($GroupID) {
            $addFilter = $true
            $filter = "group.id eq ""$GroupID""" 
            If ($Expand) { $filter += "&expand=group/$GroupID" }
        }
        If ($UserID) { 
            $addFilter = $true
            $filter = "user.id eq ""$UserID""" 
            If ($Expand) { $filter += "&expand=user/$UserID" }
        }
        If ($addFilter) {
            $resource += "&filter= $filter"
        }
    }
    Process {
        $request = Invoke-OktaApiRequest -Method $method -Resource $resource -OktaOrg $oktaDefOrg
    }
    End {
        Return $request
    }
}

Function Get-OktaActiveApps {
    Param(
        [Parameter(Mandatory=$false)][String]$OktaOrg = $oktaDefOrg,
        [Parameter(Mandatory=$false)][Int]$Limit = $oktaOrgs.$OktaOrg.pageSize
    )
    Return Get-OktaApps -Status ACTIVE -Limit $Limit
}