function Invoke-ExecGroupMembers {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.Group.ReadWrite
    .DESCRIPTION
        Adds or removes exactly one group member after explicit approval. Entra and
        Microsoft 365 groups use Graph; classic mail groups use Exchange Online.
        The result is successful only after direct membership is verified.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $Body = $Request.Body
    $Action = $Body.action
    $GroupId = [string]$Body.groupId
    $TenantFilter = [string]$Body.tenantFilter
    $Users = @($Body.users | Where-Object { $_ })

    if ($Body.approved -ne $true) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Forbidden
                Body       = @{ Results = 'Explicit approved: true is required.' }
            })
    }

    if ($Action -notin @('addMember', 'removeMember') -or !$GroupId -or !$TenantFilter -or $Users.Count -ne 1) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Required parameters: action (addMember or removeMember), groupId, tenantFilter, and exactly one user.' }
            })
    }

    try {
        $Group = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/groups/$GroupId`?`$select=id,displayName,mailEnabled,securityEnabled,groupTypes" -tenantid $TenantFilter
        if (!$Group.id) {
            throw "Group '$GroupId' was not found."
        }

        $UserInput = $Users[0]
        $UserIdentifier = [string]($UserInput.value ?? $UserInput)
        $User = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users/$UserIdentifier`?`$select=id,displayName,userPrincipalName,mail" -tenantid $TenantFilter
        if (!$User.id) {
            throw "User '$UserIdentifier' was not found."
        }

        $GetMembership = {
            @(
                New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users/$($User.id)/memberOf`?`$select=id&`$top=999" -tenantid $TenantFilter
            ).id -contains $Group.id
        }
        $BeforeMember = & $GetMembership
        if (($Action -eq 'addMember' -and $BeforeMember) -or ($Action -eq 'removeMember' -and !$BeforeMember)) {
            $State = $BeforeMember ? 'already a member' : 'already absent'
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{ Results = "$($User.userPrincipalName) is $State for group $($Group.displayName); no write was performed." }
                })
        }

        $IsMicrosoft365 = @($Group.groupTypes) -contains 'Unified'
        $IsExchangeBacked = [bool]$Group.mailEnabled -and !$IsMicrosoft365
        if ($IsExchangeBacked) {
            $CmdletName = $Action -eq 'addMember' ? 'Add-DistributionGroupMember' : 'Remove-DistributionGroupMember'
            $OperationGuid = [Guid]::NewGuid().ToString()
            $ExoRequest = @{
                CmdletInput   = @{
                    CmdletName = $CmdletName
                    Parameters = @{
                        Identity                         = $Group.id
                        Member                           = $User.userPrincipalName
                        BypassSecurityGroupManagerCheck = $true
                    }
                }
                OperationGuid = $OperationGuid
            }
            $RawExoResult = New-ExoBulkRequest -tenantid $TenantFilter -cmdletArray @($ExoRequest)
            $ExoErrors = @($RawExoResult | ForEach-Object { $_.error } | Where-Object { $_ })
            if ($ExoErrors.Count -gt 0) {
                throw ($ExoErrors -join '; ')
            }
            $Route = 'Exchange'
        } else {
            if ($Action -eq 'addMember') {
                $GraphBody = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($User.id)" }
                $null = New-GraphPOSTRequest -type POST -uri "https://graph.microsoft.com/v1.0/groups/$($Group.id)/members/`$ref" -tenantid $TenantFilter -body ($GraphBody | ConvertTo-Json -Compress)
            } else {
                $null = New-GraphPOSTRequest -type DELETE -uri "https://graph.microsoft.com/v1.0/groups/$($Group.id)/members/$($User.id)/`$ref" -tenantid $TenantFilter
            }
            $Route = 'Graph'
        }

        $AfterMember = $BeforeMember
        foreach ($DelaySeconds in @(0, 1, 2, 4)) {
            if ($DelaySeconds -gt 0) {
                Start-Sleep -Seconds $DelaySeconds
            }
            $AfterMember = & $GetMembership
            if (($Action -eq 'addMember' -and $AfterMember) -or ($Action -eq 'removeMember' -and !$AfterMember)) {
                break
            }
        }

        if (($Action -eq 'addMember' -and !$AfterMember) -or ($Action -eq 'removeMember' -and $AfterMember)) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::Conflict
                    Body       = @{
                        Results      = 'write-not-verified'
                        beforeMember = $BeforeMember
                        afterMember  = $AfterMember
                        route        = $Route
                    }
                })
        }

        $Verb = $Action -eq 'addMember' ? 'added' : 'removed'
        $Direction = $Action -eq 'addMember' ? 'to' : 'from'
        $Message = "Successfully $Verb $($User.userPrincipalName) $Direction group $($Group.displayName) using $Route; membership verified."
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Message -Sev 'Info'
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{ Results = $Message }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Message = "Failed to manage membership for group $GroupId - $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Message -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $Message }
            })
    }
}
