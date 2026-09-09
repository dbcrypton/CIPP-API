BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Identity/Administration/Groups/Invoke-ExecGroupMembers.ps1'

    class HttpResponseContext {
        [object]$StatusCode
        [object]$Body
    }
    $Accelerators = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ('HttpStatusCode' -as [type])) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }

    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) }
    function Get-CippException {
        param($Exception)
        [pscustomobject]@{ NormalizedError = $Exception.Exception.Message }
    }
    function Start-Sleep { param($Seconds) }
    function New-GraphGetRequest {
        param($uri, $tenantid)
        if ($uri -like '*/memberOf*') {
            return $script:isMember ? @([pscustomobject]@{ id = 'group-guid' }) : @()
        }
        if ($uri -like '*/groups/*') {
            return $script:group
        }
        if ($uri -like '*/users/*') {
            return [pscustomobject]@{
                id                = 'user-guid'
                displayName       = 'Test User'
                userPrincipalName = 'test.user@contoso.com'
                mail              = 'test.user@contoso.com'
            }
        }
    }
    function New-GraphPOSTRequest {
        param($type, $uri, $tenantid, $body)
        $script:graphWrites.Add([pscustomobject]@{ type = $type; uri = $uri; body = $body })
        if (!$script:suppressMutation) {
            $script:isMember = $type -eq 'POST'
        }
    }
    function New-ExoBulkRequest {
        param($tenantid, $cmdletArray)
        $script:exoWrites.Add($cmdletArray[0])
        if (!$script:suppressMutation) {
            $script:isMember = $cmdletArray[0].CmdletInput.CmdletName -eq 'Add-DistributionGroupMember'
        }
        return @([pscustomobject]@{ error = $null })
    }
    function New-Request {
        param([string]$Action, [bool]$Approved = $true)
        [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ExecGroupMembers' }
            Headers = @{}
            Body    = [pscustomobject]@{
                action       = $Action
                approved     = $Approved
                groupId      = 'group-guid'
                tenantFilter = 'contoso.com'
                users        = @('user-guid')
            }
        }
    }

    . $FunctionPath
}

Describe 'Invoke-ExecGroupMembers guarded routing' {
    BeforeEach {
        $script:isMember = $false
        $script:suppressMutation = $false
        $script:graphWrites = [System.Collections.Generic.List[object]]::new()
        $script:exoWrites = [System.Collections.Generic.List[object]]::new()
        $script:group = [pscustomobject]@{
            id              = 'group-guid'
            displayName     = 'Test Security Group'
            groupTypes      = @()
            mailEnabled     = $false
            securityEnabled = $true
        }
    }

    It 'rejects a write unless approved is exactly true' {
        $Response = Invoke-ExecGroupMembers -Request (New-Request -Action removeMember -Approved $false)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Forbidden)
        $script:graphWrites.Count | Should -Be 0
        $script:exoWrites.Count | Should -Be 0
    }

    It 'removes one Entra member with the exact Graph ref DELETE and verifies absence' {
        $script:isMember = $true

        $Response = Invoke-ExecGroupMembers -Request (New-Request -Action removeMember)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:graphWrites.Count | Should -Be 1
        $script:graphWrites[0].type | Should -Be 'DELETE'
        $script:graphWrites[0].uri | Should -Be 'https://graph.microsoft.com/v1.0/groups/group-guid/members/user-guid/$ref'
        $script:isMember | Should -BeFalse
    }

    It 'adds then removes one Entra member through the exact Graph ref requests' {
        $AddResponse = Invoke-ExecGroupMembers -Request (New-Request -Action addMember)
        $RemoveResponse = Invoke-ExecGroupMembers -Request (New-Request -Action removeMember)

        $AddResponse.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $RemoveResponse.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:graphWrites[0].type | Should -Be 'POST'
        $script:graphWrites[0].uri | Should -Be 'https://graph.microsoft.com/v1.0/groups/group-guid/members/$ref'
        ($script:graphWrites[0].body | ConvertFrom-Json).'@odata.id' | Should -Be 'https://graph.microsoft.com/v1.0/directoryObjects/user-guid'
        $script:graphWrites[1].type | Should -Be 'DELETE'
    }

    It 'uses Exchange for a mail-enabled security group' {
        $script:group.mailEnabled = $true

        $Response = Invoke-ExecGroupMembers -Request (New-Request -Action addMember)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:graphWrites.Count | Should -Be 0
        $script:exoWrites[0].CmdletInput.CmdletName | Should -Be 'Add-DistributionGroupMember'
        $script:exoWrites[0].CmdletInput.Parameters.Member | Should -Be 'test.user@contoso.com'
    }

    It 'reports write-not-verified when membership does not change' {
        $script:isMember = $true
        $script:suppressMutation = $true

        $Response = Invoke-ExecGroupMembers -Request (New-Request -Action removeMember)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
        $Response.Body.Results | Should -Be 'write-not-verified'
        $Response.Body.afterMember | Should -BeTrue
    }
}
