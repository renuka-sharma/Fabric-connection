<#
.SYNOPSIS
    Manage Fabric API on-premises gateway connections with Service Principal credentials
    using Azure Key Vault secret references.

.DESCRIPTION
    This script is designed to run in Azure DevOps Pipelines (or any CI/CD system).
    It supports OnPremisesGateway connections only, where credentials are:
      1. RSA-OAEP encrypted using the gateway's public key
      2. Referenced via Azure Key Vault (servicePrincipalSecretReference)

    No plaintext secrets are passed in the request body.

.NOTES
    Prerequisites:
      1. An Azure AD (Entra ID) App Registration with a client secret.
      2. Fabric tenant setting "Service principals can use Fabric APIs" enabled
         for a security group that contains your SPN.
      3. The SPN must have permissions on the gateway.
      4. A Key Vault connection in Fabric with access to the secret.
      5. For Azure DevOps: store TenantId, ClientId, ClientSecret as secret
         pipeline variables or pull them from Azure Key Vault.

    Author : Example — adapt to your environment
    Date   : 2026-04-01
#>

[CmdletBinding()]
param(
    # --- Authentication -------------------------------------------------------
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,            # App Registration (SPN) Application (client) ID

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,        # Current SPN client secret (used to AUTHENTICATE to Fabric)

    # --- Connection target (the data-source SPN whose secret is in Key Vault) -
    [Parameter(Mandatory = $true)]
    [string]$DataSourceSpnClientId,   # Client ID of the SPN used BY the connection

    [Parameter(Mandatory = $true)]
    [string]$DataSourceSpnTenantId,   # Tenant ID of the SPN used BY the connection

    # --- Key Vault secret reference -------------------------------------------
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultConnectionId,    # The Fabric connection ID of your Key Vault connection

    [Parameter(Mandatory = $true)]
    [string]$KeyVaultSecretName,      # Name of the secret in Key Vault

    [string]$KeyVaultSecretVersion,   # Version (optional, omit or "" for latest)

    # --- Connection details ---------------------------------------------------
    [string]$ConnectionId,            # Existing connection ID (for UPDATE scenario)
    [string]$GatewayId,               # Gateway ID (required for on-prem scenarios)
    [string]$DisplayName = "Automated-SPN-Connection",
    [string]$ServerName = "myserver.database.windows.net",
    [string]$DatabaseName = "mydatabase",

    # --- Behaviour flags ------------------------------------------------------
    [ValidateSet("CreateOnPremGateway", "UpdateOnPremGateway")]
    [string]$Action = "CreateOnPremGateway",

    [bool]$SkipTestConnection = $false
)

# ============================================================================
#  SECTION 1 — Obtain a Bearer Token (client_credentials flow)
# ============================================================================
function Get-FabricAccessToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://api.fabric.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body `
                        -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Error "Failed to obtain access token: $_"
        throw
    }
}

# ============================================================================
#  SECTION 2 — Helper: standard headers
# ============================================================================
function Get-FabricHeaders {
    param([string]$Token)
    return @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
}

# ============================================================================
#  SECTION 3 — List existing connections (useful for discovery)
# ============================================================================
function Get-FabricConnections {
    param([string]$Token)

    $uri = "https://api.fabric.microsoft.com/v1/connections"
    $headers = Get-FabricHeaders -Token $Token

    try {
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
        return $result.value
    }
    catch {
        Write-Error "Failed to list connections: $_"
        throw
    }
}

# ============================================================================
#  SECTION 4 — ON-PREMISES GATEWAY: encrypt credentials with gateway public key
#
#  For on-prem gateway connections, the Fabric API requires credentials to be
#  RSA-OAEP encrypted using the gateway member's public key.
#  This section uses .NET's RSACryptoServiceProvider directly.
# ============================================================================
function Get-GatewayPublicKey {
    <#
    .SYNOPSIS
        Retrieves the public key of a gateway, needed to encrypt credentials.
        Uses the Power BI REST API (the Fabric API delegates to the same backend).
    #>
    param(
        [string]$Token,
        [string]$GatewayId
    )

    $uri = "https://api.powerbi.com/v1.0/myorg/gateways/$GatewayId"
    $headers = Get-FabricHeaders -Token $Token

    try {
        $gateway = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
        Write-Host "  Gateway '$($gateway.name)' public key retrieved."
        return $gateway.publicKey
    }
    catch {
        Write-Error "Failed to retrieve gateway info: $_"
        throw
    }
}

function Get-EncryptedCredentials {
    <#
    .SYNOPSIS
        Encrypts service principal credentials (with Key Vault secret reference)
        using the gateway's RSA public key via .NET RSACryptoServiceProvider.
    #>
    param(
        [object]$GatewayPublicKey,
        [string]$SpnClientId,
        [string]$SpnTenantId,
        [string]$KeyVaultConnectionId,
        [string]$KeyVaultSecretName,
        [string]$KeyVaultSecretVersion
    )

    # Build the credential JSON payload that the gateway expects.
    # Uses servicePrincipalSecretReference to point to Key Vault instead of
    # passing the secret value directly.
    $secretRef = @{
        connectionId = $KeyVaultConnectionId
        secretName   = $KeyVaultSecretName
    }
    if ($KeyVaultSecretVersion) {
        $secretRef.version = $KeyVaultSecretVersion
    }

    $credentialData = @{
        credentialData = @(
            @{ name = "servicePrincipalClientId"; value = $SpnClientId }
            @{ name = "servicePrincipalTenantId"; value = $SpnTenantId }
        )
        servicePrincipalSecretReference = $secretRef
    } | ConvertTo-Json -Depth 4 -Compress

    # RSA-OAEP encryption using .NET
    $exponentBytes = [Convert]::FromBase64String($GatewayPublicKey.exponent)
    $modulusBytes  = [Convert]::FromBase64String($GatewayPublicKey.modulus)

    $rsaParams = [System.Security.Cryptography.RSAParameters]::new()
    $rsaParams.Exponent = $exponentBytes
    $rsaParams.Modulus  = $modulusBytes

    $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    $rsa.ImportParameters($rsaParams)

    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($credentialData)
    $encryptedBytes = $rsa.Encrypt($plainBytes, $true)  # $true = OAEP padding

    return [Convert]::ToBase64String($encryptedBytes)
}

function New-OnPremGatewayConnection {
    param(
        [string]$Token,
        [string]$GatewayId,
        [string]$DisplayName,
        [string]$ServerName,
        [string]$DatabaseName,
        [string]$SpnClientId,
        [string]$SpnTenantId,
        [string]$KeyVaultConnectionId,
        [string]$KeyVaultSecretName,
        [string]$KeyVaultSecretVersion,
        [bool]  $SkipTestConnection = $false
    )

    # Step 1: get gateway public key
    $publicKey = Get-GatewayPublicKey -Token $Token -GatewayId $GatewayId

    # Step 2: encrypt credentials (with Key Vault reference)
    $encryptedCreds = Get-EncryptedCredentials `
        -GatewayPublicKey $publicKey `
        -SpnClientId $SpnClientId `
        -SpnTenantId $SpnTenantId `
        -KeyVaultConnectionId $KeyVaultConnectionId `
        -KeyVaultSecretName $KeyVaultSecretName `
        -KeyVaultSecretVersion $KeyVaultSecretVersion

    # Step 3: build Key Vault secret reference for the API request
    $secretRef = @{
        connectionId = $KeyVaultConnectionId
        secretName   = $KeyVaultSecretName
    }
    if ($KeyVaultSecretVersion) {
        $secretRef.version = $KeyVaultSecretVersion
    }

    # Step 4: call Create Connection
    $uri = "https://api.fabric.microsoft.com/v1/connections"
    $headers = Get-FabricHeaders -Token $Token

    $body = @{
        connectivityType  = "OnPremisesGateway"
        gatewayId         = $GatewayId
        displayName       = $DisplayName
        connectionDetails = @{
            type           = "SQL"
            creationMethod = "SQL"
            parameters     = @(
                @{ dataType = "Text"; name = "server";   value = $ServerName   }
                @{ dataType = "Text"; name = "database"; value = $DatabaseName }
            )
        }
        privacyLevel      = "Organizational"
        credentialDetails = @{
            singleSignOnType     = "None"
            connectionEncryption = "Encrypted"
            skipTestConnection   = $SkipTestConnection
            credentials          = @{
                credentialType                  = "ServicePrincipal"
                servicePrincipalClientId        = $SpnClientId
                tenantId                        = $SpnTenantId
                servicePrincipalSecretReference = $secretRef
                values                          = @(
                    @{
                        gatewayId            = $GatewayId
                        encryptedCredentials = $encryptedCreds
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 7

    Write-Host "Creating OnPremisesGateway connection '$DisplayName' ..."
    try {
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method POST -Body $body
        Write-Host "  -> Created successfully. Connection ID: $($result.id)"
        return $result
    }
    catch {
        Write-Error "Failed to create on-prem gateway connection: $_"
        if ($_.Exception.Response) {
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            Write-Error $reader.ReadToEnd()
        }
        throw
    }
}

function Update-OnPremGatewayConnectionSpnSecret {
    param(
        [string]$Token,
        [string]$ConnectionId,
        [string]$GatewayId,
        [string]$SpnClientId,
        [string]$SpnTenantId,
        [string]$KeyVaultConnectionId,
        [string]$KeyVaultSecretName,
        [string]$KeyVaultSecretVersion,
        [bool]  $SkipTestConnection = $false
    )

    # Step 1: get gateway public key
    $publicKey = Get-GatewayPublicKey -Token $Token -GatewayId $GatewayId

    # Step 2: encrypt credentials (with Key Vault reference)
    $encryptedCreds = Get-EncryptedCredentials `
        -GatewayPublicKey $publicKey `
        -SpnClientId $SpnClientId `
        -SpnTenantId $SpnTenantId `
        -KeyVaultConnectionId $KeyVaultConnectionId `
        -KeyVaultSecretName $KeyVaultSecretName `
        -KeyVaultSecretVersion $KeyVaultSecretVersion

    # Step 3: build Key Vault secret reference for the API request
    $secretRef = @{
        connectionId = $KeyVaultConnectionId
        secretName   = $KeyVaultSecretName
    }
    if ($KeyVaultSecretVersion) {
        $secretRef.version = $KeyVaultSecretVersion
    }

    # Step 4: call Update Connection (PATCH)
    $uri = "https://api.fabric.microsoft.com/v1/connections/$ConnectionId"
    $headers = Get-FabricHeaders -Token $Token

    $body = @{
        connectivityType  = "OnPremisesGateway"
        credentialDetails = @{
            skipTestConnection = $SkipTestConnection
            credentials        = @{
                credentialType                  = "ServicePrincipal"
                servicePrincipalClientId        = $SpnClientId
                tenantId                        = $SpnTenantId
                servicePrincipalSecretReference = $secretRef
                values                          = @(
                    @{
                        gatewayId            = $GatewayId
                        encryptedCredentials = $encryptedCreds
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 6

    Write-Host "Updating on-prem gateway connection '$ConnectionId' with Key Vault secret reference ..."
    try {
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method PATCH -Body $body
        Write-Host "  -> Updated successfully."
        return $result
    }
    catch {
        Write-Error "Failed to update on-prem gateway connection: $_"
        if ($_.Exception.Response) {
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            Write-Error $reader.ReadToEnd()
        }
        throw
    }
}


# ============================================================================
#  MAIN EXECUTION
# ============================================================================

Write-Host "============================================="
Write-Host " Fabric Connection Manager — Action: $Action"
Write-Host "============================================="
Write-Host ""

# Step 1: Authenticate
Write-Host "[1/3] Authenticating as service principal ..."
$accessToken = Get-FabricAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
Write-Host "  -> Token acquired.`n"

# Step 2: (Optional) List existing connections for reference
Write-Host "[2/3] Listing existing connections ..."
try {
    $connections = Get-FabricConnections -Token $accessToken
    Write-Host "  -> Found $($connections.Count) connection(s)."
    foreach ($conn in $connections) {
        Write-Host "     - [$($conn.connectivityType)] $($conn.displayName) (ID: $($conn.id))"
    }
}
catch {
    Write-Warning "  Could not list connections (non-fatal): $_"
}
Write-Host ""

# Step 3: Execute requested action
Write-Host "[3/3] Executing action: $Action ..."
switch ($Action) {

    "CreateOnPremGateway" {
        if (-not $GatewayId) {
            Write-Error "GatewayId is required for CreateOnPremGateway action."
            exit 1
        }
        New-OnPremGatewayConnection `
            -Token $accessToken `
            -GatewayId $GatewayId `
            -DisplayName $DisplayName `
            -ServerName $ServerName `
            -DatabaseName $DatabaseName `
            -SpnClientId $DataSourceSpnClientId `
            -SpnTenantId $DataSourceSpnTenantId `
            -KeyVaultConnectionId $KeyVaultConnectionId `
            -KeyVaultSecretName $KeyVaultSecretName `
            -KeyVaultSecretVersion $KeyVaultSecretVersion `
            -SkipTestConnection $SkipTestConnection
    }

    "UpdateOnPremGateway" {
        if (-not $ConnectionId -or -not $GatewayId) {
            Write-Error "Both ConnectionId and GatewayId are required for UpdateOnPremGateway."
            exit 1
        }
        Update-OnPremGatewayConnectionSpnSecret `
            -Token $accessToken `
            -ConnectionId $ConnectionId `
            -GatewayId $GatewayId `
            -SpnClientId $DataSourceSpnClientId `
            -SpnTenantId $DataSourceSpnTenantId `
            -KeyVaultConnectionId $KeyVaultConnectionId `
            -KeyVaultSecretName $KeyVaultSecretName `
            -KeyVaultSecretVersion $KeyVaultSecretVersion `
            -SkipTestConnection $SkipTestConnection
    }
}

Write-Host "`nDone."
