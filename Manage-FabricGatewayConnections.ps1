<#
.SYNOPSIS
    Manage Fabric API on-premises gateway connections with Service Principal credentials.

.DESCRIPTION
    This script is designed to run in Azure DevOps Pipelines (or any CI/CD system).
    It supports OnPremisesGateway connections only, where credentials are:
      1. Fetched from Azure Key Vault via the ADO variable group at runtime
      2. RSA-OAEP encrypted using the gateway's public key (fetched from Power BI API)
      3. Sent as an encrypted blob to the Fabric API

    The actual secret value is never logged — it is encrypted before being sent.

.NOTES
    Prerequisites:
      1. An Azure AD (Entra ID) App Registration with a client secret.
      2. Fabric tenant setting "Service principals can use Fabric APIs" enabled
         for a security group that contains your SPN.
      3. The SPN must have permissions on the gateway.
      4. For Azure DevOps: store TenantId, ClientId, ClientSecret, and
         DataSourceSpnSecret as secret pipeline variables (linked to Key Vault).

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

    # --- Connection target (the data-source SPN) ------------------------------
    [Parameter(Mandatory = $true)]
    [string]$DataSourceSpnClientId,   # Client ID of the SPN used BY the connection

    [Parameter(Mandatory = $true)]
    [string]$DataSourceSpnTenantId,   # Tenant ID of the SPN used BY the connection

    [Parameter(Mandatory = $true)]
    [string]$DataSourceSpnSecret,     # Secret for the data-source SPN (fetched from Key Vault, encrypted before use)

    # --- Connection details ---------------------------------------------------
    [string]$ConnectionId,            # Existing connection ID (for UPDATE scenario)
    [string]$GatewayId,               # Gateway ID (required for on-prem scenarios)
    [string]$DisplayName = "Automated-SPN-Connection",
    [string]$ServerName,
    [string]$DatabaseName,

    # --- Behaviour flags ------------------------------------------------------
    [ValidateSet("CreateOnPremGateway", "UpdateOnPremGateway")]
    [string]$Action = "UpdateOnPremGateway",

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
        Encrypts service principal credentials using the gateway's RSA public key
        via .NET RSACryptoServiceProvider (RSA-OAEP padding).
    #>
    param(
        [object]$GatewayPublicKey,
        [string]$SpnClientId,
        [string]$SpnTenantId,
        [string]$SpnSecret
    )

    # Build the credential JSON payload that the gateway expects.
    # For ServicePrincipal type, the credentialData contains:
    #   servicePrincipalClientId, servicePrincipalKey, servicePrincipalTenantId
    $credentialData = @{
        credentialData = @(
            @{ name = "servicePrincipalClientId"; value = $SpnClientId }
            @{ name = "servicePrincipalKey";      value = $SpnSecret   }
            @{ name = "servicePrincipalTenantId"; value = $SpnTenantId }
        )
    } | ConvertTo-Json -Depth 3 -Compress

    # RSA-OAEP encryption using .NET
    $exponentBytes = [Convert]::FromBase64String($GatewayPublicKey.exponent)
    $modulusBytes  = [Convert]::FromBase64String($GatewayPublicKey.modulus)

    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
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
        [string]$SpnSecret,
        [bool]  $SkipTestConnection = $false
    )

    # Step 1: get gateway public key
    $publicKey = Get-GatewayPublicKey -Token $Token -GatewayId $GatewayId

    # Step 2: encrypt credentials
    $encryptedCreds = Get-EncryptedCredentials `
        -GatewayPublicKey $publicKey `
        -SpnClientId $SpnClientId `
        -SpnTenantId $SpnTenantId `
        -SpnSecret $SpnSecret

    # Step 3: call Create Connection
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
                credentialType = "ServicePrincipal"
                values         = @(
                    @{
                        gatewayId            = $GatewayId
                        encryptedCredentials = $encryptedCreds
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 6

    Write-Host "Creating OnPremisesGateway connection '$DisplayName' ..."
    try {
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method POST -Body $body
        Write-Host "  -> Created successfully. Connection ID: $($result.id)"
        return $result
    }
    catch {
        Write-Error "Failed to create on-prem gateway connection: $_"
        if ($_.ErrorDetails.Message) {
            Write-Error "API response: $($_.ErrorDetails.Message)"
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
        [string]$SpnSecret,
        [bool]  $SkipTestConnection = $false
    )

    # Step 1: get gateway public key
    $publicKey = Get-GatewayPublicKey -Token $Token -GatewayId $GatewayId

    # Step 2: encrypt new credentials
    $encryptedCreds = Get-EncryptedCredentials `
        -GatewayPublicKey $publicKey `
        -SpnClientId $SpnClientId `
        -SpnTenantId $SpnTenantId `
        -SpnSecret $SpnSecret

    # Step 3: call Update Connection (PATCH)
    $uri = "https://api.fabric.microsoft.com/v1/connections/$ConnectionId"
    $headers = Get-FabricHeaders -Token $Token

    $body = @{
        connectivityType  = "OnPremisesGateway"
        credentialDetails = @{
            skipTestConnection = $SkipTestConnection
            credentials        = @{
                credentialType = "ServicePrincipal"
                values         = @(
                    @{
                        gatewayId            = $GatewayId
                        encryptedCredentials = $encryptedCreds
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 5

    Write-Host "Updating on-prem gateway connection '$ConnectionId' with new SPN secret ..."
    try {
        $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method PATCH -Body $body
        Write-Host "  -> Updated successfully."
        return $result
    }
    catch {
        Write-Error "Failed to update on-prem gateway connection: $_"
        if ($_.ErrorDetails.Message) {
            Write-Error "API response: $($_.ErrorDetails.Message)"
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
        if (-not $ServerName -or -not $DatabaseName) {
            Write-Error "ServerName and DatabaseName are required for CreateOnPremGateway."
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
            -SpnSecret $DataSourceSpnSecret `
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
            -SpnSecret $DataSourceSpnSecret `
            -SkipTestConnection $SkipTestConnection
    }
}

Write-Host "`nDone."
