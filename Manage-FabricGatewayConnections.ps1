#Requires -Version 7

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
    [string]$ClientSecret,        # Client secret used to AUTHENTICATE to Fabric

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
function Get-AccessToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$Scope
    )

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $Scope
        grant_type    = "client_credentials"
    }

    try {
        $response = Invoke-FabricRestMethod -Uri $tokenUrl -Method POST -Body $body `
                        -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Error "Failed to obtain access token for scope '$Scope': $_"
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
#  SECTION 3 — HTTP wrapper: retries on HTTP 429 with Retry-After back-off
# ============================================================================
function Invoke-FabricRestMethod {
    <#
    .SYNOPSIS
        Thin wrapper around Invoke-RestMethod that retries up to MaxRetries times
        when the server responds with HTTP 429, honouring the Retry-After header.
    #>
    param(
        [string]   $Uri,
        [string]   $Method,
        [hashtable]$Headers,
        [object]   $Body,
        [string]   $ContentType,
        [int]      $MaxRetries = 3
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{ Uri = $Uri; Method = $Method }
            if ($Headers)     { $params['Headers']     = $Headers     }
            if ($Body)        { $params['Body']        = $Body        }
            if ($ContentType) { $params['ContentType'] = $ContentType }

            return Invoke-RestMethod @params
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -eq 429 -and $attempt -le $MaxRetries) {
                $retryAfter = 5   # fallback wait in seconds
                $responseHeaders = $_.Exception.Response.Headers
                if ($responseHeaders -and $responseHeaders.Contains('Retry-After')) {
                    $headerValue = $responseHeaders.GetValues('Retry-After') | Select-Object -First 1
                    $parsed = 0
                    if ([int]::TryParse($headerValue, [ref]$parsed) -and $parsed -gt 0) {
                        $retryAfter = $parsed
                    }
                }
                Write-Warning "HTTP 429 — rate limited. Retrying in $retryAfter second(s) (attempt $attempt of $MaxRetries) ..."
                Start-Sleep -Seconds $retryAfter
            }
            else {
                throw
            }
        }
    }
}

# ============================================================================
#  SECTION 4 — List existing connections (useful for discovery)
# ============================================================================
function Get-FabricConnections {
    param([string]$Token)

    $uri     = "https://api.fabric.microsoft.com/v1/connections"
    $headers = Get-FabricHeaders -Token $Token

    try {
        $result = Invoke-FabricRestMethod -Uri $uri -Headers $headers -Method GET
        return $result.value
    }
    catch {
        Write-Error "Failed to list connections: $_"
        throw
    }
}

# ============================================================================
#  SECTION 5 — ON-PREMISES GATEWAY: encrypt credentials with gateway public key
#
#  For on-prem gateway connections, the Fabric API requires credentials to be
#  RSA-OAEP encrypted using the gateway member's public key.
#  This section uses .NET's RSACryptoServiceProvider directly — no NuGet needed.
# ============================================================================
function Get-GatewayPublicKey {
    <#
    .SYNOPSIS
        Retrieves the public key of a gateway, needed to encrypt credentials.
        Uses the Power BI REST API, which requires a Power BI-scoped token
        (https://analysis.windows.net/powerbi/api/.default).
    #>
    param(
        [string]$PowerBiToken,
        [string]$GatewayId
    )

    $uri     = "https://api.powerbi.com/v1.0/myorg/gateways/$GatewayId"
    $headers = Get-FabricHeaders -Token $PowerBiToken

    try {
        $gateway = Invoke-FabricRestMethod -Uri $uri -Headers $headers -Method GET
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
        Encrypts service principal credentials using hybrid encryption matching the
        Microsoft Power BI SDK (AsymmetricHigherKeyEncryptionHelper).

    .DESCRIPTION
        Direct RSA encryption of the credential JSON fails because the payload
        (~275 bytes) exceeds the RSA-OAEP limit of a 2048-bit gateway key (190 bytes
        with SHA-256, 214 bytes with SHA-1).  The gateway expects hybrid encryption:

          1. Generate ephemeral AES-256 key (32 bytes) + HMAC-SHA256 key (64 bytes)
          2. Encrypt the credential JSON with AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)
          3. RSA-OAEP-SHA1 encrypt only the 98-byte key bundle — well within the limit
          4. Return base64(RSA-encrypted keys) + base64(AES ciphertext blob)

        Output format mirrors AsymmetricHigherKeyEncryptionHelper.cs in PowerBI-CSharp.
    #>
    param(
        [object]$GatewayPublicKey,
        [string]$SpnClientId,
        [string]$SpnTenantId,
        [string]$SpnSecret
    )

    # Build the credential JSON payload the gateway expects.
    $credentialData = @{
        credentialData = @(
            @{ name = "servicePrincipalClientId"; value = $SpnClientId }
            @{ name = "servicePrincipalKey";      value = $SpnSecret   }
            @{ name = "servicePrincipalTenantId"; value = $SpnTenantId }
        )
    } | ConvertTo-Json -Depth 3 -Compress

    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($credentialData)

    # --- Step 1: Generate ephemeral keys ---
    $rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $keyEnc = New-Object byte[] 32   # AES-256 key
    $keyMac = New-Object byte[] 64   # HMAC-SHA256 key
    $rng.GetBytes($keyEnc)
    $rng.GetBytes($keyMac)

    # --- Step 2: AES-256-CBC encrypt, then HMAC-SHA256 authenticate ---
    $aes         = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key     = $keyEnc
    $aes.GenerateIV()
    $iv         = $aes.IV
    $encryptor  = $aes.CreateEncryptor()
    $ciphertext = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    # Algorithm identifier bytes: AES256CbcPkcs7=0, HMACSHA256=0  (matches SDK enums)
    $algoBytes  = [byte[]](0, 0)
    $hmac       = New-Object System.Security.Cryptography.HMACSHA256 @(,$keyMac)
    $tag        = $hmac.ComputeHash($algoBytes + $iv + $ciphertext)

    # Ciphertext blob: algoBytes(2) + tag(32) + IV(16) + ciphertext(N)
    $ciphertextBlob = $algoBytes + $tag + $iv + $ciphertext

    # --- Step 3: Package ephemeral keys ---
    # keys[0] = KeyLengths.KeyLength32 (enum value 0)
    # keys[1] = KeyLengths.KeyLength64 (enum value 1)
    # keys[2..33]  = AES key  (32 bytes)
    # keys[34..97] = HMAC key (64 bytes)
    $keys    = New-Object byte[] 98
    $keys[0] = 0
    $keys[1] = 1
    [Array]::Copy($keyEnc, 0, $keys, 2,  32)
    [Array]::Copy($keyMac, 0, $keys, 34, 64)

    # --- Step 4: RSA-OAEP-SHA1 encrypt the 98-byte key bundle ---
    # OaepSHA1 allows up to 214 bytes with a 2048-bit key (vs 190 for OaepSHA256)
    # and matches the padding the gateway backend expects.
    $exponentBytes      = [Convert]::FromBase64String($GatewayPublicKey.exponent)
    $modulusBytes       = [Convert]::FromBase64String($GatewayPublicKey.modulus)
    $rsaParams          = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Exponent = $exponentBytes
    $rsaParams.Modulus  = $modulusBytes
    $rsa                = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportParameters($rsaParams)
    $encryptedKeys      = $rsa.Encrypt($keys, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)

    # --- Step 5: Concatenate both base64 blobs (matches SDK output format) ---
    return [Convert]::ToBase64String($encryptedKeys) + [Convert]::ToBase64String($ciphertextBlob)
}

function New-OnPremGatewayConnection {
    param(
        [string]$FabricToken,
        [string]$PowerBiToken,
        [string]$GatewayId,
        [string]$DisplayName,
        [string]$ServerName,
        [string]$DatabaseName,
        [string]$SpnClientId,
        [string]$SpnTenantId,
        [string]$SpnSecret,
        [bool]  $SkipTestConnection = $false
    )

    # Step 1: get gateway public key (Power BI API — needs Power BI-scoped token)
    $publicKey = Get-GatewayPublicKey -PowerBiToken $PowerBiToken -GatewayId $GatewayId

    # Step 2: encrypt credentials
    $encryptedCreds = Get-EncryptedCredentials `
        -GatewayPublicKey $publicKey `
        -SpnClientId $SpnClientId `
        -SpnTenantId $SpnTenantId `
        -SpnSecret $SpnSecret

    # Step 3: call Create Connection (Fabric API — needs Fabric-scoped token)
    $uri     = "https://api.fabric.microsoft.com/v1/connections"
    $headers = Get-FabricHeaders -Token $FabricToken

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
        $result = Invoke-FabricRestMethod -Uri $uri -Headers $headers -Method POST -Body $body -ContentType "application/json"
        Write-Host "  -> Created successfully. Connection ID: $($result.id)"
        return $result
    }
    catch {
        Write-Error "Failed to create on-prem gateway connection: $_"
        # FIX 2: Use ErrorDetails.Message — PS7 closes the response stream on error
        if ($_.ErrorDetails.Message) {
            Write-Error "API response: $($_.ErrorDetails.Message)"
        }
        throw
    }
}

function Update-OnPremGatewayConnectionSpnSecret {
    param(
        [string]$FabricToken,
        [string]$PowerBiToken,
        [string]$ConnectionId,
        [string]$GatewayId,
        [string]$SpnClientId,
        [string]$SpnTenantId,
        [string]$SpnSecret,
        [bool]  $SkipTestConnection = $false
    )

    # Step 1: get gateway public key (Power BI API — needs Power BI-scoped token)
    $publicKey = Get-GatewayPublicKey -PowerBiToken $PowerBiToken -GatewayId $GatewayId

    # Step 2: encrypt new credentials
    $encryptedCreds = Get-EncryptedCredentials `
        -GatewayPublicKey $publicKey `
        -SpnClientId $SpnClientId `
        -SpnTenantId $SpnTenantId `
        -SpnSecret $SpnSecret

    # Step 3: call Update Connection (PATCH — Fabric API — needs Fabric-scoped token)
    $uri     = "https://api.fabric.microsoft.com/v1/connections/$ConnectionId"
    $headers = Get-FabricHeaders -Token $FabricToken

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
        $result = Invoke-FabricRestMethod -Uri $uri -Headers $headers -Method PATCH -Body $body
        Write-Host "  -> Updated successfully."
        return $result
    }
    catch {
        Write-Error "Failed to update on-prem gateway connection: $_"
        # FIX 2: Use ErrorDetails.Message — PS7 closes the response stream on error
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

# Step 1: Authenticate — acquire one token per API surface
Write-Host "[1/3] Authenticating as service principal ..."
$fabricToken = Get-AccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
                   -Scope "https://api.fabric.microsoft.com/.default"
$powerBiToken = Get-AccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
                   -Scope "https://analysis.windows.net/powerbi/api/.default"
Write-Host "  -> Tokens acquired (Fabric + Power BI).`n"

# Step 2: List existing connections for reference
Write-Host "[2/3] Listing existing connections ..."
try {
    $connections = Get-FabricConnections -Token $fabricToken
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
            Write-Error "GatewayId is required for CreateOnPremGateway."
            exit 1
        }
        if (-not $ServerName -or -not $DatabaseName) {
            Write-Error "ServerName and DatabaseName are required for CreateOnPremGateway."
            exit 1
        }
        New-OnPremGatewayConnection `
            -FabricToken $fabricToken `
            -PowerBiToken $powerBiToken `
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
            -FabricToken $fabricToken `
            -PowerBiToken $powerBiToken `
            -ConnectionId $ConnectionId `
            -GatewayId $GatewayId `
            -SpnClientId $DataSourceSpnClientId `
            -SpnTenantId $DataSourceSpnTenantId `
            -SpnSecret $DataSourceSpnSecret `
            -SkipTestConnection $SkipTestConnection
    }
}

Write-Host "`nDone."