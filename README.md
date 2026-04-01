# Fabric On-Premises Gateway Connection Manager

Automates the creation and SPN secret rotation of Microsoft Fabric **on-premises data gateway** connections via Azure DevOps pipelines. Eliminates manual updates in the Power BI / Fabric portal and ensures connections never break due to expired secrets.

---

## Why this exists

Fabric connections that use a Service Principal (SPN) for authentication store the SPN secret inside the connection object. When that secret expires in Azure Entra ID, every data refresh using that connection fails — silently, until someone notices broken reports.

Updating the secret manually through the Fabric portal is not sustainable across multiple connections. The portal also handles a non-obvious encryption step behind the scenes: for on-premises gateway connections, credentials must be **RSA-OAEP encrypted** with the gateway's public key before the Fabric API will accept them. This script replicates that encryption so the entire process can run unattended.

---

## Repository structure

```
Fabric-connection/
├── Manage-FabricGatewayConnections.ps1   # PowerShell script — core logic
├── azure-pipelines-rotate-spn-secret.yml # ADO pipeline definition
└── README.md
```

---

## How it works

Two SPNs are involved — do not confuse them:

| SPN | Role | Where it appears |
|---|---|---|
| **Automation SPN** | Authenticates the pipeline to the Fabric API | `FabricSpnClientId` / `FabricSpnClientSecret` |
| **Data-source SPN** | Credential stored inside the Fabric connection | `DataSourceSpnClientId` / `DataSourceSpnSecret` |

The automation SPN is the robot running the pipeline. The data-source SPN is the identity whose secret is expiring and needs rotating.

### Flow

```
ADO schedule / manual trigger
        │
        ▼
1. Automation SPN authenticates to Entra ID → bearer token
        │
        ▼
2. Fetch gateway RSA public key from Power BI API
   (Fabric API does not expose this — Power BI API does)
        │
        ▼
3. Build credential JSON payload:
   { servicePrincipalClientId, servicePrincipalKey, servicePrincipalTenantId }
   Encrypt with gateway public key using RSA-OAEP (.NET RSACryptoServiceProvider)
        │
        ▼
4a. CREATE  →  POST  /v1/connections          (new connection)
4b. UPDATE  →  PATCH /v1/connections/{id}     (rotate existing secret)
```

The plaintext secret is fetched from Key Vault at runtime via the ADO variable group, encrypted immediately, and never logged.

---

## Prerequisites

### 1. Azure Entra ID

- An App Registration for the **automation SPN** with a client secret.
- An App Registration for the **data-source SPN** (the one connecting to your data source).

### 2. Azure Key Vault

Create the following secrets in your Key Vault:

| Secret name | Value |
|---|---|
| `FabricSpnTenantId` | Tenant ID of the automation SPN |
| `FabricSpnClientId` | Client ID of the automation SPN |
| `FabricSpnClientSecret` | Client secret of the automation SPN |
| `DataSourceSpnClientId` | Client ID of the data-source SPN |
| `DataSourceSpnTenantId` | Tenant ID of the data-source SPN |
| `DataSourceSpnNewSecret` | Current valid secret of the data-source SPN |

### 3. Azure DevOps

- A **Variable Group** named `FabricSecrets` linked to the Key Vault above.
- An **Azure Resource Manager service connection** with read access to the Key Vault subscription.
- Update `"MyAzureServiceConnection"` in the pipeline YAML with your actual service connection name.

### 4. Microsoft Fabric

- Fabric admin setting **"Service principals can use Fabric APIs"** must be enabled for a security group that contains the automation SPN. Set this in the Fabric Admin portal under Developer settings.

### 5. On-premises data gateway

- The automation SPN must be a **gateway admin**. Set this in the Power BI portal under the gateway settings. Without this the pipeline cannot fetch the gateway public key and will fail with a 403.

---

## Pipeline parameters

| Parameter | Required for | Description |
|---|---|---|
| `action` | Both | `CreateOnPremGateway` or `UpdateOnPremGateway` |
| `gatewayId` | Both | Object ID of the on-premises gateway (from Power BI portal → gateway settings) |
| `connectionId` | Update only | ID of the existing Fabric connection to update |
| `serverName` | Create only | SQL server hostname e.g. `myserver.database.windows.net` |
| `databaseName` | Create only | Database name |
| `displayName` | Create only | Display name for the new connection in Fabric |
| `skipTestConnection` | Optional | Skip the connectivity test after create/update. Useful if the secret has not fully propagated yet. Default: `false` |

---

## Usage

### First run — create a new connection

Run the pipeline manually with:

```
action        = CreateOnPremGateway
gatewayId     = <your gateway object ID>
serverName    = <your SQL server>
databaseName  = <your database>
displayName   = <name for the connection in Fabric>
```

On success the pipeline log prints:

```
-> Created successfully. Connection ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**Save this connection ID.** Every rotation run needs it as the `connectionId` parameter. Store it in Key Vault, an ADO pipeline variable, or a config file in your repo.

### Subsequent runs — rotate the secret

The pipeline runs automatically every Monday at 06:00 UTC. To run manually:

```
action        = UpdateOnPremGateway
gatewayId     = <same gateway ID>
connectionId  = <ID saved from the create run>
```

> **Important:** Update `DataSourceSpnNewSecret` in Key Vault with the new secret value **before** running the pipeline. The pipeline reads it at runtime — Key Vault must already have the new value.

### Rotating multiple connections

Run the pipeline once per connection, passing a different `connectionId` each time. To fully automate this, extend the script to accept a comma-separated list of connection IDs and loop through them.

---

## Security notes

- **No plaintext secrets in pipeline logs.** All secrets are injected as masked variables from the Key Vault-linked variable group.
- **No NuGet dependencies.** Encryption uses `System.Security.Cryptography.RSACryptoServiceProvider` from the .NET runtime — always available on `windows-latest` ADO agents, no install step required.
- **The automation SPN should have minimum permissions.** It needs gateway admin rights and the Fabric API SPN setting enabled — nothing broader.
- **The data-source SPN secret is encrypted before it leaves the pipeline.** The Fabric API never receives the plaintext value — only the RSA-OAEP encrypted blob, which only the gateway can decrypt.

---

## Troubleshooting

| Error | Likely cause | Fix |
|---|---|---|
| `403` on gateway public key fetch | Automation SPN is not a gateway admin | Add SPN as gateway admin in Power BI portal |
| `InvalidCredentialDetails` from Fabric API | Encryption payload malformed | Check that `servicePrincipalKey` field name is correct in the credential JSON |
| `IncorrectCredentials` from Fabric API | Wrong secret value in Key Vault | Verify `DataSourceSpnNewSecret` in Key Vault matches the current active secret in Entra ID |
| `Parameter cannot be found` on pipeline start | Script and pipeline parameter mismatch | Ensure `ScriptArguments` in the YAML matches the `param()` block in the script exactly |
| `Constructor not found` on RSAParameters | Old version of the script using `::new()` | Ensure you are using the fixed script with `New-Object System.Security.Cryptography.RSAParameters` |
| Pipeline passes but connection still fails at refresh | `skipTestConnection` was `true` and secret is wrong | Run with `skipTestConnection = false` to surface the real error |

---

## References

- [Fabric Connections API — Create Connection](https://learn.microsoft.com/en-us/rest/api/fabric/core/connections/create-connection)
- [Fabric Connections API — Update Connection](https://learn.microsoft.com/en-us/rest/api/fabric/core/connections/update-connection)
- [Configure credentials programmatically (Power BI)](https://learn.microsoft.com/en-us/power-bi/developer/embedded/configure-credentials)
- [Power BI Gateways API](https://learn.microsoft.com/en-us/rest/api/power-bi/gateways)
- [Service principals in Fabric](https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-developer#service-principals-can-create-workspaces-connections-and-deployment-pipelines)
