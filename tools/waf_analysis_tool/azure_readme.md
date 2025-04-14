# Azure WAF Integration

> ⚠️ **ALPHA STAGE NOTICE** ⚠️
> 
> This integration is currently in alpha stage and untested in production environments.  
> Features, API endpoints, and documentation may change without notice.  
> Use with caution and not recommended for production deployments at this time.

## Azure Service Principal Requirements

### Creating Service Principal
1. Log in to Azure Portal (https://portal.azure.com)
2. Navigate to "Azure Active Directory" > "App Registrations"
3. Click "New registration" and provide a name (e.g., "CyberAgents-WAF-Tool")
4. Set the appropriate redirect URI (can be set to Web and any URL for API-only access)
5. After creation, generate a client secret in "Certificates & secrets" section
6. Note the Application (client) ID, Directory (tenant) ID, and Secret value

### Required Role Assignments
Assign the following RBAC roles to your service principal:

- **Reader** role at the subscription level (minimal access)
- **Web Application Firewall Reader** on WAF policy resources
- **Network Reader** to access Application Gateway resources

## Azure Resource Provider Operations

The tool interacts with these Azure resource providers:

1. **Microsoft.Network** - For Application Gateway and Front Door resources
2. **Microsoft.Cdn** - For Azure CDN WAF profiles  

### Application Gateway WAF API Operations

| API Operation | Method & Path | Purpose |
|---------------|--------------|---------|
| List App Gateways | `GET /subscriptions/{subId}/providers/Microsoft.Network/applicationGateways` | List all application gateways |
| Get App Gateway | `GET /subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Network/applicationGateways/{name}` | Get gateway details |
| List WAF Policies | `GET /subscriptions/{subId}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies` | List all WAF policies |
| Get WAF Policy | `GET /subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/{name}` | Get policy details |

### Front Door WAF API Operations

| API Operation | Method & Path | Purpose |
|---------------|--------------|---------|
| List Front Doors | `GET /subscriptions/{subId}/providers/Microsoft.Network/frontDoors` | List all front doors |
| Get Front Door | `GET /subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Network/frontDoors/{name}` | Get front door details |
| List FD WAF Policies | `GET /subscriptions/{subId}/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies` | List WAF policies |
| Get FD WAF Policy | `GET /subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/{name}` | Get policy details |

## Authentication Flow

Azure authentication is performed using the Microsoft Authentication Library (MSAL):

1. Application credentials (client ID, tenant ID, client secret) are used
2. OAuth 2.0 client credentials flow is implemented
3. Access tokens are requested with scope `https://management.azure.com/.default`
4. Tokens are cached and refreshed as needed

## IAM Security Best Practices

1. **Managed Identities**: For cloud-hosted tools, prefer managed identities over service principals
2. **Scoped Access**: Limit access to specific resource groups when possible
3. **Secret Rotation**: Rotate client secrets every 90 days
4. **Conditional Access**: Consider implementing conditional access policies
5. **Secret Management**: Store secrets in Azure Key Vault rather than environment variables
6. **Minimal Permissions**: Use custom roles with minimal permissions when standard roles are too broad

## Limitations

- API rate limits: 12,000 requests per hour (subscription level)
- Resource quotas may limit the number of WAF policies per subscription (check current limits)
- Policy changes can take 5-7 minutes to propagate

## Example Response

```json
{
  "value": [
    {
      "name": "MyAppGatewayWAF",
      "id": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/MyResourceGroup/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/MyAppGatewayWAF",
      "type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
      "properties": {
        "policySettings": {
          "mode": "Prevention",
          "state": "Enabled",
          "requestBodyCheck": true
        },
        "customRules": [],
        "managedRules": {
          "managedRuleSets": [
            {
              "ruleSetType": "OWASP",
              "ruleSetVersion": "3.1"
            }
          ]
        }
      }
    }
  ]
}
``` 