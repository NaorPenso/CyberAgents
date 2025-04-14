# Imperva WAF Integration

> ⚠️ **ALPHA STAGE NOTICE** ⚠️
> 
> This integration is currently in alpha stage and untested in production environments.  
> Features, API endpoints, and documentation may change without notice.  
> Use with caution and not recommended for production deployments at this time.

## API Access Requirements

### API Key Generation
1. Log in to Imperva Cloud WAF Portal (https://my.imperva.com)
2. Navigate to "Account Settings" > "API"
3. Click "Add API ID" to create a new API key
4. Name the key (e.g., "CyberAgents-WAF-Tool")
5. Copy the generated API key securely

### Required Permissions
The API key needs the following permissions:

- **Sites: Read** - To view protected sites information
- **Security Rules: Read** - To view WAF rules configuration
- **Security Events: Read** - To retrieve attack information
- **Account: Read** - To get account-level information

## API Operations Used

| Operation | Endpoint | Purpose |
|-----------|----------|---------|
| List Sites | `GET /api/prov/v1/sites` | Retrieve all protected assets |
| Site Details | `GET /api/prov/v1/sites/{site_id}` | Get specific site configuration |
| Security Rules | `GET /api/prov/v1/sites/{site_id}/security` | Get security rule configurations |
| WAF Statistics | `GET /api/prov/v1/sites/{site_id}/waf/statistics` | Retrieve attack statistics |
| Events | `GET /api/prov/v1/sites/{site_id}/logs/attack` | Get attack log events |

## IAM Best Practices

1. **Least Privilege**: Create a dedicated API key with only read permissions
2. **API Key Rotation**: Rotate the key every 90 days
3. **IP Restrictions**: Restrict API key usage to specific IP addresses where possible
4. **Audit Logging**: Enable audit logging for all API operations

## Limitations

- Rate limiting: 100 requests per minute
- Some operations may take longer to complete for sites with extensive protection
- Events retrieval is limited to a maximum of 1000 events per request

## Example Response

```json
{
  "sites": [
    {
      "site_id": "123456",
      "domain": "example.com",
      "status": "active",
      "waf_enabled": true,
      "account_id": "7890",
      "created_at": "2023-01-15T12:00:00Z"
    }
  ]
}
``` 