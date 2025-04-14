# Cloudflare WAF Integration

> ⚠️ **ALPHA STAGE NOTICE** ⚠️
> 
> This integration is currently in alpha stage and untested in production environments.  
> Features, API endpoints, and documentation may change without notice.  
> Use with caution and not recommended for production deployments at this time.

## API Access Requirements

### API Key Generation
1. Log in to Cloudflare Dashboard (https://dash.cloudflare.com)
2. Navigate to "My Profile" > "API Tokens"
3. Click "Create Token" or use "Global API Key" (less recommended)
4. For custom token, use the template "Read All Resources" or create custom permissions
5. Store the generated token securely

### Required Permissions
When creating a custom API token, ensure it has these permissions:

- **Zone:WAF:Read** - Read WAF rules and configurations
- **Zone:Read** - Read zone information
- **Account:Firewall Services:Read** - Read firewall configurations
- **Analytics:Read** - Access analytics data

## API Operations Used

| Operation | Endpoint | Purpose |
|-----------|----------|---------|
| List Zones | `GET /zones` | Retrieve all protected domains |
| WAF Packages | `GET /zones/{zone_id}/firewall/waf/packages` | Get WAF packages info |
| WAF Rules | `GET /zones/{zone_id}/firewall/waf/packages/{package_id}/rules` | List WAF rules |
| Firewall Rules | `GET /zones/{zone_id}/firewall/rules` | Get firewall rules |
| Security Events | `GET /zones/{zone_id}/security/events` | Retrieve security events |

## Authentication Methods

Two methods are supported:

1. **API Token** (preferred):
   - Header format: `Authorization: Bearer {token}`
   - Scope-limited tokens with restricted permissions

2. **API Key**:
   - Headers required:
     - `X-Auth-Email: {email}`
     - `X-Auth-Key: {key}`
   - Has account-wide permissions (use with caution)

## IAM Best Practices

1. **Use API Tokens**: Prefer tokens over global API keys
2. **Limit by IP**: Restrict token usage to specific IP addresses
3. **TTL Settings**: Set appropriate Time-To-Live for tokens (e.g., 90 days)
4. **Audit Usage**: Regularly audit token usage via Cloudflare logs
5. **Rotate Credentials**: Rotate tokens on a regular schedule

## Limitations

- Rate limits vary by plan (Enterprise: 1,700 req/min, Pro: 1,000 req/min)
- Maximum of 100 results per page for most list operations
- Security event data retention depends on plan level

## Example Response

```json
{
  "success": true,
  "result": [
    {
      "id": "waf_package_id",
      "name": "OWASP ModSecurity Core Rule Set",
      "description": "Core rule set for WAF",
      "detection_mode": "traditional",
      "zone_id": "zone123"
    }
  ],
  "errors": [],
  "messages": []
}
``` 