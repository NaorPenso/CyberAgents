# AWS WAF Integration

> ⚠️ **ALPHA STAGE NOTICE** ⚠️
> 
> This integration is currently in alpha stage and untested in production environments.  
> Features, API endpoints, and documentation may change without notice.  
> Use with caution and not recommended for production deployments at this time.

## IAM Access Requirements

### IAM User/Role Setup
1. Access AWS IAM Console (https://console.aws.amazon.com/iam/)
2. Create a dedicated IAM user or role for the WAF Analysis Tool
3. Attach the appropriate IAM policies or create a custom policy
4. Generate access key and secret key (for IAM user) 
5. Store credentials securely in the .env file

### Required IAM Permissions
The IAM user or role requires these specific permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "wafv2:Get*",
                "wafv2:List*",
                "cloudfront:DescribeDistribution",
                "cloudfront:ListDistributions",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeListeners",
                "apigateway:GET"
            ],
            "Resource": "*"
        }
    ]
}
```

This policy allows read-only access to WAF configurations and associated resources.

## AWS API Operations Used

| Service | API Operation | Purpose |
|---------|--------------|---------|
| WAFv2 | `ListWebACLs` | List all Web ACLs in the account |
| WAFv2 | `GetWebACL` | Get detailed configuration of a Web ACL |
| WAFv2 | `ListRuleGroups` | List all rule groups |
| WAFv2 | `GetRuleGroup` | Get detailed configuration of a rule group |
| WAFv2 | `ListIPSets` | List IP sets used in rules |
| WAFv2 | `ListLoggingConfigurations` | Get logging configurations |
| CloudFront | `ListDistributions` | List CloudFront distributions that may use WAF |
| ELB | `DescribeLoadBalancers` | List load balancers that may use WAF |
| API Gateway | `GetRestApis` | List API Gateway APIs that may use WAF |

## IAM Best Practices

1. **Least Privilege**: Use only the required permissions listed above
2. **Use IAM Roles**: For EC2 or Lambda integrations, use IAM roles instead of access keys
3. **Temporary Credentials**: Consider using STS for temporary credential generation
4. **Access Key Rotation**: Rotate access keys every 90 days
5. **Multi-Factor Authentication**: Enable MFA for the IAM user
6. **VPC Endpoints**: Consider using VPC endpoints for WAF API calls where applicable

## Cross-Region Considerations

AWS WAF operates differently across regions:
- CloudFront integrations use global WAF resources
- Regional resources (ALB, API Gateway) use regional WAF resources
- The tool must query both global (`us-east-1`) and configured regional endpoints

## Limitations

- API throttling limits: 
  - Read operations: 100 requests per second
  - Write operations: Not applicable (read-only access)
- Maximum 100 Web ACLs per region per account
- Rate-based rule limits vary by account

## Example Response (ListWebACLs)

```json
{
  "WebACLs": [
    {
      "Name": "MyWebACL",
      "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
      "ARN": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/MyWebACL/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
      "Description": "Web ACL for main website protection"
    }
  ]
}
``` 