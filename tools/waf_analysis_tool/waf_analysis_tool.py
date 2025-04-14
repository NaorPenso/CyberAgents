"""WAF Analysis Tool for retrieving configuration and assets from WAF providers.

This tool connects to various Web Application Firewall providers (Imperva, Cloudflare,
AWS WAF, and Azure WAF) to retrieve configuration details and information about
protected assets.
"""

import logging
import os
from typing import Any, ClassVar, Dict, Optional

import boto3
import requests
from azure.identity import ClientSecretCredential
from azure.mgmt.frontdoor import FrontDoorManagementClient
from crewai.tools import BaseTool
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

# Set up logging
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


class WAFAnalysisInput(BaseModel):
    """Input model for the WAF Analysis Tool."""

    provider: str = Field(
        ...,
        description="WAF provider ('imperva', 'cloudflare', 'aws', 'azure')",
    )
    query_type: str = Field(
        ...,
        description="Info type ('configuration', 'assets', 'rules')",
    )
    resource_id: Optional[str] = Field(
        None, description="Specific resource ID to query (if applicable)"
    )

    model_config = ConfigDict(extra="forbid")


class WAFAnalysisTool(BaseTool):
    """Tool for analyzing web application firewall configurations and protected assets.

    This tool connects to various WAF providers (Imperva, Cloudflare, AWS, Azure)
    to retrieve configuration details and information about protected assets.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: ClassVar[str] = "waf_analysis_tool"
    description: str = (
        "Analyzes WAF configurations and protected assets from "
        "Imperva, Cloudflare, AWS, and Azure."
    )
    input_schema: ClassVar[type] = WAFAnalysisInput

    # API endpoints
    IMPERVA_API_URL: str = os.getenv(
        "IMPERVA_API_URL", "https://api.imperva.com/api/v1"
    )
    CLOUDFLARE_API_URL: str = os.getenv(
        "CLOUDFLARE_API_URL", "https://api.cloudflare.com/client/v4"
    )
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AZURE_API_VERSION: str = os.getenv("AZURE_API_VERSION", "2020-11-01")

    # Request timeout
    REQUEST_TIMEOUT: int = int(os.getenv("WAF_REQUEST_TIMEOUT", "30"))

    def _run(
        self, provider: str, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run WAF analysis synchronously.

        Args:
            provider: WAF provider to query ('imperva', 'cloudflare', 'aws', 'azure')
            query_type: Type of information to retrieve ('configuration', 'assets', 'rules')
            resource_id: Specific resource ID to query (if applicable)

        Returns:
            Dictionary containing requested WAF information or error message
        """
        provider = provider.lower()
        query_type = query_type.lower()

        # Validate provider
        if provider not in ["imperva", "cloudflare", "aws", "azure"]:
            return {
                "error": f"Unsupported provider: {provider}. "
                "Supported providers are: imperva, cloudflare, aws, azure"
            }

        # Validate query type
        if query_type not in ["configuration", "assets", "rules"]:
            return {
                "error": f"Unsupported query type: {query_type}. "
                "Supported query types are: configuration, assets, rules"
            }

        try:
            # Call provider-specific method
            if provider == "imperva":
                return self._get_imperva_data(query_type, resource_id)
            elif provider == "cloudflare":
                return self._get_cloudflare_data(query_type, resource_id)
            elif provider == "aws":
                return self._get_aws_data(query_type, resource_id)
            elif provider == "azure":
                return self._get_azure_data(query_type, resource_id)
            else:
                return {"error": f"Unsupported provider: {provider}"}
        except Exception as e:
            logger.exception(f"Error retrieving WAF data from {provider}: {e}")
            return {"error": f"Error retrieving WAF data: {str(e)}"}

    async def _arun(
        self, provider: str, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run WAF analysis asynchronously.

        This method is a wrapper around the synchronous method as the
        implementation is primarily synchronous.

        Args:
            provider: WAF provider to query ('imperva', 'cloudflare', 'aws', 'azure')
            query_type: Type of information to retrieve ('configuration', 'assets', 'rules')
            resource_id: Specific resource ID to query (if applicable)

        Returns:
            Dictionary containing requested WAF information or error message
        """
        return self._run(provider, query_type, resource_id)

    def _get_imperva_data(
        self, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get data from Imperva WAF.

        Args:
            query_type: Type of information to retrieve
            resource_id: Specific site ID to query (if applicable)

        Returns:
            Dictionary containing Imperva WAF data
        """
        api_key = os.getenv("IMPERVA_API_KEY")
        if not api_key:
            return {"error": "Imperva API key not found in environment variables"}

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        try:
            # Handle different query types
            if query_type == "assets":
                # Get list of protected sites
                endpoint = f"{self.IMPERVA_API_URL}/sites"
                response = requests.get(
                    endpoint, headers=headers, timeout=self.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                return {"assets": response.json()}

            elif query_type == "configuration":
                # Get site configuration
                if not resource_id:
                    return {"error": "Site ID is required for configuration queries"}

                endpoint = f"{self.IMPERVA_API_URL}/sites/{resource_id}"
                response = requests.get(
                    endpoint, headers=headers, timeout=self.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                return {"configuration": response.json()}

            elif query_type == "rules":
                # Get security rules
                if not resource_id:
                    return {"error": "Site ID is required for rules queries"}

                endpoint = f"{self.IMPERVA_API_URL}/sites/{resource_id}/security"
                response = requests.get(
                    endpoint, headers=headers, timeout=self.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                return {"rules": response.json()}

            else:
                return {"error": f"Unsupported query type: {query_type}"}

        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying Imperva API: {e}")
            return {"error": f"Error querying Imperva API: {str(e)}"}

    def _get_cloudflare_data(
        self, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get data from Cloudflare WAF.

        Args:
            query_type: Type of information to retrieve
            resource_id: Specific zone ID to query (if applicable)

        Returns:
            Dictionary containing Cloudflare WAF data
        """
        api_key = os.getenv("CLOUDFLARE_API_KEY")
        email = os.getenv("CLOUDFLARE_EMAIL")

        if not api_key:
            return {"error": "Cloudflare API key not found in environment variables"}

        if not email and "X-Auth-Email" in api_key:
            return {"error": "Cloudflare email not found in environment variables"}

        # Determine authentication method
        if api_key.startswith("Bearer "):
            # Token-based auth
            headers = {
                "Authorization": api_key,
                "Content-Type": "application/json",
            }
        else:
            # Key-based auth
            headers = {
                "X-Auth-Key": api_key,
                "X-Auth-Email": email,
                "Content-Type": "application/json",
            }

        try:
            # Handle different query types
            if query_type == "assets":
                # Get list of zones
                endpoint = f"{self.CLOUDFLARE_API_URL}/zones"
                response = requests.get(
                    endpoint, headers=headers, timeout=self.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                return {"assets": response.json()}

            elif query_type == "configuration":
                # Get zone details
                if not resource_id:
                    return {"error": "Zone ID is required for configuration queries"}

                endpoint = f"{self.CLOUDFLARE_API_URL}/zones/{resource_id}"
                response = requests.get(
                    endpoint, headers=headers, timeout=self.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                return {"configuration": response.json()}

            elif query_type == "rules":
                # Get WAF rules
                if not resource_id:
                    return {"error": "Zone ID is required for rules queries"}

                endpoint = (
                    f"{self.CLOUDFLARE_API_URL}/zones/"
                    f"{resource_id}/firewall/waf/packages"
                )
                response = requests.get(
                    endpoint, headers=headers, timeout=self.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                packages = response.json()

                # Get rules for each package
                rules = []
                for package in packages.get("result", []):
                    package_id = package.get("id")
                    rules_endpoint = (
                        f"{self.CLOUDFLARE_API_URL}/zones/{resource_id}/firewall/waf/"
                        f"packages/{package_id}/rules"
                    )
                    rules_response = requests.get(
                        rules_endpoint, headers=headers, timeout=self.REQUEST_TIMEOUT
                    )
                    rules_response.raise_for_status()
                    rules.append(
                        {
                            "package": package.get("name"),
                            "rules": rules_response.json().get("result", []),
                        }
                    )

                return {"rules": rules}

            else:
                return {"error": f"Unsupported query type: {query_type}"}

        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying Cloudflare API: {e}")
            return {"error": f"Error querying Cloudflare API: {str(e)}"}

    def _get_aws_data(
        self, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get data from AWS WAF.

        Args:
            query_type: Type of information to retrieve
            resource_id: Specific resource ID to query (if applicable)

        Returns:
            Dictionary containing AWS WAF data
        """
        aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")

        if not aws_access_key or not aws_secret_key:
            return {"error": "AWS credentials not found in environment variables"}

        try:
            # Initialize AWS WAF client
            wafv2_client = boto3.client(
                "wafv2",
                region_name=self.AWS_REGION,
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
            )

            # Handle different query types
            if query_type == "assets":
                # Get list of Web ACLs (both global and regional)
                global_acls = wafv2_client.list_web_acls(Scope="CLOUDFRONT")
                regional_acls = wafv2_client.list_web_acls(Scope="REGIONAL")

                # Get associated resources for each ACL
                assets = []
                for acl in global_acls.get("WebACLs", []) + regional_acls.get(
                    "WebACLs", []
                ):
                    acl_id = acl.get("Id")
                    acl_name = acl.get("Name")
                    acl_arn = acl.get("ARN")

                    # Determine scope from ARN
                    scope = "CLOUDFRONT" if ":global/webacl/" in acl_arn else "REGIONAL"

                    # Get resources for this ACL
                    resources = wafv2_client.list_resources_for_web_acl(
                        WebACLArn=acl_arn,
                        ResourceType="APPLICATION_LOAD_BALANCER",
                    )

                    assets.append(
                        {
                            "acl_id": acl_id,
                            "acl_name": acl_name,
                            "scope": scope,
                            "resources": resources.get("ResourceArns", []),
                        }
                    )

                return {"assets": assets}

            elif query_type == "configuration":
                # Get Web ACL configuration
                if not resource_id:
                    return {
                        "error": "Web ACL ID and scope required for configuration queries"
                    }

                # Parse resource_id to get ACL ID and scope
                if ":" in resource_id:
                    acl_id, scope = resource_id.split(":", 1)
                else:
                    acl_id = resource_id
                    scope = "REGIONAL"  # Default to regional

                # Get ACLs first to find the ARN
                acls = wafv2_client.list_web_acls(Scope=scope)
                acl_arn = None
                for acl in acls.get("WebACLs", []):
                    if acl.get("Id") == acl_id or acl.get("Name") == acl_id:
                        acl_arn = acl.get("ARN")
                        break

                if not acl_arn:
                    return {"error": f"Web ACL ID {acl_id} not found in scope {scope}"}

                # Get ACL configuration
                acl_config = wafv2_client.get_web_acl(
                    Name=acl.get("Name"), Scope=scope, Id=acl.get("Id")
                )

                return {"configuration": acl_config}

            elif query_type == "rules":
                # Get rule groups
                regional_rule_groups = wafv2_client.list_rule_groups(Scope="REGIONAL")
                global_rule_groups = wafv2_client.list_rule_groups(Scope="CLOUDFRONT")

                rule_groups = []
                # Process regional rule groups
                for group in regional_rule_groups.get("RuleGroups", []):
                    group_name = group.get("Name")
                    group_id = group.get("Id")
                    group_detail = wafv2_client.get_rule_group(
                        Name=group_name, Scope="REGIONAL", Id=group_id
                    )
                    rule_groups.append(
                        {
                            "name": group_name,
                            "id": group_id,
                            "scope": "REGIONAL",
                            "detail": group_detail,
                        }
                    )

                # Process global rule groups
                for group in global_rule_groups.get("RuleGroups", []):
                    group_name = group.get("Name")
                    group_id = group.get("Id")
                    group_detail = wafv2_client.get_rule_group(
                        Name=group_name, Scope="CLOUDFRONT", Id=group_id
                    )
                    rule_groups.append(
                        {
                            "name": group_name,
                            "id": group_id,
                            "scope": "CLOUDFRONT",
                            "detail": group_detail,
                        }
                    )

                return {"rules": rule_groups}

            else:
                return {"error": f"Unsupported query type: {query_type}"}

        except boto3.exceptions.Boto3Error as e:
            logger.error(f"Error querying AWS WAF: {e}")
            return {"error": f"Error querying AWS WAF: {str(e)}"}

    def _get_azure_data(
        self, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get data from Azure WAF.

        Args:
            query_type: Type of information to retrieve
            resource_id: Specific resource ID to query (if applicable)

        Returns:
            Dictionary containing Azure WAF data
        """
        client_id = os.getenv("AZURE_CLIENT_ID")
        client_secret = os.getenv("AZURE_CLIENT_SECRET")
        tenant_id = os.getenv("AZURE_TENANT_ID")
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

        if not all([client_id, client_secret, tenant_id, subscription_id]):
            return {"error": "Azure credentials not found in environment variables"}

        try:
            # Create credential
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

            # Create Front Door Management client
            fd_client = FrontDoorManagementClient(
                credential=credential, subscription_id=subscription_id
            )

            # Handle different query types
            if query_type == "assets":
                # Get list of Front Doors
                front_doors = []
                for fd in fd_client.front_doors.list():
                    front_doors.append(
                        {
                            "id": fd.id,
                            "name": fd.name,
                            "location": fd.location,
                            "resource_group": fd.id.split("/")[4],
                            "frontend_endpoints": (
                                [ep.name for ep in fd.frontend_endpoints]
                                if hasattr(fd, "frontend_endpoints")
                                else []
                            ),
                        }
                    )

                # Get list of WAF policies
                waf_policies = []
                for policy in fd_client.policies.list():
                    waf_policies.append(
                        {
                            "id": policy.id,
                            "name": policy.name,
                            "resource_group": policy.id.split("/")[4],
                            "policy_settings": (
                                {
                                    "enabled_state": (
                                        policy.policy_settings.enabled_state
                                        if hasattr(policy, "policy_settings")
                                        else None
                                    ),
                                    "mode": (
                                        policy.policy_settings.mode
                                        if hasattr(policy, "policy_settings")
                                        else None
                                    ),
                                }
                                if hasattr(policy, "policy_settings")
                                else {}
                            ),
                        }
                    )

                return {
                    "assets": {"front_doors": front_doors, "waf_policies": waf_policies}
                }

            elif query_type == "configuration":
                # Get specific Front Door or WAF policy
                if not resource_id:
                    return {
                        "error": "Resource ID is required for configuration queries"
                    }

                # Check if resource_id is a Front Door or WAF policy
                if "/frontdoors/" in resource_id.lower():
                    # It's a Front Door
                    resource_parts = resource_id.split("/")
                    if len(resource_parts) >= 2:
                        resource_group = resource_parts[0]
                        front_door_name = resource_parts[1]
                    else:
                        return {
                            "error": (
                                "Invalid resource ID format. "
                                "Expected: 'resource_group/front_door_name'"
                            )
                        }

                    front_door = fd_client.front_doors.get(
                        resource_group_name=resource_group,
                        front_door_name=front_door_name,
                    )

                    # Convert to serializable dictionary
                    fd_dict = {
                        "id": front_door.id,
                        "name": front_door.name,
                        "location": front_door.location,
                        "frontend_endpoints": (
                            [
                                {
                                    "name": ep.name,
                                    "web_application_firewall_policy_link": (
                                        ep.web_application_firewall_policy_link.id
                                        if hasattr(
                                            ep, "web_application_firewall_policy_link"
                                        )
                                        else None
                                    ),
                                }
                                for ep in front_door.frontend_endpoints
                            ]
                            if hasattr(front_door, "frontend_endpoints")
                            else []
                        ),
                    }

                    return {"configuration": fd_dict}

                elif "/policies/" in resource_id.lower():
                    # It's a WAF policy
                    resource_parts = resource_id.split("/")
                    if len(resource_parts) >= 2:
                        resource_group = resource_parts[0]
                        policy_name = resource_parts[1]
                    else:
                        return {
                            "error": (
                                "Invalid resource ID format. "
                                "Expected: 'resource_group/policy_name'"
                            )
                        }

                    policy = fd_client.policies.get(
                        resource_group_name=resource_group,
                        policy_name=policy_name,
                    )

                    # Convert to serializable dictionary
                    policy_dict = {
                        "id": policy.id,
                        "name": policy.name,
                        "policy_settings": (
                            {
                                "enabled_state": policy.policy_settings.enabled_state,
                                "mode": policy.policy_settings.mode,
                                "redirect_url": policy.policy_settings.redirect_url,
                                "custom_block_response_status_code": (
                                    policy.policy_settings.custom_block_response_status_code
                                ),
                            }
                            if hasattr(policy, "policy_settings")
                            else {}
                        ),
                        "custom_rules": (
                            [
                                {
                                    "name": rule.name,
                                    "action": rule.action,
                                    "priority": rule.priority,
                                }
                                for rule in policy.custom_rules.rules
                            ]
                            if hasattr(policy, "custom_rules")
                            else []
                        ),
                        "managed_rules": (
                            [
                                {
                                    "rule_set_type": rule.rule_set_type,
                                    "rule_set_version": rule.rule_set_version,
                                }
                                for rule in policy.managed_rules.rule_sets
                            ]
                            if hasattr(policy, "managed_rules")
                            else []
                        ),
                    }

                    return {"configuration": policy_dict}

                else:
                    return {
                        "error": (
                            "Invalid resource ID. "
                            "Must contain '/frontdoors/' or '/policies/'"
                        )
                    }

            elif query_type == "rules":
                # Get WAF policy rules
                if not resource_id:
                    return {"error": "Resource ID is required for rules queries"}

                # Parse resource ID
                resource_parts = resource_id.split("/")
                if len(resource_parts) >= 2:
                    resource_group = resource_parts[0]
                    policy_name = resource_parts[1]
                else:
                    return {
                        "error": (
                            "Invalid resource ID format. "
                            "Expected: 'resource_group/policy_name'"
                        )
                    }

                # Get the policy
                policy = fd_client.policies.get(
                    resource_group_name=resource_group,
                    policy_name=policy_name,
                )

                rules_data = {
                    "custom_rules": (
                        [
                            {
                                "name": rule.name,
                                "action": rule.action,
                                "priority": rule.priority,
                                "match_conditions": (
                                    [
                                        {
                                            "match_variable": cond.match_variable,
                                            "operator": cond.operator,
                                            "negation_condition": (
                                                cond.negation_condition
                                            ),
                                            "match_value": cond.match_value,
                                        }
                                        for cond in rule.match_conditions
                                    ]
                                    if hasattr(rule, "match_conditions")
                                    else []
                                ),
                            }
                            for rule in policy.custom_rules.rules
                        ]
                        if hasattr(policy, "custom_rules")
                        and hasattr(policy.custom_rules, "rules")
                        else []
                    ),
                    "managed_rules": (
                        [
                            {
                                "rule_set_type": rule.rule_set_type,
                                "rule_set_version": rule.rule_set_version,
                                "exclusions": (
                                    [
                                        {
                                            "match_variable": excl.match_variable,
                                            "selector": excl.selector,
                                            "selector_match_operator": (
                                                excl.selector_match_operator
                                            ),
                                        }
                                        for excl in rule.exclusions
                                    ]
                                    if hasattr(rule, "exclusions")
                                    else []
                                ),
                            }
                            for rule in policy.managed_rules.rule_sets
                        ]
                        if hasattr(policy, "managed_rules")
                        and hasattr(policy.managed_rules, "rule_sets")
                        else []
                    ),
                }

                return {"rules": rules_data}

            else:
                return {"error": f"Unsupported query type: {query_type}"}

        except Exception as e:
            logger.error(f"Error querying Azure WAF: {e}")
            return {"error": f"Error querying Azure WAF: {str(e)}"}
