"""WAF Analysis Tool for connecting to and analyzing WAF configurations.

This tool connects to various Web Application Firewall (WAF) providers including
Imperva, Cloudflare, AWS, and Azure to retrieve configurations and information
about protected assets.
"""

import logging
import os
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional

import boto3
import requests
import yaml
from azure.identity import ClientSecretCredential
from azure.mgmt.frontdoor import FrontDoorManagementClient
from crewai.tools import BaseTool
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Load environment variables
load_dotenv()

# Set up logging
logger = logging.getLogger(__name__)


class WAFAnalysisInput(BaseModel):
    """Input for WAF Analysis Tool."""

    provider: str = Field(
        ...,
        description="WAF provider to query ('imperva', 'cloudflare', 'aws', 'azure')",
    )
    query_type: str = Field(
        ...,
        description="Type of information to retrieve ('configuration', 'assets', 'rules')",
    )
    resource_id: Optional[str] = Field(
        None, description="Specific resource ID to query (if applicable)"
    )

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v):
        """Validate that the provider is supported."""
        valid_providers = ["imperva", "cloudflare", "aws", "azure"]
        if v.lower() not in valid_providers:
            raise ValueError(f"Provider must be one of: {', '.join(valid_providers)}")
        return v.lower()

    @field_validator("query_type")
    @classmethod
    def validate_query_type(cls, v):
        """Validate that the query type is supported."""
        valid_query_types = ["configuration", "assets", "rules"]
        if v.lower() not in valid_query_types:
            raise ValueError(
                f"Query type must be one of: {', '.join(valid_query_types)}"
            )
        return v.lower()

    model_config = ConfigDict(arbitrary_types_allowed=True)


class WAFAnalysisTool(BaseTool):
    """Tool for analyzing Web Application Firewall configurations.

    This tool connects to various WAF providers (Imperva, Cloudflare, AWS, Azure)
    to retrieve configuration details and information about protected assets.
    """

    name: ClassVar[str] = "waf_analysis_tool"
    description: str = (
        "Analyzes web application firewall configurations and protected assets "
        "from multiple providers including Imperva, Cloudflare, AWS, and Azure."
    )
    input_schema: ClassVar[type] = WAFAnalysisInput

    # Configuration defaults (will be overridden by YAML config)
    enabled_providers: List[str] = Field(
        default=["imperva", "cloudflare", "aws", "azure"]
    )
    imperva_api_url: str = Field(default="https://api.imperva.com/api/v1")
    cloudflare_api_url: str = Field(default="https://api.cloudflare.com/client/v4")
    aws_region: str = Field(default="us-east-1")
    azure_api_version: str = Field(default="2020-11-01")
    request_timeout: int = Field(default=30)

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    @classmethod
    def _load_config_from_yaml(cls):
        """Load configuration from tool.yaml file.

        Returns:
            Dict containing configuration values
        """
        try:
            # Get the directory containing this file
            current_dir = Path(__file__).parent
            config_path = current_dir / "tool.yaml"

            # Load YAML configuration
            with open(config_path, "r") as file:
                config = yaml.safe_load(file)

            # Extract parameters from configuration
            parameters = config.get("configuration", {}).get("parameters", {})

            # Create a dictionary of configuration values
            yaml_config = {
                "enabled_providers": parameters.get("enabled_providers", {}).get(
                    "default", ["imperva", "cloudflare", "aws", "azure"]
                ),
                "imperva_api_url": parameters.get("imperva_api_url", {}).get(
                    "default", "https://api.imperva.com/api/v1"
                ),
                "cloudflare_api_url": parameters.get("cloudflare_api_url", {}).get(
                    "default", "https://api.cloudflare.com/client/v4"
                ),
                "aws_region": parameters.get("aws_region", {}).get(
                    "default", "us-east-1"
                ),
                "azure_api_version": parameters.get("azure_api_version", {}).get(
                    "default", "2020-11-01"
                ),
                "request_timeout": parameters.get("request_timeout", {}).get(
                    "default", 30
                ),
            }

            logger.info(f"Loaded WAF Analysis Tool configuration from {config_path}")
            return yaml_config
        except Exception as e:
            # Log error but return defaults
            logger.error(f"Error loading WAF Analysis Tool configuration: {str(e)}")
            return {
                "enabled_providers": ["imperva", "cloudflare", "aws", "azure"],
                "imperva_api_url": "https://api.imperva.com/api/v1",
                "cloudflare_api_url": "https://api.cloudflare.com/client/v4",
                "aws_region": "us-east-1",
                "azure_api_version": "2020-11-01",
                "request_timeout": 30,
            }

    def __init__(self, **kwargs):
        """Initialize the WAF Analysis Tool."""
        # Initialize with default values first
        super().__init__(**kwargs)

        # Load configuration from YAML and update instance attributes
        config = self._load_config_from_yaml()
        for key, value in config.items():
            setattr(self, key, value)

        # Load API credentials from environment variables
        self.imperva_api_key = os.getenv("IMPERVA_API_KEY")
        self.cloudflare_api_key = os.getenv("CLOUDFLARE_API_KEY")
        self.cloudflare_email = os.getenv("CLOUDFLARE_EMAIL")

        # AWS credentials
        self.aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")

        # Override AWS region from environment if specified
        env_region = os.getenv("AWS_REGION")
        if env_region:
            self.aws_region = env_region

        # Azure credentials
        self.azure_client_id = os.getenv("AZURE_CLIENT_ID")
        self.azure_client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.azure_tenant_id = os.getenv("AZURE_TENANT_ID")

        # Override request timeout from environment if specified
        env_timeout = os.getenv("WAF_REQUEST_TIMEOUT")
        if env_timeout:
            self.request_timeout = int(env_timeout)

    def _run(
        self, provider: str, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run WAF analysis for the specified provider.

        Args:
            provider: WAF provider to query ('imperva', 'cloudflare', 'aws', 'azure')
            query_type: Type of information to retrieve ('configuration', 'assets', 'rules')
            resource_id: Specific resource ID to query (if applicable)

        Returns:
            Dictionary containing the query results
        """
        # Check if the provider is enabled
        if provider not in self.enabled_providers:
            return {"error": f"Provider '{provider}' is not enabled in configuration"}

        try:
            # Call the appropriate provider method based on provider parameter
            if provider == "imperva":
                return self._query_imperva(query_type, resource_id)
            elif provider == "cloudflare":
                return self._query_cloudflare(query_type, resource_id)
            elif provider == "aws":
                return self._query_aws(query_type, resource_id)
            elif provider == "azure":
                return self._query_azure(query_type, resource_id)
            else:
                return {"error": f"Unsupported provider: {provider}"}
        except Exception as e:
            logger.exception(f"Error querying {provider} WAF: {str(e)}")
            return {"error": f"Error querying {provider} WAF: {str(e)}"}

    async def _arun(
        self, provider: str, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run WAF analysis asynchronously (wraps _run for now).

        Args:
            provider: WAF provider to query ('imperva', 'cloudflare', 'aws', 'azure')
            query_type: Type of information to retrieve ('configuration', 'assets', 'rules')
            resource_id: Specific resource ID to query (if applicable)

        Returns:
            Dictionary containing the query results
        """
        # For simplicity, we're using the synchronous implementation
        # In a real-world scenario, this would be an async implementation
        return self._run(provider, query_type, resource_id)

    def _query_imperva(
        self, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query Imperva WAF API.

        Args:
            query_type: Type of information to retrieve
            resource_id: Specific site ID to query (if applicable)

        Returns:
            Dictionary containing the Imperva WAF query results
        """
        if not self.imperva_api_key:
            return {"error": "Imperva API key not configured"}

        headers = {
            "Authorization": f"Bearer {self.imperva_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            if query_type == "assets":
                # List all protected sites
                url = f"{self.imperva_api_url}/sites"
                response = requests.get(
                    url, headers=headers, timeout=self.request_timeout
                )
                response.raise_for_status()
                return {"assets": response.json()}

            elif query_type == "configuration":
                # Get configuration for a specific site
                if not resource_id:
                    return {"error": "Site ID required for configuration query"}

                url = f"{self.imperva_api_url}/sites/{resource_id}"
                response = requests.get(
                    url, headers=headers, timeout=self.request_timeout
                )
                response.raise_for_status()
                return {"configuration": response.json()}

            elif query_type == "rules":
                # Get security rules for a specific site
                if not resource_id:
                    return {"error": "Site ID required for rules query"}

                url = f"{self.imperva_api_url}/sites/{resource_id}/security"
                response = requests.get(
                    url, headers=headers, timeout=self.request_timeout
                )
                response.raise_for_status()
                return {"rules": response.json()}

            else:
                return {"error": f"Unsupported query type for Imperva: {query_type}"}

        except requests.RequestException as e:
            logger.exception(f"Error querying Imperva API: {str(e)}")
            return {"error": f"Error querying Imperva API: {str(e)}"}

    def _query_cloudflare(
        self, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query Cloudflare WAF API.

        Args:
            query_type: Type of information to retrieve
            resource_id: Specific zone ID to query (if applicable)

        Returns:
            Dictionary containing the Cloudflare WAF query results
        """
        if not self.cloudflare_api_key:
            return {"error": "Cloudflare API key not configured"}

        # Configure headers based on available credentials
        headers = {
            "Content-Type": "application/json",
        }

        # Use API token if available, otherwise use API key with email
        if self.cloudflare_api_key.startswith("Bearer"):
            headers["Authorization"] = self.cloudflare_api_key
        else:
            if not self.cloudflare_email:
                return {"error": "Cloudflare email not configured for API key auth"}
            headers["X-Auth-Key"] = self.cloudflare_api_key
            headers["X-Auth-Email"] = self.cloudflare_email

        try:
            if query_type == "assets":
                # List all zones (domains)
                url = f"{self.cloudflare_api_url}/zones"
                response = requests.get(
                    url, headers=headers, timeout=self.request_timeout
                )
                response.raise_for_status()
                return {"assets": response.json()}

            elif query_type == "configuration":
                # Get WAF configuration for a specific zone
                if not resource_id:
                    return {"error": "Zone ID required for configuration query"}

                url = f"{self.cloudflare_api_url}/zones/{resource_id}/firewall/waf/packages"
                response = requests.get(
                    url, headers=headers, timeout=self.request_timeout
                )
                response.raise_for_status()
                return {"configuration": response.json()}

            elif query_type == "rules":
                # Get WAF rules for a specific zone
                if not resource_id:
                    return {"error": "Zone ID required for rules query"}

                url = f"{self.cloudflare_api_url}/zones/{resource_id}/firewall/rules"
                response = requests.get(
                    url, headers=headers, timeout=self.request_timeout
                )
                response.raise_for_status()
                return {"rules": response.json()}

            else:
                return {"error": f"Unsupported query type for Cloudflare: {query_type}"}

        except requests.RequestException as e:
            logger.exception(f"Error querying Cloudflare API: {str(e)}")
            return {"error": f"Error querying Cloudflare API: {str(e)}"}

    def _query_aws(
        self, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query AWS WAF API.

        Args:
            query_type: Type of information to retrieve
            resource_id: Specific Web ACL ID to query (if applicable)

        Returns:
            Dictionary containing the AWS WAF query results
        """
        if not self.aws_access_key or not self.aws_secret_key:
            return {"error": "AWS credentials not configured"}

        try:
            # Initialize AWS WAFv2 client
            wafv2_client = boto3.client(
                "wafv2",
                region_name=self.aws_region,
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
            )

            # Determine scope (REGIONAL or CLOUDFRONT) based on resource_id format if provided
            scope = "REGIONAL"
            if resource_id and "cloudfront" in resource_id.lower():
                scope = "CLOUDFRONT"

            if query_type == "assets":
                # List all Web ACLs
                response = wafv2_client.list_web_acls(Scope=scope, Limit=100)
                return {"assets": response.get("WebACLs", [])}

            elif query_type == "configuration":
                # Get Web ACL configuration
                if not resource_id:
                    return {"error": "Web ACL ID required for configuration query"}

                # Parse the ARN or ID from resource_id
                acl_id, acl_name = self._parse_aws_resource_id(resource_id)
                if not acl_id or not acl_name:
                    return {"error": "Invalid Web ACL ID format"}

                response = wafv2_client.get_web_acl(
                    Name=acl_name, Id=acl_id, Scope=scope
                )
                return {"configuration": response.get("WebACL", {})}

            elif query_type == "rules":
                # Get rule groups
                response = wafv2_client.list_rule_groups(Scope=scope, Limit=100)
                return {"rules": response.get("RuleGroups", [])}

            else:
                return {"error": f"Unsupported query type for AWS: {query_type}"}

        except Exception as e:
            logger.exception(f"Error querying AWS WAF API: {str(e)}")
            return {"error": f"Error querying AWS WAF API: {str(e)}"}

    def _query_azure(
        self, query_type: str, resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query Azure WAF API.

        Args:
            query_type: Type of information to retrieve
            resource_id: Specific resource ID to query (if applicable)

        Returns:
            Dictionary containing the Azure WAF query results
        """
        # Check that all required Azure credentials are present
        azure_creds = [
            self.azure_client_id,
            self.azure_client_secret,
            self.azure_tenant_id,
        ]
        if not all(azure_creds):
            return {"error": "Azure credentials not configured"}

        try:
            # Create Azure credential
            credential = ClientSecretCredential(
                tenant_id=self.azure_tenant_id,
                client_id=self.azure_client_id,
                client_secret=self.azure_client_secret,
            )

            # Initialize FrontDoor client
            frontdoor_client = FrontDoorManagementClient(
                credential=credential,
                subscription_id=resource_id if resource_id else "",
            )

            if query_type == "assets":
                # List all front doors
                if not resource_id:
                    return {"error": "Subscription ID required for assets query"}

                frontdoors = list(frontdoor_client.front_doors.list_all())
                return {"assets": [fd.as_dict() for fd in frontdoors]}

            elif query_type == "configuration":
                # Get Front Door configuration
                if not resource_id or "/" not in resource_id:
                    return {
                        "error": (
                            "Resource ID required in format "
                            "'subscription_id/resource_group/name'"
                        )
                    }

                parts = resource_id.split("/")
                if len(parts) < 3:
                    return {"error": "Invalid resource ID format"}

                subscription_id, resource_group, name = parts
                frontdoor = frontdoor_client.front_doors.get(resource_group, name)
                return {"configuration": frontdoor.as_dict()}

            elif query_type == "rules":
                # Get WAF policies
                if not resource_id:
                    return {"error": "Subscription ID required for rules query"}

                policies = list(
                    frontdoor_client.policies.list_by_subscription(resource_id)
                )
                return {"rules": [policy.as_dict() for policy in policies]}

            else:
                return {"error": f"Unsupported query type for Azure: {query_type}"}

        except Exception as e:
            logger.exception(f"Error querying Azure WAF API: {str(e)}")
            return {"error": f"Error querying Azure WAF API: {str(e)}"}

    def _parse_aws_resource_id(self, resource_id: str) -> tuple:
        """Parse AWS resource ID to extract the ID and name.

        Args:
            resource_id: AWS resource ID or ARN

        Returns:
            Tuple containing (id, name) or (None, None) if invalid
        """
        # If resource_id is an ARN, extract the ID from it
        if resource_id.startswith("arn:aws:wafv2:"):
            parts = resource_id.split("/")
            if len(parts) >= 2:
                acl_id = parts[-1]
                acl_name = parts[-2]
                return acl_id, acl_name

        # If resource_id is in format "name/id"
        elif "/" in resource_id:
            acl_name, acl_id = resource_id.split("/", 1)
            return acl_id, acl_name

        # If resource_id is just the ID (less common)
        else:
            return resource_id, resource_id

        return None, None
