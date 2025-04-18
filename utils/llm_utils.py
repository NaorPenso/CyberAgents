"""Utility functions for creating LLM configurations using a central factory approach."""

import logging
import os
from typing import Any, Dict, Optional

from dotenv import load_dotenv

# --- LangChain Imports ---
# Import necessary classes. Use try-except blocks for optional dependencies.
try:
    from langchain_openai import AzureChatOpenAI, ChatOpenAI
except ImportError:
    ChatOpenAI = None
    AzureChatOpenAI = None
    logging.warning("langchain-openai not installed. OpenAI/Azure support disabled.")

try:
    from langchain_community.chat_models import ChatOllama
except ImportError:
    ChatOllama = None
    logging.warning(
        "langchain-community potentially not fully installed. Ollama support may be limited."
    )

# AWS Bedrock - Try preferred langchain-aws first, then legacy
BedrockChat = None  # Define upfront to avoid NameError if all imports fail
try:
    from langchain_aws import (
        ChatBedrock as BedrockChat,  # Use preferred class and alias
    )
except ImportError:
    logging.warning("langchain-aws not found. Trying legacy Bedrock import...")
    try:
        from langchain_community.chat_models.bedrock import (  # Use legacy class
            BedrockChat,
        )
    except ImportError:
        logging.warning(
            "Neither langchain-aws nor langchain_community Bedrock found. "
            "AWS Bedrock support disabled."
        )  # BedrockChat remains None

# Cerebras
try:
    from langchain_cerebras import ChatCerebras
except ImportError:
    ChatCerebras = None
    logging.warning(
        "langchain-cerebras package not found or ChatCerebras class unavailable. "
        "Cerebras support disabled."
    )

load_dotenv()
logger = logging.getLogger(__name__)
# Ensure logging level respects .env setting
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

DEFAULT_PROVIDER = "openai"

# --- Provider Configuration Map ---
# Maps provider name to its LangChain class and required/optional env vars + init args
PROVIDER_CONFIG: Dict[str, Dict[str, Any]] = {
    "openai": {
        "class": ChatOpenAI,
        "env_vars": {
            "api_key": "OPENAI_API_KEY",
            "base_url": "OPENAI_API_BASE",
            "model": "OPENAI_MODEL_NAME",
            "temperature": "OPENAI_TEMPERATURE",
        },
        # Ensure keys match ChatOpenAI constructor parameters
        "init_map": {
            "api_key": "openai_api_key",
            "base_url": "openai_api_base",
            "model": "model_name",
            "temperature": "temperature",
        },
        "required": ["OPENAI_API_KEY", "OPENAI_MODEL_NAME"],
    },
    "azure_openai": {
        "class": AzureChatOpenAI,
        "env_vars": {
            "api_key": "AZURE_OPENAI_API_KEY",
            "endpoint": "AZURE_OPENAI_API_BASE",
            "version": "AZURE_OPENAI_API_VERSION",
            "deployment": "AZURE_OPENAI_DEPLOYMENT_NAME",
            "temperature": "AZURE_OPENAI_TEMPERATURE",
            "model": "AZURE_OPENAI_MODEL_NAME",
        },
        # Ensure keys match AzureChatOpenAI constructor parameters
        "init_map": {
            "api_key": "azure_api_key",
            "endpoint": "azure_endpoint",
            "version": "api_version",
            "deployment": "deployment_name",
            "model": "model_name",
            "temperature": "temperature",
        },
        "required": [
            "AZURE_OPENAI_API_KEY",
            "AZURE_OPENAI_API_BASE",
            "AZURE_OPENAI_API_VERSION",
            "AZURE_OPENAI_DEPLOYMENT_NAME",
        ],
    },
    "aws_bedrock": {
        "class": BedrockChat,  # Now guaranteed to be defined (or None)
        "env_vars": {
            "region": "AWS_REGION_NAME",
            "model_id": "AWS_BEDROCK_MODEL_ID",
            "temperature": "AWS_BEDROCK_TEMPERATURE",
        },
        # Ensure keys match ChatBedrock constructor parameters
        # Credentials typically handled by boto3/environment
        "init_map": {
            "region": "region_name",
            "model_id": "model_id",
            "temperature": "temperature",
        },  # Temperature often in model_kwargs
        "required": ["AWS_REGION_NAME", "AWS_BEDROCK_MODEL_ID"],
        "credential_keys": [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
        ],  # For optional check log
    },
    "cerebras": {
        "class": ChatCerebras,
        "env_vars": {
            "api_key": "CEREBRAS_API_KEY",
            "base_url": "CEREBRAS_API_BASE",
            "model": "CEREBRAS_MODEL_NAME",
            "temperature": "CEREBRAS_TEMPERATURE",
        },
        "init_map": {
            "api_key": "cerebras_api_key",
            "base_url": "base_url",
            "model": "model",
            "temperature": "temperature",
        },
        "required": ["CEREBRAS_API_KEY", "CEREBRAS_MODEL_NAME"],
    },
    "ollama": {
        "class": ChatOllama,
        "env_vars": {
            "base_url": "OLLAMA_BASE_URL",
            "model": "OLLAMA_MODEL",
            "temperature": "OLLAMA_TEMPERATURE",
        },
        # Ensure keys match ChatOllama constructor parameters
        "init_map": {
            "base_url": "base_url",
            "model": "model",
            "temperature": "temperature",
        },
        "required": ["OLLAMA_MODEL"],  # Base URL might have default
    },
}


# Keep CustomChatOpenAI ONLY if truly needed
# for specific model behavior (like o3-mini removing temp)
# If standard ChatOpenAI handles model-specific quirks, this class can be removed.
class CustomChatOpenAI(ChatOpenAI):
    """Custom ChatOpenAI class that doesn't use temperature for the o3-mini model."""

    @property
    def _invocation_params(self):
        """Get the parameters used to invoke the model."""
        params = super()._invocation_params
        # Using model_name directly as it's set during init
        if (
            hasattr(self, "model_name")
            and self.model_name == "o3-mini"
            and "temperature" in params
        ):
            logger.debug("Removing temperature for o3-mini model in _invocation_params")
            del params["temperature"]
        return params

    @property
    def _llm_type(self) -> str:
        """Return type of llm."""
        return "custom_chat_openai"

    # No need to override dict() if _invocation_params is correct
    # def dict(self, **kwargs): ...

    # Overriding generation methods is usually not needed if _invocation_params is correct
    # async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs): ...
    # def _generate(self, messages, stop=None, run_manager=None, **kwargs): ...


def _check_provider_availability(provider_key: str, config: Dict[str, Any]) -> bool:
    """Check if provider class is available and required env vars are set."""
    LLMClass = config.get("class")
    if LLMClass is None:
        class_name_log = config.get("class_name", provider_key)
        logger.error(
            f"Provider '{provider_key}' LangChain class ({class_name_log}) not available."
        )
        return False

    missing_required = [
        env_var for env_var in config.get("required", []) if not os.getenv(env_var)
    ]
    if missing_required:
        logger.error(
            f"Missing required env vars for '{provider_key}': {', '.join(missing_required)}"
        )
        return False

    # Optional credential check (just logs warning)
    if "credential_keys" in config:
        missing_creds = [k for k in config["credential_keys"] if not os.getenv(k)]
        if len(missing_creds) == len(config["credential_keys"]):
            logger.warning(
                f"Optional credential keys "
                f"({', '.join(config['credential_keys'])}) not found "
                f"for {provider_key}. Assuming IAM role or standard auth."
            )
    return True


def _build_constructor_args(
    provider_key: str, config: Dict[str, Any]
) -> Dict[str, Any]:
    """Builds the dictionary of arguments for the LLM class constructor."""
    kwargs: Dict[str, Any] = {}
    env_vars_to_read: Dict[str, str] = config.get("env_vars", {})
    init_map: Dict[str, str] = config.get("init_map", {})

    for map_key, init_arg_name in init_map.items():
        env_var_name = env_vars_to_read.get(map_key)
        if not env_var_name:
            continue

        value = os.getenv(env_var_name)

        # Assign value if present
        if value is not None and value.strip() != "":
            # Handle temperature conversion
            if "temperature" in map_key.lower():
                try:
                    kwargs[init_arg_name] = float(value)
                except (ValueError, TypeError):
                    logger.warning(
                        f"Invalid value '{value}' for {env_var_name} (temperature). Ignoring."
                    )
            else:
                # <<< FIX: Add provider prefix for Cerebras model name >>>
                if provider_key == "cerebras" and init_arg_name == "model":
                    value = f"cerebras/{value}"
                    logger.debug(
                        f"Prepending provider prefix for Cerebras model: {value}"
                    )
                kwargs[init_arg_name] = value
        # Handle optional OpenAI base URL explicitly
        elif (
            map_key == "base_url"
            and init_arg_name == "openai_api_base"
            and provider_key == "openai"
        ):
            kwargs[init_arg_name] = None

    # Apply default temperature if not set
    default_temp = 0.7
    temp_arg_name = next(
        (name for key, name in init_map.items() if key == "temperature"), None
    )

    if temp_arg_name and temp_arg_name not in kwargs:
        # Bedrock handles temperature differently (usually via model_kwargs)
        if provider_key == "aws_bedrock":
            kwargs["model_kwargs"] = kwargs.get("model_kwargs", {})
            if "temperature" not in kwargs["model_kwargs"]:
                kwargs["model_kwargs"]["temperature"] = default_temp
                logger.debug(
                    f"Applying default temp {default_temp} to Bedrock model_kwargs"
                )
        else:
            kwargs[temp_arg_name] = default_temp
            logger.debug(
                f"Applying default temp {default_temp} to {provider_key} "
                f"as '{temp_arg_name}'"
            )

    logger.debug(f"Generated kwargs for {provider_key}: {kwargs}")
    return kwargs


def _get_llm_init_kwargs(provider_key: str) -> Optional[Dict[str, Any]]:
    """Validates config and builds kwargs for LLM constructor."""
    if provider_key not in PROVIDER_CONFIG:
        logger.error(f"Provider '{provider_key}' not found in PROVIDER_CONFIG.")
        return None

    config = PROVIDER_CONFIG[provider_key]

    if not _check_provider_availability(provider_key, config):
        return None  # Errors logged in check function

    return _build_constructor_args(provider_key, config)


def _instantiate_llm(provider_key: str) -> Optional[Any]:
    """Attempts to instantiate an LLM for the given provider key."""
    config = PROVIDER_CONFIG.get(provider_key)
    if not config:
        logger.error(f"Configuration for provider '{provider_key}' not found.")
        return None

    LLMClass = config.get("class")
    if LLMClass is None:
        logger.error(f"LangChain class for provider '{provider_key}' not available.")
        return None

    init_kwargs = _get_llm_init_kwargs(provider_key)
    if init_kwargs is None:
        # Error already logged by _get_llm_init_kwargs
        return None

    instance = None
    try:
        # Determine model identifier key and value for special handling/logging
        model_identifier_key = next(
            (k for k in ["model", "model_id", "deployment"] if k in config["init_map"]),
            None,
        )
        model_identifier_arg_name = (
            config["init_map"].get(model_identifier_key)
            if model_identifier_key
            else None
        )
        model_value = (
            init_kwargs.get(model_identifier_arg_name)
            if model_identifier_arg_name
            else "N/A"
        )

        # Special handling for OpenAI 'o3-mini' if CustomChatOpenAI exists and is needed
        if (
            provider_key == "openai"
            and model_value == "o3-mini"
            and CustomChatOpenAI is not None  # Check if class is defined/imported
        ):
            logger.info("Using CustomChatOpenAI wrapper for o3-mini model.")
            instance = CustomChatOpenAI(**init_kwargs)
        else:
            instance = LLMClass(**init_kwargs)

        # Basic verification after instantiation
        id_attr_val = (
            getattr(instance, "model_name", None)
            or getattr(instance, "model_id", None)
            or getattr(instance, "model", None)
            or getattr(instance, "deployment_name", None)
        )
        if id_attr_val:
            logger.info(
                f"Successfully configured {provider_key} LLM "
                f"(Model/ID/Deployment: {id_attr_val})."
            )
        else:
            logger.warning(
                f"Instantiated {provider_key} ({LLMClass.__name__}) but couldn't verify "
                f"model identifier."
            )

    except ImportError as ie:
        logger.exception(f"ImportError during {provider_key} instantiation: {ie}")
        instance = None
    except Exception as e:
        logger.exception(
            f"Failed to instantiate provider '{provider_key}' ({LLMClass.__name__}): {e}"
        )
        instance = None

    return instance


def _get_llm_details_for_logging(llm_instance: Any) -> Dict[str, str]:
    """Extracts provider name and model identifier for logging."""
    provider_name = "Unknown"
    model_id = "N/A"

    if llm_instance is None:
        return {"provider": provider_name, "model_id": model_id}

    # Determine provider name based on class
    for key, config in PROVIDER_CONFIG.items():
        if config.get("class") and isinstance(llm_instance, config["class"]):
            provider_name = key
            break
    # Handle CustomChatOpenAI inheritance
    if isinstance(llm_instance, ChatOpenAI) and provider_name == "Unknown":
        provider_name = (
            "openai (Custom)"
            if isinstance(llm_instance, CustomChatOpenAI)
            else "openai"
        )

    # Determine model identifier
    model_id = (
        getattr(llm_instance, "model_name", None)
        or getattr(llm_instance, "model_id", None)
        or getattr(llm_instance, "model", None)
        or getattr(llm_instance, "deployment_name", "N/A")
    )  # Provide default

    return {"provider": provider_name, "model_id": model_id}


def create_central_llm() -> Any:
    """Creates a single LLM instance based on PRIMARY_LLM_PROVIDER from .env."""
    primary_provider = os.getenv("PRIMARY_LLM_PROVIDER", DEFAULT_PROVIDER).lower()
    llm_instance = None
    primary_error = None

    logger.info(
        f"Attempting to initialize LLM using primary provider: '{primary_provider}'"
    )

    # --- Try Primary Provider ---
    try:
        llm_instance = _instantiate_llm(primary_provider)
    except Exception as e:
        # Catch potential errors from _instantiate_llm itself, though it should handle most
        primary_error = (
            f"Unexpected error during instantiation of '{primary_provider}': {e}"
        )
        logger.exception(primary_error)

    # --- Fallback Logic ---
    if llm_instance is None:
        # Log primary failure reason if instantiation returned None or raised Exception
        if (
            not primary_error
        ):  # Get error reason if instantiation returned None gracefully
            primary_error = (
                f"Primary provider '{primary_provider}' failed to initialize "
                f"(check logs for details)."
            )

        logger.warning(f"{primary_error} Attempting fallback to '{DEFAULT_PROVIDER}'.")

        # Avoid fallback if the primary *was* the default
        if primary_provider != DEFAULT_PROVIDER:
            try:
                llm_instance = _instantiate_llm(DEFAULT_PROVIDER)
                if llm_instance:
                    logger.info(
                        f"Successfully initialized using fallback provider "
                        f"'{DEFAULT_PROVIDER}'."
                    )
                else:
                    # Instantiation failed, error already logged by _instantiate_llm
                    raise RuntimeError(
                        f"Fallback provider '{DEFAULT_PROVIDER}' also failed to initialize."
                    )
            except Exception as fallback_e:
                final_error = (
                    f"Fatal: Could not initialize any LLM provider. "
                    f"Primary error: {primary_error} | Fallback error: {fallback_e}"
                )
                logger.critical(final_error)
                raise RuntimeError(final_error) from fallback_e
        else:
            # Primary was default and failed
            final_error = (
                f"Fatal: Could not initialize default LLM provider "
                f"'{DEFAULT_PROVIDER}'. Error: {primary_error}"
            )
            logger.critical(final_error)
            raise RuntimeError(final_error)

    # --- Final Logging & Return ---
    log_details = _get_llm_details_for_logging(llm_instance)
    logger.info(
        f"Central LLM ready: Provider='{log_details['provider']}', "
        f"Model/ID/Deployment='{log_details['model_id']}'"
    )
    return llm_instance


# Note: The old create_llm function based on USE_LOCAL_LLM is now removed by this refactoring.
