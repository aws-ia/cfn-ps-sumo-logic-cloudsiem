import securityhub
import os
from typing import TYPE_CHECKING, Any, Dict, Optional
import json
import logging

# Setup Default Logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)



def parameter_pattern_validator(parameter_name: str, parameter_value: Optional[str], pattern: str, is_optional: bool = False) -> dict:
    """Validate CloudFormation Custom Resource Properties and/or Lambda Function Environment Variables.
    Args:
        parameter_name: CloudFormation custom resource parameter name and/or Lambda function environment variable name
        parameter_value: CloudFormation custom resource parameter value and/or Lambda function environment variable value
        pattern: REGEX pattern to validate against.
        is_optional: Allow empty or missing value when True
    Raises:
        ValueError: Parameter has a value of empty string.
        ValueError: Parameter is missing
        ValueError: Parameter does not follow the allowed pattern
    Returns:
        Validated Parameter
    """
    if parameter_value == "" and not is_optional:
        raise ValueError(f"'{parameter_name}' parameter has a value of empty string.")
    elif not parameter_value and not is_optional:
        raise ValueError(f"'{parameter_name}' parameter is missing.")
    elif not re.match(pattern, str(parameter_value)):
        raise ValueError(f"'{parameter_name}' parameter with value of '{parameter_value}'" + f" does not follow the allowed pattern: {pattern}.")
    return {parameter_name: parameter_value}

def get_validated_parameters(event: Dict[str, Any]) -> dict:
    """Validate AWS CloudFormation parameters.
    Args:
        event: event data
    Returns:
        Validated parameters
    """
    params = {}
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]

    true_false_pattern = r"^true|false$"
    version_pattern = r"^[0-9.]+$"
    sns_topic_pattern = r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"

    # Required Parameters
    params.update(parameter_pattern_validator("AWS_PARTITION", os.environ.get("AWS_PARTITION"), pattern=r"^(aws[a-zA-Z-]*)?$"))
    params.update(parameter_pattern_validator("CIS_VERSION", os.environ.get("CIS_VERSION"), pattern=version_pattern))
    params.update(parameter_pattern_validator("CONFIGURATION_ROLE_NAME", os.environ.get("CONFIGURATION_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", os.environ.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", os.environ.get("DELEGATED_ADMIN_ACCOUNT_ID"), pattern=r"^\d{12}$"))
    params.update(parameter_pattern_validator("DISABLE_SECURITY_HUB", os.environ.get("DISABLE_SECURITY_HUB"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("ENABLE_CIS_STANDARD", os.environ.get("ENABLE_CIS_STANDARD"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("ENABLE_PCI_STANDARD", os.environ.get("ENABLE_PCI_STANDARD"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("ENABLE_NIST_STANDARD", os.environ.get("ENABLE_NIST_STANDARD"), pattern=true_false_pattern))
    params.update(
        parameter_pattern_validator(
            "ENABLE_SECURITY_BEST_PRACTICES_STANDARD", os.environ.get("ENABLE_SECURITY_BEST_PRACTICES_STANDARD"), pattern=true_false_pattern
        )
    )
    params.update(
        parameter_pattern_validator("HOME_REGION", os.environ.get("HOME_REGION"), pattern=r"^(?!(.*--))(?!(.*-$))[a-z0-9]([a-z0-9-]){0,62}$")
    )
    params.update(parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", os.environ.get("MANAGEMENT_ACCOUNT_ID"), pattern=r"^\d{12}$"))
    params.update(parameter_pattern_validator("PCI_VERSION", os.environ.get("PCI_VERSION"), pattern=version_pattern))
    params.update(parameter_pattern_validator("NIST_VERSION", os.environ.get("NIST_VERSION"), pattern=version_pattern))
    params.update(
        parameter_pattern_validator("REGION_LINKING_MODE", os.environ.get("REGION_LINKING_MODE"), pattern=r"^ALL_REGIONS|SPECIFIED_REGIONS$")
    )
    params.update(parameter_pattern_validator("SNS_TOPIC_ARN", os.environ.get("SNS_TOPIC_ARN"), pattern=sns_topic_pattern))
    params.update(
        parameter_pattern_validator("SECURITY_BEST_PRACTICES_VERSION", os.environ.get("SECURITY_BEST_PRACTICES_VERSION"), pattern=version_pattern)
    )

    # Optional Parameters
    params.update(parameter_pattern_validator("ENABLED_REGIONS", os.environ.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True))

    return params

def get_standards_dictionary(params: dict) -> dict:
    """Get Standards Dictionary used to process standard configurations.
    Args:
        params: Configuration parameters
    Returns:
        Dictionary of standards data
    """
    return {
        "SecurityBestPracticesVersion": params["SECURITY_BEST_PRACTICES_VERSION"],
        "CISVersion": params["CIS_VERSION"],
        "PCIVersion": params["PCI_VERSION"],
        "NISTVersion": params["NIST_VERSION"],
        "StandardsToEnable": {
            "cis": params["ENABLE_CIS_STANDARD"] == "true",
            "pci": params["ENABLE_PCI_STANDARD"] == "true",
            "nist": params["ENABLE_NIST_STANDARD"] == "true",
            "sbp": params["ENABLE_SECURITY_BEST_PRACTICES_STANDARD"] == "true",
        },
    }


def process_event_sns(event: dict) -> None:
    """Process SNS event.
    Args:
        event: event data
    """
    params = get_validated_parameters({})

    for record in event["Records"]:
        record["Sns"]["Message"] = json.loads(record["Sns"]["Message"])
        LOGGER.info({"SNS Record": record})
        message = record["Sns"]["Message"]

        if message["Action"] == "configure":
            securityhub.enable_account_securityhub(
                message["AccountId"], message["Regions"], params["CONFIGURATION_ROLE_NAME"], params["AWS_PARTITION"], get_standards_dictionary(params)
            )
        elif message["Action"] == "disable":
            LOGGER.info("Disabling SecurityHub")
            securityhub.disable_securityhub(message["AccountId"], params["CONFIGURATION_ROLE_NAME"], message["Regions"])
