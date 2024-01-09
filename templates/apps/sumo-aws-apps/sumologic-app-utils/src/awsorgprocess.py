import copy
import json
import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Optional

import boto3
from mypy_boto3_sts.client import STSClient
from botocore.exceptions import ClientError
from botocore.config import Config
import uuid

# Setup Default Logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"}) 
ID = str(uuid.uuid4())[0:8]

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


    # Required Parameters
    params.update(parameter_pattern_validator("CONFIG_ROLE_NAME", os.environ.get("CONFIG_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("ALL_SUPPORTED", os.environ.get("ALL_SUPPORTED"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("INCLUDE_GLOBAL_RESOURCE_TYPES", os.environ.get("INCLUDE_GLOBAL_RESOURCE_TYPES"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update({"RESOURCE_TYPES": os.environ.get("RESOURCE_TYPES")})
    params.update(parameter_pattern_validator("FREQUENCY", os.environ.get("FREQUENCY"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("CONFIG_BUCKET", os.environ.get("CONFIG_BUCKET"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("ENABLED_REGIONS", os.environ.get("ENABLED_REGIONS"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("CONFIG_ASSUME_ROLE_NAME", os.environ.get("CONFIG_ASSUME_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$"))
    return params

def assume_role(role: str, role_session_name: str, account: str = None, session: boto3.Session = None) -> boto3.Session:
    if not session:
        session = boto3.Session()
    sts_client: STSClient = session.client("sts", config=BOTO3_CONFIG)
    sts_arn = sts_client.get_caller_identity()["Arn"]
    logger.info(f"USER: {sts_arn}")
    if not account:
        account = sts_arn.split(":")[4]
    partition = sts_arn.split(":")[1]
    role_arn = f"arn:{partition}:iam::{account}:role/{role}"

    response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)
    logger.info(f"ASSUMED ROLE: {response['AssumedRoleUser']['Arn']}")

    return boto3.Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )
    
def create_account_config(account_id: str, regions: list, config_assume_role_name: str, RoleARN: str, AllSupported: str,
                    IncludeGlobalResourceTypes: str, ResourceTypes: str, Frequency: str,
                    ConfigBucket: str):
    
    account_session = assume_role(config_assume_role_name, f"sumo-aws-config-recorder-check-{ID}", account_id)

    for region in regions:
        session_config = account_session.client("config", region_name=region, config=BOTO3_CONFIG)
        resource_groups_client = account_session.client('resource-groups',region_name=region, config=BOTO3_CONFIG)
        config_recorder_response = session_config.describe_configuration_recorder_status()
        logger.info(f'config recorder response:{config_recorder_response}')

        try:
            resource_groups_response = resource_groups_client.get_group(
                GroupName="sumologic"
            )
            if 'Group' not in resource_groups_response or len(resource_groups_response['Group'])<1:
                resource_groups_response = resource_groups_client.create_group(
                    Name='sumologic',
                    Description='Group resource create by sumologic auto. pls do not remove or add tag in group',
                    ResourceQuery={
                        "Type": "TAG_FILTERS_1_0",
                        "Query": json.dumps(
                            {
                                "ResourceTypeFilters": ["AWS::AllSupported"],
                                "TagFilters": [
                                    {"Key": "sumologic", "Values": ["©2023 Sumo Logic"]}
                                ]
                            }
                        )
                    }
                )
                resource_group_arn = resource_groups_response['Group']['GroupArn']
            else:
                resource_group_arn = resource_groups_response['Group']['GroupArn']                
        except Exception:
            resource_groups_response = resource_groups_client.create_group(
                Name='sumologic',
                Description='Group resource create by sumologic auto. pls do not remove or add tag in group',
                ResourceQuery={
                    "Type": "TAG_FILTERS_1_0",
                    "Query": json.dumps(
                        {
                            "ResourceTypeFilters": ["AWS::AllSupported"],
                            "TagFilters": [
                                {"Key": "sumologic", "Values": ["©2023 Sumo Logic"]}
                            ]
                        }
                    )
                }                    
            )
            resource_group_arn = resource_groups_response['Group']['GroupArn']  
                                                                    
        if 'ConfigurationRecordersStatus' not in config_recorder_response or \
                len(config_recorder_response['ConfigurationRecordersStatus']) < 1:
            logger.info(f'account: {account_id} on region: {region} Config not enabled')
            if AllSupported:
                ConfigurationRecorder={
                    "name":'default',
                    "roleARN": f"{RoleARN}" ,
                    "recordingGroup":{
                        "allSupported": AllSupported,
                        "includeGlobalResourceTypes":IncludeGlobalResourceTypes
                    }
                }
            else:
                ConfigurationRecorder={
                    "name":'default',
                    "roleARN": f"{RoleARN}" ,
                    "recordingGroup":{
                        "allSupported": AllSupported,
                        "includeGlobalResourceTypes":IncludeGlobalResourceTypes,
                        "resourceTypes": [
                                ResourceTypes
                        ]
                    }
                } 

            response = session_config.put_configuration_recorder(
                ConfigurationRecorder = ConfigurationRecorder                 
            )

            response = session_config.put_delivery_channel(
                DeliveryChannel={
                    "name":"default",
                    "s3BucketName": f"{ConfigBucket}",
                    "configSnapshotDeliveryProperties": {
                        "deliveryFrequency":f"{Frequency}"
                    }
                }
            )

            response = session_config.start_configuration_recorder(
                ConfigurationRecorderName="default"
            )

            resource_groups_response = resource_groups_client.tag(
                Arn=f"{resource_group_arn}",
                Tags={
                    'disable-awsconfig-when-remove-cfn':'true'
                }
            )
        else:
            for config_recorder in config_recorder_response['ConfigurationRecordersStatus']:
                if not config_recorder['recording']:
                    logger.info(f'account: {account_id} on region: {region} Config enabled, but not recording')
                    channels = session_config.describe_delivery_channels()
                    bucket_name=None
                    if "DeliveryChannels" in channels:
                        for channel in channels["DeliveryChannels"]:
                            bucket_name = channel["s3BucketName"] if "s3BucketName" in channel else None
                            name = channel["name"]
                            break
                    if bucket_name==None:
                        response = session_config.put_delivery_channel(
                            DeliveryChannel={
                                "name":"default",
                                "s3BucketName": f"{ConfigBucket}",
                                "configSnapshotDeliveryProperties": {
                                    "deliveryFrequency":f"{Frequency}"
                                }
                            }
                        )
                        resource_groups_response = resource_groups_client.tag(
                            Arn=f"{resource_group_arn}",
                            Tags={
                                'remove-s3-in-delivery-channel-when-remove-cfn':'true'
                            }
                        )                        
                    resource_groups_response = resource_groups_client.tag(
                        Arn=f"{resource_group_arn}",
                        Tags={
                            'stop-delivery-channel-when-remove-cfn':'true'
                        }
                    )
                    response = session_config.start_configuration_recorder(
                        ConfigurationRecorderName="default"
                    ) 
def delete_account_config(account_id: str, regions: list, config_assume_role_name: str):
    
    account_session = assume_role(config_assume_role_name, "sumo-aws-config-recorder-check", account_id)

    for region in regions:
        session_config = account_session.client("config", region_name=region, config=BOTO3_CONFIG)
        resource_groups_client = account_session.client('resource-groups',region_name=region, config=BOTO3_CONFIG)

        config_recorder_response = session_config.describe_configuration_recorder_status()
        logger.info(f'config recorder response:{config_recorder_response}')
        try:
            resource_groups_response = resource_groups_client.get_group(
                GroupName="sumologic"
            )
            if 'Group' in resource_groups_response or len(resource_groups_response['Group'])>=1:
                resource_group_arn = resource_groups_response['Group']['GroupArn']
                logger.info(f"Resource group arn: {resource_group_arn}")
                tags_response = resource_groups_client.get_tags(
                    Arn=f"{resource_group_arn}"
                )
                logger.info(f"Tags response: {tags_response}")
                if len(tags_response["Tags"])>=1:
                    if "disable-awsconfig-when-remove-cfn" in tags_response["Tags"]:
                        if "true" in tags_response["Tags"]["disable-awsconfig-when-remove-cfn"]:
                            config_recorder_response = session_config.delete_configuration_recorder(
                                ConfigurationRecorderName='default'
                            )
                    if "remove-s3-in-delivery-channel-when-remove-cfn" in tags_response["Tags"]:
                        if "true" in tags_response["Tags"]["remove-s3-in-delivery-channel-when-remove-cfn"]:
                            response = session_config.put_delivery_channel(
                                DeliveryChannel={
                                    "name":f"default",
                                    "s3BucketName": "",
                                    "configSnapshotDeliveryProperties": {
                                        "deliveryFrequency":"TwentyFour_Hours"
                                    }
                                }
                            )
                    if "stop-delivery-channel-when-remove-cfn" in tags_response["Tags"]:        
                        if "true" in tags_response["Tags"]["stop-delivery-channel-when-remove-cfn"]:
                            response = session_config.stop_configuration_recorder(
                                ConfigurationRecorderName="default"
                            )
                response = resource_groups_client.delete_group(GroupName="sumologic") 
        except Exception as exc: 
            logger.error(f'Delete config recorder error:{exc}')                

def is_region_available(region):

    regional_sts = boto3.client('sts', region_name=region)
    try:
        regional_sts.get_caller_identity()
        return True
    except ClientError as error:
        if "InvalidClientTokenId" in str(error):
            logger.info(f"Region: {region} is not available")
            return False
        else:
            logger.error(f"{error}") 

def get_available_service_regions(user_regions: str, aws_service: str) -> list:
    available_regions = []
    try:
        if user_regions.strip():
            logger.info(f"USER REGIONS: {str(user_regions)}")
            service_regions = [value.strip() for value in user_regions.split(",") if value != '']
        else:
            service_regions = boto3.session.Session().get_available_regions(
                aws_service
            )
        logger.info(f"SERVICE REGIONS: {service_regions}")
    except ClientError as ce:
        logger.error(f"get_available_service_regions error: {ce}")
        raise ValueError("Error getting service regions")
    
    for region in service_regions:
        if is_region_available(region):
            available_regions.append(region)

    set_res = set(available_regions)
    logger.info(f"AVAILABLE REGIONS: {list(set_res)}")

    return list(set_res)

def is_region_available(region):

    regional_sts = boto3.client('sts', region_name=region)
    try:
        regional_sts.get_caller_identity()
        return True
    except ClientError as error:
        if "InvalidClientTokenId" in str(error):
            logger.info(f"Region: {region} is not available")
            return False
        else:
            logger.error(f"{error}") 

def process_event_organizations(event: dict) -> None:
    """Process Organizations event.
    Args:
        event: event data
    """
    event_info = {"Event": event}
    logger.info(event_info)
    params = get_validated_parameters({})

    AllSupported = (params.get("ALL_SUPPORTED", "false")).lower() in "true"
    IncludeGlobalResourceTypes = (params.get("INCLUDE_GLOBAL_RESOURCE_TYPES", "false")).lower() in "true" 
    ResourceTypes = params["RESOURCE_TYPES"]
    Frequency = params["FREQUENCY"]
    ConfigBucket = params["CONFIG_BUCKET"]  
    config_role_name = params["CONFIG_ROLE_NAME"]
    config_assume_role_name = params["CONFIG_ASSUME_ROLE_NAME"]

    logger.info(f'detail: {event["detail"]}')

    if event["detail"]["eventName"] == "AcceptHandShake" and event["responseElements"]["handshake"]["state"] == "ACCEPTED":
        for party in event["responseElements"]["handshake"]["parties"]:
            if party["type"] == "ACCOUNT":
                aws_account_id = party["id"]
                available_regions = get_available_service_regions(params["ENABLED_REGIONS"],"config")
                RoleARN = f'arn:aws:iam::{aws_account_id}:role/{config_role_name}'
                sleep(300)
                create_account_config(aws_account_id,available_regions,config_assume_role_name,RoleARN,AllSupported,IncludeGlobalResourceTypes,ResourceTypes,Frequency,ConfigBucket)
                break
    elif event["detail"]["eventName"] == "CreateAccountResult":
        aws_account_id = event["detail"]["serviceEventDetails"]["createAccountStatus"]["accountId"]
        available_regions = get_available_service_regions(params["ENABLED_REGIONS"],"config")
        RoleARN = f'arn:aws:iam::{aws_account_id}:role/{config_role_name}'
        logger.info(f'Create account: {aws_account_id}, regions: {available_regions}, RoleARN: {RoleARN}')
        sleep(300)
        create_account_config(aws_account_id,available_regions,config_assume_role_name,RoleARN,AllSupported,IncludeGlobalResourceTypes,ResourceTypes,Frequency,ConfigBucket)
    elif event["detail"]["eventName"] == "RemoveAccountFromOrganization":
        
        aws_account_id = event["detail"]["requestParameters"]["accountId"]
        available_regions = get_available_service_regions(params["ENABLED_REGIONS"],"config")
        RoleARN = f'arn:aws:iam::{aws_account_id}:role/{config_role_name}'
        logger.info(f'Remove account: {aws_account_id}, regions: {available_regions}, RoleARN: {RoleARN}')
        delete_account_config(aws_account_id,available_regions,config_assume_role_name)
    else:
        logger.info("Organization event does not match expected values.")
    return None