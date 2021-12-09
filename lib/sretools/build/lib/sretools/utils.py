import boto3
import json
import logging
import os
from sretools import storage


# Begin merge
# ----------------------------------------------------------
#
# aws_tags_dict
#
# ----------------------------------------------------------
def aws_tags_dict(tag_list: list) -> dict:
    """
    Convenience function to relieve fumbling around with AWS tag lists.

    Given a list of AWS tags, (common to most AWS object types), converts
    the list into a dict keyed by tag:Key.

    Args:
        tag_list - list of dicts from AWS API tag.

    Returns:
        dict of Key, Value pairs.  If supplied tag list contains
        no values, returns an empty dict.
    """
    if tag_list is None or not isinstance(tag_list, list):
        raise ValueError(f"tag_list should be a list of dicts, got: {tag_list}")

    return_dict = {}
    for tagd in tag_list:
        if 'Key' not in tagd or 'Value' not in tagd:
            raise ValueError(f"element of tag_list should be a tag dict, got {tagd}")
        return_dict[tagd['Key']] = tagd['Value']
    return return_dict

# ----------------------------------------------------------
#
# check_dryrun
#
# ----------------------------------------------------------
def check_dryrun(filename: str) -> bool:
    """
    Check dryrun option from os environ (GALAGA_DRYRUN)
    This function needs to be invoked by installer at
    the beginning of the main function

    Args:
        filename - the filename of the installer

    Returns:
        True if dryrun is set, else False
    """
    dryrun = os.environ.get('GALAGA_DRYRUN')

    if "1" == dryrun:
        print(f"Invoke installer {filename} with dryrun option.")
        return True
    else:
        print(f"Invoking installer {filename}.")
        return False

# ----------------------------------------------------------
#
# print_status
#
# ----------------------------------------------------------
def print_status(status: dict) -> None:
    """
    Print status dictionary to json object
    The purpose of this function is to resolve following error
    when loading json object from json string:
    TypeError: Object of type datetime is not JSON serializable

    Args:
        status: status dictionary to print
        
    Returns:
        None
    """

    print(json.dumps(status, sort_keys=False, indent=2, default=str))

# ----------------------------------------------------------
#
# add_arcade_cname
#
# ----------------------------------------------------------
def add_arcade_cname(arcade: str,
                     source: str,
                     target: str) -> bool:
    """
    Add source -> target cname record to arcade
    
    Args:
        arcade: The name of arcade
        source: Source string
        target: Target string

    Returns:
        True/False

    """
    r53 = boto3.client('route53')
    zones = r53.list_hosted_zones_by_name(DNSName=arcade)
    zone_id = zones['HostedZones'][0]['Id']
    try:
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': f'add {source} -> {target}',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': source,
                            'Type': 'CNAME',
                            'TTL': 300,
                            'ResourceRecords': [{'Value': target}]
                        }
                    }]
            })
        return True
    except Exception as e:
        logging.error(e)
        return False
    #
    
# ----------------------------------------------------------
#
# delete_arcade_cname
#
# ----------------------------------------------------------
def delete_arcade_cname(arcade: str,
                        source: str) -> None:
    """
    Delete cname start with source for an arcade

    Args:
        arcade: The name of arcade
        source: Source string

    Returns:
        None

    """
    r53 = boto3.client('route53')
    zones = r53.list_hosted_zones_by_name(DNSName=arcade)
    zone_id = zones['HostedZones'][0]['Id']
    response = r53.list_resource_record_sets(HostedZoneId=zone_id,
                                             StartRecordName=source, MaxItems='1')

    if source in response['ResourceRecordSets'][0]['Name']:
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': f'delete {source}',
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': response['ResourceRecordSets'][0]
                    }]
            })

# ----------------------------------------------------------
#
# get_account_id
#
# ----------------------------------------------------------
def get_account_id() -> str:
    """
    """
    client = boto3.client('sts')
    response = client.get_caller_identity()
    # print(json.dumps(response, sort_keys=False, indent=2, default=str))
    return response["Account"]


# ----------------------------------------------------------
#
# get_short_narc_id
#
# ----------------------------------------------------------
def get_short_narc_id(narcid: str) -> str:
    """
    Get the short narc id by using first 8 characters of asd/asteroid name
    Args:
        narcid: the original narc id
    Returns: the short narc id in string format
    """
    groups = narcid.split('-')
    groups[1] = groups[1][:8]
    groups[2] = groups[2][:8]
    return "-".join(groups)


# ----------------------------------------------------------
#
# check_if_sig
#
# ----------------------------------------------------------
def check_if_sg(sg_name: str) -> str:
    """
    Check to see if a SG is present.
    
    Args:
        sg_name: security group name
        
    Returns:
        security group id if the sg is there, empty string if not
    """
    client = boto3.client('ec2')
    response = client.describe_security_groups(
        Filters=[
            {
                'Name': 'tag:Name',
                'Values': [f"{sg_name}*"]
            }
        ]
    )

    if len(response['SecurityGroups']) != 1:
        return ""
    return response['SecurityGroups'][0]['GroupId']


# ----------------------------------------------------------
#
# setup_arcade_session
#
# ----------------------------------------------------------
def setup_arcade_session(arcade_name: str) -> boto3.session.Session:
    """
    Create AWS session with arcade region set.

    Args:

    Returns:
    """

    # figure out what region cluster/arcade lives in
    # getting location from arcade scoped bucket is faster than looking for vpc
    bucket_session = boto3.session.Session(region_name='us-east-2')
    s3_client = bucket_session.client('s3')
    buckets = storage.get_arcade_buckets(bucket_session, arcade_name)
    arcade_region = s3_client.get_bucket_location(Bucket=buckets['app'])['LocationConstraint']
    # print("----Arcade region----")
    # print(arcade_region)

    return boto3.session.Session(region_name=arcade_region)
