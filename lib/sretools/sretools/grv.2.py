import boto3
import json
import os
import logging
from botocore.exceptions import ClientError

from modules import storage


def find_iam_arn(arcade_name: str, component_name: str) -> str:
    """Finds IAM role and returns a ARN of the ROLE

    Args:
        arcade_name (str): [Name of the Arcade]
        component_name (str): [Name of the Component]

    Raises:
        Exception: []

    Returns:
        str: [description]
    """
    client = boto3.client('iam')
    arcade_trim = os.environ.get('ARCADE_NAME').split('.')[0]
    response = client.list_policies(Scope='Local', PathPrefix=f'/')
    try:
        for p in response['Policies']:
            if f'{arcade_trim}-{component_name}' in p['PolicyName']:
                logging.info(p['Arn'])
                return p['Arn']
    except Exception as e:
        logging.info(e)
        raise Exception(e)


def delete_iam_policy(ARN: str) -> bool:
    """Deletes IAM policy

    Args:
        ARN (str): [ARN of the ROLE]

    Returns:
        bool: [True if ROLE has been deleted, False if the ROLE was not deleted]
    """
    client = boto3.client('iam')
    response = client.delete_policy(PolicyArn=ARN)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logging.info(f'{ARN} Policy has been removed')
        return True
    else:
        logging.info('Failed to delete or no policy has been deleted')
        return False


def check_if_policy(arcade_name: str, component_name: str):
    """Checks IAM to see if the policy is present

    Args:
        arcade_name (str): [Name of the Arcade]
        component_name (str): [Name of the Componet]
        ex: check_if_policy(arcade_name=arcade, component_name='SecretsManager')

    Returns:
        [Bool]: [True if policy is present, False if policy is not present]
    """
    policy_list = []
    arcade_trim = arcade_name.split('.')[0]
    client =  boto3.client('iam')
    response = client.list_policies(Scope='Local', PathPrefix=f'/')
    
    for p in response['Policies']:
        if f'{arcade_trim}-{component_name}' in p['PolicyName']:
            policy_list.append(p['PolicyName'])

    if policy_list == []:
        return False
    else:
        logging.info(policy_list)
        return True


def get_vpc_cidr(vpc_id: str) -> str:
    """Get VPC cidr from vcp_id

    Args: vpc_id string: vpc_id in string format

    Returns: string: vpc cidr ex: '10.1.0.0/17'
    """
    client = boto3.client('ec2')
    response = client.describe_vpcs(VpcIds=[vpc_id])
    
    if response['Vpcs']:
        return response['Vpcs'][0]['CidrBlock']
    else:
        return ""


def get_vpc_az(vpc_id: str, subnet_ids: list) -> list:
    client = boto3.client('ec2')
    response = client.describe_subnets(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }
        ],
        SubnetIds=subnet_ids,
    )

    get_list_of_az = [x['AvailabilityZone'] for x in response['Subnets'] if response['Subnets']]

    return get_list_of_az


def get_vpc_id(grv_name: str) -> str:
    """ Get vpc id by gravitar name
    Args: string, gravitar name
    Returns: the vpc id associated with the gravitar, or empty string
    """
    if not grv_name:
        return ""

    client = boto3.client('ec2')
    response = client.describe_vpcs(
        DryRun=False,
        Filters=[{'Name': 'tag:Name', 'Values': [grv_name]}]
    )

    if response['Vpcs']:
        # there is only one vpc associated a gravitar
        return response['Vpcs'][0]['VpcId']
    else:
        return ""


def find_vpc_name(vpc_id: str) -> str:
    """Find the vpc name tag for a given vpc.
    Args: vpc_id: vpc id
    Returns: gravitar name
    """
    ec2 = boto3.resource('ec2')
    vpcs = ec2.vpcs.filter(VpcIds=[vpc_id])

    vpc = next(iter(vpcs), None)

    if vpc:
        for items in vpc.tags:
            if items['Key'] == 'Name':
                return items['Value']

    return ""


def get_grv_buckets(gravitar: str) -> dict:
    """Return the gravitar buckets as a dictionary.
    Args:
        gravitar: The name of gravitar
    Returns:
        A dictionary with key(app, infrastructure, assets): value (bucket name)
    """
    gravitar = gravitar.replace('_', '')
    s3_client = boto3.client('s3')

    bucket_dict = {}
    buckets = s3_client.list_buckets()

    for bucket in buckets['Buckets']:
        if f"{gravitar}" in bucket['Name']:
            bucket_dict[bucket['Name'].split('.')[-3]] = bucket['Name']
    return bucket_dict


def get_gravitar_info(gravitar: str) -> dict:
    """Get the gravitar info from the S3 infrastructure bucket.
    Args:
        gravitar: the name of gravitar
    Returns:
        json object if gravitar info exists, else None
    """
    grv_infra_bucket = get_grv_buckets(gravitar)['infrastructure']
    return storage.load_json(grv_infra_bucket, 'gravitar/grv_info.json')


def find_grv_subnets(gravitar: str, prefix: str = "core") -> list:
    """
    Args:
        gravitar: gravitar name
        prefix: a prefix to the gravitar name
    Returns: a list of subnet ids
    """
    value = f'{prefix}.{gravitar}'
    client = boto3.client('ec2')

    subnets = client.describe_subnets(
        Filters=[{'Name': 'tag:logical_name', "Values": [value]}]).get("Subnets", [])

    return [x['SubnetId'] for x in subnets]


def check_if_sg(sg_name: str) -> str:
    """Check to see if a SG is present.
    Args: sg_name: security group name
    Returns: security group id if the sg is there, empty string if not
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


def create_grv_sg(sg_name: str, vpc_id: str) -> str:
    """Create a sg for the use with the cluster.
    Args:
        sg_name: security group name
        vpc_id: vpc id
    Returns: security group id
    """
    client = boto3.client('ec2')

    sg_id = check_if_sg(sg_name)

    if not sg_id:
        response = client.create_security_group(
            Description=f'{sg_name}',
            GroupName=f'{sg_name}',
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": f'{sg_name}'
                        },
                        {
                            "Key": "grv_name",
                            "Value": find_vpc_name(vpc_id)
                        }
                    ]
                }
            ]
        )
        sg_id = response['GroupId']

    client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'IpProtocol': '-1',
                'FromPort': 0,
                'ToPort': 65535,
                'IpRanges': [{'CidrIp': '10.0.0.0/8', 'Description': 'Temporary inbound rule for Arcade Testing'}]
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Temporary inbound rule for Arcade Testing'}]
            }
        ]
    )
    return sg_id


def delete_grv_sg(sg_name: str):
    """Delete a security group
    Args: sg_name: security group name
    Returns: None
    """
    sg_id = check_if_sg(sg_name)
    if not sg_id:
        return

    ec2_client = boto3.client('ec2')
    ec2_client.delete_security_group(GroupId=sg_id, DryRun=False)


def find_role(role_name: str) -> dict:
    """Find a role and checks to see if it exist.
    Args:
        role_name: short name of the role
    Returns:
        dict: The role dict, or empty dict if role does not exists
    """
    client = boto3.client('iam')
    try:
        res = client.get_role(RoleName=role_name)
        return res
    except client.exceptions.NoSuchEntityException:
        return {}


def create_role(role_name: str, policy_arns: list, assume_policy, custom_policy=None) -> str:
    """Create a role and attaches the initial policy to the role.
    Args:
        role_name: the role name
        policy_arns: the arns of policy
        assume_policy: policy string
        custom_policy: custom configuration for access that is not a provided policy
    Returns: the ARN of the Role
    """
    iam_client = boto3.client('iam')

    json_object = json.dumps(assume_policy)

    if custom_policy:
        custom_policy_arn = create_policy("ECRAccessPolicy", custom_policy)
        policy_arns.append(custom_policy_arn)

    response = find_role(role_name)

    if not response:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json_object
        )

    for arn in policy_arns:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=arn,
        )
    return response['Role']['Arn']


# TODO: delete_role is not used and tested. Skip it now
# def delete_role(role_name: str, policy_arn='arn:aws:iam::aws:policy/AmazonEKSClusterPolicy') -> str:
def delete_role(role_name: str) -> str:
    """Delete a role.

    Args:
        role_name (str): [Name of the role]
        # policy_arn (str, optional): [description]. Defaults to 'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'.

    Returns:
        str: [description]
    """
    iam_client = boto3.client('iam')
    try:
        logging.info(f'{role_name} is being deleted!')
        # response_detach_policy = iam_client.detach_role_policy(
        #     RoleName=role_name, PolicyArn=policy_arn)
        # logging.info(f'{role_name} {policy_arn} has been removed!')
        response = iam_client.delete_role(RoleName=role_name)
        logging.info(f'{role_name} Role Deleted!')
        return response
    except ClientError as e:
        return e


def create_policy(policy_name, policy_document):
    """Create a AWS policy."""
    json_object = json.dumps(policy_document)
    iam_client = boto3.client('iam')
    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json_object,
        )
    except ClientError as ce:
        logging.debug(ce)
        return ce

    return response['Policy']['Arn']


def find_grv_tag(session: boto3.session.Session, arcade_name: str,
                 tag_key: str) -> str:
    """Return the tag value of a gravitar
    Args:
        session: A boto3 session for accessing client and resource
        arcade_name: The name of arcade
        tag_key: The tag key

    Returns: The tag value or empty string

    """
    client = session.client('ec2')
    response = client.describe_vpcs(
        DryRun=False,
        Filters=[{'Name': 'tag:Name', 'Values': [arcade_name]}]
    )

    if response['Vpcs']:
        for tag in response['Vpcs'][0]['Tags']:
            if tag['Key'] == tag_key:
                return tag['Value']
        return ""
    else:
        return ""


def update_grv_tag(session: boto3.session.Session, arcade_name: str,
                   tag_key: str, tag_value: str) -> str:
    """Add or update gravitar tag value.
    Args:
        session: A boto3 session for accessing client and resource
        arcade_name: The name of arcade
        tag_key: The tag key
        tag_value: The related tag value

    Returns: The tag value or empty string

    """
    client = session.client('ec2')
    response = client.describe_vpcs(
        DryRun=False,
        Filters=[{'Name': 'tag:Name', 'Values': [arcade_name]}]
    )

    if response['Vpcs']:
        vpc_id = response['Vpcs'][0]['VpcId']
        client.create_tags(
            Resources=[vpc_id],
            Tags=[
                {
                    'Key': tag_key,
                    'Value': tag_value
                }
            ]
        )
        return tag_value
    else:
        return ""

