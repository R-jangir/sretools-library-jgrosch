import boto3
import time
import os, sys
from botocore.exceptions import ClientError

from sretools import grv, utils

# ----------------------------------------------------------
#
# find_alb_arn
#
# ----------------------------------------------------------
def find_alb_arn(alb_name: str) -> str:
    """
    Find the ALB Arn.

    Args:
        alb_name: name of alb
        
    Returns:
        ARN of the given alb, or empty string
    """
    client = boto3.client('elbv2')
    try:
        response = client.describe_load_balancers(Names=[alb_name])
        return response['LoadBalancers'][0]['LoadBalancerArn']
    except ClientError as e:
        return ''

    # End of find_alb_arn


# ----------------------------------------------------------
#
# alb_create
#
# ----------------------------------------------------------
def alb_create(grv_name: str,
               public: bool) -> dict:
    """
    Create an Application Load Balancer.

    Args:
        grv_name: gravitar name
        public: is this a public or internal alb
        
    Returns:
        dict of alb status response or exception dict
    """
    client = boto3.client('elbv2')

    vpc_id = grv.get_vpc_id(grv_name)

    alb_dict = get_alb_dict(grv_name, public)

    subnets = grv.find_grv_subnets(grv_name, alb_dict['subnet_name'])

    if not subnets:
        return {'Code': 'failed',
                'Reason': f"{alb_dict['subnet_name']} subnets do not exists for {grv_name}"}

    alb_sgs = []
    alb_sg_id = grv.check_if_sg(alb_dict['sg_name'])

    if not alb_sg_id:
        alb_sg_id = grv.create_grv_sg(sg_name=alb_dict['sg_name'], vpc_id=vpc_id)

    alb_sgs.append(alb_sg_id)

    if alb_dict['subnet_name'] == 'wan':
        alb_nat_sg_id = grv.check_if_sg(f"nat.{grv_name}")
        alb_sgs.append(alb_nat_sg_id)

    response = client.create_load_balancer(
        Name=alb_dict['name'],
        Subnets=subnets,
        SecurityGroups=alb_sgs,
        Scheme=alb_dict['scheme'],
        Tags=[
            {
                'Key': 'Name',
                'Value': alb_dict['name'],
            },
            {
                'Key': 'grv_name',
                'Value': grv_name,
            }
        ],
        Type='application',
    )

    alb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    status = get_alb_status(alb_dict['name'])

    while 'provisioning' == status['State']['Code']:
        print(f"Waiting for the alb {alb_dict['name']} to be active")
        time.sleep(20)
        status = get_alb_status(alb_dict['name'])

    print(f"{alb_dict['name']} ALB Created with scheme {alb_dict['scheme']}")

    target = status['DNSName']
    source = f"{target.split('-')[0]}_alb.{grv_name}"
    utils.add_arcade_cname(grv_name, source, target)

    try:
        client.create_listener(
            DefaultActions=[
                {
                    'Type': 'fixed-response',
                    'FixedResponseConfig': {
                        'StatusCode': '503',
                        'ContentType': 'text/plain'
                    },
                },
            ],
            LoadBalancerArn=alb_arn,
            Port=80,
            Protocol='HTTP',
        )
    except ClientError as e:
        return e.response

    return status
    # End of alb_create


# ----------------------------------------------------------
#
# delete_alb
#
# ----------------------------------------------------------
def delete_alb(grv_name: str,
               public: bool) -> bool:
    """
    Delete an ALB.

    Args:
        grv_name: gravitar name to delete ALBs from
        public: is this a public or internal alb
        
    Returns:
        True if alb is deleted or not available, or False
    """
    client = boto3.client('elbv2')

    alb_dict = get_alb_dict(grv_name, public)

    utils.delete_arcade_cname(grv_name, alb_dict['sg_name'])

    alb_arn = find_alb_arn(alb_dict['name'])

    if not alb_arn:
        return True

    response = client.delete_load_balancer(LoadBalancerArn=alb_arn)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        return False

    print(f"Deleted alb {alb_dict['name']}")
    while True:
        if not grv.check_if_sg(alb_dict['sg_name']):
            break
        try:
            grv.delete_grv_sg(alb_dict['sg_name'])
        except ClientError as e:
            if e.response['Error']['Code'] != 'DependencyViolation':
                raise e
        time.sleep(10)
    print(f"Deleted security group {alb_dict['sg_name']}")

    return True
    # End of delete_alb

# ----------------------------------------------------------
#
# get_alb_status
#
# ----------------------------------------------------------
def get_alb_status(alb_name: str) -> dict:
    """
    Get the alb status.

    Args:
        alb_name: alb name
        
    Returns:
        status dict of the response or exception dict
    """
    client = boto3.client('elbv2')
    try:
        response = client.describe_load_balancers(Names=[alb_name])
    except ClientError as e:
        return e.response

    return response['LoadBalancers'][0]

    # End of get_alb_status


# ----------------------------------------------------------
#
# find_sg_attached
#
# ----------------------------------------------------------
def find_sg_attached(alb_name: str) -> str:
    """
    Return the security group attached to a alb.

    Args:
        alb_name: the name of the alb
        
    Returns:
        the id of security group, or empty string
    """
    client = boto3.client('elbv2')
    try:
        response = client.describe_load_balancers(Names=[alb_name])
        return response['LoadBalancers'][0]['SecurityGroups'][0]
    except ClientError as e:
        return ''

    # End of find_sg_attached


# ----------------------------------------------------------
#
# alb_connect_sg
#
# ----------------------------------------------------------
def alb_connect_sg(grv_name: str,
                   cluster_name: str,
                   public: bool) -> bool:
    """
    Connect gravitar security group to alb.

    Args:
        grv_name: gravitar name
        cluster_name: the name of eks cluster
        public: is this a public or internal alb
        
    Returns:
        success as a bool
    """
    client = boto3.client('elbv2')
    alb_dict = get_alb_dict(grv_name, public)

    alb_arn = find_alb_arn(alb_dict['name'])
    if not alb_arn:
        return False

    eks_sg_filter = f"eks-cluster-sg-{cluster_name}"
    eks_sg_id = grv.check_if_sg(eks_sg_filter)

    if not eks_sg_id:
        return False

    response = client.describe_load_balancers(LoadBalancerArns=[alb_arn])

    alb_sgs = response['LoadBalancers'][0]['SecurityGroups']
    if eks_sg_id in alb_sgs:
        return True

    alb_sgs.append(eks_sg_id)
    response = client.set_security_groups(
        LoadBalancerArn=alb_arn,
        SecurityGroups=alb_sgs
    )

    return True


# ----------------------------------------------------------
#
# alb_info
#
# ----------------------------------------------------------
def alb_info(grv_name: str) -> dict:
    """
    Get alb information.

    Args:
        grv_name: gravitar name
        
    Returns:
        a dictionary containing information of load balancers and security groups
    """
    client = boto3.client('elbv2')
    alb_public = get_alb_dict(grv_name, True)['name']
    alb_private = get_alb_dict(grv_name, False)['name']
    response = client.describe_load_balancers(Names=[alb_public, alb_private])

    alb_info = {'loadbalancers': {}}
    for loadbalancer in response["LoadBalancers"]:
        tags_response = client.describe_tags(
            ResourceArns=[loadbalancer["LoadBalancerArn"]]
        )
        name = loadbalancer["LoadBalancerName"]
        alb_info["loadbalancers"][name] = loadbalancer
        alb_info["loadbalancers"][name]['Tags'] = tags_response['TagDescriptions'][0]['Tags']
        alb_info["loadbalancers"][name]['TagSane'] = \
            utils.aws_tags_dict(tags_response['TagDescriptions'][0]['Tags'])

    alb_sg_filter = f'_alb.{grv_name}'
    ec2_client = boto3.client('ec2')
    ec2_response = ec2_client.describe_security_groups(
        Filters=[
            {
                'Name': 'group-name',
                'Values': [alb_sg_filter]
            },
        ],
        DryRun=False
    )
    alb_info['securitygroups'] = {}
    for securitygroup in ec2_response['SecurityGroups']:
        alb_info['securitygroups'][securitygroup['GroupId']] = securitygroup
        alb_info['securitygroups'][securitygroup['GroupId']]['TagSane'] = \
            utils.aws_tags_dict(securitygroup['Tags'])
    return alb_info


# ----------------------------------------------------------
#
# get_alb_dict
#
# ----------------------------------------------------------
def get_alb_dict(gravitar: str,
                 public: bool) -> dict:
    """
    Return alb name dictionary for a gravitar and public flag.

    Args:
        gravitar: the name of the gravitor
        public: the bool flag indicating whether it is public or private
        
    Returns:
        A dictionary in the format of {name, sg_name, schema, subnets}
    """
    # albs have a specific naming scheme.
    # Security groups are based on unmodified gravitar name for consistency
    # with Gravitar security groups.
    alb_gravitar = gravitar.replace('_', '').replace('.', '-')
    prefix = 'public' if public else 'private'
    scheme = 'internet-facing' if public else 'internal'
    subnet_name = 'wan' if public else 'core'

    alb_dict = {'name': f"{prefix}-{alb_gravitar}",
                'sg_name': f'{prefix}_alb.{gravitar}',
                'scheme': scheme,
                'subnet_name': subnet_name}
    return alb_dict
