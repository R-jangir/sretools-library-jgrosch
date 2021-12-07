import boto3
import logging
import time
import yaml

from botocore.exceptions import ClientError
from kubernetes import client, config
from kubernetes.client.rest import ApiException

#from modules import grv, utils

ASSUME_CLUSTER_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}


ASSUME_NODEGROUP_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

ECR_ACCESS_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        }
    ]
}


# ----------------------------------------------------------
#
# get_eks_status
#
# ----------------------------------------------------------
def get_eks_status(cluster_name: str) -> dict:
    """
    Return the status of a EKS cluster.

    Args:
        cluster_name: cluster name
        
    Returns:
        status dict of the response or exception dict
    """
    client = boto3.client('eks')
    try:
        response = client.describe_cluster(name=cluster_name)
    except ClientError as e:
        return e.response
    return response['cluster']


# ----------------------------------------------------------
#
# get_eks_nodegroup_status
#
# ----------------------------------------------------------
def get_eks_nodegroup_status(cluster_name: str, node_group_name: str) -> dict:
    """
    Return the status of a EKS nodegroup.

    Args:
        cluster_name: the name of the cluster
        node_group_name: The name of the nodegroup
        
    Returns:
        status dict of the response or exception dict
    """
    if not cluster_name or not node_group_name:
        return {'Error': "Invalid cluster name or nodegroup name"}

    client = boto3.client('eks')
    try:
        response = client.describe_nodegroup(
            clusterName=cluster_name,
            nodegroupName=node_group_name
        )
        return response['nodegroup']
    except ClientError as e:
        return e.response


# ----------------------------------------------------------
#
# create_eks
#
# ----------------------------------------------------------
def create_eks(cluster_prefix: str, gravitar: str, eks_version: str = '1.20') -> dict:
    """
    Create an EKS cluster.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        eks_version: eks version. Defaults to '1.20'.
        
    Returns:
        status dict of the response or exception dict
    """
    eks_name = f"{cluster_prefix}-{gravitar.replace('.', '-')}"

    status = get_eks_status(eks_name)

    if 'Error' in status:
        # Create the cluster when it does not exist.
        eks_cluster_role = 'EKSClusterRole'
        eks_cluster_policy_arns = ['arn:aws:iam::aws:policy/AmazonEKSClusterPolicy']
        eks_sg_name = f"{cluster_prefix}_eks.{gravitar}"

        vpc_id = grv.get_vpc_id(gravitar)
        eks_sg_id = grv.check_if_sg(eks_sg_name)
        if not eks_sg_id:
            eks_sg_id = grv.create_grv_sg(sg_name=eks_sg_name, vpc_id=vpc_id)

        client = boto3.client('eks')

        role_status = grv.find_role(eks_cluster_role)

        if role_status:
            role_to_use = role_status['Role']['Arn']
        else:
            role_to_use = grv.create_role(role_name=eks_cluster_role,
                                          policy_arns=eks_cluster_policy_arns,
                                          assume_policy=ASSUME_CLUSTER_ROLE_POLICY_DOCUMENT,
                                          custom_policy=ECR_ACCESS_POLICY_DOCUMENT)

        core_subnets = grv.find_grv_subnets(gravitar, "core")
        print(f'Creating Cluster {eks_name}...')
        response = client.create_cluster(
            name=eks_name.replace(".", "-"),
            version=eks_version,
            roleArn=role_to_use,
            resourcesVpcConfig={
                'subnetIds': core_subnets,
                'securityGroupIds': [eks_sg_id],
                'endpointPublicAccess': True
            },
            tags={
                'grv_name': gravitar,
            }
        )

        status = response['cluster']

        while 'CREATING' == status['status']:
            print(f'Waiting for the cluster {eks_name} to be active.')
            time.sleep(120)
            status = get_eks_status(eks_name)

        print(f"Cluster {eks_name} is created!")
        return status
    elif 'CREATING' == status['status']:
        while 'CREATING' == status['status']:
            print(f'Waiting for the cluster {eks_name} to be active.')
            time.sleep(120)
            status = get_eks_status(eks_name)
        return status
    else:
        print(f'Cluster {eks_name} already exists, status: {status["status"]}')
        return status


# ----------------------------------------------------------
#
# create_eks_nodegroup
#
# ----------------------------------------------------------
def create_eks_nodegroup(cluster_prefix: str, gravitar: str, nodes: int = 4,
                         instance_type: str = 't3.medium', size: int = 20) -> dict:
    """
    Create an EKS nodegroup for the cluster.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        nodes: the number of nodes
        instance_type: the type of instance, default is 't3.medium'
        size: the gibibyte size of the disk, default is 20
        
    Returns:
        status dict of the response or exception dict
    """
    eks_name = f"{cluster_prefix}-{gravitar.replace('.', '-')}"
    eks_nodegroup_name = f"{cluster_prefix}_nodegroup-{gravitar.replace('.', '-')}"

    status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    if 'Error' in status:
        eks_node_instance_role = 'EKSNodeInstanceRole'
        eks_node_instance_policy_arns = ['arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy',
                                         'arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
                                         'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly']

        nodegroup_subnets = grv.find_grv_subnets(gravitar, "core")
        ssh_net_sg_id = grv.check_if_sg(f"ssh_inet.{gravitar}")

        role_status = grv.find_role(eks_node_instance_role)

        if role_status:
            role_to_use = role_status['Role']['Arn']
        else:
            role_to_use = grv.create_role(role_name=eks_node_instance_role,
                                          policy_arns=eks_node_instance_policy_arns,
                                          assume_policy=ASSUME_NODEGROUP_ROLE_POLICY_DOCUMENT)

        eks_client = boto3.client('eks')
        print(f'Creating nodegroup {eks_nodegroup_name}...')
        response = eks_client.create_nodegroup(
            clusterName=eks_name,
            nodegroupName=eks_nodegroup_name,
            scalingConfig={
                'minSize': nodes,
                'maxSize': nodes,
                'desiredSize': nodes
            },
            diskSize=size,
            subnets=nodegroup_subnets,
            instanceTypes=[instance_type],
            amiType='AL2_x86_64',
            remoteAccess={
                'ec2SshKey': f'bootstrap.{gravitar}',
                'sourceSecurityGroups': [ssh_net_sg_id]
            },
            nodeRole=role_to_use,
            tags={
                'grv_name': gravitar
            },
            capacityType='ON_DEMAND',
        )

        status = response['nodegroup']

        while 'CREATING' == status['status']:
            print(f'Waiting for nodegroup {eks_nodegroup_name} to be active')
            time.sleep(120)
            status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    elif 'CREATING' == status['status']:
        while 'CREATING' == status['status']:
            print(f'Waiting for nodegroup {eks_nodegroup_name} to be active')
            time.sleep(120)
            status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    return status


# ----------------------------------------------------------
#
# delete_eks
#
# ----------------------------------------------------------
def delete_eks(cluster_prefix: str, gravitar: str) -> dict:
    """
    Delete EKS cluster with given cluster name.

    Args:
        cluster_prefix: name of the eks to be deleted
        gravitar: name of gravitar
        
    Returns:
        status dict of the response or exception dict
    """
    eks_name = f"{cluster_prefix}-{gravitar.replace('.', '-')}"
    eks_sg_name = f"{cluster_prefix}_eks.{gravitar}"

    status = get_eks_status(eks_name)

    if 'Error' in status:
        grv.delete_grv_sg(eks_sg_name)
        return status

    if 'DELETING' == status['status']:
        while 'Error' not in status and 'DELETING' == status['status']:
            print(f'Waiting for eks {eks_name} to be deleted.')
            time.sleep(30)
            status = get_eks_status(eks_name)
    else:
        client = boto3.client('eks')
        print(f'Deleting eks {eks_name}...')
        response = client.delete_cluster(name=eks_name)
        status = response['cluster']

        while 'Error' not in status and 'DELETING' == status['status']:
            print(f'Waiting for eks {eks_name} to be deleted.')
            time.sleep(30)
            status = get_eks_status(eks_name)

    grv.delete_grv_sg(eks_sg_name)
    return status


# ----------------------------------------------------------
#
# delete_eks_nodegroup
#
# ----------------------------------------------------------
def delete_eks_nodegroup(cluster_prefix: str, gravitar: str) -> dict:
    """
    Delete eks nodegroup for the cluster.

    Args:
        cluster_prefix: the prefix of cluster
        gravitar: the name of gravitar
        
    Returns:
        status dict of the response or exception dict
    """
    eks_name = f"{cluster_prefix}-{gravitar.replace('.', '-')}"
    eks_nodegroup_name = f"{cluster_prefix}_nodegroup-{gravitar.replace('.', '-')}"

    status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)

    if 'Error' in status:
        return status

    if 'DELETING' == status['status']:
        while 'Error' not in status and 'DELETING' == status['status']:
            print(f'Waiting for nodegroup {eks_nodegroup_name} to be deleted.')
            time.sleep(30)
            status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)
            logging.debug(status)
    else:
        eks_client = boto3.client('eks')
        response = eks_client.delete_nodegroup(
            clusterName=eks_name,
            nodegroupName=eks_nodegroup_name
        )

        status = response['nodegroup']

        while 'Error' not in status and 'DELETING' == status['status']:
            print(f'Waiting for nodegroup {eks_nodegroup_name} to be deleted.')
            time.sleep(30)
            status = get_eks_nodegroup_status(eks_name, eks_nodegroup_name)
            logging.debug(status)

    logging.debug(status)
    return status


# ----------------------------------------------------------
#
# list_eks
#
# ----------------------------------------------------------
def list_eks(gravitar='') -> list:
    """
    Return the cluster info as list

    Args:
        gravitar: the name of gravitar
        
    Returns:
        List of EKS clusters, or empty list if there is no cluster.
    """
    client = boto3.client('eks')
    response = client.list_clusters()

    if not gravitar:
        return response['clusters']

    suffix = gravitar.replace('.', '-')
    gravitar_clusters = []
    for cluster in response['clusters']:
        if cluster.endswith(suffix):
            gravitar_clusters.append(cluster)
    return gravitar_clusters


# ----------------------------------------------------------
#
# info_eks
#
# ----------------------------------------------------------
def info_eks(cluster_name: str) -> dict:
    """
    Return the info of an EKS cluster as a dict.

    Args:
        cluster_name: cluster name
        
    Returns:
        eks dict (with nodegroups) or empty dict
    """
    client = boto3.client('eks')
    try:
        response = client.describe_cluster(name=cluster_name)
    except ClientError as e:
        return {}

    eks_info = response['cluster']

    res = client.list_nodegroups(clusterName=cluster_name)
    eks_info['nodegroups'] = res['nodegroups']
    return eks_info


# ----------------------------------------------------------
#
# info_eks_nodegroup
#
# ----------------------------------------------------------
def info_eks_nodegroup(cluster_name: str, nodegroup: str) -> dict:
    """
    Return the info of an EKS nodegroup as a dict.

    Args:
        cluster_name: the name of the cluster
        nodegroup: The name of the nodegroup
        
    Returns:
        nodegroup dict or empty dict
    """
    if not cluster_name or not nodegroup:
        return {}

    client = boto3.client('eks')
    response = client.list_nodegroups(clusterName=cluster_name)

    if nodegroup not in response['nodegroups']:
        return {}

    response = client.describe_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup,
    )

    return response['nodegroup']


# ----------------------------------------------------------
#
# apply_awsauth_configmap
#
# ----------------------------------------------------------
def apply_awsauth_configmap(cluster_prefix: str, gravitar: str):
    """
    Apply AWS auth configmap to the EKS context.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        
    Returns:
        bool
    """
    if not cluster_prefix or not gravitar:
        return False

    cluster_name = f'{cluster_prefix}-{gravitar.replace(".", "-")}'
    arcade_session = utils.setup_arcade_session(arcade_name=gravitar)
    eks_admin_role = 'EKSAdminRole'

    # This is used when the EKS cluster is initially Created
    # use load_arcade_k8s_config for all other k8s configuration
    eks = arcade_session.client('eks')
    try:
        response = eks.describe_cluster(name=cluster_name)
    except ClientError as e:
        logging.warning(f"Cluster error: {e}")
        return False
    context_cert_data = response["cluster"]["certificateAuthority"]["data"]
    context_server = response["cluster"]["endpoint"]
    context_arn = response["cluster"]["arn"]
    context_name = response["cluster"]["name"]
    context_region = context_arn.split(":")[3]

    iam_client = arcade_session.client('iam')
    role_res = iam_client.get_role(RoleName=eks_admin_role)
    eksadminrolearn = role_res['Role']['Arn']

    context_dict_yaml = f"""
apiVersion: v1
kind: Config
preferences: {{}}
current-context: {context_name}
clusters:
- cluster:
    certificate-authority-data: {context_cert_data}
    server: {context_server}
  name: {context_arn}
contexts:
- context:
    cluster: {context_arn}
    user: {context_arn}
  name: {context_name}
users:
- name: {context_arn}
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      args:
      - eks
      - get-token
      - --region
      - {context_region}
      - --cluster-name
      - {context_name}
      command: aws
"""

    contexts = {}
    contexts['creator'] = yaml.safe_load(context_dict_yaml)
    contexts['role'] = yaml.safe_load(context_dict_yaml)
    contexts['role']['users'][0]['user']['exec']['args'].append('--role-arn')
    contexts['role']['users'][0]['user']['exec']['args'].append(eksadminrolearn)

    grv_info = grv.get_gravitar_info(gravitar)
    vpc_id = list(grv_info['vpc'].keys())[0]
    owner_id = grv_info['vpc'][vpc_id]['OwnerId']

    eks_node_instance_role = 'EKSNodeInstanceRole'

    # 4 braces are necessary to escape formatted text braces.
    awsauth_configmap_yaml = f"""
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: arn:aws:iam::{owner_id}:role/{eks_node_instance_role}
      username: system:node:{{{{EC2PrivateDNSName}}}}
      groups:
        - system:bootstrappers
        - system:nodes
    - rolearn: arn:aws:iam::{owner_id}:role/Amazon{eks_admin_role}
      username: {eks_admin_role}:{{{{SessionName}}}}
      groups:
        - system:masters
    - rolearn: arn:aws:iam::{owner_id}:role/{eks_admin_role}
      username: Amazon{eks_admin_role}:{{{{SessionName}}}}
      groups:
        - system:masters
"""

    awsauth_configmap = yaml.safe_load(awsauth_configmap_yaml)

    for entity in ['role', 'creator']:
        config.load_kube_config_from_dict(contexts[entity])
        v1 = client.CoreV1Api()

        try:
            response = v1.create_namespaced_config_map(
                namespace="kube-system",
                body=awsauth_configmap,
            )
            logging.info(f"Created aws-auth ConfigMap by {entity}")
            return True
        except ApiException as e:
            if e.status == 409:
                api_response = v1.replace_namespaced_config_map(
                    name=awsauth_configmap['metadata']['name'],
                    namespace=awsauth_configmap['metadata']['namespace'],
                    body=awsauth_configmap,
                )
                logging.info(f"Replaced aws-auth ConfigMap by {entity}")
                return True
            if e.status == 401:
                continue
            logging.warning(e)
            raise e

    return False
