import base64
import boto3
import logging
import time
import yaml

from botocore.exceptions import ClientError
from modules import grv


# ----------------------------------------------------------
#
# get_msk_status
#
# ----------------------------------------------------------
def get_msk_status(cluster_name: str) -> dict:
    """
    Return the status of a MSK cluster.

    Args:
        cluster_name: cluster name
        
    Returns:
        status dict of the response or exception dict
    """
    client = boto3.client('kafka')
    response = client.list_clusters(ClusterNameFilter=cluster_name)
    if not response['ClusterInfoList']:
        return {}
    logging.debug(response['ClusterInfoList'])
    return response['ClusterInfoList'][0]


# ----------------------------------------------------------
#
# get_msk_configuration
#
# ----------------------------------------------------------
def get_msk_configuration(cluster_name: str) -> dict:
    """
    Return the status of a MSK configuration.

    Args:
        cluster_name: the name of the cluster
        
    Returns:
        status dict of the response or empty dict
    """
    if not cluster_name:
        return {}

    client = boto3.client('kafka')
    response = client.list_configurations()

    for configuration in response['Configurations']:
        if configuration['Name'].endswith(cluster_name):
            return configuration
    return {}


# ----------------------------------------------------------
#
# create_msk
#
# ----------------------------------------------------------
def create_msk(cluster_prefix: str,
               gravitar: str,
               instance_type: str,
               brokers_per_az: int,
               ebs_size: int,
               kafka_version: str = '2.6.2') -> dict:
    """
    Create an EKS cluster.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        instance_type: kafka instance type kafka.m5.large
        brokers_per_az: brokers per az
        ebs_size: size of the ebs volume per broker
        kafka_version: kafka version. Defaults to '2.6.2'.
        
    Returns:
        status dict of the response or exception dict
    """
    msk_name = f"{cluster_prefix}-{gravitar.replace('_', '').replace('.', '-')}"

    status = get_msk_status(msk_name)

    if not status:
        # Create the cluster when it does not exist.
        msk_sg_name = f"{cluster_prefix}_msk.{gravitar}"

        vpc_id = grv.get_vpc_id(gravitar)
        msk_sg_id = grv.check_if_sg(msk_sg_name)
        if not msk_sg_id:
            msk_sg_id = grv.create_grv_sg(sg_name=msk_sg_name, vpc_id=vpc_id)

        client = boto3.client('kafka')

        core_subnets = grv.find_grv_subnets(gravitar, "core")
        number_of_brokers = len(core_subnets) * brokers_per_az
        msk_config = get_msk_configuration(msk_name)
        if not msk_config:
            return msk_config
        msk_config_arn = msk_config['Arn']
        msk_config_rev = msk_config['LatestRevision']['Revision']
        print(f'Creating MSK cluster {msk_name}...')
        status = client.create_cluster(
            BrokerNodeGroupInfo={
                'BrokerAZDistribution': 'DEFAULT',
                'ClientSubnets': core_subnets,
                'InstanceType': 'kafka.m5.large',
                'StorageInfo': {
                    'EbsStorageInfo': {
                        'VolumeSize': ebs_size
                    }
                },
                'SecurityGroups': [msk_sg_id]
            },
            ClusterName=msk_name,
            ConfigurationInfo={
                'Arn': msk_config_arn,
                'Revision': msk_config_rev
            },
            EncryptionInfo={
                'EncryptionInTransit': {
                    'ClientBroker': 'TLS_PLAINTEXT',
                    'InCluster': True
                }
            },
            EnhancedMonitoring='PER_TOPIC_PER_BROKER',
            KafkaVersion=kafka_version,
            NumberOfBrokerNodes=number_of_brokers,
            Tags={
                'grv_name': gravitar,
            }
        )

        while 'CREATING' == status['State']:
            print(f'Waiting for the MSK cluster {msk_name} to be active.')
            time.sleep(120)
            status = get_msk_status(msk_name)

        print(f"Cluster {msk_name} is created!")
        return status
    elif 'CREATING' == status['State']:
        while 'CREATING' == status['State']:
            print(f'Waiting for the MSK cluster {msk_name} to be active.')
            time.sleep(120)
            status = get_msk_status(msk_name)
        return status
    else:
        print(f'MSK cluster {msk_name} already exists, status: {status["State"]}')
        return status


# ----------------------------------------------------------
#
# create_msk_configuration
#
# ----------------------------------------------------------
def create_msk_configuration(cluster_prefix: str,
                             gravitar: str,
                             kafka_version: str,
                             server_properties: str) -> dict:
    """
    Create an MSK configuration for the MSK cluster, if it doesn't already exist.

    Args:
        cluster_prefix: the prefix of a cluster
        gravitar: gravitar name
        kafka_version: version of kafka for this configuration
        server_properties: kafka options
        
    Returns:
        status dict of the response or get
    """
    msk_name = f"{cluster_prefix}-{gravitar.replace('_', '').replace('.', '-')}"

    status = get_msk_configuration(msk_name)

    if not status:
        msk_client = boto3.client('kafka')
        print(f'Creating MSK configuration {msk_name}...')
        status = msk_client.create_configuration(
            Description=f"Configuration for {msk_name}",
            KafkaVersions=[
                kafka_version,
            ],
            Name=msk_name,
            ServerProperties=server_properties
        )

    return status


# ----------------------------------------------------------
#
# delete_msk
#
# ----------------------------------------------------------
def delete_msk(cluster_prefix: str,
               gravitar: str) -> dict:
    """
    Delete MSK cluster with given cluster prefix.

    Args:
        cluster_prefix: name of the msk to be deleted
        gravitar: name of gravitar
        
    Returns:
        empty dict if deletion happens otherwise status is returned
    """
    msk_name = f"{cluster_prefix}-{gravitar.replace('_', '').replace('.', '-')}"
    msk_sg_name = f"{cluster_prefix}_msk.{gravitar}"

    status = get_msk_status(msk_name)

    if not status:
        grv.delete_grv_sg(msk_sg_name)
        return status

    if status and 'DELETING' == status['State']:
        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk cluster {msk_name} to be deleted.')
            time.sleep(30)
            status = get_msk_status(msk_name)
    else:
        client = boto3.client('kafka')
        print(f'Deleting msk cluster {msk_name}...')
        msk_arn = status['ClusterArn']
        status = client.delete_cluster(ClusterArn=msk_arn)

        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk cluster {msk_name} to be deleted.')
            time.sleep(30)
            status = get_msk_status(msk_name)

    grv.delete_grv_sg(msk_sg_name)
    return status


# ----------------------------------------------------------
#
# delete_msk_configuration
#
# ----------------------------------------------------------
def delete_msk_configuration(cluster_prefix: str,
                             gravitar: str) -> dict:
    """
    Delete msk nodegroup for the cluster.

    Args:
        cluster_prefix: the prefix of cluster
        gravitar: the name of gravitar
        
    Returns:
        empty dict if deletion happens otherwise status is returned
    """
    msk_name = f"{cluster_prefix}-{gravitar.replace('_', '').replace('.', '-')}"

    status = get_msk_configuration(msk_name)

    if not status:
        return status

    if status and 'DELETING' == status['State']:
        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk configuration {msk_name} to be deleted.')
            time.sleep(30)
            status = get_msk_configuration(msk_name)
            logging.debug(status)
    else:
        msk_client = boto3.client('kafka')
        msk_config_arn = status['Arn']
        status = msk_client.delete_configuration(Arn=msk_config_arn)

        while status and 'DELETING' == status['State']:
            print(f'Waiting for msk configuration {msk_name} to be deleted.')
            time.sleep(30)
            status = get_msk_configuration(msk_name)
            logging.debug(status)

    logging.debug(status)
    return status
