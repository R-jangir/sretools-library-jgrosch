import base64
import boto3
import docker
import logging


# ----------------------------------------------------------
#
# pull_image
#
# ----------------------------------------------------------
def pull_image(docker_client: docker.client.DockerClient,
               auth_token: dict,
               image_name: str) -> docker.models.images.Image:
    """
    Pull docker image from ecr to local.

    Args:
        docker_client: docker client
        auth_token: ecr authorization token
        image_name: the name of the docker image (for example batu:latest)

    Returns:
        an instance of docker.models.images.Image

    """
    username, password = base64.b64decode(
        auth_token['authorizationData'][0]['authorizationToken']
    ).decode().split(':')

    auth_config = {'username': username, 'password': password}
    registry = auth_token['authorizationData'][0]['proxyEndpoint']
    docker_client.login(username=username, password=password, registry=registry)
    pull_name = f"{registry.replace('https://', '')}/{image_name}"
    logging.info(f"Pulling docker image {pull_name}...")
    image = docker_client.images.pull(pull_name, auth_config=auth_config)

    return image


# ----------------------------------------------------------
#
# push_image
#
# ----------------------------------------------------------
def push_image(docker_client: docker.client.DockerClient,
               auth_token: dict,
               image: docker.models.images.Image,
               image_name: str) -> str:
    """
    Push a local image to target ecr.

    Args:
        docker_client: docker client
        auth_token: target ecr authorization token
        image: a docker image from local
        image_name: the name of the docker image (for example batu:latest)

    Returns:
        The full name of the image in target ecr.

    """
    username, password = base64.b64decode(
        auth_token['authorizationData'][0]['authorizationToken']
        ).decode().split(':')
    
    auth_config = {'username': username, 'password': password}
    registry = auth_token['authorizationData'][0]['proxyEndpoint']
    push_name = f"{registry.replace('https://', '')}/{image_name}"
    image.tag(push_name)

    logging.info(f"Pushing docker image {push_name}...")
    docker_client.images.push(push_name, auth_config=auth_config)

    return push_name


# ----------------------------------------------------------
#
# copy_image
#
# ----------------------------------------------------------
def copy_image(source_session: boto3.session.Session,
               target_session: boto3.session.Session,
               image_name: str, repository: str = '') -> str:
    """
    Copy a docker image from source ecr to target ecr.

    Args:
        source_session: the boto3 session for accessing source ecr
        target_session: the boto3 session for accessing target ecr
        image_name: the name of the docker image (for example batu:latest)
        repository: the repository needs to be created

    Returns:
        The full name of the image in target ecr.

    """
    source_client = source_session.client('ecr')
    source_token = source_client.get_authorization_token()

    docker_client = docker.from_env()

    image = pull_image(docker_client, source_token, image_name)

    target_client = target_session.client('ecr')
    target_token = target_client.get_authorization_token()
    target_registry = target_token['authorizationData'][0]['proxyEndpoint']

    image.tag(f"{target_registry.replace('https://', '')}/{image_name}")

    if repository:
        target_client.create_repository(repositoryName=repository)

    return push_image(docker_client, target_token, image, image_name)
