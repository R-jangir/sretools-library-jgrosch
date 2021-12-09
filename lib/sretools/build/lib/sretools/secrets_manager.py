#!/usr/bin/env python3

import boto3
import json
import logging
import random
import secrets

from botocore.exceptions import ClientError


# ----------------------------------------------------------
#
# rds_default_creds
#
# ----------------------------------------------------------
def rds_default_creds(arcade_name: str,
                      name='rds_default_credentials',
                      length=12) -> boolean:
    """
    Generates Default RDS creds for secrets manager per arcade
    
    Args:
        arcade_name (str): [arcade name]
        name (str, optional): [name of the secret]. Defaults to 'rds_default_credentials'.
        length (int, optional): [length of password]. Defaults to 12.

    Returns:
        [bool]: [True if Secret is created, False if the Secret failed to create]
    """
    arcade_trim = arcade_name.split('.')[0]
    try:
        create_p = secrets.token_urlsafe(length)
        s_value = {
            'username': f'{arcade_trim}_admin',
            'password': create_p
        }
    
        create_rds_cred = create_secret(
            arcade_name=arcade_name,
            name=name,
            secret_value=s_value
        )
        return True
    except ClientError as e:
        print(e)
        logging.info(e)
        return False


# ----------------------------------------------------------
#
# update_secret_version
#
# ----------------------------------------------------------
def update_secret_version(arcade_name: str,
                          name: str,
                          secret_value: str,
                          versions=None) -> dict:
    """
    Puts Value with Version in Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [Name of the secret]
        secret_value (str): [The secret]
        versions ([type], optional): [A version for the secret]. Defaults to None.
        ex: update_secret_version(name="my-test-secret-str", secret_value="test-secret-str-new-version", versions=["new-version"])

    Returns:
        [dict]: [aws api return]
    """
    client = boto3.client("secretsmanager")
    kwargs = {"SecretId": f"{arcade_name}/{name}"}

    if isinstance(secret_value, dict):
        kwargs['SecretString'] = json.dumps(secret_value)

    elif isinstance(secret_value, str):
        kwargs['SecretString'] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs['SecretBinary'] = secret_value

    if versions is not None:
        kwargs['VersionStages'] = versions

    response = client.put_secret_value(**kwargs)

    return response    
    

# ----------------------------------------------------------
#
# create_secret
#
# ----------------------------------------------------------
def create_secret(arcade_name: str,
                  name: str,
                  secret_value,
                  versions=None) -> dict:
    """
    Creates a Secret In AWS Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [Name of the secret]
        secret_value : [The secret]
        versions ([type], optional): [description]. Defaults to None.
        
    Returns:
        [dict]: [Returns the ARN and Secret Name]
    """
    client = boto3.client('secretsmanager')
    kwargs = {"Name": f"{arcade_name}/{name}"}

    if isinstance(secret_value, dict):
        kwargs['SecretString'] = json.dumps(secret_value)

    elif isinstance(secret_value, str):
        kwargs['SecretString'] = secret_value

    elif isinstance(secret_value, bytes):
        kwargs['SecretBinary'] = secret_value
        
    if versions is None:
        response = client.create_secret(**kwargs)
        logging.info(response)
        return {'SecretName': response['Name'], 'SecretARN': response['ARN']}
    else:
        response = client.create_secret(**kwargs)
        logging.info(response)
        add_version = update_secret_version(
            name=name, secret_value=secret_value, 
            versions=[versions])
        return {'SecretName': add_version['Name'], 'SecretARN': add_version['ARN']}


# ----------------------------------------------------------
#
# delete_secret
#
# ----------------------------------------------------------
def delete_secret(arcade_name: str,
                  name: str,
                  without_recovery=False) -> dict:
    """
    Deletes Secret from Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [Name of the Secret]
        without_recovery (bool, optional): [Delete with no Recovery]. Defaults to False.

    Returns:
        [dict]: [aws api return]
    """
    client = boto3.client('secretsmanager')
    secret_full_path = f"{arcade_name}/{name}"
    response = client.delete_secret(SecretId=secret_full_path, ForceDeleteWithoutRecovery=without_recovery)
    logging.info(response)
    return response


# ----------------------------------------------------------
#
# get_secret
#
# ----------------------------------------------------------
def get_secret(arcade_name: str,
               name: str,
               version=None) -> str:
    """
    Gets A Secret Value from Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [name of the secret]
        version ([type], optional): [version of the secret]. Defaults to None.

    Returns:
        [str]: [value of the secret]
    """
    client = boto3.client('secretsmanager')
    kwargs = {"SecretId": f"{arcade_name}/{name}"}

    if version is not None:
        kwargs['VersionStage'] = version
    
    response = client.get_secret_value(**kwargs)
    logging.info(response)
    return response['SecretString']


# ----------------------------------------------------------
#
# update_secret
#
# ----------------------------------------------------------
def update_secret(arcade_name: str,
                  name: str,
                  secret_value: str) -> dict:
    """
    Update a secret in Secrets Manager

    Args:
        arcade_name (str): [Name of the Arcade]
        name (str): [name of the secret]
        secret_value (str): [vaule of the secret]

    Returns:
        [dict]: [aws api reponse]
    """
    client = boto3.client('secretsmanager')
    kwargs = {"SecretId": f"{arcade_name}/{name}"}

    if isinstance(secret_value, str):
        kwargs["SecretString"] = secret_value
    
    elif isinstance(secret_value, bytes):
        kwargs["SecretBinary"] = secret_value

    response = client.update_secret(**kwargs)
    logging.info(response)

    return {'SecretName': response['Name'], 'SecretARN': response['ARN']}
