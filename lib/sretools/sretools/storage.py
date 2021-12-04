import boto3
import json
import logging
import hashlib


def key_exists(bucket, s3_file_path) -> bool:
    """Check for key in bucket.

    Args:
        bucket: s3 bucket
        s3_file_path: Full path in s3 with filename
    Returns:
        bool: key exists
    """
    s3_client = boto3.client('s3')
    response = s3_client.list_objects_v2(Bucket=bucket,
                                         Prefix=s3_file_path)
    return 'Contents' in response


def load_json(bucket, s3_file_path) -> dict:
    """Load json object from json file in s3 bucket
    Args:
        bucket: s3 bucket
        s3_file_path: Full path in s3 with filename
    Returns:
        dict: return the json object from json file in s3
        {}: if file is invalid or file path is invalid.
    """

    s3_client = boto3.client('s3')
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=s3_file_path)
        return json.loads(obj['Body'].read().decode('utf-8'))
    except Exception as e:
        logging.error(f"Exception: {e}")
        return {}


def upload_to_s3(bucket: str, data: str, key: str) -> bool:
    """Uploads a json str to s3

    Args:
        bucket: s3 bucket name
        data: a serialized json str
        key: s3 object key
    Returns:
        Bool: True (If upload was successful) False (If upload was unsuccessful)
    """
    client = boto3.client('s3')
    try:
        client.put_object(Bucket=bucket, Key=key, Body=data)
        return True
    except Exception as e:
        logging.error(f"Exception: {e}")
        return False


def get_arcade_buckets(session: boto3.session.Session, arcade: str) -> dict:
    """Return the arcade buckets as a dictionary.

    Args:
        session: A boto3 session for accessing client and resource
        arcade: The name of arcade
    Returns:
        A dictionary with key(app, infrastructure, assets): value (bucket name)
    """
    arcade = arcade.replace('_', '')
    s3_client = session.client('s3')

    bucket_dict = {}
    buckets = s3_client.list_buckets()

    for bucket in buckets['Buckets']:
        if f"{arcade}" in bucket['Name']:
            bucket_dict[bucket['Name'].split('.')[-3]] = bucket['Name']
    return bucket_dict


def get_account_global_bucket(session: boto3.session.Session) -> str:
    """Get account global s3 bucket.

    If the bucket does not exits, create a new one

    Args:
        session: A boto3 session for accessing client and resource

    Returns: the account global s3 bucket name

    """
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity().get('Account')
    account_hash = hashlib.md5(account_id.encode('utf-8')).hexdigest()
    bucket_name = f"asd-{account_hash}"

    resource = session.resource('s3')
    bucket = resource.Bucket(bucket_name)

    if not bucket.creation_date:
        resource.create_bucket(Bucket=bucket_name,
                               CreateBucketConfiguration={'LocationConstraint': session.region_name})
    return bucket_name
