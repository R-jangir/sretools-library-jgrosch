import boto3
import hashlib
import json
import logging

from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Begin merge
# ----------------------------------------------------------
#
# load_json
#
# ----------------------------------------------------------
def load_json(bucket: str,
              s3_file_path: str) -> dict:
    """
    Load json object from json file in s3 bucket
    
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

# ----------------------------------------------------------
#
# key_exists
#
# ----------------------------------------------------------
def key_exists(bucket: str,
               s3_file_path: str) -> bool:
    """
    Check for key in bucket.

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


# End merge

# ----------------------------------------------------------
#
# s3_file_timestamp
#
# ----------------------------------------------------------
def s3_file_timestamp(session: boto3.session.Session, 
                      bucket: str,
                      s3_file_path: str):
    """
    Returns Timestamp for a file in S3

    Args:
        session (boto3.session.Session): [Boto3 Session]
        bucket (str): [Name of the S3 Bucket]
        s3_file_path (str): [S3 file path]

    Returns:
        [type]: [description]
    """
    s3_client = session.client('s3')
    obj = s3_client.get_object(Bucket=bucket, Key=s3_file_path)
    date = obj['LastModified']

    return date.strftime('%Y-%m-%d %H:%M:%S')


# ----------------------------------------------------------
#
# get_arcade_buckets
#
# ----------------------------------------------------------
def get_arcade_buckets(session: boto3.session.Session,
                       arcade: str) -> dict:
    """
    Return the arcade buckets as a dictionary.

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


# ----------------------------------------------------------
#
# upload_s3
#
# ----------------------------------------------------------
def upload_to_s3(session: boto3.session.Session,
                 bucket: str,
                 data: str,
                 key: str) -> bool:
    """
    Uploads a json str to s3

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        data: a serialized json str
        key: s3 object key
        
    Returns:
        Bool: True (If upload was successful) False (If upload was unsuccessful)
    """
    client = session.client('s3')
    try:
        client.put_object(Bucket=bucket, Key=key, Body=data)
        return True
    except (ClientError, NoCredentialsError) as e:
        logging.error(f'AWS error: {e}')
        return False


# ----------------------------------------------------------
#
# upload_asteroid_json
#
# ----------------------------------------------------------
def upload_asteroid_json(session: boto3.session.Session,
                         bucket: str,
                         prefix: str,
                         name: str,
                         version: str,
                         data: str) -> str:
    """
    Upload asd/asteroid json to s3. Always add a new s3 key and
    update latest key to the new data.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        prefix: prefix of the s3 key ('asd' or 'asteroid')
        name: asd service or asteroid name
        version: version str
        data: a serialized json str

    Returns:
        the s3 key of latest version or empty string

    """

    date_radix = datetime.utcnow().strftime("%Y/%m/%d/%H/%M")
    filename = f"{name}.json"
    hash_json = hashlib.md5(str(filename).encode('utf-8')).hexdigest()
    radix_hash = f"{prefix}/{name}/{version}/{date_radix}/{hash_json}.json"
    radix_hash_latest = f'{prefix}/{name}/latest/latest.json'

    new_version = upload_to_s3(session, bucket, data, radix_hash)

    new_latest = upload_to_s3(session, bucket, data, radix_hash_latest)

    if new_version and new_latest:
        print(f'{bucket} {radix_hash}')
        print(f'{bucket} {radix_hash_latest}')
        return radix_hash_latest
    else:
        return ''


# ----------------------------------------------------------
#
# find_s3_keys
#
# ----------------------------------------------------------
def find_s3_keys(session: boto3.session.Session,
                 bucket: str,
                 prefix: str) -> list:
    """
    Find objects from s3 bucket

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        prefix: s3 key prefix

    Returns:
        a list of keys matching prefix

    """
    try:
        s3_client = session.client('s3')
        response = s3_client.list_objects(Bucket=bucket, Prefix=prefix)
        output = []
        for content in response.get('Contents', []):
            output.append(content.get('Key'))
        return output
    except (ClientError, NoCredentialsError) as e:
        logging.info(f'AWS error: {e} for key: {prefix}')
        return []


# ----------------------------------------------------------
#
# s3_json_to_dict
#
# ----------------------------------------------------------
def s3_json_to_dict(session: boto3.session.Session,
                    bucket: str,
                    s3_file_path: str) -> dict:
    """
    Load json file in s3 and return as a dictionary

    Args:
        session: A boto3 session for accessing client and resource
        bucket: bucket name
        s3_file_path: Full path in S3 with filename

    Returns:
        dict: return the dictionary from json file in s3, or empty dictionary
    """

    s3_client = session.client('s3')
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=s3_file_path)
        return json.loads(obj['Body'].read())
    except Exception as e:
        logging.info(f"Exception: {e} for key: {s3_file_path}")
        return {}


# ----------------------------------------------------------
#
# get_account_global_bucket
#
# ----------------------------------------------------------
def get_account_global_bucket(session: boto3.session.Session) -> str:
    """
    Get account global s3 bucket.
    If the bucket does not exits, create a new one

    Args:
        session: A boto3 session for accessing client and resource

    Returns:
        the account global s3 bucket name

    """
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity().get('Account')
    account_hash = hashlib.md5(account_id.encode('utf-8')).hexdigest()
    bucket_name = f"asd-{account_hash}"

    resource = session.resource('s3')
    bucket = resource.Bucket(bucket_name)

    if not bucket.creation_date:
        resource.create_bucket(Bucket=bucket_name,
                               CreateBucketConfiguration=
                               {'LocationConstraint': session.region_name})
    return bucket_name


# ----------------------------------------------------------
#
# delete_s3_prefix
#
# ----------------------------------------------------------
def delete_s3_prefix(session: boto3.session.Session,
                     bucket: str,
                     prefix: str) -> None:
    """
    Delete keys in s3 with prefix.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        prefix: s3 key prefix

    Returns:
        None

    """
    bucket = session.resource('s3').Bucket(bucket)
    bucket.objects.filter(Prefix=prefix).delete()

    return


# ----------------------------------------------------------
#
# download_s3_file
#
# ----------------------------------------------------------
def download_s3_file(session: boto3.session.Session,
                     bucket: str,
                     key: str,
                     filename: str) -> None:
    """
    Download s3 file to local.

    Args:
        session: A boto3 session for accessing client and resource
        bucket: s3 bucket name
        key: s3 key
        filename: local file name

    Returns:
        None
    """

    session.resource('s3').Bucket(bucket).download_file(key, filename)

    return
    #
