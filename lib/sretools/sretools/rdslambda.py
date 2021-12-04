#!/usr/bin/env python3

import boto3
import json
import os
import argparse
import logging
import time
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
from modules import grv

def attach_VPC_Lambda_Policy(owner_id: str, rds_lambda_role: str):
    response = client.attach_role_policy(
    PolicyArn=f'arn:aws:iam::{owner_id}:policy/AWSLambdaVPCAccessExecutionRole',
    RoleName=f'{rds_lambda_role}',)


def main():
    parser = argparse.ArgumentParser(
        description='Create IAM Role for RDS Schema')

    parser.add_argument("-a", "--arcade", help="ARCADE name", required=True)
    parser.add_argument("-v", "--verbose",
                        help='Verbose Output', action='store_true')

    args = parser.parse_args()
    arcade_name = args.arcade

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    grv_info = grv.get_gravitar_info(arcade_name)
    vpc_id = list(grv_info['vpc'].keys())[0]
    owner_id = grv_info['vpc'][vpc_id]['OwnerId']
    gravitar = grv.find_vpc_name(vpc_id)
    if arcade_name != gravitar:
        exit(1)
    rds_lambda_policy = 'RDSLambdaPolicy'
    rds_lambda_role = 'RDSLambdaRole'
    rds_assume_lambda_policy = 'RDSAssumeLambdaRole'
    RDS_LAMBDA_POLICY_DOCUMENT = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }
        ]
    }
    RDS_ASSUME_LAMBDA_POLICY_DOCUMENT = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "sts:AssumeRole"
                ],
                "Resource": [
                    f"arn:aws:iam::{owner_id}:role/{rds_lambda_role}"
                ]
            }
        ]
    }
    ASSUME_RDS_LAMBDA_POLICY_DOCUMENT = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{owner_id}:root"
                },
                "Action": "sts:AssumeRole",
                "Condition": {}
            }
        ]
    }
    role_dict = grv.find_role(rds_lambda_role)
    if role_dict != {}:
        role_arn = role_dict['Role']['Arn']
        print("RDS Lambda role already exists")
    else:
        assume_policy_arn = grv.create_policy(rds_assume_lambda_policy, RDS_ASSUME_LAMBDA_POLICY_DOCUMENT)
        policy_arn = grv.create_policy(rds_lambda_policy, RDS_LAMBDA_POLICY_DOCUMENT)
        rds_lambda_policy_arns = [policy_arn]
        role_arn = grv.create_role(rds_lambda_role, rds_lambda_policy_arns, ASSUME_RDS_LAMBDA_POLICY_DOCUMENT)
        attach_VPC_Lambda_Policy(owner_id, rds_lambda_role)
        print("RDS Lambda role created")

    print(role_arn)


if __name__ == '__main__':
    main()