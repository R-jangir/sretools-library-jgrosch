#!/usr/bin/env python3

import os, sys

# ----------------------------------------------------------
#
# check_aws_env
#
# ----------------------------------------------------------
def check_aws_env() -> dict:

    home               = os.getenv('HOME')
    awsConfigFile      = 'aws-setting.json'
    awsDirFound        = True
    awsConfigFileFoune = True
    
    awsFiles = ['config', 'credentials']

    if not os.path.exists(f"{home}/Keys/{awsConfigFile}"):
        awsConfigFileFound = False
        
    if not os.path.exists(f"{home}/.aws"):
        awsDirFound = False

    for af in awsFiles:
        if not os.path.exists(f"{home}/.aws/{af}"):
            awsDirFound = False

    if awsDirFound == False:
        i = 0

    #
    # if $HOME/aws-settings.json not found
    # ask manager for your copy
    # exit
    #
    # if .aws/{config,credentials} not found and
    # if $HOME/aws-settings.json found do the following
    #
    # aws configure set aws_access_key_id  $AWS_ACCESS_KEY_ID
    # aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
    # aws configure set region $AWS_DEFAULT_REGION
    # aws configure set output json
    #
    
    AWS = {}

    AWS['AWS_ACCESS_KEY']            = os.getenv('AWS_ACCESS_KEY')
    AWS['AWS_ACCESS_KEY_ID']         = os.getenv('AWS_ACCESS_KEY_ID')
    AWS['AWS_DEFAULT_REGION']        = os.getenv('AWS_DEFAULT_REGION')
    AWS['AWS_DEFAULT_OUTPUT']        = os.getenv('AWS_DEFAULT_OUTPUT')
    AWS['AWS_SECRET_ACCESS_KEY']     = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS['AWS_SECRET_KEY']            = os.getenv('AWS_SECRET_KEY')
    AWS['GRV_AWS_ACCESS_KEY_ID']     = os.getenv('GRV_AWS_ACCESS_KEY_ID')
    AWS['GRV_AWS_DEFAULT_REGION']    = os.getenv('GRV_AWS_DEFAULT_REGION')
    AWS['GRV_AWS_SECRET_ACCESS_KEY'] = os.getenv('GRV_AWS_SECRET_ACCESS_KEY')

    AWS['AWS_REGION']                = os.getenv('AWS_REGION')



    return AWS
    #
    #
    #

def main():
    D = check_aws_env()

    sys.exit(0)

if __name__ == '__main__':
    main()
