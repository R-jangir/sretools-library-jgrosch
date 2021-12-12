#!/usr/bin/env python3

# -----------------------------------------------------------------------
#
#                               < aws.py >
#
# -----------------------------------------------------------------------


# -----------------------------------------------------------------------
#
# File Name    : aws.py
#
# Author       : Josef Grosch
#
# Date         : 10 Dec 2021
#
# Modification : 
#
# Application  : 
#
# Description  :
#
# Notes        :
#
# Version      : 0.5
#
# Functions    :
#
# -----------------------------------------------------------------------


# -----------------------------------------------------------------------
#
#                              Copyright
#
#                    (C) Copyright 2021 Appepar, Inc.
#
#                         All Rights Reserved
#
# -----------------------------------------------------------------------


# -----------------------------------------------------------------------
#
# Import
#
# -----------------------------------------------------------------------
import os, sys
import json
import subprocess
import grp


# ----------------------------------------------------------
#
# _configure_aws
#
# ----------------------------------------------------------
def _configure_aws(AWS):
    """
    """
    
    configDict = {'AWS_ACCESS_KEY_ID':'aws_access_key_id',
                  'AWS_SECRET_ACCESS_KEY':'aws_secret_access_key',
                  'AWS_DEFAULT_REGION':'region',
                  'AWS_DEFAULT_OUTPUT':'output'}

    configStr = 'aws configure set'

    for key in configDict:
        cmd = []
        cmd.append(configStr)
        awsValue    = AWS[key]
        configValue = configDict[key]
        cmd.append(configValue)
        cmd.append(awsValue)
        cmdStr = ' '.join(cmd)
        print("{}\n".format(cmdStr))
        try:
            cp = subprocess.run(cmdList,
                                universal_newlines=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        except:
            print("\n\nERROR: {} failed.".format(cmdList))
            exit(1)

        stdOut = cp.stdout
        stdErr = cp.stderr
        returnCode = cp.returncode

        if returnCode != 0:
            print("\nERROR: {} failed.".format(cmdStr))
            sys.exit(1)
    
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

    return
    #

    
# ----------------------------------------------------------
#
# _init_aws_dict
#
# ----------------------------------------------------------
def _init_aws_dict(awsEnv: list) -> dict:
    """
    """
    AWS = {}

    for entry in awsEnv:
        AWS[entry] = "EMPTY"

    AWS['AWS_DICT_LEN'] = len(AWS)

    return AWS
    #

# ----------------------------------------------------------
#
# check_aws_env
#
# ----------------------------------------------------------
def check_aws_env() -> dict:
    """
    """
    configAWS = os.getenv('CONFIG_AWS')
    if configAWS == '0' or configAWS == None:
        return({})
    
    home  = os.getenv('HOME')
    
    awsConfigFile      = 'aws-account.json'
    awsDirFound        = True
    awsConfigFileFound = True
    fqpConfigFile      = f"{home}/Keys/{awsConfigFile}"
    
    awsFiles = ['config', 'credentials']
    awsEnvVariables = ['AWS_DICT_LEN',           'AWS_ACCESS_KEY',
                       'AWS_ACCESS_KEY_ID',      'AWS_DEFAULT_REGION',
                       'AWS_DEFAULT_OUTPUT',     'AWS_SECRET_ACCESS_KEY',
                       'AWS_SECRET_KEY',         'GRV_AWS_ACCESS_KEY_ID',
                       'GRV_AWS_DEFAULT_REGION', 'GRV_AWS_SECRET_ACCESS_KEY',
                       'AWS_REGION',             'DEFAULT_REALM'
                       ]
    
    AWS = _init_aws_dict(awsEnvVariables)

    if not os.path.exists(fqpConfigFile):
        awsConfigFileFound = False
        print("Error: {} not found. Ask manager for URL to file"
              .format(fqpConfigFile)) 
        return({})
    else:
        # check permission & ownership
        user  = os.getenv('USER')
        uid   = os.getuid()
        euid  = os.geteuid()
        if euid == None:
            euid = uid
            
        admin = grp.getgrnam(user)
        gid   = admin.gr_gid
        gname = admin.gr_name

        fStat = os.stat(fqpConfigFile)
        fUid  = fStat.st_uid
        fGid  = fStat.st_gid
    
    if not os.path.exists(f"{home}/.aws"):
        awsDirFound = False

    for af in awsFiles:
        if not os.path.exists(f"{home}/.aws/{af}"):
            awsDirFound = False

    if awsDirFound == False:
        i = 0
        # Error: ~/.aws not found which means aws not setup

    if awsConfigFileFound == False:
        i = 0
        # Error: ~/Keys/aws-account.json no found.

        
    
    missingEnvVar = 0
    for entry in awsEnvVariables:
        if entry == 'AWS_DICT_LEN':
            continue

        awsEnv = os.getenv(entry)
        if awsEnv == None:
            missingEnvVar += 1
        else:
            AWS[entry] = os.getenv(entry)

    if missingEnvVar > 0:
        k = 0

    _configure_aws(AWS)
        
    return AWS
    #


def main():
    D = check_aws_env()

    j = 0
    
    sys.exit(0)
    #

    
if __name__ == '__main__':
    main()



# -----------------------------------------------------------------------
#
#                          < End of Startup.py >
#
# -----------------------------------------------------------------------
