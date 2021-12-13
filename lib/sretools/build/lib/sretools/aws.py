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
# Modification : 10 Dec 2021 - Initial coding
#
# Application  : Arcade
#
# Description  : A library of routines to check a user access to
#                Addepar AWS spaces. Additional these routines can
#                setup a users access to a given Addepar AWS realm.
#
# Notes        : For this library to function correctly it requires
#                two external items
#
#                1) The user must have the file ~/Keys/aws-account.json
#                   owned by the user with the permissions of 0400. This
#                   file is maintined by the SRE Tools group
#
#                2) The user must have the following text at the end
#                   of their .bashrc
#
#                       if [ -f ~/.aws-bashrc ]; then
#                           source ~/.aws-bashrc
#                       fi
#
#                   This file places the following variables into the
#                   users environment based on the contents of
#                   ~/Keys/aws-account.json
#
#                       AWS_ACCESS_KEY
#                       AWS_ACCESS_KEY_ID
#                       AWS_DEFAULT_OUTPUT
#                       AWS_DEFAULT_REGION
#                       AWS_REGION
#                       AWS_SECRET_ACCESS_KEY
#                       AWS_SECRET_KEY
#                       DEFAULT_REALM
#                       GRV_AWS_ACCESS_KEY_ID
#                       GRV_AWS_DEFAULT_REGION
#                       GRV_AWS_SECRET_ACCESS_KEY
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


# -----------------------------------------------------------------------
#
# isFileSecure
#
# -----------------------------------------------------------------------
def isFileSecure(fqpName: str) -> bool:
    """
    Check if a file is secure, ie. The file owned by the calling user
    and the file permissions are either 0600 (-rw------) or
    0400 (-r--------)

    Args:
        fqpName: Fully qualified path file name

    Returns:
        Boolean, True if file is secure, False if file is
        Not secure.

    Note:
        This function needs to be moved to utils.py
        
    """
    
    fileOkFlag = True

    if not os.path.exists(fqpName):
        fileOkFlag = False

    if fileOkFlag:
        uid  = os.getuid()
        euid = os.geteuid()

        if uid != euid:
            fileOkFlag = False
        else:
            user     = os.getenv('USER')
            userInfo = grp.getgrnam(user)
            gid      = userInfo.gr_gid
    
            fileStat = os.stat(fqpName)
            fileUid  = fileStat.st_uid
            fileGid  = fileStat.st_gid

            if ((uid != fileUid) or (gid != fileGid)):
                fileOkFlag = False
            else:
                fileStatus = os.stat(fqpName)
                filePerms = oct(fileStatus.st_mode)[-3:]
                fileOkFlag = False
                if filePerms == '600': 
                    fileOkFlag = True
                if filePerms == '400':
                    fileOkFlag = True

    return fileOkFlag
    #
    
# ----------------------------------------------------------
#
# _configure_aws
#
# ----------------------------------------------------------
def _configure_aws(AWS):
    """
    """

    # aws configure set aws_access_key_id  $AWS_ACCESS_KEY_ID
    # aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
    # aws configure set region $AWS_DEFAULT_REGION
    # aws configure set output json

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
            exit(400)

        stdOut = cp.stdout
        stdErr = cp.stderr
        returnCode = cp.returncode

        if returnCode != 0:
            print("\nERROR: {} failed.".format(cmdStr))
            sys.exit(400)
    
    return
    #

    
# ----------------------------------------------------------
#
# _init_aws_dict
#
# ----------------------------------------------------------
def _init_aws_dict(awsEnv: list) -> dict:
    """
    Initialize a dictonary of AWS environment variables

    Args:
        awsEnv: A list of AWS environment variables
        
    Returns:
        A dictonary of AWS evironment variables with
        each variable (key) set to 'EMPTY' (value)
    
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
    earlyExit = False
    
    configAWS = os.getenv('CONFIG_AWS')
    if configAWS != None:
        if configAWS.lowar() == 'yes':
            return({})
    
    home  = os.getenv('HOME')
    
    awsConfigFile      = 'aws-account.json'
    awsDirFound        = True
    awsConfigFileFound = True
    fqpConfigFile      = f"{home}/Keys/{awsConfigFile}"

    fileOkFlag = isFileSecure(fqpConfigFile)
    if not fileOkFlag:
        print(f'ERROR: {fqpConfigFile} is insecure')
        print('Permissions should be either 0600 or 0400')
        exit(403)
    
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


# ----------------------------------------------------------
#
# main
#
# ----------------------------------------------------------
def main():
    D = check_aws_env()

    j = 0
    
    sys.exit(0)
    #

    
# ----------------------------------------------------------
#
# entry point
#
# ----------------------------------------------------------
if __name__ == '__main__':
    main()



# -----------------------------------------------------------------------
#
#                          < End of Startup.py >
#
# -----------------------------------------------------------------------
