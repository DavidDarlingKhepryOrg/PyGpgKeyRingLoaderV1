#!/usr/bin/python

import collections
import gnupg
import io
import keyring
import logging
import os
import platform
import secretstorage
import subprocess
import sys

from contextlib import redirect_stdout

from pprint import pprint

if platform.system() != 'Windows':
    gpgPgmPath = 'gpg'
else:
    gpgPgmPath = os.path.abspath('/Program Files (x86)/GNU/GnuPG/gpg2.exe')

def main():
    
    dftPassword = '[passphrase_needed]'
    ownerTrustFileName = 'OutputFiles/GpgKeysOwnerTrust.txt'
    gpgKeysOutFileName = 'OutputFiles/GpgKeyringEntries.ini'
    allKeysOutFileName = 'OutputFiles/AllKeyringEntries.ini'
    
    # obtain any command-line arguments
    # overriding any values set so far
    nextArg = ""
    for argv in sys.argv:
        if nextArg != "":
            if nextArg == "dftPassword":
                dftPassword = argv
            nextArg = ""
        else:
            if argv.lower() == "--dftpassword" or argv.lower() == "-dftpassword":
                nextArg = "dftPassword"

    # instantiate and initialize
    # logging objects and handlers
    dftMsgFormat = '%(asctime)s\t%(levelname)s\t%(module)s\t%(funcName)s\t%(lineno)d\t%(message)s'
    dftDateFormat = '%Y-%m-%d %H:%M:%S'
                
    # set the default logger's values
    logging.basicConfig(level=logging.INFO,
                        format=dftMsgFormat,
                        datefmt=dftDateFormat)
    
    public_keys, secret_keys, gpg_keyring_ids = getGpgKeys(isTestMode=False,
                                                           pgmLogger=logging)

    gpgKeysOutFileNameExpanded = getPathExpanded(gpgKeysOutFileName, None, pgmLogger=logging)
    errStr = createFolderIfNotExist(gpgKeysOutFileNameExpanded, containsFileName=True, pgmLogger=logging)
        
    with io.open(gpgKeysOutFileNameExpanded, 'w', encoding='cp1252') as outFile:
        print('[DEFAULT]')
        print('')
        print('    postToKeyring=True')
        print('    redactPasswords=True')
        print('    deletePasswords=False')
        print('')
        print ('[gpgKeys]')
        print ('')
        outFile.write('[DEFAULT]%s' % os.linesep)
        outFile.write(os.linesep)
        outFile.write('    postToKeyring=True%s' % os.linesep)
        outFile.write('    redactPasswords=True%s' % os.linesep)
        outFile.write('    deletePasswords=False%s' % os.linesep)
        outFile.write(os.linesep)
        outFile.write('[gpgKeys]%s' % os.linesep)
        outFile.write(os.linesep)
        for gpg_keyring_id in gpg_keyring_ids.items():
            
            keyId = '%s' % gpg_keyring_id[0]
            userName = '%s' % gpg_keyring_id[1]
            
            # fetch the user's current password
            # via then keyId and userName
            currPwd, errStr = getPwdViaKeyring(keyId,
                                           userName,
                                           redactPasswords=False,
                                           logResults=False,
                                           pgmLogger=logging,
                                           isTestMode=True,
                                           defaultPassword=dftPassword)
            
            # if no errors
            # so far......
            if errStr == None:
                
                keyIdLast8 = keyId[-8:]
                
                # output the current user's keyId, userName, and password
                strValue = '%s%s,%s=%s' % ('    ', keyIdLast8, userName, currPwd if not None else dftPassword)
                print (strValue)
                outFile.write(strValue)
                outFile.write(os.linesep)
                
                # load the keyId and userName
                # into the user's keyring along
                # with the corresponding password
                setPwdViaKeyring(keyIdLast8,
                                 userName,
                                 currPwd if not None else dftPassword,
                                 pgmLogger=logging)
            

               
    dictEntries, nominalDict, orderedEntries, errStr = getKeyringEntries(
                                                            redactPasswords=False,
                                                            isTestMode=False,
                                                            pgmLogger=logging)

    # export the GPG keys ownertrust to a file
    ownerTrustFileNameExpanded, errStr = exportUserTrustFile(ownerTrustFileName, isTestMode=True, pgmLogger=logging)
    
    print ('')

    print ('All Keyring Entries Presently in the User\'s Keyring')
    print ('')
    
    allKeysOutFileNameExpanded = getPathExpanded(allKeysOutFileName, None, pgmLogger=logging)
    errStr = createFolderIfNotExist(allKeysOutFileName, containsFileName=True, pgmLogger=logging)
    
    with io.open(allKeysOutFileName, 'w', encoding='cp1252') as outFile:
        outFile.write('[allKeyringEntries]%s' % os.linesep)
        outFile.write(os.linesep)
        for item in orderedEntries.items():
            strValue = '    ' + '='.join(item)
            print(strValue)
            outFile.write(strValue)
            outFile.write(os.linesep)
        
    return


#===============================        
# Get password in user's keyring
#===============================        

def getPwdViaKeyring(key,
                     login,
                     redactPasswords=True,
                     logResults=False,
                     pgmLogger=None,
                     isTestMode=False,
                     defaultPassword='[redacted]'):
    
    errStr = None
    password = None
                
    # get the password for the specified key and login
    try:
        password = keyring.get_password(key, login)
        if password != None:
            if logResults:
                pgmLogger.info("SUCCESS: Retrieval of password for key: %s and login: %s" % (key, login))
                if redactPasswords:
                    pgmLogger.info("Key: %s, Login: %s, Password: %s" % (key, login, '[redacted]'))
                else:                    
                    pgmLogger.info("Key: %s, Login: %s, Password: %s" % (key, login, password))
#                 if isTestMode:
#                     password = '[redacted]'
        else:
            if defaultPassword != None:
                password = defaultPassword
            else:
                errStr = "ERROR: key: %s for login: %s not in keyring" % (key, login)
                pgmLogger.error(errStr)
    except Exception as e:
        errStr = str(e)
        pgmLogger.error("FAILURE: Retrieval of password for key: %s and login: %s" % (key, login))
        pgmLogger.error(errStr)
        
    return password, errStr

    
#===============================
# Set password in user's keyring
#===============================
    
def setPwdViaKeyring(key,
                     userName,
                     password,
                     pgmLogger=None):
    
    errStr = None
    
    # get the password for the specified user and service
    try:
        keyring.set_password(key, userName, password)
    except Exception as e:
        errStr = str(e)
        pgmLogger.error("FAILURE: Setting of password for key: %s and user: %s" % (key, userName))
        pgmLogger.error(errStr)
        
    return errStr
    
    
#==================================
# Delete password in user's keyring
#==================================
    
def dltPwdViaKeyring(key,
                     userName,
                     pgmLogger=None):
    
    errStr = None
    
    # delete the entry for the specified service and user
    try:
        keyring.delete_password(key, userName)
    except Exception as e:
        errStr = str(e)
        pgmLogger.error("FAILURE: Password for key: %s and user: %s was NOT deleted!" % (key, userName))
        pgmLogger.error(errStr)
        
    return errStr
    

#===============================
# Obtain dictionary of all 
# entries in local keyring
#===============================    

def getKeyringEntries(redactPasswords=True,
                      logResults=False,
                      isTestMode=False,
                      pgmLogger=None):
    
    errStr = None
    entries = {}
    nominalDict = {}
    orderedDict = collections.OrderedDict()
    
    # get the password for the specified user and service
    try:
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        for item in collection.get_all_items():
            entries[item.get_label()] = item.get_attributes()
            service = item.get_attributes()['service']
            username = item.get_attributes()['username']
            password, errStr = getPwdViaKeyring(
                                    service,
                                    username,
                                    redactPasswords=redactPasswords,
                                    logResults=logResults,
                                    pgmLogger=pgmLogger,
                                    isTestMode=isTestMode)
            if redactPasswords:
                password = '[redacted]'
            nominalDict['%s,%s' % (service, username)] = password
        if len(nominalDict) > 0:
            orderedDict = collections.OrderedDict(sorted(nominalDict.items()))
        if isTestMode:
            for k,v in orderedDict.items():
                print('%s=%s' % (k, v))
    except Exception as e:
        errStr = str(e)
        pgmLogger.error("FAILURE: Could not obtain list of keyring entries")
        pgmLogger.error(errStr)
        
    return entries, nominalDict, orderedDict, errStr
    

# =====================================================================
# List both the public and private keys
# =====================================================================

def getGpgKeys(isTestMode=False,
                pgmLogger=None):
    
    public_keys = {}
    secret_keys = {}
    gpg_keyring_ids = {}

    # ============================
    # Initialize the GPG object
    # that will be used to perform
    # the cryptographic operation
    # ============================
    
    gpg = None
    if platform.system() != 'Windows':
        gpg = gnupg.GPG()
    else:
        gpg = gnupg.GPG()
    
    public_keys = gpg.list_keys()
    for gpgKey in public_keys:
        gpg_keyring_ids[gpgKey['keyid']] = gpgKey['uids'][0]
    secret_keys = gpg.list_keys(True)

    if isTestMode:
        print('public keys')
        pprint(public_keys)
        for gpgKey in public_keys:
            print('key: %s, value: %s' %(gpgKey['uids'][0], gpgKey['keyid']))
    
    if isTestMode:
        print('secret keys')
        pprint(secret_keys)
        for gpgKey in secret_keys:
            print('key: %s, value: %s' %(gpgKey['uids'][0], gpgKey['keyid']))
    
    return public_keys, secret_keys, gpg_keyring_ids
    

# =====================================================================
# List both the public and private keys
# =====================================================================

def exportUserTrustFile(ownerTrustFileName,
                        isTestMode=False,
                        pgmLogger=None):
    
    errStr = None
    
    ownerTrustFileNameExpanded = getPathExpanded(ownerTrustFileName,
                                                 pgmLogger=pgmLogger)
    
    errStr = createFolderIfNotExist(ownerTrustFileNameExpanded,
                                    containsFileName=True,
                                    pgmLogger=pgmLogger)
    
    if not errStr:
    
        # ============================
        # Initialize the GPG object
        # that will be used to perform
        # the cryptographic operation
        # ============================
        
        gpg = None
        if platform.system() != 'Windows':
            gpg = gnupg.GPG()
        else:
            gpg = gnupg.GPG()
            
        with open(ownerTrustFileNameExpanded, 'w') as outFile:
            with redirect_stdout(outFile):
                subprocess.call([gpgPgmPath, '--export-ownertrust'], stdout=outFile, shell=False)
    
    return ownerTrustFileNameExpanded, errStr


# =============================================================================    
# Expand the specified folder path as needed
# =============================================================================    

def getPathExpanded(path,
                    parentPath = '',
                    pgmLogger=None):
    # default the return value
    pathExpanded = path
    # if it even has a value
    if pathExpanded != None and pathExpanded != '':
        # if the home folder is specified
        if pathExpanded.startswith("~") == True:
            # expand the file path with the home folder
            pathExpanded = os.path.expanduser(pathExpanded)
        # split the folder into its drive and tail
        drive, tail = os.path.splitdrive(pathExpanded)
        # if it's a sub-folder
        if drive == '' and tail.startswith("/") == False:
            if parentPath == None:
                parentPath = ''
            pathExpanded = os.path.join(parentPath, pathExpanded)
        # obtain the folder's absolute path
        pathExpanded = os.path.abspath(pathExpanded)
    # return expanded folder path
    return pathExpanded


# =============================================================================    
# Create a folder if it does not already exist
# =============================================================================    

def createFolderIfNotExist(folderNameExpanded,
                           containsFileName=False,
                           pgmLogger=None):
    
    errStr = None
    
    # if folder name has a value
    # and the folder name not blank
    # and the folder does NOT yet exist
    if (folderNameExpanded != None
    and folderNameExpanded != ""
    and os.path.exists(folderNameExpanded) == False):
        # create the specified folder
        try:
            if containsFileName == True:
                if os.path.dirname(folderNameExpanded) != '':
                    if os.path.exists(os.path.dirname(folderNameExpanded)) == False:
                        os.makedirs(os.path.dirname(folderNameExpanded))
            else:
                os.makedirs(folderNameExpanded)
        except Exception as e:
            errStr = str(e)
            pgmLogger.error(errStr)

    return errStr


# =============================================================================    
# execute the "main" method
# =============================================================================    

if __name__ == "__main__":
    main()
