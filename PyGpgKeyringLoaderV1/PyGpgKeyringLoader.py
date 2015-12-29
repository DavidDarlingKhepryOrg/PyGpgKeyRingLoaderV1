#!/usr/bin/python

import collections
import datetime
import gnupg
import io
import keyring
import logging
import os
import platform
import subprocess
import sys
import time

if platform.system() != 'Windows':
    import secretstorage # @UnusedImport
else:
    from keyring.backends.Windows import win32cred # @UnusedImport

from collections import OrderedDict

from contextlib import redirect_stdout

from pprint import pprint

isTestMode = False

if platform.system() != 'Windows':
    gpgPgmPath = 'gpg'
else:
    gpgPgmPath = os.path.abspath('/Program Files (x86)/GNU/GnuPG/gpg2.exe')

def main():
    
#    dftPassword = '[passphrase_needed]'
    dftPassword = '[redacted]'
    allOwnerTrust = 6
    dftOwnerTrust = 5
    ownerTrustFileName = 'OutputFiles/GpgKeysOwnerTrust.txt'
    gpgKeysOutFileName = 'OutputFiles/GpgKeyringEntries.ini'
    allKeysOutFileName = 'OutputFiles/AllKeyringEntries.ini'
    gpgKeysFolderName = 'gpgKeys'
    
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
    
    # add all of the GPG keys in the "gpgKeys" folder to the GPG keyring
    gpgKeysFolderNameExpanded = getPathExpanded(gpgKeysFolderName, pgmLogger=logging)
    for root, dirs, files in os.walk(gpgKeysFolderNameExpanded):
        for file in files:
            fullPath = os.path.join(root, file)
            if os.path.exists(fullPath):
                addGpgKey(fullPath, isTestMode=isTestMode, pgmLogger=logging)
    
    # now get all of the public and secret keys presently in the GPG keyring
    public_keys, secret_keys, gpg_keyring_ids = getGpgKeys(isTestMode=isTestMode,
                                                           pgmLogger=logging)

    gpg_keyring_ids_by_keyIds = {}
    gpg_keyring_ids_by_userNames = {}
    
    for gpg_keyring_id in gpg_keyring_ids.items():
        
        keyId = '%s' % gpg_keyring_id[0]
        userName = '%s' % gpg_keyring_id[1]
        gpg_keyring_ids_by_keyIds[keyId] = userName
        gpg_keyring_ids_by_userNames[userName] = keyId
    
    # derive the owner trust based upon
    # whether or not a secret key is present
    
    ownerTrustFileNameExpanded = getPathExpanded(ownerTrustFileName,
                                                 pgmLogger=logging)
    errStr = createFolderIfNotExist(ownerTrustFileNameExpanded,
                                    containsFileName=True,
                                    pgmLogger=logging)

    if errStr == None:
        print ('')
        print ('Export OwnerTrust File Name: "%s"' % ownerTrustFileName)
        print ('')
        ownerTrustFileNameExpanded, errStr = exportOwnerTrustFileViaGpgKeys(ownerTrustFileName, public_keys, secret_keys, dftOwnerTrust, allOwnerTrust, isTestMode=isTestMode, pgmLogger=logging)

    if errStr == None:
        print ('')
        print ('Import OwnerTrust File Name: "%s"' % ownerTrustFileName)
        print ('')
        errStr = importOwnerTrustFile(ownerTrustFileName, isTestMode=isTestMode, pgmLogger=logging)
        

    gpgKeysOutFileNameExpanded = getPathExpanded(gpgKeysOutFileName, None, pgmLogger=logging)
    errStr = createFolderIfNotExist(gpgKeysOutFileNameExpanded, containsFileName=True, pgmLogger=logging)

    print ('')
    print ('GPG Keyring Entries File Name: "%s"' % gpgKeysOutFileNameExpanded)
    print ('')
        
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
        for userName, keyId in collections.OrderedDict(sorted(gpg_keyring_ids_by_userNames.items())).items():
            
            # fetch the user's current password
            # via then keyId and userName
            currPwd, errStr = getPwdViaKeyring(keyId,
                                           userName,
                                           redactPasswords=False,
                                           logResults=False,
                                           pgmLogger=logging,
                                           isTestMode=isTestMode,
                                           defaultPassword=dftPassword)
            
            # if no errors
            # so far......
            if errStr == None:
                
                # get last 8 chars
                # of the GPG key's ID
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
            

               
    keyringEntries, pwdSvcUsrTriplets, svcUsrPwdTriplets, usrSvcPwdTriplets, errStr = getKeyringEntries(redactPasswords=False,
                                                                                                        isTestMode=isTestMode,
                                                                                                        pgmLogger=logging)

    allKeysOutFileNameExpanded = getPathExpanded(allKeysOutFileName, None, pgmLogger=logging)
    errStr = createFolderIfNotExist(allKeysOutFileName, containsFileName=True, pgmLogger=logging)

    print ('')
    print ('User\'s Keyring Entries Keyring File Name: "%s"' % allKeysOutFileNameExpanded)
    print ('')
    
    with io.open(allKeysOutFileName, 'w', encoding='cp1252') as outFile:
        
        print('[DEFAULT]')
        print('')
        print('    postToKeyring=True')
        print('    redactPasswords=True')
        print('    deletePasswords=False')
        print('')

        outFile.write('[DEFAULT]%s' % os.linesep)
        outFile.write(os.linesep)
        outFile.write('    postToKeyring=True%s' % os.linesep)
        outFile.write('    redactPasswords=True%s' % os.linesep)
        outFile.write('    deletePasswords=False%s' % os.linesep)
        outFile.write(os.linesep)
        
        print ('[keyringEntriesByUsrSvcPwd]')
        print (os.linesep)
        outFile.write('[keyringEntriesByUsrSvcPwd]%s' % os.linesep)
        outFile.write(os.linesep)
        for usr, svc, pwd in sorted(usrSvcPwdTriplets):
            strValue = '    %s,%s=%s' % (svc, usr, pwd)
            print(strValue)
            outFile.write(strValue)
            outFile.write(os.linesep)

        print (os.linesep)
        outFile.write(os.linesep)
        
        print ('[keyringEntriesBySvcUsrPwd]')
        print (os.linesep)
        outFile.write('[keyringEntriesBySvcUsrPwd]%s' % os.linesep)
        outFile.write(os.linesep)
        for svc, usr, pwd in sorted(svcUsrPwdTriplets):
            strValue = '    %s,%s=%s' % (svc, usr, pwd)
            print(strValue)
            outFile.write(strValue)
            outFile.write(os.linesep)

        print (os.linesep)
        outFile.write(os.linesep)
        
        print ('[keyringEntriesByPwdSvcUsr]')
        print (os.linesep)
        outFile.write('[keyringEntriesByPwdSvcUsr]%s' % os.linesep)
        outFile.write(os.linesep)
        for pwd, svc, usr in sorted(pwdSvcUsrTriplets):
            strValue = '    %s,%s=%s' % (svc, usr, pwd)
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
    pwdSvcUsrTriplets = []
    svcUsrPwdTriplets = []
    usrSvcPwdTriplets = []
    
    # get the password for the specified user and service
    try:
        # use secretstorage library
        # for non-Windows operating system
        # (may not be useful for MacOS)
        if platform.system() != 'Windows':
            bus = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(bus)
            for item in collection.get_all_items():
                entries[item.get_label()] = item.get_attributes()
                application = item.get_attributes()['application']
                if application == 'python-keyring':
                    service = item.get_attributes()['service']
                    userName = item.get_attributes()['username']
                    password, errStr = getPwdViaKeyring(
                                            service,
                                            userName,
                                            redactPasswords=redactPasswords,
                                            logResults=logResults,
                                            pgmLogger=pgmLogger,
                                            isTestMode=isTestMode)
                    if redactPasswords:
                        password = '[redacted]'
                    # push triplets to lists
                    pwdSvcUsrTriplets.append((password, service, userName))
                    svcUsrPwdTriplets.append((service, userName, password))
                    usrSvcPwdTriplets.append((userName, service, password))
        # otherwise
        else:
            # use WinVault for Windows operating system
            for credential in win32cred.CredEnumerate(): # @UndefinedVariable
                # pprint (credential)
                application = credential['Comment']
                if application == 'Stored using python-keyring':
                    # password = str(credential['CredentialBlob']).replace('\\x00','')[2:-1] 
                    service = credential['TargetName']
                    userName = credential['UserName']
                    password, errStr = getPwdViaKeyring(
                                            service,
                                            userName,
                                            redactPasswords=redactPasswords,
                                            logResults=logResults,
                                            pgmLogger=pgmLogger,
                                            isTestMode=isTestMode)
                    if redactPasswords:
                        password = '[redacted]'
                    # push triplets to lists
                    pwdSvcUsrTriplets.append((password, service, userName))
                    svcUsrPwdTriplets.append((service, userName, password))
                    usrSvcPwdTriplets.append((userName, service, password))
        if isTestMode:
            for k,v in orderedDict.items():
                print('%s=%s' % (k, v))
    except Exception as e:
        errStr = str(e)
        pgmLogger.error("FAILURE: Could not obtain list of keyring entries")
        pgmLogger.error(errStr)
        
    return entries, pwdSvcUsrTriplets, svcUsrPwdTriplets, usrSvcPwdTriplets, errStr
    

# =====================================================================
# Add a GPG key to the GPG keyring via an export file
# =====================================================================

def addGpgKey(gpgKeyFileName,
              isTestMode=False,
              pgmLogger=None):
    
    errStr = None
    
    # ============================
    # Initialize the GPG object
    # that will be used to perform
    # the cryptographic operation
    # ============================

    try:
            
        gpg = None
        
        if platform.system() != 'Windows':
            gpg = gnupg.GPG()
        else:
            gpg = gnupg.GPG()

        gpgKeyFileNameExpanded = getPathExpanded(gpgKeyFileName, pgmLogger=pgmLogger)
        
        if os.path.exists(gpgKeyFileNameExpanded):
            subprocess.call([gpgPgmPath, '--import', '%s' % gpgKeyFileNameExpanded], shell=False)
        else:
            errStr = 'GPG key file for import does NOT exist: %s' % gpgKeyFileNameExpanded
            pgmLogger.error(errStr)
        
    except Exception as e:
        errStr = str(e)
        pgmLogger.error(errStr)
    
    return errStr
    

# =====================================================================
# Get both the public and private GPG keys
# =====================================================================

def getGpgKeys(isTestMode=False,
                pgmLogger=None):
    
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
# Export the owner trust file via StdOut
# =====================================================================

def exportOwnerTrustFileViaStdOut(ownerTrustFileName,
                                  stdOutToFile=False,
                                  isTestMode=False,
                                  pgmLogger=None):
    
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
        
        try:
            if stdOutToFile:
                with open(ownerTrustFileNameExpanded, 'w') as outFile:
                    with redirect_stdout(outFile):
                        subprocess.call([gpgPgmPath, '--export-ownertrust'], stdout=outFile, shell=False)
            else:
                subprocess.call([gpgPgmPath, '--export-ownertrust'], shell=False)
        except Exception as e:
            errStr = str(e)
            pgmLogger.error(errStr)
    
    return ownerTrustFileNameExpanded, errStr
    

# =====================================================================
# Export the owner trust file via StdOut
# =====================================================================

def exportOwnerTrustFileViaGpgKeys(ownerTrustFileName,
                                   public_keys,
                                   secret_keys,
                                   dftOwnerTrust,
                                   allOwnerTrust,
                                   isTestMode=False,
                                   pgmLogger=None):
    
    ownerTrustFileNameExpanded = getPathExpanded(ownerTrustFileName,
                                                 pgmLogger=pgmLogger)
    
    errStr = createFolderIfNotExist(ownerTrustFileNameExpanded,
                                    containsFileName=True,
                                    pgmLogger=pgmLogger)
    
    if errStr == None:

        dateFmt = '%a %d %b %Y %I:%M:%S %p'
        dateStr = datetime.datetime.strftime(datetime.datetime.now(), dateFmt) + ' ' + time.strftime('%Z')
        print ('# List of assigned trustvalues, created %s' % dateStr)
        print ('# (Use \'gpg --import-ownertrust "%s"\' to restore them)' % ownerTrustFileNameExpanded)
        
        # '-':0 no owner trust assigned
        # 'e':? trust calculation has failed
        # 'q':2 not enough information calculation of trust
        # 'n':3 never trust this key
        # 'm':4 is marginally trusted
        # 'f':5 is fully trusted
        # 'u':6 is ultimately trusted
        ownerTrustDict = {'u': 6, 'f':5, 'm':4, 'n':3, 'q':2, '-':0}
        
        tempDict = {}
        for public_key in public_keys:
            tempDict[public_key['fingerprint']] = public_key.copy()
            
        publicKeys = OrderedDict()
        for tempKey in sorted(tempDict):
            publicKeys[tempKey] = tempDict[tempKey]
            
        secretKeys = {}
        for secret_key in secret_keys:
            secretKeys[secret_key['fingerprint']] = secret_key.copy()
        
        if not errStr:
            with open(ownerTrustFileNameExpanded, 'w') as outFile:
                outFile.write('# List of assigned trustvalues, created %s%s' % (dateStr, os.linesep))
                outFile.write('# (Use \'gpg --import-ownertrust "%s"\' to restore them)%s' % (ownerTrustFileNameExpanded, os.linesep))
                for key, value in publicKeys.items():
                    if value['ownertrust'] == '-':
                        if key in secretKeys.keys():
                            ownerTrust = allOwnerTrust
                        else:
                            ownerTrust = dftOwnerTrust
                    else:
                        ownerTrust = ownerTrustDict[value['ownertrust']]
                    print('%s:%s:' % (value['fingerprint'], ownerTrust))
                    outFile.write('%s:%s:' % (value['fingerprint'], ownerTrust))
                    outFile.write(os.linesep)
    
    return ownerTrustFileNameExpanded, errStr
    

# =====================================================================
# Import the owner trust file via an owner trust file
# =====================================================================

def importOwnerTrustFile(ownerTrustFileName,
                         isTestMode=False,
                         pgmLogger=None):
    
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
        
        try:
            subprocess.call([gpgPgmPath, '--import-ownertrust', '%s' % ownerTrustFileNameExpanded], shell=False)
        except Exception as e:
            errStr = str(e)
            pgmLogger.error(errStr)
    
    return errStr



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
