
from impacket.examples.secretsdump import NTDSHashes
from impacket.dcerpc.v5 import drsuapi, samr
from impacket import ntlm

import binascii
import struct

class NTDSPrincipalSecrets:

    def __init__(self, sAMAccountName: str, rid: str, ntHash: str, lmHash: str, aesKey: list, lmHistory: list, ntHistory: list, cleartext: list) -> None:
        self.sAMAccountName = sAMAccountName
        self.rid            = rid
        self.ntHash         = ntHash
        self.ntHistory      = ntHistory
        self.lmHash         = lmHash
        self.lmHistory      = lmHistory
        self.aesKey         = aesKey
        self.cleartext      = cleartext

class NTDSAESKeyAndCleartext:

    def __init__(self, aesKey: list, cleartext: list):
        self.aesKey = aesKey
        self.cleartext = cleartext

class NTDSDCSyncHashes:

    @staticmethod
    def getPrincipalSecrets(drsr, record, prefixTable=None) -> NTDSPrincipalSecrets:
        return NTDSDCSyncHashes.__internalGetPrincipalSecrets(drsr, record, prefixTable=None)

    @staticmethod
    def __internalGetPrincipalSecrets(drsr, record, prefixTable=None) -> NTDSPrincipalSecrets:
        replyVersion = "V%d" %record["pdwOutVersion"]

        # Value returned
        sAMAccountName = ""
        rid = struct.unpack("<L", record["pmsgOut"][replyVersion]["pObjects"]["Entinf"]["pName"]["Sid"][-4:])[0]
        LMHash = ""
        NTHash = ""
        LMHistory = list()
        NTHistory = list()
        aesKeyAndCleartext = NTDSAESKeyAndCleartext(list(), list())

        for attr in record["pmsgOut"][replyVersion]["pObjects"]["Entinf"]["AttrBlock"]["pAttr"]:
            try:
                attId = drsuapi.OidFromAttid(prefixTable, attr["attrTyp"])
                LOOKUP_TABLE = NTDSHashes.ATTRTYP_TO_ATTID
            except Exception as e:
                # Fallbacking to fixed table and hope for the best
                attId = attr["attrTyp"]
                LOOKUP_TABLE = NTDSHashes.NAME_TO_ATTRTYP

            # Hash LM
            if attId == LOOKUP_TABLE["dBCSPwd"]:
                LMHash = NTDSDCSyncHashes.__getHash(attr, drsr, rid)

            # Hash NT
            elif attId == LOOKUP_TABLE["unicodePwd"]:
                NTHash = NTDSDCSyncHashes.__getHash(attr, drsr, rid)

            # Hash LM History
            elif attId == LOOKUP_TABLE['lmPwdHistory']:
                LMHistory = NTDSDCSyncHashes.__getHashHistory(attr, drsr, rid)

            # Hash NT History
            elif attId == LOOKUP_TABLE['ntPwdHistory']:
                NTHistory = NTDSDCSyncHashes.__getHashHistory(attr, drsr, rid)

            # sAMAccountName
            elif attId == LOOKUP_TABLE["sAMAccountName"]:
                sAMAccountName = NTDSDCSyncHashes.__getSAMAccountName(attr)
            
            # AES Key
            if attId == LOOKUP_TABLE["supplementalCredentials"]:
                aesKeyAndCleartext = NTDSDCSyncHashes.__getAESKeyAndCleartext(attr, drsr)

        return NTDSPrincipalSecrets(sAMAccountName, rid, NTHash, LMHash, aesKeyAndCleartext.aesKey, LMHistory, NTHistory, aesKeyAndCleartext.cleartext)

    @staticmethod
    def __getHash(attr, drsr, rid) -> str:
        if attr["AttrVal"]["valCount"] > 0:
            encryptedPwd = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"])
            encryptedHash = drsuapi.DecryptAttributeValue(drsr, encryptedPwd)
            Hash = drsuapi.removeDESLayer(encryptedHash, rid)
        else:
            Hash = ntlm.NTOWFv1("", "")

        return binascii.hexlify(Hash).decode("utf-8")

    @staticmethod
    def __getHashHistory(attr, drsr, rid) -> list:
        History = list()

        if attr['AttrVal']['valCount'] > 0:
            encryptedHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
            tmpHistory = drsuapi.DecryptAttributeValue(drsr, encryptedHistory)
            for i in range(0, len(tmpHistory) // 16):
                NTHashHistory = drsuapi.removeDESLayer(tmpHistory[i * 16:(i + 1) * 16], rid)
                History.append(NTHashHistory)
        
        return History

    @staticmethod
    def __getSAMAccountName(attr) -> str:
        if attr["AttrVal"]["valCount"] > 0:
            try:
                return b"".join(attr["AttrVal"]["pAVal"][0]["pVal"]).decode("utf-16le")
            except:
                return "unknown"
        else:
            return "unknown"            

    @staticmethod
    def __getAESKeyAndCleartext(attr, drsr) -> NTDSAESKeyAndCleartext:
        # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
        returnData = NTDSAESKeyAndCleartext(list(), list())

        if attr["AttrVal"]["valCount"] < 0:
            return
        
        blob = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"])
        plainText = drsuapi.DecryptAttributeValue(drsr, blob)
        
        if len(plainText) < 24:
            return

        try:
            userProperties = samr.USER_PROPERTIES(plainText)
        except:
            # On some old w2k3 there might be user properties that don't
            # match [MS-SAMR] structure, discarding them
            return

        propertiesData = userProperties["UserProperties"]
        for propertyCount in range(userProperties["PropertyCount"]):
            userProperty = samr.USER_PROPERTY(propertiesData)
            propertiesData = propertiesData[len(userProperty):]

            # For now, we will only process Newer Kerberos Keys and CLEARTEXT
            if userProperty["PropertyName"].decode("utf-16le") == "Primary:Kerberos-Newer-Keys":
                propertyValueBuffer = binascii.unhexlify(userProperty["PropertyValue"])
                kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                data = kerbStoredCredentialNew["Buffer"]

                for credential in range(kerbStoredCredentialNew["CredentialCount"]):
                    keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                    data = data[len(keyDataNew):]
                    keyValue = propertyValueBuffer[keyDataNew["KeyOffset"]:][:keyDataNew["KeyLength"]]

                    if  keyDataNew["KeyType"] in NTDSHashes.KERBEROS_TYPE:
                        answer = "%s:%s" % (NTDSHashes.KERBEROS_TYPE[keyDataNew["KeyType"]], keyValue.hex())
                    else:
                        answer = "%s:%s" % (hex(keyDataNew["KeyType"]), keyValue.hex())

                    returnData.aesKey.append(answer)

            elif userProperty["PropertyName"].decode("utf-16le") == "Primary:CLEARTEXT":
                # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
                # This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
                try:
                    answer = "%s" % (binascii.unhexlify(userProperty["PropertyValue"]).decode("utf-16le"))
                except UnicodeDecodeError:
                    # This could be because we're decoding a machine password. Printing it hex
                    answer = "0x%s" % (userProperty["PropertyValue"].decode("utf-8"))

                returnData.cleartext.append(answer)

        return returnData

class NTDSHashes:
    class SECRET_TYPE:
        NTDS = 0
        NTDS_CLEARTEXT = 1
        NTDS_KERBEROS = 2

    NAME_TO_INTERNAL = {
        'uSNCreated':b'ATTq131091',
        'uSNChanged':b'ATTq131192',
        'name':b'ATTm3',
        'objectGUID':b'ATTk589826',
        'objectSid':b'ATTr589970',
        'userAccountControl':b'ATTj589832',
        'primaryGroupID':b'ATTj589922',
        'accountExpires':b'ATTq589983',
        'logonCount':b'ATTj589993',
        'sAMAccountName':b'ATTm590045',
        'sAMAccountType':b'ATTj590126',
        'lastLogonTimestamp':b'ATTq589876',
        'userPrincipalName':b'ATTm590480',
        'unicodePwd':b'ATTk589914',
        'dBCSPwd':b'ATTk589879',
        'ntPwdHistory':b'ATTk589918',
        'lmPwdHistory':b'ATTk589984',
        'pekList':b'ATTk590689',
        'supplementalCredentials':b'ATTk589949',
        'pwdLastSet':b'ATTq589920',
    }

    NAME_TO_ATTRTYP = {
        'userPrincipalName': 0x90290,
        'sAMAccountName': 0x900DD,
        'unicodePwd': 0x9005A,
        'dBCSPwd': 0x90037,
        'ntPwdHistory': 0x9005E,
        'lmPwdHistory': 0x900A0,
        'supplementalCredentials': 0x9007D,
        'objectSid': 0x90092,
        'userAccountControl':0x90008,
    }

    ATTRTYP_TO_ATTID = {
        'userPrincipalName': '1.2.840.113556.1.4.656',
        'sAMAccountName': '1.2.840.113556.1.4.221',
        'unicodePwd': '1.2.840.113556.1.4.90',
        'dBCSPwd': '1.2.840.113556.1.4.55',
        'ntPwdHistory': '1.2.840.113556.1.4.94',
        'lmPwdHistory': '1.2.840.113556.1.4.160',
        'supplementalCredentials': '1.2.840.113556.1.4.125',
        'objectSid': '1.2.840.113556.1.4.146',
        'pwdLastSet': '1.2.840.113556.1.4.96',
        'userAccountControl':'1.2.840.113556.1.4.8',
    }

    KERBEROS_TYPE = {
        1:'dec-cbc-crc',
        3:'des-cbc-md5',
        17:'aes128-cts-hmac-sha1-96',
        18:'aes256-cts-hmac-sha1-96',
        0xffffff74:'rc4_hmac',
    }