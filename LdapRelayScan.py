"""
MIT License

Copyright (c) 2023 Nick Powers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

========

Modified by Adrian Vollmer in 2023
"""

import urllib.parse
import dns.resolver
import ldap3
import argparse
import sys
import ssl
import socket
import getpass
import asyncio
from msldap.connection import MSLDAPClientConnection
from msldap.commons.factory import LDAPConnectionFactory


class CheckLdaps:
    def __init__(self, nameserver, username, cmdLineOptions):
        self.options = cmdLineOptions
        self.__nameserver = nameserver
        self.__username = username


# Conduct a bind to LDAPS and determine if channel
# binding is enforced based on the contents of potential
# errors returned. This can be determined unauthenticated,
# because the error indicating channel binding enforcement
# will be returned regardless of a successful LDAPS bind.
def run_ldaps_noEPA(inputUser, inputPassword, dcTarget):
    try:
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        ldapServer = ldap3.Server(
            dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls
        )
        ldapConn = ldap3.Connection(
            ldapServer,
            user=inputUser,
            password=inputPassword,
            authentication=ldap3.NTLM,
        )
        if not ldapConn.bind():
            if "data 80090346" in str(ldapConn.result):
                return True  # channel binding IS enforced
            elif "data 52e" in str(ldapConn.result):
                return False  # channel binding not enforced
            else:
                print("[!] UNEXPECTED ERROR: " + str(ldapConn.result))
        else:
            # LDAPS bind successful
            return False  # because channel binding is not enforced
            exit()
    except Exception as e:
        print(
            "[!] %s - %s - Ensure DNS is resolving properly, and that you can reach LDAPS on this host"
            % (dcTarget, e)
        )


# Conduct a bind to LDAPS with channel binding supported
# but intentionally miscalculated. In the case that and
# LDAPS bind has without channel binding supported has occured,
# you can determine whether the policy is set to "never" or
# if it's set to "when supported" based on the potential
# error recieved from the bind attempt.
async def run_ldaps_withEPA(inputUser, inputPassword, dcTarget, fqdn, timeout):
    try:
        inputPassword = urllib.parse.quote(inputPassword)
        url = (
            "ldaps+ntlm-password://" + inputUser + ":" + inputPassword + "@" + dcTarget
        )
        conn_url = LDAPConnectionFactory.from_url(url)
        ldaps_client = conn_url.get_client()
        ldaps_client.target.timeout = timeout
        ldapsClientConn = MSLDAPClientConnection(
            ldaps_client.target, ldaps_client.creds
        )
        _, err = await ldapsClientConn.connect()
        if err is not None:
            raise err
        # forcing a miscalculation of the "Channel Bindings" av pair in Type 3 NTLM message
        ldapsClientConn.cb_data = b"\0" * 71
        _, err = await ldapsClientConn.bind()
        if "data 80090346" in str(err):
            return True
        elif "data 52e" in str(err):
            return False
        elif err is not None:
            print("[!] ERROR while connecting to " + dcTarget + ": " + err)
        elif err is None:
            return False
    except Exception as e:
        print("[!] something went wrong during ldaps_withEPA bind:" + str(e))


# DNS query of an SRV record that should return
# a list of domain controllers.
def ResolveDCs(nameserverIp, fqdn):
    dcList = []
    DnsResolver = dns.resolver.Resolver()
    DnsResolver.timeout = 20
    DnsResolver.nameservers = [nameserverIp]
    dcQuery = DnsResolver.resolve("_ldap._tcp.dc._msdcs." + fqdn, "SRV", tcp=True)
    testout = str(dcQuery.response).split("\n")
    for line in testout:
        if "IN A" in line:
            dcList.append(line.split(" ")[0].rstrip(line.split(" ")[0][-1]))
    return dcList


# Conduct an anonymous bind to the provided "nameserver"
# arg during execution. This should work even if LDAP
# server integrity checks are enforced. The FQDN of the
# internal domain will be parsed from the basic server
# info gathered from that anonymous bind.
def InternalDomainFromAnonymousLdap(nameserverIp):
    #  tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    # ldapServer = ldap3.Server(dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
    ldapServer = ldap3.Server(nameserverIp, use_ssl=False, port=389, get_info=ldap3.ALL)
    ldapConn = ldap3.Connection(ldapServer, authentication=ldap3.ANONYMOUS)
    ldapConn.bind()
    parsedServerInfo = str(ldapServer.info).split("\n")
    fqdn = ""
    for line in parsedServerInfo:
        if "$" in line:
            fqdn = line.strip().split("@")[1]
    return fqdn


# Domain Controllers do not have a certificate setup for
# LDAPS on port 636 by default. If this has not been setup,
# the TLS handshake will hang and you will not be able to
# interact with LDAPS. The condition for the certificate
# existing as it should is either an error regarding
# the fact that the certificate is self-signed, or
# no error at all. Any other "successful" edge cases
# not yet accounted for.
def DoesLdapsCompleteHandshake(dcIp):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    ssl_context = ssl.SSLContext(
        protocol=ssl.PROTOCOL_TLS_CLIENT,
        suppress_ragged_eofs=False,
        do_handshake_on_connect=False,
    )
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_sock = ssl_context.wrap_socket(s)
    ssl_sock.connect((dcIp, 636))

    try:
        ssl_sock.do_handshake()
        ssl_sock.close()
        return True
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            ssl_sock.close()
            return True
        if "handshake operation timed out" in str(e):
            ssl_sock.close()
            return False
        else:
            print("[!] Unexpected error during LDAPS handshake: " + str(e))
        ssl_sock.close()


# Conduct and LDAP bind and determine if server signing
# requirements are enforced based on potential errors
# during the bind attempt.
def run_ldap(inputUser, inputPassword, dcTarget):
    ldapServer = ldap3.Server(dcTarget, use_ssl=False, port=389, get_info=ldap3.ALL)
    ldapConn = ldap3.Connection(
        ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM
    )
    if not ldapConn.bind():
        ldapConn_result_str = str(ldapConn.result)
        if "stronger" in ldapConn_result_str:
            return True  # because LDAP server signing requirements ARE enforced
        elif "data 52e" in ldapConn_result_str or "data 532" in ldapConn_result_str:
            print(
                "[!!!] invalid credentials - aborting to prevent unnecessary authentication"
            )
            exit()
        else:
            print("[!] UNEXPECTED ERROR: " + ldapConn_result_str)
    else:
        # LDAPS bind successful
        return False  # because LDAP server signing requirements are not enforced
        exit()


def parse_args():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Checks Domain Controllers for LDAP authentication protection."
        + " You can check for only LDAPS protections (channel binding), this is done unauthenticated. "
        + "Alternatively you can check for both LDAPS and LDAP (server signing) protections. "
        + "This requires a successful LDAP bind.",
    )
    parser.add_argument(
        "-m", "--method",
        choices=["LDAPS", "BOTH"],
        default="LDAPS",
        help="LDAPS or BOTH - LDAPS checks for channel binding, BOTH checks for "
        "LDAP signing and LDAP channel binding [authentication required]",
    )
    parser.add_argument(
        "dc_ip",
        help="DNS Nameserver on network. Any DC's IPv4 address should work.",
    )
    parser.add_argument(
        "-u", "--username",
        action="store",
        help="Domain username value.",
    )
    parser.add_argument(
        "-t", "--timeout",
        default=10,
        action="store",
        type=int,
        help="The timeout for MSLDAP client connection.",
    )
    parser.add_argument(
        "-p", "--password",
        help="Domain username value.",
    )
    parser.add_argument(
        "--nthash", metavar="nthash", action="store", help="NT hash of password"
    )
    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.method == "BOTH":
        if options.username is None:
            print("[*] Using BOTH method requires a username parameter")
            exit()
    if (
        options.method == "BOTH"
        and options.username is not None
        and (options.password is not None or options.nthash is not None)
    ):
        if options.password is None and options.nthash is not None:
            password = "aad3b435b51404eeaad3b435b51404ee:" + options.nthash
        elif options.password is not None and options.nthash is None:
            password = options.password
        else:
            print("[!] Something incorrect while providing credential material options")

    if (
        options.method == "BOTH"
        and options.password is None
        and options.nthash is None
    ):
        password = getpass.getpass(prompt="Password: ")
    fqdn = InternalDomainFromAnonymousLdap(options.dc_ip)

    domainUser = options.username or "guest"
    password = options.password or "default"

    print("[*] Checking DCs for LDAP NTLM relay protections")
    username = fqdn + "\\" + domainUser
    # print("VALUES AUTHING WITH:\nUser: "+domainUser+"\nPass: " +password + "\nDomain:  "+fqdn)

    dcList = ResolveDCs(options.dc_ip, fqdn)
    print("[*] Domain Controllers identified")
    for dc in dcList:
        print("   " + dc)

    return dict(
        dc_list=dcList,
        username=username,
        password=password,
        fqdn=fqdn,
        method=options.method,
        timeout=options.timeout,
    )


def scan(dc, username=None, password=None, fqdn=None, method=None, timeout=None):
    if method == "BOTH":
        ldapIsProtected = run_ldap(username, password, dc)
        if not ldapIsProtected:
            print("[+] (LDAP)  SERVER SIGNING REQUIREMENTS NOT ENFORCED!")
        elif ldapIsProtected:
            print("[-] (LDAP)  server enforcing signing requirements")

    if DoesLdapsCompleteHandshake(dc):
        ldapsChannelBindingAlwaysCheck = run_ldaps_noEPA(username, password, dc)
        ldapsChannelBindingWhenSupportedCheck = asyncio.run(
            run_ldaps_withEPA(username, password, dc, fqdn, timeout)
        )
        if not ldapsChannelBindingAlwaysCheck and ldapsChannelBindingWhenSupportedCheck:
            print(
                '[-] (LDAPS) channel binding is set to "when supported" - this '
                "may prevent an NTLM relay depending on the client's "
                "support for channel binding."
            )
        elif (
            not ldapsChannelBindingAlwaysCheck
            and not ldapsChannelBindingWhenSupportedCheck
        ):
            print('[+] (LDAPS) CHANNEL BINDING SET TO "NEVER"')
        elif ldapsChannelBindingAlwaysCheck:
            print('[-] (LDAPS) channel binding set to "required"')
        else:
            print("[!] Something went wrong...")
            print(
                "For troubleshooting:\nldapsChannelBindingAlwaysCheck - "
                + str(ldapsChannelBindingAlwaysCheck)
                + "\nldapsChannelBindingWhenSupportedCheck: "
                + str(ldapsChannelBindingWhenSupportedCheck)
            )
            exit()
        # print("For troubleshooting:\nldapsChannelBindingAlwaysCheck - "
        #       str(ldapsChannelBindingAlwaysCheck)+"\nldapsChannelBindingWhenSupportedCheck: "
        #       str(ldapsChannelBindingWhenSupportedCheck))

    else:
        print(
            "[!] " + dc + " - cannot complete TLS handshake, cert likely not configured"
        )


def main():
    args = parse_args()
    dc_list = args["dc_list"]
    del args["dc_list"]
    for dc in dc_list:
        scan(dc, **args)


if __name__ == "__main__":
    main()
