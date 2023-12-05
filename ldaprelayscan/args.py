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
import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="Checks Domain Controllers for LDAP authentication protection."
        + " You can check for only LDAPS protections (channel binding), this is done unauthenticated. "
        + "Alternatively you can check for both LDAPS and LDAP (server signing) protections. "
        + "This requires a successful LDAP bind.",
    )
    parser.add_argument(
        "-m",
        "--method",
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
        "-u",
        "--username",
        action="store",
        help="Domain username value.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        default=10,
        action="store",
        type=int,
        help="The timeout for MSLDAP client connection.",
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Domain username value.",
    )
    parser.add_argument(
        "--nthash", metavar="nthash", action="store", help="NT hash of password"
    )
    options = parser.parse_args()
    return options


def process_args(options):
    # Avoid top-level import for quick `--help` response
    import getpass
    from ldaprelayscan.scan import ResolveDCs, InternalDomainFromAnonymousLdap

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

    if options.method == "BOTH" and options.password is None and options.nthash is None:
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
