#!/usr/bin/env python2
#
# Samba source code references:
#   source4/dns_server/dlz_bind9.c
#   python/samba/netcmd/computer.py
#   python/samba/remove_dc.py

from __future__ import print_function
from pprint import pprint
import sys

from samba import WERRORError, werror
from samba.samdb import SamDB
from samba.param import LoadParm
from samba.dcerpc.dnsp import DNS_TYPE_NS, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_SRV, DNS_TYPE_PTR, DNS_TYPE_SOA
from samba.credentials import Credentials, MUST_USE_KERBEROS

dns_typemap = {
    DNS_TYPE_NS:    "NS",
    DNS_TYPE_A:     "A",
    DNS_TYPE_AAAA:  "AAAA",
    DNS_TYPE_CNAME: "CNAME",
    DNS_TYPE_SOA:   "SOA",
    DNS_TYPE_SRV:   "SRV",
    DNS_TYPE_PTR:   "PTR",
}

def query(samdb, q):
    print("\nDNS Lookup:", q)

    try:
        dns_a_dn, records = samdb.dns_lookup(q)
    except WERRORError as we:
        print("Error looking up {}: {}".format(q, we))
        return
        # Expected errors here:
        #   werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST: Good zone, bad name
        #   werror.WERR_DNS_ERROR_RCODE_NAME_ERROR: Bad zone


    print(dns_a_dn)

    for i, r in enumerate(records):
        print("[{}]".format(i))
        print("  dwReserved:", r.dwReserved)
        print("  dwSerial:", r.dwSerial)
        print("  dwTimeStamp:", r.dwTimeStamp)
        print("  dwTtlSeconds:", r.dwTtlSeconds)
        print("  flags:", r.flags)
        print("  rank:", r.rank)
        print("  version:", r.version)
        print("  wDataLength:", r.wDataLength)
        print("  wType:", dns_typemap[r.wType])
        print("  data:", r.data)
        if r.wType == DNS_TYPE_SOA:
            soa = r.data
            print("    expire:", soa.expire)
            print("    minimum:", soa.minimum)
            print("    mname:", soa.mname)
            print("    refresh:", soa.refresh)
            print("    retry:", soa.retry)
            print("    rname:", soa.rname)
            print("    serial:", soa.serial)


def main():
    lp = LoadParm()
    lp.load_default()

    print("\nLoaded loadparm:")
    print("  samdb_url:      ", lp.samdb_url())
    print("  server_role:    ", lp.server_role())

    creds = Credentials()
    creds.guess(lp)
    print("\nCredentials:")
    creds.set_kerberos_state(MUST_USE_KERBEROS)
    # If MUST_USE_KERBEROS and we have no ticket, yields this error:
    # "Failed to connect to 'ldap://dc1' with backend 'ldap': LDAP client internal error: NT_STATUS_INVALID_PARAMETER"


    # Local
    #samdb = SamDB(lp=lp)

    # Remote
    samdb = SamDB(lp=lp, url='ldap://dc1', credentials=creds)

    print("\nOpened SAM DB:")
    print("  domain_dn:      ", samdb.domain_dn())
    print("  domain_dns_name:", samdb.domain_dns_name())

    for q in sys.argv[1:]:
        query(samdb, q)

if __name__ == '__main__':
    main()
