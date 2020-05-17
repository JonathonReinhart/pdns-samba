from samba.credentials import Credentials, MUST_USE_KERBEROS
from samba.param import LoadParm
from samba.samdb import SamDB
import logging
import sys
import os

from .samba_responder import SambaResponder

logger = logging.getLogger(__file__)

def parse_args():
    import argparse
    ap = argparse.ArgumentParser()
    def ldap_url(s):
        prefixes = ('ldap://', 'ldapi://', 'ldaps://')
        if not any(s.startswith(p) for p in prefixes):
            raise ValueError("url must start with one of " + " ".join(prefixes))
        return s
    ap.add_argument('--url', type=ldap_url, required=True)
    ap.add_argument('--debug', action='store_true')
    ap.add_argument('--unix')

    return ap.parse_args()

def main():
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)

    inpipe = sys.stdin
    outpipe = sys.stdout

    if args.unix:
        import socket
        try:
            os.remove(args.unix)
        except OSError:
            pass

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(args.unix)
        os.chmod(args.unix, 0o777)
        logger.debug("Bound unix socket: {}".format(args.unix))

        logger.info("Waiting for connection at {}".format(args.unix))
        sock.listen(1)
        csock, client_address = sock.accept()

        logger.info("Accepted connection from {}".format(client_address))
        inpipe = outpipe = csock.makefile()


    lp = LoadParm()
    lp.load_default()

    creds = Credentials()
    creds.guess(lp)
    creds.set_kerberos_state(MUST_USE_KERBEROS)
    # If MUST_USE_KERBEROS and we have no ticket, yields this error:
    # "Failed to connect to 'ldap://dc1' with backend 'ldap': LDAP client
    # internal error: NT_STATUS_INVALID_PARAMETER"

    # lp is required by ldap_connect_send() -> lpcfg_resolve_context()
    samdb = SamDB(lp=lp, url=args.url, credentials=creds)

    logger.debug("Opened SAM DB:")
    logger.debug("  domain_dn:       {}".format(samdb.domain_dn()))
    logger.debug("  domain_dns_name: {}".format(samdb.domain_dns_name()))

    try:
        r = SambaResponder(samdb, inpipe, outpipe)
        r.run()
    finally:
        if args.unix:
            try:
                os.remove(args.unix)
            except OSError:
                pass
