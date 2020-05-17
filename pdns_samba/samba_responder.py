import logging

# Samba source code references:
#   source4/dns_server/dlz_bind9.c
#   python/samba/netcmd/computer.py
#   python/samba/remove_dc.py
from samba import WERRORError, werror
from samba.dcerpc.dnsp import (
        DNS_TYPE_NS, DNS_TYPE_A, DNS_TYPE_AAAA,
        DNS_TYPE_CNAME, DNS_TYPE_MX, DNS_TYPE_SRV,
        DNS_TYPE_PTR, DNS_TYPE_SOA, DNS_TYPE_TXT,
        )

from .responder import PipeResponder

logger = logging.getLogger(__file__)

dns_typemap = {
    DNS_TYPE_NS:    "NS",
    DNS_TYPE_A:     "A",
    DNS_TYPE_AAAA:  "AAAA",
    DNS_TYPE_CNAME: "CNAME",
    DNS_TYPE_MX:    "MX",
    DNS_TYPE_SOA:   "SOA",
    DNS_TYPE_SRV:   "SRV",
    DNS_TYPE_TXT:   "TXT",
    DNS_TYPE_PTR:   "PTR",
}

class SambaResponder(PipeResponder):
    def __init__(self, samdb, inpipe, outpipe):
        super(SambaResponder, self).__init__(inpipe=inpipe, outpipe=outpipe)
        self._samdb = samdb

    def handle_query(self, query):
        try:
            dns_a_dn, records = self._samdb.dns_lookup(query.qname)
        except WERRORError as we:
            # Expected errors here:
            #   werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST: Good zone, bad name
            #   werror.WERR_DNS_ERROR_RCODE_NAME_ERROR: Bad zone
            # TODO: Adapt these errors?
            raise

        logger.debug(dns_a_dn)
        for rec in records:
            rtype = dns_typemap[rec.wType]
            if query.qtype in ('ANY', rtype):
                yield self._get_response(query, rec)

    def _get_response(self, query, rec):
        """Maps a SamDB dns response to a response Data object"""
        content = {
            DNS_TYPE_SOA: self._content_for_SOA,
            DNS_TYPE_TXT: self._content_for_TXT,
            DNS_TYPE_MX: self._content_for_MX,
            DNS_TYPE_SRV: self._content_for_SRV,
        }.get(rec.wType, self._content_default)(rec)

        return query.response(
                qtype = dns_typemap[rec.wType],
                ttl = rec.dwTtlSeconds,
                content = content,
                )

    def _content_default(self, rec):
        return rec.data

    def _content_for_SOA(self, rec):
        soa = rec.data

        # https://doc.powerdns.com/authoritative/appendices/types.html#soa
        # primary hostmaster serial refresh retry expire default_ttl
        return ' '.join(str(x) for x in (
            soa.mname,      # primary
            soa.rname,      # hostmaster
            soa.serial,     # serial
            soa.refresh,    # refresh
            soa.retry,      # retry
            soa.expire,     # expire
            soa.minimum,    # default_ttl
            ))

    def _content_for_TXT(self, rec):
        # https://doc.powerdns.com/authoritative/appendices/types.html#txt
        # TODO: Need to return a quoted string with internal quotes escaped
        raise NotImplementedError("TXT not yet implemented")

    # https://doc.powerdns.com/authoritative/backends/pipe.html#pipe-command
    # "For MX and SRV, content consists of the priority, followed by a tab,
    # followed by the actual content."
    def _content_for_MX(self, rec):
        raise NotImplementedError("MX not yet implemented")

    def _content_for_SRV(self, rec):
        raise NotImplementedError("SRV not yet implemented")
