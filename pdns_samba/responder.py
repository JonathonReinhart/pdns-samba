# This implements the PowerDNS "Pipe" backend protocol:
# https://doc.powerdns.com/authoritative/backends/pipe.html#pipebackend-protocol
# Questions come in over a file descriptor, by default standard input. Answers
# are sent out over another file descriptor, standard output by default.
# Questions and answers are terminated by single newline (\n) characters.
# Fields in lines must be separated by tab (\t) characters.
import logging

logger = logging.getLogger(__file__)

DEFAULT_TTL = 86400

class PipeResponder(object):
    def __init__(self, inpipe, outpipe):
        """Create a new pipe backend responder

        Parameters:
        inpipe   The input pipe file-like object on which
                 PowerDNS sends questions to the responder 
        outpipe  The output pipe file-like object on which
                 the responder sends answers to PowerDNS
        """
        self._inpipe = inpipe
        self._outpipe = outpipe

        self._cmdmap = {
            # command: (handler, send_END)
            'HELO': (self._handle_hello, False),
            'Q':    (self._handle_Q, True),
        }

        self.abi_version = None
        self.banner = 'pdns-samba'
    
    def run(self):
        while True:
            # "Fields are tab separated, and terminated with a single \n."
            line = self._inpipe.readline()
            if not line:
                break

            line = line[:-1]
            logger.debug("Received line: {!r}".format(line))

            fields = line.split('\t')
            cmd, fields = fields[0], fields[1:]

            def no_handler(fields):
                raise Exception("No handler for command {!r} {!r}".format(cmd, fields))
            
            handler, send_END = self._cmdmap.get(cmd, (no_handler, False))

            try:
                response = handler(fields)
            except:
                logger.exception("Handler {}({}) raised an exception"
                        .format(handler, fields))
                self._respond('FAIL')
                continue

            if not response:
                logger.error("Handler {}({}) returned no response"
                        .format(handler, fields))
                self._respond('FAIL')
                continue

            # Handlers return a sequence of tuples
            for r in response:
                self._respond(*r)
            if send_END:
                self._respond('END')


    def _respond(self, *data):
        logging.debug("Responding with {!r}".format(data))
        self._outpipe.write('\t'.join(data) + '\n')
        self._outpipe.flush()


    def _handle_hello(self, fields):
        ver = int(fields[0])
        if self.abi_version is not None:
            logger.warning("HELO already received (old ver {}, new ver {})"
                    .format(self.abi_version, ver))
        self.abi_version = ver

        if not ver in (1, 2, 3):
            raise Exception("Unsupported ABI version: {}".format(ver))

        return (
            ('OK', self.banner),
        )


    def _handle_Q(self, fields):
        qname, qclass, qtype = fields[0:3]
        id = int(fields[3])
        remote_ipaddr = fields[4]

        local_ipaddr = None
        if self.abi_version >= 2:
            local_ipaddr = fields[5]

        edns_subnet = None
        if self.abi_version >= 3:
            edns_subnet = fields[6]

        q = Query(
                qname=qname,
                qclass=qclass,
                qtype=qtype,
                id=id,
                remote_ipaddr=remote_ipaddr,
                local_ipaddr=local_ipaddr,
                edns_subnet=edns_subnet,
                )

        logger.info(str(q))
        results = self.handle_query(q)
        return [r.get_data(self.abi_version) for r in results]


    def handle_query(self, query):
        raise NotImplementedError()


class Query(object):
    def __init__(self, qname, qclass, qtype, id,
            remote_ipaddr, local_ipaddr, edns_subnet):
        self.qname = qname
        self.qclass = qclass
        self.qtype = qtype
        self.id = id
        self.remote_ipaddr = remote_ipaddr
        self.local_ipaddr = local_ipaddr
        self.edns_subnet = edns_subnet

    def __repr__(self):
        return ("Query(qname={!r}, qclass={!r}, qtype={!r}, id={!r}, "
                "remote_ipaddr={!r}, local_ipaddr={!r}, edns_subnet={!r})"
                .format(self.qname, self.qclass, self.qtype, self.id,
                    self.remote_ipaddr, self.local_ipaddr, self.edns_subnet))

    def response(self, qtype, content, **kw):
        return Data(
                qname=self.qname,
                qclass=self.qclass,
                qtype=qtype,
                content=content,
                **kw)


class Data(object):
    def __init__(self, qname, qclass, qtype, content, ttl=DEFAULT_TTL,
            id=1, scopebits=0, auth=1):
        self.qname = qname
        self.qclass = qclass
        self.qtype = qtype
        self.ttl = ttl
        self.id = id
        self.scopebits = scopebits
        self.auth = auth
        self.content = content

    def __repr__(self):
        return ("Data(qname={!r}, qclass={!r}, qtype={!r}, ttl={!r}, id={!r}, "
                "scopebits={!r}, auth={!r}, content={!r})"
                .format(self.qname, self.qclass, self.qtype, self.ttl, self.id,
                    self.scopebits, self.auth, self.content))

    def get_data(self, abi_version):
        result = ['DATA']

        if abi_version == 3:
            result += [str(self.scopebits), str(self.auth)]

        result += [
                self.qname, self.qclass, self.qtype,
                str(self.ttl), str(self.id), self.content,
            ]
        return result
