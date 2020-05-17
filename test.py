import sys
import logging
from pdns_samba.responder import PipeResponder

logging.basicConfig(level=logging.DEBUG)

class TestResponder(PipeResponder):
    def handle_query(self, query):
        if query.qtype in ('A', 'ANY'):
            yield query.response('A', '7.0.0.1')
            yield query.response('A', '7.0.0.2')


r = TestResponder(sys.stdin, sys.stdout)
r.run()
