#!/bin/bash
python -m pdns_samba --url ldap://dc1.ad-test.vx --debug "$@"
