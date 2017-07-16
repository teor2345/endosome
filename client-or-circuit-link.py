#!/usr/bin/env python
# Open a Tor circuit with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

MAX_RESPONSE_LEN = 10*1024*1024

# Request:
# VERSIONS, NETINFO, CREATE_FAST
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO, CREATED_FAST

cell_list = []
netinfo_payload = pack_netinfo_payload('127.0.0.1')
netinfo_cell = make_cell('NETINFO', payload=netinfo_payload)
cell_list.append(netinfo_cell)
create_fast_payload=pack_create_fast_payload()
create_fast_cell = make_cell('CREATE_FAST',
                             # Automatically choose a valid circuit ID for the
                             # link version
                             circ_id=None,
                             payload=create_fast_payload)
cell_list.append(create_fast_cell)

# Try the default set of link versions: we will get 4 or 5, depending on
# the Tor version
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection, sending link versions cell only'
(context, response_bytes) = link_request_cell_list(RELAYIP, ORPORT,
                                                   cell_list)
print 'Connection context:\n{}'.format(link_format_context(context))
print 'Connection cells:\n{}'.format(link_format_cell_bytes(context,
                                                           response_bytes))

# Try link version 3
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection, sending link versions cell only'
(context, response_bytes) = link_request_cell_list(RELAYIP, ORPORT,
                                                   cell_list,
                                                   link_version_list=[3])
print 'Connection context:\n{}'.format(link_format_context(context))
print 'Connection cells:\n{}'.format(link_format_cell_bytes(context,
                                                           response_bytes))
