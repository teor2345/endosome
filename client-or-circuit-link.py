#!/usr/bin/env python
# Open a Tor circuit with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import stem.client.cell

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

# Request:
# VERSIONS, NETINFO, CREATE_FAST
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO, CREATED_FAST

cell_list = []
netinfo_payload = pack_netinfo_payload('127.0.0.1')

netinfo_cell = {
  'cell_command_string': 'NETINFO',
  'payload_bytes': netinfo_payload,
}

cell_list.append(netinfo_cell)
create_fast_payload=pack_create_fast_payload()

cell_list.append(stem.client.cell.CreateFastCell())

# Try the default set of link versions: we will get 4 or 5, depending on
# the Tor version
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection, sending link version and netinfo cells'
(context, response_bytes) = link_request_cell_list(RELAYIP, ORPORT, cell_list)
print 'Connection context:\n{}'.format(link_format_context(context))
print 'Connection cells:\n{}'.format(format_cell_bytes(context,
                                                            response_bytes))

# Try link version 3
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection, sending link versions cell only'
(context, response_bytes) = link_request_cell_list(RELAYIP, ORPORT, cell_list, link_version_list=[3])
print 'Connection context:\n{}'.format(link_format_context(context))
print 'Connection cells:\n{}'.format(format_cell_bytes(context,
                                                            response_bytes))
