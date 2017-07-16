#!/usr/bin/env python
# Do a Tor OR link version negotiation with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

# Request:
# VERSIONS, NETINFO
#
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO

# Try the default set of link versions: we will get 4 or 5, depending on
# the Tor version
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection, sending link versions cell only'
(context, response_bytes) = link_request_cell_list(RELAYIP, ORPORT,
                                                   [])
print 'Connection context:\n{}'.format(link_format_context(context))
print 'Connection cells:\n{}'.format(link_format_cell_bytes(context,
                                                           response_bytes))

# Try link version 3
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection, sending link versions cell only'
(context, response_bytes) = link_request_cell_list(RELAYIP, ORPORT,
                                                   [],
                                                   link_version_list=[3])
print 'Connection context:\n{}'.format(link_format_context(context))
print 'Connection cells:\n{}'.format(link_format_cell_bytes(context,
                                                           response_bytes))

# Try without netinfo
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection, sending link versions cell only'
(context, response_bytes) = link_request_cell_list(RELAYIP, ORPORT,
                                                   [],
                                                   send_netinfo=False)
print 'Connection context:\n{}'.format(link_format_context(context))
print 'Connection cells:\n{}'.format(link_format_cell_bytes(context,
                                                            response_bytes))
