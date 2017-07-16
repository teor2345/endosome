#!/usr/bin/env python
# Open a Tor circuit with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

# Request:
# VERSIONS, NETINFO, CREATE_FAST
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO, CREATED_FAST

# Try no netinfo:
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v4 or v5 circuit without NETINFO'
link_context = link_open(RELAYIP, ORPORT, send_netinfo=False)
circuit_context = circuit_create(link_context)
print '\nLink context:\n{}'.format(link_format_context(link_context))
print '\nCircuit context:\n{}'.format(circuit_format_context(circuit_context))
