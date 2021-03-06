#!/usr/bin/env python
# Do a Tor OR client version negotiation with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# This script just sends a versions cell

import binascii

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

MAX_RESPONSE_LEN = 10*1024*1024

# Request:
# VERSIONS: CircID(2)=None CommandCode=VERSIONS PayloadLength=2
#           SupportedVersionList=3,4,5
# Expected Response:
# VERSIONS: CircID(2)=None CommandCode=VERSIONS PayloadLength=4
#           SupportedVersionList=3,4
# CERTS: CircID(4)=None CommandCode=CERTS N=5 (CertType CLEN Certificate)*5
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n547
#   ed25519: https://trac.torproject.org/projects/tor/ticket/22861
# AUTH_CHALLENGE: CircID(4)=None CommandCode=AUTH_CHALLENGE
#                 Challenge(32)=RandomBytes N_Methods(2)=2 Methods=1,3
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n604
#   ed25519: https://trac.torproject.org/projects/tor/ticket/22861
# NETINFO: CircID(4)=None CommandCode=NETINFO Timestamp=Now
#          RemoteAddressType=IPv4 RemoteAddressLength=4
#          RemoteAddress=127.0.0.1 LocalAddressCount=1 LocalAddressType=IPv4
#          LocalAddressLength=4 LocalAddress=RelayPublicIPAddress ZeroPad(491)

REQUEST = pack_versions_cell()

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
#print '\nRequest Bytes:\n{}'.format(binascii.hexlify(REQUEST))
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST))
response = ssl_request(RELAYIP, ORPORT, REQUEST, MAX_RESPONSE_LEN)
#print '\nResponse Bytes:\n{}'.format(binascii.hexlify(response))
print 'Response Cells:\n{}'.format(format_cells(response))
