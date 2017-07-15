#!/usr/bin/env python
# Do a Tor OR client handshake with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii

from endosome import *

# The default IP and Port
RELAYIP = "127.0.0.1"
ORPORT = 12345

MAX_RESPONSE_LEN = 10*1024*1024

# Request:
# VERSIONS, NETINFO
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO

version_list = [4]
link_version = version_list[-1]
REQUEST  = pack_versions_cell(version_list)
REQUEST += pack_netinfo_cell('127.0.0.1', link_version=link_version)

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
#print '\nRequest Bytes:\n{}'.format(binascii.hexlify(REQUEST))
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST,
                                               link_version_list=version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST, MAX_RESPONSE_LEN)
#print '\nResponse Bytes:\n{}'.format(binascii.hexlify(response))
print 'Response Cells:\n{}'.format(format_cells(response,
                                               link_version_list=version_list))
