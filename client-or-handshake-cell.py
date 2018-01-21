#!/usr/bin/env python
# Do a Tor OR client handshake with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii

import stem.client.cell

from endosome import *
from stem.client import AddrType, Address

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

# Request:
# VERSIONS, NETINFO
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO

version_list = [4]
link_version = version_list[-1]
REQUEST  = stem.client.cell.VersionsCell.pack(version_list)
REQUEST += stem.client.cell.NetinfoCell.pack(link_version, Address(AddrType.IPv4, '127.0.0.1'), [])

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
#print '\nRequest Bytes:\n{}'.format(binascii.hexlify(REQUEST))
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST,
                                               link_version_list=version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST)
#print '\nResponse Bytes:\n{}'.format(binascii.hexlify(response))
print 'Response Cells:\n{}'.format(format_cells(response,
                                               link_version_list=version_list))
