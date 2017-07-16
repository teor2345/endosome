#!/usr/bin/env python
# Find out what cells can be sent before a VERSIONS cell.
# See https://trac.torproject.org/projects/tor/ticket/22929
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

MAX_RESPONSE_LEN = 10*1024*1024

# Request:
# PADDING, VERSIONS
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE

version_list = [3]
REQUEST  = pack_padding_cell()
REQUEST += pack_versions_cell(version_list)

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST, MAX_RESPONSE_LEN)
print 'Response Cells:\n{}'.format(format_cells(response, version_list))

# The relay fails to respond, and logs:
# [info] channel_tls_handle_cell: Received unexpected cell command 0 in chan
# state opening / conn state waiting for renegotiation or V3 handshake;
# closing the connection.

# Request:
# VPADDING * N, VERSIONS
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE

version_list = [4]
# You can send as many of these as you like. No, really, as many as you like.
# 
REQUEST  = pack_vpadding_cell(0) * 5000
REQUEST += pack_versions_cell(version_list)

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST, MAX_RESPONSE_LEN)
print 'Response Cells:\n{}'.format(format_cells(response, version_list))

# Standard response

# Request:
# VPADDING, PADDING, VERSIONS
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE

version_list = [4]
REQUEST  = pack_vpadding_cell(0)
REQUEST += pack_padding_cell()
REQUEST += pack_versions_cell(version_list)

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST, MAX_RESPONSE_LEN)
print 'Response Cells:\n{}'.format(format_cells(response, version_list))

# The relay fails to respond, and logs:
# [info] channel_tls_handle_cell: Received unexpected cell command 0 in chan
# state opening / conn state handshaking (Tor, v3 handshake); closing the
# connection.
