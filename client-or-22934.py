#!/usr/bin/env python
# Find out why PADDING cells can't be sent *after* a VERSIONS cell
# See https://trac.torproject.org/projects/tor/ticket/22934
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii

import stem.client.cell

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

# Request:
# VERSIONS, PADDING
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE

version_list = [3]
REQUEST  = stem.client.cell.VersionsCell.pack(version_list)
REQUEST += pack_padding_cell(version_list[0])

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST)
print 'Response Cells:\n{}'.format(format_cells(response, version_list))

# Even an intervening VPADDING cell doesn't help

version_list = [4]
REQUEST  = stem.client.cell.VersionsCell.pack(version_list)
REQUEST += pack_vpadding_cell(100, version_list[0])
REQUEST += pack_padding_cell(version_list[0])

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST)
print 'Response Cells:\n{}'.format(format_cells(response, version_list))

# The relay fails to respond, and logs:
# [info] channel_tls_process_versions_cell: Negotiated version 3 with
# [scrubbed]:57908; Sending cells: VERSIONS CERTS AUTH_CHALLENGE NETINFO
# [info] channel_tls_handle_cell: Received unexpected cell command 0 in chan
# state opening / conn state handshaking (Tor, v3 handshake); closing the
# connection.
# [info] conn_close_if_marked: Conn (addr [scrubbed], fd 9, type OR, state 7)
# marked, but wants to flush 2033 bytes. (Marked at
# src/or/connection_or.c:1338)
# [info] conn_close_if_marked: We stalled too much while trying to write 2033
# bytes to address [scrubbed].  If this happens a lot, either something is
# wrong with your network connection, or something is wrong with theirs.
# (fd 9, type OR, state 7, marked at src/or/connection_or.c:1338).
#
# This is a bug, see https://trac.torproject.org/projects/tor/ticket/22934

# But it works if you send a lot of them

version_list = [4]
REQUEST  = stem.client.cell.VersionsCell.pack(version_list)
REQUEST += pack_vpadding_cell(100, version_list[0]) * 1000
REQUEST += pack_padding_cell(version_list[0])

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST)
print 'Response Cells:\n{}'.format(format_cells(response, version_list))
