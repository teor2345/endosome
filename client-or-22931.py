#!/usr/bin/env python
# Find out what happens when multiple VERSIONS cells are sent.
# See https://trac.torproject.org/projects/tor/ticket/22931
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
# VERSIONS * 2
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE

version_list = [3]
REQUEST  = stem.client.cell.VersionsCell(version_list).pack() * 2

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST)
print 'Response Cells:\n{}'.format(format_cells(response, version_list))

# The relay also logs:
# [info] channel_tls_process_versions_cell: Received a VERSIONS cell on a
# connection with its version already set to 3; dropping
#
# [migration note] Stem dropped support for force_link_version becasue I
# couldn't find a scenario where it was actually useful. Happy to add it back
# if you can think of one.

#version_list = [4]
#REQUEST  = stem.client.cell.VersionsCell(version_list).pack()
#REQUEST += stem.client.cell.VersionsCell(version_list.pack(version_list[0])

#print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
#print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
#response = ssl_request(RELAYIP, ORPORT, REQUEST)
#print 'Response Cells:\n{}'.format(format_cells(response, version_list))

# The relay also logs:
# [info] channel_tls_process_versions_cell: Received a VERSIONS cell on a
# connection with its version already set to 4; dropping

version_list = [4]
REQUEST  = stem.client.cell.VersionsCell(version_list).pack()*2

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
# Parsing the second versions cell fails because its circuit id length is wrong
#print '\nRequest Cells:\n{}'.format(format_cells(REQUEST, version_list))
response = ssl_request(RELAYIP, ORPORT, REQUEST)
print 'Response Cells:\n{}'.format(format_cells(response, version_list))

# The second versions cell looks like some other kind of cell to the relay,
# because its circ_id_len is wrong, so the command is read from the second
# payload length byte
