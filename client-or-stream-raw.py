#!/usr/bin/env python
# Open a Tor circuit with a local Tor relay, and send a begindir cell
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

REQUEST = 'GET /tor/server/authority HTTP/1.0\r\n\r\n'
MAX_RESPONSE_LEN = 10*1024*1024

# Request:
# VERSIONS, NETINFO, CREATE_FAST, BEGINDIR, RELAY_DATA
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO, CREATED_FAST, CONNECTED, RELAY_DATA

# Create the BEGINDIR cell

begindir_cell = {
  'cell_command_string': 'RELAY',
  'relay_command_string': 'RELAY_BEGIN_DIR',
  'stream_id': 1,
}

# Create the RELAY_DATA cell

request_cell = {
  'cell_command_string': 'RELAY',
  'relay_command_string': 'RELAY_DATA',
  'stream_id': 1,
  'relay_payload_bytes': REQUEST,
}

# Try the default set of link versions: we will get 4 or 5, depending on
# the Tor version
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v4 or v5 link, circuit, and request cells'
link_context = link_open(RELAYIP, ORPORT)
(link_context, circuit_context, _, _, _) = circuit_request_cell_list(link_context, [begindir_cell, request_cell], do_shutdown=False)

destroy_cell = circuit_close(circuit_context)
print '\nLink context:\n{}'.format(link_format_context(link_context))
print '\nCircuit context:\n{}'.format(circuit_format_context(circuit_context))
# We don't want to decrypt or re-digest outbound cells, so we pass None for
# is_cell_outbound_flag
# Validation doesn't work yet, there's something buggy in the hashing,
# probably around is_cell_outbound_flag

# Try link version 3
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v3 link, circuit, and request cells'
link_context = link_open(RELAYIP, ORPORT, link_version_list=[3])
(link_context, circuit_context, _, _, response_cells_bytes) = circuit_request_cell_list(link_context, [begindir_cell, request_cell], do_shutdown=False)
destroy_cell = circuit_close(circuit_context)
response_cells_bytes += circuit_read_cell_bytes(circuit_context)

print '\nCells Received:\n{}'.format(format_cell_bytes(circuit_context,
                                                  response_cells_bytes,
                                                  is_cell_outbound_flag=False,
                                                  validate=False))

# Multiple circuits and streams don't work yet
# There's probably something buggy in the data structures
