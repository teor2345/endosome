#!/usr/bin/env python
# Open a Tor circuit with a local Tor relay, and send a begindir cell
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

# Request:
# VERSIONS, NETINFO, CREATE_FAST, BEGINDIR
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO, CREATED_FAST, CONNECTED

# Create the cell
begindir_cell = circuit_make_relay_cell('RELAY',
                                        'RELAY_BEGIN_DIR',
                                        stream_id=1)

# Try the default set of link versions: we will get 4 or 5, depending on
# the Tor version
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v4 or v5 link, circuit, and BEGINDIR cell'
link_context = link_open(RELAYIP, ORPORT)
(link_context,
 circuit_context,
 sent_crypt_cells_bytes,
 sent_plain_cells_bytes,
 response_cells_bytes) = circuit_request_cell_list(link_context,
                                                   [begindir_cell])
print '\nLink context:\n{}'.format(link_format_context(link_context))
print '\nCircuit context:\n{}'.format(circuit_format_context(circuit_context))
# We don't want to decrypt or re-digest outbound cells, so we pass None for
# is_cell_outbound_flag
print '\nBEGINDIR Sent (crypt):\n{}'.format(format_cell_bytes(circuit_context,
                                                  sent_crypt_cells_bytes,
                                                  is_cell_outbound_flag=None,
                                                  validate=False))
print '\nBEGINDIR Sent (plain):\n{}'.format(format_cell_bytes(circuit_context,
                                                  sent_plain_cells_bytes,
                                                  is_cell_outbound_flag=None,
                                                  validate=True))
print '\nBEGINDIR Received:\n{}'.format(format_cell_bytes(circuit_context,
                                                  response_cells_bytes,
                                                  is_cell_outbound_flag=False,
                                                  validate=True))

# Try link version 3
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v3 link, circuit, and BEGINDIR cell'
link_context = link_open(RELAYIP, ORPORT, link_version_list=[3])
(link_context,
 circuit_context,
 sent_crypt_cells_bytes,
 sent_plain_cells_bytes,
 response_cells_bytes) = circuit_request_cell_list(link_context,
                                                   [begindir_cell])
print '\nLink context:\n{}'.format(link_format_context(link_context))
print '\nCircuit context:\n{}'.format(circuit_format_context(circuit_context))
print '\nBEGINDIR Sent (crypt):\n{}'.format(format_cell_bytes(circuit_context,
                                                  sent_crypt_cells_bytes,
                                                  is_cell_outbound_flag=None,
                                                  validate=False))
print '\nBEGINDIR Sent (plain):\n{}'.format(format_cell_bytes(circuit_context,
                                                  sent_plain_cells_bytes,
                                                  is_cell_outbound_flag=None,
                                                  validate=True))
print '\nBEGINDIR Received:\n{}'.format(format_cell_bytes(circuit_context,
                                                  response_cells_bytes,
                                                  is_cell_outbound_flag=False,
                                                  validate=True))

# Try multiple circuits:
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v4 or v5 link, some circuits, and some BEGINDIR cells'
link_context = link_open(RELAYIP, ORPORT)
for i in xrange(1, 10):
    # There is no flow control on BEGINDIR cells, so we can send as many as we
    # like
    begindir_cell_list = []
    # Each stream needs a different id
    for j in xrange(1, i):
        b_cell = begindir_cell.copy()
        b_cell['stream_id'] = j
        begindir_cell_list.append(b_cell)
    (link_context,
     circuit_context,
     sent_crypt_cells_bytes,
     sent_plain_cells_bytes,
     response_cells_bytes) = circuit_request_cell_list(link_context,
                                                       begindir_cell_list,
                                                       do_shutdown=False)
print '\nLink context:\n\n{}'.format(link_format_context(link_context))
