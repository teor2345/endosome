#!/usr/bin/env python
# Open a Tor circuit with a local Tor relay, and send a drop cell
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

from endosome import *

# The default IP and Port
RELAYIP = '127.0.0.1'
ORPORT = 12345

# Request:
# VERSIONS, NETINFO, CREATE_FAST, DROP
# Expected Response:
# VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO, CREATED_FAST

drop_cell = {
  'cell_command_string': 'RELAY',
  'relay_command_string': 'RELAY_DROP',
  'relay_payload_bytes': pack_relay_drop_data(),
}

# Try the default set of link versions: we will get 4 or 5, depending on
# the Tor version
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v4 or v5 link, circuit, and DROP cell'
link_context = link_open(RELAYIP, ORPORT)
circuit_context = circuit_create(link_context)
(sent_cell_list,
 crypt_cell_bytes,
 plain_cell_bytes) = circuit_write_cell_list(circuit_context,
                                             [drop_cell])
print '\nLink context:\n{}'.format(link_format_context(link_context))
print '\nCircuit context:\n{}'.format(circuit_format_context(circuit_context))
# We don't want to decrypt or re-digest outbound cells, so we pass None for
# is_cell_outbound_flag
print '\nDrop Cell (crypt):\n{}'.format(format_cell_bytes(circuit_context,
                                                  crypt_cell_bytes,
                                                  is_cell_outbound_flag=None,
                                                  validate=False))
print '\nDrop Cell (plain):\n{}'.format(format_cell_bytes(circuit_context,
                                                  plain_cell_bytes,
                                                  is_cell_outbound_flag=None,
                                                  validate=True))
#print '\nDrop Cell (dict):\n{}'.format(sent_cell_list)

# Try link version 3
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v3 link, circuit, and DROP cell'
link_context = link_open(RELAYIP, ORPORT, link_version_list=[3])
circuit_context = circuit_create(link_context)
(sent_cell_list,
 crypt_cell_bytes,
 plain_cell_bytes) = circuit_write_cell_list(circuit_context,
                                             [drop_cell])
print '\nLink context:\n{}'.format(link_format_context(link_context))
print '\nCircuit context:\n{}'.format(circuit_format_context(circuit_context))
print '\nDrop Cell (crypt):\n{}'.format(format_cell_bytes(circuit_context,
                                                  crypt_cell_bytes,
                                                  is_cell_outbound_flag=None,
                                                  validate=False))
print '\nDrop Cell (plain):\n{}'.format(format_cell_bytes(circuit_context,
                                                  plain_cell_bytes,
                                                  is_cell_outbound_flag=None,
                                                  validate=True))
#print '\nDrop Cell (dict):\n{}'.format(sent_cell_list)

# Try multiple circuits:
print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print 'Opening Tor connection and creating a v4 or v5 link, some circuits, and some DROP cells'
link_context = link_open(RELAYIP, ORPORT)
for i in xrange(1, 10):
    circuit_context = circuit_create(link_context)
    # There is no flow control on DROP cells, so we can send as many as we like
    (sent_cell_list,
     crypt_cell_bytes,
     plain_cell_bytes) = circuit_write_cell_list(circuit_context,
                                                 [drop_cell]*10*i)
print '\nLink context:\n\n{}'.format(link_format_context(link_context))
