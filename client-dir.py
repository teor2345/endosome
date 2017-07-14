#!/usr/bin/env python
# Get a Tor Directory document from a local Tor relay's DirPort
# Tested: Python 2.7.13 on macOS 10.12.5 with tor 0.3.0.9.

import socket

# The default IP and Port
RELAYIP = "127.0.0.1"
DIRPORT = 23456
REQUEST = "GET /tor/server/authority HTTP/1.0\r\n\r\n"

# Request:
#   GET /tor/server/authority HTTP/1.0\r\n\r\n
#   https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt#n3647
#
# Expected Response:
#   Relay descriptor
#   https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt#n368

#curl -v http://"$RELAYIP:$DIRPORT"/tor/server/authority

print 'Server: {}:{}'.format(RELAYIP, DIRPORT)
dsock = socket.create_connection((RELAYIP, DIRPORT))
print REQUEST
dsock.sendall(REQUEST)
desc = dsock.recv(10*1024*1024)
print desc
