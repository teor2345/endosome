#!/usr/bin/env python
# Get a Tor Directory document from a local Tor relay's DirPort
# Tested: Python 2.7.13 on macOS 10.12.5 with tor 0.3.0.9.

from endosome import *

# The default IP and Port
RELAYIP = "127.0.0.1"
DIRPORT = 23456

REQUEST = "GET /tor/server/authority HTTP/1.0\r\n\r\n"
MAX_RESPONSE_LEN = 10*1024*1024

# Request:
#   GET /tor/server/authority HTTP/1.0\r\n\r\n
#   https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt#n3647
#
# Expected Response:
#   Relay descriptor
#   https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt#n368

#curl -v http://"$RELAYIP:$DIRPORT"/tor/server/authority

print 'HTTP Server: {}:{}'.format(RELAYIP, DIRPORT)
print REQUEST
desc = tcp_request(RELAYIP, DIRPORT, REQUEST, MAX_RESPONSE_LEN)
print desc
