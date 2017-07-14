#!/bin/sh
# Get a Tor Directory document from a local Tor relay's DirPort
# Tested: Python 2.7.13 on macOS 10.12.5 with tor 0.3.0.9.

# The default IP and Port
RELAYIP=${RELAYIP:-"127.0.0.1"}
DIRPORT=${DIRPORT:-23456}

# Request:
#   GET /tor/server/authority HTTP/1.0\r\n\r\n
#   https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt#n3647
#
# Expected Response:
#   Relay descriptor
#   https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt#n368

curl -v http://"$RELAYIP:$DIRPORT"/tor/server/authority

# This should work, but for some reason, it doesn't
#cat << EOF | nc -c "$RELAYIP" "$DIRPORT" > authority
#GET /tor/server/authority HTTP/1.0
#
#EOF
#wc -l authority
