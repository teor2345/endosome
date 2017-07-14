#!/bin/sh
# Do a Tor OR client handshake with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# The default IP and Port
RELAYIP=${RELAYIP:-"127.0.0.1"}
ORPORT=${ORPORT:-12345}

# Request:
# VERSIONS: CircID(2)=None CommandCode=VERSIONS PayloadLength=2
#           SupportedVersionList=4
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n399
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n419
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
# NETINFO: CircID(4)=None CommandCode=NETINFO Timestamp=None
#          RemoteAddressType=IPv4 RemoteAddressLength=4 RemoteAddress=0.0.0.0
#          LocalAddressCount=0 ZeroPad(498)
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n684
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1480
# CREATE_FAST: CircID(4)=0x80000000 CommandCode=CREATE_FAST X(20)=RandomBytes
#          ZeroPad(489)
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n962
#
# Expected Response:
# VERSIONS: CircID(2)=None CommandCode=VERSIONS PayloadLength=4
#           SupportedVersionList=3,4
# CERTS: CircID(4)=None CommandCode=CERTS N=5 (CertType CLEN Certificate)*5
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n547
#   ed25519: https://trac.torproject.org/projects/tor/ticket/22861
# AUTH_CHALLENGE: CircID(4)=None CommandCode=AUTH_CHALLENGE
#                 Challenge(32)=RandomBytes N_Methods(2)=2 Methods=1,3
#   https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n604
#   ed25519: https://trac.torproject.org/projects/tor/ticket/22861
# NETINFO: CircID(4)=None CommandCode=NETINFO Timestamp=Now
#          RemoteAddressType=IPv4 RemoteAddressLength=4
#          RemoteAddress=127.0.0.1 LocalAddressCount=1 LocalAddressType=IPv4
#          LocalAddressLength=4 LocalAddress=RelayPublicIPAddress ZeroPad(491)
# CREATE_FAST: CircID(4)=0x80000000 CommandCode=CREATE_FAST Y(20)=RandomBytes
#          ZeroPad(489)
#
# Unfortunately, there's no way to tell s_client to wait for a response, or to
# timeout
(sleep 1; echo "Use Ctrl-C to terminate openssl s_client") &
# Echo the input commands to the output
set -v
echo 0000 07 0002 0004 \
     00000000 08 00000000 04 04 00000000 00 \
         `cat /dev/zero | head -c 498 | xxd -p` \
     80000000 05 `cat /dev/random | head -c 20 | xxd -p` \
         `cat /dev/zero | head -c 489 | xxd -p` \
     | xxd -r -p | openssl s_client -connect "$RELAYIP:$ORPORT" -quiet | xxd
