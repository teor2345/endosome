#!/usr/bin/env python
# Do a Tor OR client handshake with a local Tor relay
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# This script is a raw python transliteration of client-or-handshake.sh

import binascii
import os

from endosome import *

# The default IP and Port
RELAYIP = "127.0.0.1"
ORPORT = 12345

MAX_RESPONSE_LEN = 10*1024*1024

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

ZERO = "00"
RANDOM_LEN = 20
random_X = binascii.hexlify(os.urandom(RANDOM_LEN))
REQUEST = ("0000" +     "07" + "0002" + "0004" +
           "00000000" + "08" + "00000000" + "04" + "04" + "00000000" + "00" +
           ZERO*498 +
           "80000000" + "05" + random_X +
           ZERO*489)

print 'SSL Server: {}:{}'.format(RELAYIP, ORPORT)
print REQUEST
response = ssl_request(RELAYIP, ORPORT, binascii.unhexlify(REQUEST),
                       MAX_RESPONSE_LEN)
print binascii.hexlify(response)
