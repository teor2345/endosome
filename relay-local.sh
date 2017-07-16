#!/bin/sh
# Start a local Tor relay that connects to the public network, but doesn't
# publish its descriptor

# The default ORPort
ORPORT=${ORPORT:-12345}
DIRPORT=${DIRPORT:-23456}
LOG_LEVEL=${LOG_LEVEL:-warn}
TOR=${TOR:-tor}

# Pass arguments to the tor daemon
"$TOR" PublishServerDescriptor 0 AssumeReachable 1 ExitRelay 0 \
       Log "$LOG_LEVEL stderr" DataDirectory `mktemp -d` \
       ORPort "$ORPORT" DirPort "$DIRPORT" "$@"
