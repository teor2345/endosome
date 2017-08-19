#!/bin/sh
# Start a local Tor relay that connects to the public network, but doesn't
# publish its descriptor

# The default ORPort
ORPORT=${ORPORT:-12345}
DIRPORT=${DIRPORT:-23456}
LOG_LEVEL=${LOG_LEVEL:-warn}
TOR=${TOR:-tor}

# Pass arguments to the tor daemon
# These options MUST NOT be used on a relay that publishes its descriptor:
# they are unsafe for user anonymity
"$TOR" PublishServerDescriptor 0 AssumeReachable 1 ExitRelay 0 \
       ProtocolWarnings 1 SafeLogging 0 LogTimeGranularity 1 \
       PidFile tor.pid \
       Log "$LOG_LEVEL stderr" DataDirectory `mktemp -d` \
       ORPort "$ORPORT" DirPort "$DIRPORT" "$@"
