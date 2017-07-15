# Endosome: a Tor cell construction kit

Endosome is a proof-of-concept Tor cell construction kit.

## What does endosome do?

Endosome constructs cells from scratch, and uses them to connect to a Tor
relay over its ORPort.

It doesn't keep your traffic private: use a real Tor client for that.

## How does endosome work?

Start a local tor relay using:

    ./relay-local.sh

(This relay connects to the public tor network, but doesn't publish its
descriptor.)

Then, run the other scripts distributed with endosome. They will connect to
the relay over the ORPort (or DirPort), and produce output.

Scripts with the same basename do the same thing in different languages.

### Do the scripts have an order?

The scripts can be run in any order.

Here they are in increasing order of complexity:
* client-dir.{sh,py} (DirPort)
* client-or-handshake-raw.{sh,py} (Raw Bytes, ORPort, SSL, Circuit Initiation)
* handshake.txt (Annotated transcript of client-or-handshake-raw.{sh,py})
* client-versions.py (Cell Packing, VERSIONS Cell, Response Unpacking)
* client-or-handshake.py (NETINFO Cell Packing & Unpacking)
* client-or-circuit.py (CREATE[D]_FAST Cells, Circuit Creation)

Some scripts are designed to clarify ambiguities in the tor specification.
They are named after the corresponding tor trac ticket number.

## Reference Material

handshake.txt contains a hexdump of a typical handshake, and some working
notes.

The tor OR protocol is specified in:

https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt

The tor directory protocol is specified in:

https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt

Line numbers in links are approximate: they were generated from torspec git
revision f61e98f7a2 (also approximate).

## Why "endosome" ?

Endosomes are involved in biological cell transport pathways.

https://en.wikipedia.org/wiki/Endosome
