# Endosome: a Tor cell construction kit

Endosome is a proof-of-concept Tor cell construction kit.

## What does endosome do?

Endosome constructs cells from scratch, and uses them to connect to a Tor
relay over its ORPort.

It doesn't keep your traffic private: use a real Tor client for that.

## Dependencies

If your python version doesn't come with the ipaddress module, install it using
pip or similar.

endosome was tested on macOS 10.12 with python 2.7 and OpenSSL 1.0.2.

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

Here they are in increasing order of functionality and abstraction:

DirPort:
* client-dir.{sh,py} (DirPort)

Raw ORPort Bytes:
* client-or-handshake-raw.{sh,py} (Raw Bytes, ORPort, SSL, Circuit Initiation)
* handshake.txt (Annotated transcript of client-or-handshake-raw.{sh,py})

Tor Cells:
* client-or-versions-cell.py (Cell Packing, VERSIONS Cell, Response Unpacking)
* client-or-handshake-cell.py (NETINFO Cell Packing & Unpacking)
* client-or-circuit-cell.py (CREATE[D]_FAST Cells, Circuit Creation)

Tor Links:
* client-or-link.py (Negotiating the Link Version)
* client-or-circuit-link.py (Send NETINFO and CREATE[D]_FAST cells)

Tor Circuits:
* client-or-circuit.py (Open multiple circuits on the same link)
* client-or-circuit-drop.py (Open circuits and send DROP cells on them)

The other scripts are designed to clarify ambiguities in the tor specification.
They are named after the corresponding tor trac ticket number.

### What are the different parts of the library?

* endosome.py imports all the other files
* connect.py opens, closes, and exchanges data on TCP and SSL connections
* crypto.py contains some Tor cryptographic primitives
* pack.py packs and unpacks individual data fields
* cell.py crypts, packs, and unpacks cells
* link.py opens, closes, and exchanges data on Tor links
* circuit.py opens, closes, and exchanges data on Tor circuits

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

An endosome is a cell transport mechanism.

https://en.wikipedia.org/wiki/Endosome
