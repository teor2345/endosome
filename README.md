= Endosome: a Tor cell construction kit =

Endosome is a proof-of-concept Tor cell construction kit.

== What does endosome do? ==

Endosome constructs cells from scratch, and uses them to connect to a Tor
relay over its ORPort.

It doesn't keep your traffic private: use a real Tor client for that.

=== How does endosome work? ==

Start a local tor relay using:

    ./relay-local.sh

(This relay connects to the public tor network, but doesn't publish its
descriptor.)

Then, run the other scripts distributed with endosome. They will connect to
the relay over the ORPort (or DirPort), and produce output.

== Reference Material ==

The tor OR protocol is specified in:

https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt

The tor directory protocol is specified in:

https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt

== Why "endosome" ? ==

Endosomes are involved in biological cell transport pathways.

https://en.wikipedia.org/wiki/Endosome
