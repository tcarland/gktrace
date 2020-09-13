gktrace
========

A Traceroute implementation providing continuous per-hop, loss, 
latency, and jitter statistics per RFC3393.

It makes use of the network library *tcanetpp*.

Building:
```
cd ..
git clone https://github.com/tcarland/tcamake.git
git clone https://github.com/tcarland/tcanetpp.git
export TCAMAKE_PROJECT=1
cd tcanetpp
source resources/tcanetpp_release_mt.profile
make arlib
cd ../tcajson; make
```