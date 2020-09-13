gktrace
========

A Traceroute implementation providing continuous per-hop, loss, 
latency, and jitter statistics per RFC3393.

It makes use of the network library *tcanetpp* and *tcamake* for 
building. System dependencies are librt, pthreads, libc and libstdc++.

This project was conceived as an example of the network library this 
uses and borrows from a separate path analysis and probing tool 
developed separately using the same library.

Building gktrace:
```
$ cd ..
$ git clone https://github.com/tcarland/tcamake.git
$ git clone https://github.com/tcarland/tcanetpp.git
$ export TCAMAKE_PROJECT=1
$ export TCAMAKE_PREFIX=/usr/local
$ cd tcanetpp
$ source resources/tcanetpp_release_mt.profile
$ make arlib
$ cd ../gktrace
$ make && make install
```