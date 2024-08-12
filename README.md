gktrace
========

Timothy C. Arland <tcarland at gmail dot com>

# Overview 

A Traceroute implementation providing continuous per-hop, loss, 
latency, and jitter statistics per RFC3393.

It makes use of the network library *tcanetpp* and *tcamake* for 
building. System dependencies are librt, pthreads, libc and libstdc++.

This project was conceived as an example of the network library this 
uses and borrows from a separate path analysis and probing tool 
developed using the same library.

# Building:

To build the project, we need the dependencies in the parent directory.
First we make a project root path and acquire the *gktrace* repo.
```bash
project_root="~/src/gktrace_build"
mkdir -p ~/src/gktrace_build
cd ${project_root}
git clone https://github.com/tcarland/gktrace.git
```

## Dependencies

Install the dependencies, *tcamake* is the buld tool, and *tcanetpp* is 
network library.
```bash
git clone https://github.com/tcarland/tcamake.git
git clone https://github.com/tcarland/tcanetpp.git
export TCAMAKE_PROJECT="{$project_root}"
export TCAMAKE_PREFIX=/usr/local
cd tcanetpp
source .resources/tcanetpp_release_mt.profile
make arlib
```

## Build gktrace

```bash
$ cd ../gktrace
$ make && sudo make install
```