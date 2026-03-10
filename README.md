gktrace
========

Timothy C. Arland <tcarland at gmail dot com>

<notice>
 *
 * Copyright (c) 2010-2026 Timothy Charlton Arland <tcarland@gmail.com>
 *
 * This file is part of gktrace.
 *
 * gktrace is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * gktrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with gktrace.
 * If not, see <http://www.gnu.org/licenses/>.
 *
</notice>
 
# Overview

A Traceroute implementation providing continuous per-hop, loss,
latency, and jitter statistics per RFC3393.

It makes use of the network library *tcanetpp* and *tcamake* for
building and the following system dependencies:
- librt
- pthreads
- libc
- libstdc++.

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

Install the dependencies, *tcamake* is the build tool, and *tcanetpp* is
network library.
```bash
git clone https://github.com/tcarland/tcamake.git
git clone https://github.com/tcarland/tcanetpp.git
cd tcanetpp
source resources/release-mt.env
```

## Build gktrace

```bash
cd ../gktrace
make && make install
```

## Build gktrace_hexes (ncurses UI)

This repo also includes a second binary, `gktrace_hexes`, which uses the
ncurses-based `libhexes` library (expected to be located at `../libhexes`).

### Dependencies

- `../libhexes` (built automatically by the UI Makefile)
- ncurses development headers (e.g. `libncurses-dev`)

### Build

```bash
cd ../gktrace
make -f Makefile.hexes
```

### Run

By default the UI runs `./gktrace` and streams its stdout/stderr into the
currently active output panel.

```bash
./gktrace_hexes <gktrace-args...>
```

You can override the tracer binary path with `GKTRACE_BIN`:

```bash
GKTRACE_BIN=/usr/local/bin/gktrace ./gktrace_hexes <gktrace-args...>
```

### Keys

- The bottom console accepts gktrace arguments; press ENTER to (re)start capture in the current output panel.
- Press `:` to jump focus to the console.
- Use `CTRL-w` then `UP/DOWN` to switch focus between windows.
- `n`: create a new output panel (capture continues there)
- `TAB` / `→`: next panel, `←`: previous panel
- `s`: save current panel output to a file
- `c`: clear current panel
- `↑`/`↓`: scroll
- `q`: quit
