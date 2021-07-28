# dumdumd

High performance UDP/TCP server that... just drops everything you send to it

## Requirements

`dumdumd` requires a couple of libraries beside a normal C compiling
environment with autoconf, automake, libtool and pkgconfig.

- libev-dev || libuv1-dev
- libssl-dev
- libevent-dev
- libnghttp2-dev

## Build

```
sh autogen.sh
./configure
make
```

## Usage

```
src/dumdumd -h
```

## Author(s)

Jerry Lundström <jerry@dns-oarc.net>

## Copyright

Copyright (c) 2017-2021, OARC, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
