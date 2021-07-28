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

## Docker usage

```
docker build -t dumdumd .
docker run -ti --init --network=host dumdumd -h
```

Optional parameter `--network=host` disables Docker networking.
This improves performance when testing over physical network interfaces.

Optional parameters `-ti --init` make terminal work as you would expect,
namely SIGINT from Control+C gets propagated to dumdumd.

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
