FROM ubuntu:20.04

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y -o APT::Install-Suggests=0 -o APT::Install-Recommends=0 build-essential libev-dev libuv1-dev libssl-dev autoconf automake autotools-dev libtool pkg-config

COPY . /dumdumd

WORKDIR /dumdumd
RUN ./autogen.sh
RUN ./configure
RUN make
RUN make install

ENTRYPOINT ["dumdumd"]
