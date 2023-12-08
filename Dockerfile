ARG BASE_IMAGE=ubuntu:23.10
FROM $BASE_IMAGE AS runtime_base
MAINTAINER Petr Spacek <pspacek@isc.org>
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get upgrade -y -qqq

# runtime depedencies
RUN apt-get install -y -qqq -o APT::Install-Suggests=0 -o APT::Install-Recommends=0 \
	libev4 \
	libevent-2.1 \
	libevent-openssl-2.1 \
	libnghttp2-14 \
	libssl3 \
	libssl3 \
	libuv1

# separate image for build, will not be tagged at the end
FROM runtime_base AS build_stage
RUN apt-get install -y -qqq -o APT::Install-Suggests=0 -o APT::Install-Recommends=0 \
	autoconf \
	automake \
	build-essential \
	git \
	libev-dev \
	libevent-dev \
	libnghttp2-dev \
	libssl-dev \
	libtool \
	libuv1-dev \
	pkg-config

# copy repo as build context
COPY . /dumdumd
WORKDIR /dumdumd
RUN ./autogen.sh
RUN ./configure --prefix=/usr/local
RUN make -j$(nproc)
RUN make install
RUN git log -1 > /usr/local/dumdumd.git.log
RUN git diff > /usr/local/dumdumd.git.diff
RUN git status > /usr/local/dumdumd.git.status

# copy only installed artifacts and throw away everything else
FROM runtime_base AS installed
COPY --from=build_stage /usr/local /usr/local
