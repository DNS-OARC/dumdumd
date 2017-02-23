/*
 * dumdumd - packets sent lightning fast to dev null
 * Copyright (c) 2017, OARC, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ev.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

char* program_name = 0;
#define STATS_INIT { 0, 0, 0, 0, 0 }
struct stats {
    size_t accept;
    size_t accdrop;
    size_t conns;
    size_t bytes;
    size_t pkts;
};
struct stats _stats0 = STATS_INIT;
struct stats _stats = STATS_INIT;

static void usage(void) {
    printf(
        "usage: %s [options] [ip] <port>\n"
        /* -o            description                                                 .*/
        "  -u            Use UDP\n"
        "  -t            Use TCP\n"
        "                Using both UDP and TCP if none of the above options are used\n"
        "  -A            Use SO_REUSEADDR on sockets\n"
        "  -R            Use SO_REUSEPORT on sockets\n"
        "  -h            Print this help and exit\n"
        "  -V            Print version and exit\n",
        program_name
    );
}

static void version(void) {
    printf("%s version " PACKAGE_VERSION "\n", program_name);
}

static void stats_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    printf("accept(drop): %lu ( %lu ) conns: %lu pkts: %lu bytes %lu\n",
        _stats.accept,
        _stats.accdrop,
        _stats.conns,
        _stats.pkts,
        _stats.bytes
    );
    _stats = _stats0;
}

static char recvbuf[4*1024*1024];

static void recv_cb(struct ev_loop *loop, ev_io *w, int revents) {
    int fd = w->data - (void*)0, newfd;
    ssize_t bytes;

    for (;;) {
        bytes = recv(fd, recvbuf, sizeof(recvbuf), 0);
        if (bytes < 0) {
            perror("recv()");
            shutdown(fd, SHUT_RDWR);
        }
        if (bytes < 1) {
            ev_io_stop(loop, w);
            close(fd);
            free(w); /* TODO: Delayed free maybe? */
            return;
        }
        _stats.pkts++;
        _stats.bytes += bytes;
        if (bytes < sizeof(recvbuf)) {
            return;
        }
    }
}

static void accept_cb(struct ev_loop *loop, ev_io *w, int revents) {
    int fd = w->data - (void*)0, newfd, flags;
    struct sockaddr addr;
    socklen_t len;

    for (;;) {
        memset(&addr, 0, sizeof(struct sockaddr));
        len = sizeof(struct sockaddr);
        newfd = accept(fd, &addr, &len);
        _stats.accept++;
        if (newfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            fprintf(stderr, "accept(%d) ", fd);
            perror("");
            ev_io_stop(loop, w);
            close(fd);
            free(w); /* TODO: Delayed free maybe? */
            _stats.accdrop++;
            return;
        }

        if ((flags = fcntl(newfd, F_GETFL)) == -1
            || fcntl(newfd, F_SETFL, flags | O_NONBLOCK))
        {
            perror("fcntl()");
            shutdown(newfd, SHUT_RDWR);
            close(newfd);
            _stats.accdrop++;
            return;
        }

        {
            ev_io* io = calloc(1, sizeof(ev_io));
            if (!io) {
                perror("calloc()");
                shutdown(newfd, SHUT_RDWR);
                close(newfd);
                _stats.accdrop++;
                return;
            }
            io->data += newfd;
            ev_io_init(io, &recv_cb, newfd, EV_READ);
            ev_io_start(loop, io);
            _stats.conns++;
        }
    }
}

int main(int argc, char* argv[]) {
    int opt, use_udp = 0, use_tcp = 0, reuse_addr = 0, reuse_port = 0;
    struct addrinfo* addrinfo = 0;
    struct addrinfo hints;
    const char* node = 0;
    const char* service = 0;
    struct ev_loop *loop = EV_DEFAULT;
    ev_timer stats;

    if ((program_name = strrchr(argv[0], '/'))) {
        program_name++;
    }
    else {
        program_name = argv[0];
    }

    while ((opt = getopt(argc, argv, "utARhV")) != -1) {
        switch (opt) {
            case 'u':
                use_udp = 1;
                break;

            case 't':
                use_tcp = 1;
                break;

            case 'A':
                reuse_addr = 1;
                break;

            case 'R':
                reuse_port = 1;
                break;

            case 'h':
                usage();
                return 0;

            case 'V':
                version();
                return 0;

            default:
                usage();
                return 2;
        }
    }

    if (!use_udp && !use_tcp) {
        use_udp = 1;
        use_tcp = 1;
    }

    if (optind < argc) {
        service = argv[optind++];
    }
    else {
        usage();
        return 2;
    }
    if (optind < argc) {
        node = service;
        service = argv[optind++];
    }
    if (optind < argc) {
        usage();
        return 2;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(node, service, &hints, &addrinfo)) {
        perror("getaddrinfo()");
        return 1;
    }
    if (!addrinfo) {
        return 1;
    }

    {
        struct addrinfo* ai = addrinfo;
        int fd, optval, flags;

        for (; ai; ai = ai->ai_next) {
            switch (ai->ai_socktype) {
                case SOCK_DGRAM:
                case SOCK_STREAM:
                    break;
                default:
                    continue;
            }

            switch (ai->ai_protocol) {
                case IPPROTO_UDP:
                    if (!use_udp)
                        continue;
                    break;
                case IPPROTO_TCP:
                    if (!use_tcp)
                        continue;
                    break;
                default:
                    continue;
            }

            fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd < 0) {
                perror("socket()");
                return 1;
            }

#ifdef SO_REUSEADDR
            if (reuse_addr) {
                optval = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
                    perror("setsockopt(SO_REUSEADDR)");
                    return 1;
                }
            }
#endif
#ifdef SO_REUSEPORT
            if (reuse_port) {
                optval = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval))) {
                    perror("setsockopt(SO_REUSEPORT)");
                    return 1;
                }
            }
#endif

            if ((flags = fcntl(fd, F_GETFL)) == -1) {
                perror("fcntl(F_GETFL)");
                return 1;
            }
            if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
                perror("fcntl(F_SETFL)");
                return 1;
            }

            if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
                perror("bind()");
                return 1;
            }
            if (ai->ai_socktype == SOCK_STREAM && listen(fd, 10)) {
                perror("listen()");
                return 1;
            }

            {
                char h[NI_MAXHOST], s[NI_MAXSERV];
                ev_io* io = calloc(1, sizeof(ev_io));
                if (!io) {
                    perror("calloc()");
                    return 1;
                }
                io->data += fd;
                ev_io_init(io, ai->ai_socktype == SOCK_STREAM ? &accept_cb : &recv_cb, fd, EV_READ);
                ev_io_start(loop, io);

                if (getnameinfo(ai->ai_addr, ai->ai_addrlen, h, NI_MAXHOST, s, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV)) {
                    perror("getnameinfo()");
                    h[0] = 0;
                    s[0] = 0;
                }

                printf("listen: %d fam: %d type: %d proto: %d host: %s service: %s\n", fd, ai->ai_family, ai->ai_socktype, ai->ai_protocol, h, s);
            }
        }
    }

    freeaddrinfo(addrinfo);

    ev_timer_init(&stats, &stats_cb, 1.0, 1.0);
    ev_timer_start(loop, &stats);

    ev_run(loop, 0);

    return 0;
}
