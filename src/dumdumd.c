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

char* program_name = 0;
size_t pkts_drop = 0;

static void usage(void) {
    printf(
        "usage: %s [options] [ip] <port>\n"
        /* -o            description                                                 .*/
        "  -u            Use UDP\n"
        "  -t            Use TCP\n"
        "                Using both UDP and TCP if none of the above options are used\n"
        "  -A            Use SO_REUSEADDR on sockets\n"
        "  -R            Use SO_REUSEPORT on sockets\n"
        "  -h            Print this help and exit\n",
        program_name
    );
}

static void version(void) {
    printf("%s version " PACKAGE_VERSION "\n", program_name);
}

static void stats_cb(EV_P_ ev_timer *w, int revents) {
    printf("dropped: %lu\n", pkts_drop);
    pkts_drop = 0;
}

int main(int argc, char* argv[]) {
    int opt, use_udp = 0, use_tcp = 0, reuse_addr, reuse_port = 0;
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

    while ((opt = getopt(argc, argv, "utARh")) != -1) {
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
        int fd, optval;

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

            if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
                perror("bind()");
                return 1;
            }
            close(fd);
        }
    }

    freeaddrinfo(addrinfo);

    ev_timer_init(&stats, &stats_cb, 1.0, 1.0);
    ev_timer_start(loop, &stats);

    ev_run(loop, 0);

    return 0;
}
