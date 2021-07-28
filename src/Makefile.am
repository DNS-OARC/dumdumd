# dumdumd - packets sent lightning fast to dev null
# Copyright (c) 2017-2021, OARC, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
  -I$(top_srcdir) \
  $(libssl_CFLAGS) $(libcrypto_CFLAGS) $(libnghttp2_CFLAGS)

bin_PROGRAMS = dumdumd dumdohd

dumdumd_SOURCES = dumdumd.c
dumdumd_LDADD = $(libssl_LIBS) $(libcrypto_LIBS)

dumdohd_SOURCES = dumdohd.c
dumdohd_LDADD = $(libssl_LIBS) $(libcrypto_LIBS) $(libnghttp2_LIBS) -levent_openssl
