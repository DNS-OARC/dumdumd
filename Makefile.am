# dumdumd - packets sent lightning fast to dev null
# Copyright (c) 2017-2024 OARC, Inc.
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

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in \
    $(srcdir)/src/config.h.in~ \
    $(srcdir)/configure

SUBDIRS = src

dist_doc_DATA = CHANGES README.md LICENSE

EXTRA_DIST = m4

test: check
