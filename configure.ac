# dumdumd - packets sent lightning fast to dev null
# Copyright (c) 2017, OARC, Inc.
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

AC_PREREQ(2.61)
AC_INIT([dumdumd], [1.1.0], [admin@dns-oarc.net], [dumdumd], [https://github.com/DNS-OARC/dumdumd/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/dumdumd.c])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT([disable-static])

# Checks for libraries/headers.
AC_CHECK_HEADERS([ev.h])
AC_CHECK_LIB([ev], [ev_now])
AC_CHECK_HEADERS([uv.h])
AC_CHECK_LIB([uv], [uv_now])

# Check for OS specific libraries
# case "$host_os" in
# esac

# Output Makefiles
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
