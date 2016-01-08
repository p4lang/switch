#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([switch], [0.1], [])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])

# This prevents autotools from automatically adding -O2 flag.
: ${CXXFLAGS=""}
# XXX find a way to identify all available P4 compilers (hlir and backends)??
CFLAGS="-g -Wall -Wextra -Wno-unused-parameter"
#AC_PROG_CC_STDC
AC_PROG_CXX
AC_PROG_RANLIB

AC_CONFIG_MACRO_DIR([m4])

# enforce -std=c++11
AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

# Checks for header files.
AC_LANG_PUSH(C)

# Check for thrift support (Facebook's Thrift RPC library)
AC_PATH_PROG([THRIFT], [thrift], [])
AS_IF([test x"$THRIFT" = x],
[AC_MSG_ERROR([cannot find thrift])])

AC_CHECK_LIB([pcap], [pcap_create], [], [AC_MSG_ERROR([Missing libpcap])])
if test -n "$COVERAGE_FLAGS"; then
    AC_CHECK_LIB([gcov], [__gcov_init], [], [AC_MSG_ERROR([Missing gcov library])])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T

p4target=unknown

AC_ARG_ENABLE([bmv2], \
	[ --enable-bmv2 	Enable bmv2 as p4target],
	[case "${enableval}" in
		yes) p4target=bmv2 ;;
		*) ;;
	esac], [])

AM_CONDITIONAL(TARGET_BMV2, [test "x$p4target" =  "xbmv2"])


# Generate makefiles
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
