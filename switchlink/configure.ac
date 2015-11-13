#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([switchlink], [0.1], [])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
CFLAGS="-g -Wall -Wextra -Wno-unused-parameter"
AC_PROG_CC_STDC
AC_PROG_CXX
AC_PROG_RANLIB

AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_LANG_PUSH(C)

AC_CHECK_LIB([pcap], [pcap_create], [], [AC_MSG_ERROR([Missing libpcap])])
if test -n "$COVERAGE_FLAGS"; then
    AC_CHECK_LIB([gcov], [__gcov_init], [], [AC_MSG_ERROR([Missing gcov library])])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T

# Generate makefiles
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
