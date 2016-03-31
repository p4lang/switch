#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([switchapi], [0.1], [])
LT_INIT()
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])

# Thrift
AC_ARG_WITH([thrift],
    [AS_HELP_STRING([--with-thrift], [Thrift selector])],
    [THRIFT=$withval],
    [AC_PATH_PROG([THRIFT], [thrift], [])])
AS_IF([test x"$THRIFT" = x],
[AC_MSG_ERROR([cannot find thrift])])

AC_ARG_ENABLE([coverage],
    AS_HELP_STRING([--enable-coverage], [Enable gcov flags]))
AS_IF([test "x$enable_coverage" = "xyes"], [
    AC_DEFINE([COVERAGE], [], ["Link with gcov."])
    COVERAGE_FLAGS="--coverage"
])

# Checks for programs.
CFLAGS="-g -Wall -Wextra -Wno-unused-parameter"
AC_PROG_CC_STDC
AC_PROG_CXX
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# enforce -std=c++11
AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

# Checks for header files.
AC_LANG_PUSH(C)

AC_CHECK_HEADERS([assert.h stdio.h string.h sys/stat.h sys/types.h unistd.h], \
[], [AC_MSG_ERROR([Missing header file])])

# Thrift
AC_WITH([p4thrift],
    [
        AC_PATH_PROG([THRIFT], [p4thrift], [])
        AC_SUBST([THRIFT_LIB], ["-lp4thrift"])
        WITH_P4THRIFT="true"
        AC_CHECK_HEADER([p4thrift/P4Thrift.h], [], [AC_MSG_ERROR([P4Thrift headers not found. Install P4Thrift from http://github.com/p4lang/thrift/])])
    ],
    [
        AC_PATH_PROG([THRIFT], [thrift], [])
        AC_SUBST([THRIFT_LIB], ["-lthrift"])
        AC_CHECK_HEADER([thrift/Thrift.h], [], [AC_MSG_ERROR([Thrift headers not found. Install Thrift from http://thrift.apache.org/docs/install/])])
    ])
AM_CONDITIONAL([P4THRIFT], [test "x$WITH_P4THRIFT" != "x"])
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

# Generate makefiles
AC_CONFIG_FILES([Makefile third-party/tommyds/Makefile])
AC_OUTPUT
