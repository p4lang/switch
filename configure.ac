#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AM_EXTRA_RECURSIVE_TARGETS([switch])
AM_EXTRA_RECURSIVE_TARGETS([switch-install])

AC_PREREQ([2.69])
AC_INIT([switch], [0.1], [])
AM_PATH_PYTHON([2.7],,[:])
# This prevents autotools from automatically adding -O2 flag.
: ${CXXFLAGS=""}
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])

# Check for thrift support (Apache Thrift RPC library)
AC_PATH_PROG([THRIFT], [thrift], [])
AS_IF([test x"$THRIFT" = x], [AC_MSG_ERROR([Missing thrift executable])])
# Thrift must always be enabled by default. A real check is performed in
# p4factory/release/pkg-configure.ac.
AM_CONDITIONAL([IS_THRIFT_ENABLED], [test "x" = "x"])

AC_ARG_ENABLE([coverage],
    AS_HELP_STRING([--enable-coverage], [Enable gcov flags]))
AS_IF([test "x$enable_coverage" = "xyes"], [
    AC_DEFINE([COVERAGE], [], ["Link with gcov."])
    COVERAGE_FLAGS="--coverage"
])

#AC_PROG_CC_STDC
AC_PROG_CXX
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# enforce -std=c++11
# AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

# Checks for header files.
AC_LANG_PUSH(C)
AC_LANG_PUSH(C++)

AC_CHECK_HEADER([thrift/Thrift.h], [], \
  [AC_MSG_ERROR([Thrift headers not found])])

# Check for thrift support (Facebook's Thrift RPC library)
AC_PATH_PROG([THRIFT], [thrift], [])
AS_IF([test x"$THRIFT" = x && IS_THRIFT_ENABLED],
[AC_MSG_ERROR([cannot find thrift])])

AC_CHECK_LIB([pcap], [pcap_create], [], [AC_MSG_ERROR([Missing libpcap])])
if test -n "$COVERAGE_FLAGS"; then
    AC_CHECK_LIB([gcov], [__gcov_init], [], [AC_MSG_ERROR([Missing gcov library])])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([socket])
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_FUNC_MALLOC
AC_PROG_RANLIB
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

p4target=unknown

AC_ARG_ENABLE([bmv2], \
	[ --enable-bmv2 	Enable bmv2 as p4target],
	[case "${enableval}" in
		yes) p4target=bmv2 ;;
		*) ;;
	esac], [])

AM_CONDITIONAL(TARGET_BMV2, [test "x$p4target" =  "xbmv2"])

# Generate makefiles
AC_CONFIG_FILES([switchapi/third-party/tommyds/Makefile switchapi/Makefile
         switchsai/Makefile 
         switchlink/third-party/xxhash/Makefile switchlink/Makefile p4src/Makefile Makefile])
AC_OUTPUT
