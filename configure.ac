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
# Thrift must always be enabled by default
AM_CONDITIONAL([IS_THRIFT_ENABLED], [test "x" = "x"])

coverage_enabled=no
AC_ARG_ENABLE([coverage],
    AS_HELP_STRING([--enable-coverage], [Enable gcov flags]))
AS_IF([test "x$enable_coverage" = "xyes"], [
    coverage_enabled=yes
    AC_DEFINE([COVERAGE], [], ["Link with gcov."])
    COVERAGE_FLAGS="--coverage"
])

want_bmv2=no
AC_ARG_WITH([bmv2],
    AS_HELP_STRING([--with-bmv2], [Build for bmv2 target]),
    [want_bmv2=yes], [])

AM_CONDITIONAL([WITH_BMV2], [test "$want_bmv2" = yes])

want_p4factory=no
AC_ARG_WITH([p4factory],
    AS_HELP_STRING([--with-p4factory], [Build for p4factory target]),
    [want_p4factory=yes], [])

AM_CONDITIONAL([WITH_P4FACTORY], [test "$want_p4factory" = yes])

AC_PROG_CC_STDC
AC_PROG_CXX
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# will abort if there is no Python interpreter >= 2.7
AM_PATH_PYTHON([2.7])

AC_PROG_AWK
AC_PROG_SED
AC_PROG_GREP

# enforce -std=c++11
# AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

# Checks for header files.
AC_LANG_PUSH(C)
AC_LANG_PUSH(C++)

# To simplify usage, we will update PATH, CPPFLAGS,.. to include the 'prefix'
# ones
adl_RECURSIVE_EVAL([$bindir], [BIN_DIR])
adl_RECURSIVE_EVAL([$includedir], [INCLUDE_DIR])
adl_RECURSIVE_EVAL([$pythondir], [PYTHON_DIR])
adl_RECURSIVE_EVAL([$libdir], [LIB_DIR])

AS_IF([test "$want_bmv2" = yes], [
    AC_PATH_PROG([P4C_BM], [p4c-bmv2], [], [$PATH$PATH_SEPARATOR$BIN_DIR])
    AS_IF([test x"$P4C_BM" = x], AC_MSG_ERROR([cannot find p4c-bmv2 compiler]))

    CPPFLAGS="$CPPFLAGS -I$INCLUDE_DIR"
    AC_CHECK_HEADER([p4c_bm/pdfixed/pd/pd_common.h], [],
      [AC_MSG_ERROR([bmv2 pdfixed headers not found])])

    # TODO(antonin): this is quite nasty, and in the long term I should probably
    # adjust the installation path of the p4c_bm products instead, but I don't
    # want to break too many things at once
    ab_FIND_HEADER_PATH(["p4c_bm/pdfixed/thrift/res.thrift"], [pdfixed_path])
    pdfixed_path=`AS_DIRNAME(["$pdfixed_path"])`
    AC_SUBST([BM_PDFIXED_PATH], ["$pdfixed_path"])

    AC_CHECK_HEADER([bm_sim/Standard.h], [],
      [AC_MSG_ERROR([bmv2 Thrift headers not found])])

    ab_FIND_HEADER_PATH(["bm_sim/Standard.h"], [bm_thrift_path])
    AC_SUBST([BM_THRIFT_PATH], ["$bm_thrift_path"])

    # A little extra: check for simple_switch target; of course it is not
    # critical if we cannot find it
    AC_PATH_PROG([BM_SIMPLE_SWITCH], [simple_switch], [],
      [$PATH$PATH_SEPARATOR$BIN_DIR])
    AS_IF([test x"$BM_SIMPLE_SWITCH" = x],
      [AC_MSG_WARN([You are compiling for bmv2, but simple_switch binary was not found])])
])

AC_CHECK_HEADERS([assert.h stdio.h string.h sys/stat.h sys/types.h unistd.h], \
[], [AC_MSG_ERROR([Missing header file])])

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
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_TYPES([ptrdiff_t])
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

AC_SUBST([AM_CPPFLAGS], ["-I$INCLUDE_DIR"])
AC_SUBST([AM_LDFLAGS], ["-L$LIB_DIR"])
AC_SUBST([PYTHONPATH], ["PYTHONPATH=$PYTHONPATH:$PYTHON_DIR"])

# Generate makefiles
AC_CONFIG_FILES([switchapi/third-party/tommyds/Makefile
                 switchapi/Makefile
                 switchsai/Makefile
                 switchlink/third-party/xxhash/Makefile
                 switchlink/Makefile
                 Makefile
                 bmv2/Makefile])
AC_OUTPUT

AS_ECHO("")
AS_ECHO("Features recap ......................")
AS_ECHO("Coverage enabled .............. : $coverage_enabled")
AS_ECHO("Compile for p4factory ......... : $want_p4factory")
AS_ECHO("Compile for bmv2 .............. : $want_bmv2")
