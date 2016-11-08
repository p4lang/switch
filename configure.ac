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

want_of=no
AS_IF([test "$want_bmv2" = yes], [
  AC_ARG_WITH([of],
    AS_HELP_STRING([--with-of], [Enable openflow for bmv2 target, will build switchapi as well]),
    [want_of=yes], [])
])

AM_CONDITIONAL([WITH_BMV2], [test "$want_bmv2" = yes])

want_p4factory=no
AC_ARG_WITH([p4factory],
    AS_HELP_STRING([--with-p4factory], [Build for p4factory target]),
    [want_p4factory=yes], [])

AM_CONDITIONAL([WITH_P4FACTORY], [test "$want_p4factory" = yes])

want_switchapi=no
AC_ARG_WITH([switchapi],
    AS_HELP_STRING([--with-switchapi], [Build with switchapi]),
    [want_switchapi=yes], [])

want_switchsai=no
AC_ARG_WITH([switchsai],
    AS_HELP_STRING([--with-switchsai],
                   [Build with switchsai, will build switchapi as well]),
    [want_switchsai=yes], [])

want_switchlink=no
AC_ARG_WITH([switchlink],
    AS_HELP_STRING([--with-switchlink],
                   [Build with switchlink, will build switchsai and switchapi as well]),
    [want_switchlink=yes], [])

MY_CPPFLAGS=

AS_IF([test "$want_switchlink" = yes], [
    want_switchsai=yes
    MY_CPPFLAGS="$MY_CPPFLAGS -DSWITCHLINK_ENABLE"
    netlink_libs=$(pkg-config --libs libnl-route-3.0)
    AC_SUBST([NETLINK_LIBS], ["$netlink_libs"])
])

AS_IF([test "$want_switchsai" = yes], [
    want_switchapi=yes
    MY_CPPFLAGS="$MY_CPPFLAGS -DSWITCHSAI_ENABLE"
    AC_PATH_PROG([CTYPESGEN], [ctypesgen.py], [])
    AS_IF([test x"$CTYPESGEN" = x],
          AC_MSG_ERROR([cannot find ctypesgen.py, you can install it with 'pip install ctypesgen']))
])

AS_IF([test "$want_of" = yes], [
    want_switchapi=yes
    MY_CPPFLAGS="$MY_CPPFLAGS -DOPENFLOW_ENABLE"
])

AS_IF([test "$want_switchapi" = yes], [
    MY_CPPFLAGS="$MY_CPPFLAGS -DSWITCHAPI_ENABLE"])

AM_CONDITIONAL([WITH_SWITCHAPI], [test "$want_switchapi" = yes])
AM_CONDITIONAL([WITH_SWITCHSAI], [test "$want_switchsai" = yes])
AM_CONDITIONAL([WITH_SWITCHLINK], [test "$want_switchlink" = yes])
AM_CONDITIONAL([WITH_OF], [test "$want_of" = yes])

AC_PROG_CC_STDC
AC_PROG_CXX
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# will abort if there is no Python interpreter >= 2.7
AM_PATH_PYTHON([2.7])

AC_PROG_AWK
AC_PROG_SED
AC_PROG_GREP

# Checks for header files.
AC_LANG_PUSH(C)
AC_LANG_PUSH(C++)

warn_if_no_ptf=no

# To simplify usage, we will update PATH, CPPFLAGS,.. to include the 'prefix'
# ones
adl_RECURSIVE_EVAL([$bindir], [BIN_DIR])
AC_SUBST([BIN_DIR], ["$BIN_DIR"])
adl_RECURSIVE_EVAL([$includedir], [INCLUDE_DIR])
adl_RECURSIVE_EVAL([$pythondir], [PYTHON_DIR])
adl_RECURSIVE_EVAL([$libdir], [LIB_DIR])

AS_IF([test "$want_bmv2" = yes], [
    # A little extra: check for simple_switch target; of course it is not
    # critical if we cannot find it
    AC_PATH_PROG([BM_SIMPLE_SWITCH], [simple_switch], [],
      [$PATH$PATH_SEPARATOR$BIN_DIR])
    AS_IF([test x"$BM_SIMPLE_SWITCH" = x],
      [AC_MSG_WARN([You are compiling for bmv2, but simple_switch binary was not found])])

    warn_if_no_ptf=yes
])

AC_CHECK_HEADERS([assert.h stdio.h string.h sys/stat.h sys/types.h unistd.h], \
[], [AC_MSG_ERROR([Missing header file])])

AS_IF([test "$want_of" = yes], [
    AX_SAVE_FLAGS(SAVE_1)

    CPPFLAGS="$CPPFLAGS -D_BMV2_"
    AC_CHECK_HEADER([p4ofagent/p4ofagent.h], [], \
    [AC_MSG_ERROR([Openflow requires installing p4ofagent from https://github.com/p4lang/p4ofagent])])

    AX_RESTORE_FLAGS(SAVE_1)
])

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

# Check for libJudy
AC_CHECK_LIB([Judy], [Judy1Next], [], [AC_MSG_ERROR([Missing libJudy])])

AC_PATH_PROG([PTF], [ptf], [], [$PATH$PATH_SEPARATOR$BIN_DIR])
ptf_found=no
AS_IF([test x"$PTF" != x],
  [ptf_found=yes],
  [AS_IF([test "$warn_if_no_ptf" = yes],
    [AC_MSG_WARN([No installed version of the ptf testing framework were found])])])

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

AC_SUBST([AM_CPPFLAGS], ["$MY_CPPFLAGS"])
AC_SUBST([AM_CFLAGS], ["-Wall -Werror"])
AC_SUBST([AM_LDFLAGS], ["-L$LIB_DIR"])
AC_SUBST([MY_PYTHONPATH], ["$PYTHON_DIR"])

# Doxygen support
DX_DOXYGEN_FEATURE(ON)
DX_HTML_FEATURE(ON)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(switchapi, switchapi/Doxyfile, switchapi-doc)

# Generate makefiles
AC_CONFIG_FILES([switchapi/third-party/tommyds/Makefile
                 switchapi/Makefile
                 switchsai/Makefile
                 switchlink/third-party/xxhash/Makefile
                 switchlink/Makefile
                 bmv2/Makefile
                 Makefile])

AS_IF([test "$want_bmv2" = yes], [
  AC_CONFIG_FILES([bmv2/run_bm.sh], [chmod +x bmv2/run_bm.sh])
  AC_CONFIG_FILES([bmv2/run_drivers.sh], [chmod +x bmv2/run_drivers.sh])
  AC_CONFIG_FILES([bmv2/run_tests.sh], [chmod +x bmv2/run_tests.sh])
])

AC_CONFIG_FILES([tests/run_tests.py])

AS_IF([test "$want_of" = yes], [
  AC_CONFIG_FILES([bmv2/run_of_tests.sh], [chmod +x bmv2/run_of_tests.sh])
  AC_CONFIG_FILES([docker/configure.sh], [chmod +x docker/configure.sh])
  AC_CONFIG_FILES([docker/run_bm.sh], [chmod +x docker/run_bm.sh])
  AC_CONFIG_FILES([docker/run_drivers.sh], [chmod +x docker/run_drivers.sh])
])

export P4_NAME=switch
export P4_PATH=$ac_abs_confdir/p4src/switch.p4
export P4_PREFIX=dc

AS_IF([test "$want_of" = yes], [
export P4C_BM_FLAGS="--plugin of --openflow-mapping-dir $ac_abs_confdir/openflow_mapping --openflow-mapping-mod l2 -DOPENFLOW_ENABLE"
])

AC_CONFIG_SUBDIRS([p4-build])

AC_OUTPUT

AS_ECHO("")
AS_ECHO("switch features recap ......................")
AS_ECHO("Coverage enabled .............. : $coverage_enabled")
AS_ECHO("With switchlink ............... : $want_switchlink")
AS_ECHO("With switchsai ................ : $want_switchsai")
AS_ECHO("With switchapi ................ : $want_switchapi")
AS_ECHO("With openflow ................. : $want_of")
AS_ECHO("Compile for p4factory ......... : $want_p4factory")
AS_ECHO("Compile for bmv2 .............. : $want_bmv2")
AS_ECHO("PTF found ..................... : $ptf_found")
