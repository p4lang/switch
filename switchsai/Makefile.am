ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

libswitchsai_la_CFLAGS  = -I$(srcdir)/submodules/SAI/inc
libswitchsai_la_CFLAGS += -I$(srcdir)/../../modules/BMI/module/inc
libswitchsai_la_CFLAGS += -I$(builddir)/src/gen-cpp
libswitchsai_la_CFLAGS += -I$(top_srcdir)/switchapi/third-party/tommyds/include
libswitchsai_la_CFLAGS += -I$(top_srcdir)/p4src/includes
libswitchsai_la_CXXFLAGS = $(libswitchsai_la_CFLAGS)
libswitchsai_a_CFLAGS = $(libswitchsai_la_CFLAGS)
libswitchsai_a_CXXFLAGS = $(libswitchsai_a_CFLAGS)

thrift_cpp_sources = \
@builddir@/src/gen-cpp/switch_sai_constants.cpp \
@builddir@/src/gen-cpp/switch_sai_constants.h \
@builddir@/src/gen-cpp/switch_sai_rpc.cpp \
@builddir@/src/gen-cpp/switch_sai_rpc.h \
@builddir@/src/gen-cpp/switch_sai_types.cpp \
@builddir@/src/gen-cpp/switch_sai_types.h
thrift_py_sources = \
@builddir@/src/gen-py/switch_sai/constants.py \
@builddir@/src/gen-py/switch_sai/__init__.py \
@builddir@/src/gen-py/switch_sai/switch_sai_rpc.py \
@builddir@/src/gen-py/switch_sai/switch_sai_rpc-remote \
@builddir@/src/gen-py/switch_sai/ttypes.py

lib_LIBRARIES = libswitchsai.a
lib_LTLIBRARIES = libswitchsai.la

$(lib_LIBRARIES) : $(thrift_py_sources)
$(lib_LTLIBRARIES) : $(thrift_py_sources)

libswitchsai_la_SOURCES = \
$(thrift_cpp_sources) \
src/saiacl.c \
src/saiapi.h \
src/sai.c \
src/sai_bmlib.c \
src/saifdb.c \
src/saihostintf.c \
src/saiinternal.h \
src/saiipmc.c \
src/sail2mc.c \
src/sailag.c \
src/saimirror.c \
src/saineighbor.c \
src/sainexthop.c \
src/sainexthopgroup.c \
src/saipolicer.c \
src/saiport.c \
src/sairoute.c \
src/sairouter.c \
src/sairouterintf.c \
src/saistp.c \
src/saiswitch.c \
src/saiutils.c \
src/saivlan.c \
src/switch_sai_rpc_server.cpp

libswitchsai_a_SOURCES = $(libswitchsai_la_SOURCES)

BUILT_SOURCES = \
$(thrift_cpp_sources) \
$(thrift_py_sources)

# The recipe to invoke the thrift compiler is copied from:
# http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html
switchsai.ts : @srcdir@/src/switch_sai.thrift
	@rm -f switchsai.tmp
	@touch switchsai.tmp
	$(THRIFT) -o @builddir@/src/ --gen cpp -r @srcdir@/src/switch_sai.thrift
	$(THRIFT) -o @builddir@/src/ --gen py -r @srcdir@/src/switch_sai.thrift
	@mv -f switchsai.tmp $@

$(BUILT_SOURCES) : switchsai.ts
## Recover from the removal of $@
	@if test -f $@; then :; else \
	  trap 'rm -rf switchsai.lock switchsai.ts' 1 2 13 15; \
## mkdir is a portable test-and-set
	if mkdir switchsai.lock 2>/dev/null; then \
## This code is being executed by the first process.
	  rm -f switchsai.ts; \
	  $(MAKE) $(AM_MAKEFLAGS) switchsai.ts; \
	  result=$$?; rm -rf switchsai.lock; exit $$result; \
	else \
## This code is being executed by the follower processes.
## Wait until the first process is done.
	  while test -d switchsai.lock; do sleep 1; done; \
## Succeed if and only if the first process succeeded.
	    test -f switchsai.ts; \
	  fi; \
	fi

CLEANFILES = $(BUILT_SOURCES)
