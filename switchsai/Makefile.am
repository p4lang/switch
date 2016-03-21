ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = -I$(srcdir)/submodules/SAI/inc
AM_CPPFLAGS += -I$(top_srcdir)/switchapi/inc
AM_CPPFLAGS += -I$(builddir)/src/gen-cpp
AM_CPPFLAGS += -I$(top_srcdir)/switchapi/third-party/tommyds/include
AM_CPPFLAGS += -I$(top_srcdir)/p4src/includes

if P4THRIFT
    AM_CPPFLAGS += -DP4THRIFT
endif

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

sai_ctypesgen = @builddir@/switch_sai_thrift/sai_headers.py

BUILT_SOURCES = \
$(thrift_cpp_sources) \
$(thrift_py_sources) \
$(sai_ctypesgen)

$(sai_ctypesgen) : $(thrift_py_sources)
	$(CTYPESGEN) -I/usr/include -I$(srcdir)/submodules/SAI/inc \
		$(srcdir)/submodules/SAI/inc/*.h -o $@

# The recipe to invoke the thrift compiler is copied from:
# http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html
switchsai.ts : @srcdir@/src/switch_sai.thrift
	@rm -f switchsai.tmp
	@touch switchsai.tmp
	$(THRIFT) -o @builddir@/src/ --gen cpp -r @srcdir@/src/switch_sai.thrift
	$(THRIFT) -o @builddir@/src/ --gen py -r @srcdir@/src/switch_sai.thrift
## FIXME: p4factory legacy
	cp -r @builddir@/src/gen-py/switch_sai/ @builddir@/switch_sai_thrift
	@mv -f switchsai.tmp $@

$(thrift_cpp_sources) $(thrift_py_sources) : switchsai.ts
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

switchsai_sources = \
$(thrift_cpp_sources) \
src/saiacl.c \
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

noinst_LTLIBRARIES =
lib_LIBRARIES =
lib_LTLIBRARIES =

if WITH_BMV2
libbmswitchsai_la_CPPFLAGS = $(AM_CPPFLAGS)
libbmswitchsai_la_CPPFLAGS += -DBMV2
libbmswitchsai_la_CPPFLAGS += -I$(top_builddir)/bmv2/p4_pd
libbmswitchsai_la_CPPFLAGS += -I$(BM_PDFIXED_PATH)
noinst_LTLIBRARIES += libbmswitchsai.la
libbmswitchsai_la_SOURCES = $(switchsai_sources)
endif

# FIXME: legacy support, relies on p4factory
if WITH_P4FACTORY
lib_LIBRARIES += libswitchsai.a
libswitchsai_a_SOURCES = $(switchsai_sources)
# FIXME: this also creates shared libraries for p4factory, needs to be
# deprecated
lib_LTLIBRARIES += libswitchsai.la
# has the advantage of avoiding "created both with libtool and without" error
libswitchsai_la_CPPFLAGS = $(AM_CPPFLAGS)
libswitchsai_la_SOURCES = $(switchsai_sources)
endif

# FIXME: not sure if this serves a real purpose
$(lib_LTLIBRARIES) : $(thrift_py_sources)

CLEANFILES = $(BUILT_SOURCES) switchsai.ts
