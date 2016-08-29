ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS += -I$(srcdir)/submodules/SAI/inc
AM_CPPFLAGS += -I$(top_srcdir)/switchapi/include
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
	@$(CTYPESGEN) -I/usr/include -I$(srcdir)/submodules/SAI/inc \
		$(srcdir)/submodules/SAI/inc/*.h -o $@ > /dev/null 2>&1

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
src/saibuffer.c \
src/saifdb.c \
src/saihash.c \
src/saihostintf.c \
src/saiinternal.h \
src/saiipmc.c \
src/sail2mc.c \
src/sailag.c \
src/saimirror.c \
src/saineighbor.c \
src/sainexthop.c \
src/sainexthopgroup.c \
src/saiobject.c \
src/saipolicer.c \
src/saiport.c \
src/saiqosmaps.c \
src/saiqueue.c \
src/sairoute.c \
src/sairouter.c \
src/sairouterintf.c \
src/saischeduler.c \
src/saischedulergroup.c \
src/saistp.c \
src/saiswitch.c \
src/saiudf.c \
src/saiutils.c \
src/saivlan.c \
src/switch_sai_rpc_server.cpp

sai_headers = \
submodules/SAI/inc/sai.h \
submodules/SAI/inc/saihash.h \
submodules/SAI/inc/sailag.h \
submodules/SAI/inc/sainexthopgroup.h \
submodules/SAI/inc/saiqosmaps.h \
submodules/SAI/inc/sairouterintf.h \
submodules/SAI/inc/saistatus.h \
submodules/SAI/inc/saitypes.h \
submodules/SAI/inc/saiacl.h \
submodules/SAI/inc/saihostintf.h \
submodules/SAI/inc/saimirror.h \
submodules/SAI/inc/saiobject.h \
submodules/SAI/inc/saiqueue.h \
submodules/SAI/inc/saisamplepacket.h \
submodules/SAI/inc/saistp.h \
submodules/SAI/inc/saiudf.h \
submodules/SAI/inc/saibuffer.h \
submodules/SAI/inc/saiipmc.h \
submodules/SAI/inc/saineighbor.h \
submodules/SAI/inc/saipolicer.h \
submodules/SAI/inc/sairoute.h \
submodules/SAI/inc/saischeduler.h \
submodules/SAI/inc/saiswitch.h \
submodules/SAI/inc/saivlan.h \
submodules/SAI/inc/saifdb.h \
submodules/SAI/inc/sail2mc.h \
submodules/SAI/inc/sainexthop.h \
submodules/SAI/inc/saiport.h \
submodules/SAI/inc/sairouter.h \
submodules/SAI/inc/saischedulergroup.h \
submodules/SAI/inc/saitunnel.h \
submodules/SAI/inc/saiwred.h

saiincludedir = $(includedir)/sai
saiinclude_HEADERS = $(sai_headers)
noinst_LTLIBRARIES =
lib_LIBRARIES =
lib_LTLIBRARIES =

if WITH_BMV2
libbmswitchsai_la_CPPFLAGS = $(AM_CPPFLAGS)
libbmswitchsai_la_CPPFLAGS += -DBMV2
libbmswitchsai_la_CPPFLAGS += -I$(top_builddir)/p4-build/
libbmswitchsai_la_CPPFLAGS += -isystem$(includedir)
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
