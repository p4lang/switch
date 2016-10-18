ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = third-party/tommyds

# using AM_CPPFLAGS so it applies to all libraries

AM_CPPFLAGS += -I$(srcdir)/include
AM_CPPFLAGS += -I$(builddir)/src/gen-cpp
AM_CPPFLAGS += -I$(srcdir)/third-party/tommyds/include
AM_CPPFLAGS += -I$(top_srcdir)/p4src/includes

if P4THRIFT
    AM_CPPFLAGS += -DP4THRIFT
endif

thrift_cpp = \
@builddir@/src/gen-cpp/switch_api_constants.cpp \
@builddir@/src/gen-cpp/switch_api_constants.h \
@builddir@/src/gen-cpp/switch_api_rpc.cpp \
@builddir@/src/gen-cpp/switch_api_rpc.h \
@builddir@/src/gen-cpp/switch_api_types.cpp \
@builddir@/src/gen-cpp/switch_api_types.h 

thrift_py = \
@builddir@/gen-py/switch_api/constants.py \
@builddir@/gen-py/switch_api/__init__.py \
@builddir@/gen-py/switch_api/switch_api_rpc.py \
@builddir@/gen-py/switch_api/switch_api_rpc-remote \
@builddir@/gen-py/switch_api/ttypes.py

switchapi_ctypesgen = @builddir@/gen-py/switch_api/switch_api_headers.py
CTYPESGEN = $(top_srcdir)/third-party/ctypesgen/ctypesgen.py

BUILT_SOURCES = \
$(thrift_cpp) \
$(thrift_py) \
$(switchapi_ctypesgen)

switchapi_sources = \
$(thrift_cpp) \
src/switch_acl.c \
src/switch_acl_int.h \
src/switch_buffer.c \
src/switch_buffer_int.h \
src/switch_api_rpc_server.cpp \
src/switch_api.thrift \
src/switch_capability.c \
src/switch_capability_int.h \
src/switch_config.c \
src/switch_config_int.h \
src/switch_defines.h \
src/switch_handle.c \
src/switch_hostif.c \
src/switch_hostif_int.h \
src/switch_id.c \
src/switch_init.c \
src/switch_INT.c \
src/switch_interface.c \
src/switch_interface_int.h \
src/switch_l2.c \
src/switch_l2_int.h \
src/switch_l3.c \
src/switch_l3_int.h \
src/switch_lag.c \
src/switch_lag_int.h \
src/switch_log.c \
src/switch_log.h \
src/switch_lpm.c \
src/switch_lpm_int.h \
src/switch_mcast.c \
src/switch_mcast_int.h \
src/switch_mirror.c \
src/switch_mirror_int.h \
src/switch_nat.c \
src/switch_nat_int.h \
src/switch_neighbor.c \
src/switch_neighbor_int.h \
src/switch_nhop.c \
src/switch_nhop_int.h \
src/switch_packet.c \
src/switch_packet_int.h \
src/switch_pd.c \
src/switch_pd.h \
src/switch_pd_buffer.c \
src/switch_pd_ppg.c \
src/switch_pd_qos.c \
src/switch_pd_queue.c \
src/switch_pd_mcast.c \
src/switch_pd_nat.c \
src/switch_pd_types.h \
src/switch_port.c \
src/switch_port_int.h \
src/switch_qos.c \
src/switch_qos_int.h \
src/switch_queue.c \
src/switch_queue_int.h \
src/switch_rmac.c \
src/switch_rmac_int.h \
src/switch_scheduler.c \
src/switch_scheduler_int.h \
src/switch_stp.c \
src/switch_stp_int.h \
src/switch_tunnel.c \
src/switch_tunnel_int.h \
src/switch_utils.c \
src/switch_vlan.c \
src/switch_vlan_int.h \
src/switch_vrf.c \
src/switch_meter.c \
src/switch_meter_int.h \
src/switch_vrf_int.h \
src/switch_sflow.c \
src/switch_sflow_int.h \
src/thrift_cache.h

switchapi_includes = \
include/switchapi/switch_acl.h \
include/switchapi/switch_base_types.h \
include/switchapi/switch_buffer.h \
include/switchapi/switch_capability.h \
include/switchapi/switch_config.h \
include/switchapi/switch_dox.h \
include/switchapi/switch_handle.h \
include/switchapi/switch_hostif.h \
include/switchapi/switch_id.h \
include/switchapi/switch_interface.h \
include/switchapi/switch_INT.h \
include/switchapi/switch_l2.h \
include/switchapi/switch_l3.h \
include/switchapi/switch_lag.h \
include/switchapi/switch_log.h \
include/switchapi/switch_meter.h \
include/switchapi/switch_mcast.h \
include/switchapi/switch_mirror.h \
include/switchapi/switch_nat.h \
include/switchapi/switch_neighbor.h \
include/switchapi/switch_nhop.h \
include/switchapi/switch_port.h \
include/switchapi/switch_porting.h \
include/switchapi/switch_protocol.h \
include/switchapi/switch_qos.h \
include/switchapi/switch_queue.h \
include/switchapi/switch_rmac.h \
include/switchapi/switch_scheduler.h \
include/switchapi/switch_sflow.h \
include/switchapi/switch_status.h \
include/switchapi/switch_stp.h \
include/switchapi/switch_tunnel.h \
include/switchapi/switch_utils.h \
include/switchapi/switch_vlan.h \
include/switchapi/switch_vrf.h

$(switchapi_ctypesgen) : $(thrift_py) $(switchapi_includes)
	@echo "Running ctypesgen on switchapi include files"
	@$(CTYPESGEN) -I/usr/include -I$(top_srcdir)/p4src/includes \
		-I$(srcdir)/third-party/tommyds/include \
		-I$(includedir) --no-macros \
	    $(srcdir)/include/switchapi/*.h -o $@ > /dev/null 2>&1
	mkdir -p @builddir@/switch_api_thrift
	cp -r @builddir@/gen-py/switch_api/switch_api_headers.py \
	@builddir@/switch_api_thrift/switch_api_headers.py

# http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html
switchapi.ts : @srcdir@/src/switch_api.thrift
	@rm -f switchapi.tmp
	@touch switchapi.tmp
	$(THRIFT) -o @builddir@/src/ --gen cpp -r @srcdir@/src/switch_api.thrift
	$(THRIFT) -o @builddir@/ --gen py -r @srcdir@/src/switch_api.thrift
## FIXME: p4factory legacy
	cp -r @builddir@/gen-py/switch_api/ @builddir@/switch_api_thrift
	@mv -f switchapi.tmp $@

$(thrift_cpp) $(thrift_py): switchapi.ts
## Recover from the removal of $@
	@if test -f $@; then :; else \
	  trap 'rm -rf switchapi.lock switchapi.ts' 1 2 13 15; \
## mkdir is a portable test-and-set
	if mkdir switchapi.lock 2>/dev/null; then \
## This code is being executed by the first process.
	  rm -f switchapi.ts; \
	  $(MAKE) $(AM_MAKEFLAGS) switchapi.ts; \
	  result=$$?; rm -rf switchapi.lock; exit $$result; \
	else \
## This code is being executed by the follower processes.
## Wait until the first process is done.
	  while test -d switchapi.lock; do sleep 1; done; \
## Succeed if and only if the first process succeeded.
	    test -f switchapi.ts; \
	  fi; \
	fi

noinst_LTLIBRARIES =
lib_LIBRARIES =
lib_LTLIBRARIES =

if WITH_BMV2
libbmswitchapi_la_CPPFLAGS = $(AM_CPPFLAGS)
libbmswitchapi_la_CPPFLAGS += -DBMV2
libbmswitchapi_la_CPPFLAGS += -I$(top_builddir)/p4-build
libbmswitchapi_la_CPPFLAGS += -isystem$(includedir)
noinst_LTLIBRARIES += libbmswitchapi.la
libbmswitchapi_la_SOURCES = $(switchapi_sources) $(switchapi_includes)
libbmswitchapi_la_LIBADD = third-party/tommyds/libtommyds.la
libbmswitchapi_la_LIBADD += -lJudy
endif

# FIXME: legacy support, relies on p4factory
if WITH_P4FACTORY
lib_LIBRARIES += libswitchapi.a
libswitchapi_a_SOURCES = $(switchapi_sources) $(switchapi_includes)
# FIXME: this also creates shared libraries for p4factory, needs to be
# deprecated
lib_LTLIBRARIES += libswitchapi.la
# has the advantage of avoiding "created both with libtool and without" error
libswitchapi_la_CPPFLAGS = $(AM_CPPFLAGS)
libswitchapi_la_SOURCES = $(switchapi_sources) $(switchapi_includes)
endif

CLEANFILES = $(BUILT_SOURCES) switchapi.ts
