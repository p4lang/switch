ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = third-party/tommyds

# using AM_CPPFLAGS so it applies to all libraries

AM_CPPFLAGS = -I$(srcdir)/inc
AM_CPPFLAGS += -I$(builddir)/src/gen-cpp
AM_CPPFLAGS += -I$(srcdir)/third-party/tommyds/include
AM_CPPFLAGS += -I$(top_srcdir)/p4src/includes
AM_CPPFLAGS += -I$(includedir)

if P4THRIFT
    AM_CPPFLAGS += -DP4THRIFT
endif

BUILT_SOURCES = \
src/gen-cpp/switch_api_constants.cpp \
src/gen-cpp/switch_api_constants.h \
src/gen-cpp/switch_api_rpc.cpp \
src/gen-cpp/switch_api_rpc.h \
src/gen-cpp/switch_api_types.cpp \
src/gen-cpp/switch_api_types.h

# http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html
switchapi.ts : @srcdir@/src/switch_api.thrift
	@rm -f switchapi.tmp
	@touch switchapi.tmp
	$(THRIFT) -o @builddir@/src/ --gen cpp -r @srcdir@/src/switch_api.thrift
	$(THRIFT) -o @builddir@/src/ --gen py -r @srcdir@/src/switch_api.thrift
## FIXME: p4factory legacy
	cp -r @builddir@/src/gen-py/switch_api/ @builddir@/switch_api_thrift
	@mv -f switchapi.tmp $@

$(BUILT_SOURCES): switchapi.ts
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

switchapi_sources = \
$(BUILT_SOURCES) \
src/switch_acl.c \
src/switch_acl_int.h \
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
src/switch_mcast.c \
src/switch_mcast_int.h \
src/switch_mirror.c \
src/switch_mirror_int.h \
src/switch_neighbor.c \
src/switch_neighbor_int.h \
src/switch_nhop.c \
src/switch_nhop_int.h \
src/switch_packet.c \
src/switch_packet_int.h \
src/switch_pd.c \
src/switch_pd.h \
src/switch_pd_mcast.c \
src/switch_port.c \
src/switch_port_int.h \
src/switch_rmac.c \
src/switch_rmac_int.h \
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
src/thrift_cache.h \
inc/switchapi/switch_acl.h \
inc/switchapi/switch_base_types.h \
inc/switchapi/switch_capability.h \
inc/switchapi/switch_config.h \
inc/switchapi/switch_handle.h \
inc/switchapi/switch_hostif.h \
inc/switchapi/switch_id.h \
inc/switchapi/switch_interface.h \
inc/switchapi/switch_l2.h \
inc/switchapi/switch_l3.h \
inc/switchapi/switch_lag.h \
inc/switchapi/switch_mcast.h \
inc/switchapi/switch_meter.h \
inc/switchapi/switch_neighbor.h \
inc/switchapi/switch_nhop.h \
inc/switchapi/switch_port.h \
inc/switchapi/switch_porting.h \
inc/switchapi/switch_protocol.h \
inc/switchapi/switch_rmac.h \
inc/switchapi/switch_status.h \
inc/switchapi/switch_stp.h \
inc/switchapi/switch_tunnel.h \
inc/switchapi/switch_utils.h \
inc/switchapi/switch_vlan.h \
inc/switchapi/switch_INT.h \
inc/switchapi/switch_vrf.h

noinst_LTLIBRARIES =
lib_LIBRARIES =

if WITH_BMV2
libbmswitchapi_la_CPPFLAGS = $(AM_CPPFLAGS)
libbmswitchapi_la_CPPFLAGS += -DBMV2
libbmswitchapi_la_CPPFLAGS += -I$(top_builddir)/bmv2/p4_pd
libbmswitchapi_la_CPPFLAGS += -I$(BM_PDFIXED_PATH)/
noinst_LTLIBRARIES += libbmswitchapi.la
libbmswitchapi_la_SOURCES = $(switchapi_sources)
libbmswitchapi_la_LIBADD = third-party/tommyds/libtommyds.la
libbmswitchapi_la_LIBADD += -lJudy
endif

# FIXME: legacy support, relies on p4factory
if WITH_P4FACTORY
lib_LIBRARIES += libswitchapi.a
libswitchapi_a_SOURCES = $(switchapi_sources)
endif

CLEANFILES = $(BUILT_SOURCES) switchapi.ts
