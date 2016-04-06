ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = third-party/tommyds


if TARGET_BMV2
TARGET_CFLAGS = -D BMV2
TARGET_CFLAGS += $(P4C_LIBPDFIXED_CFLAGS)
TARGET_CFLAGS += -I $(srcdir)/../p4src/bmv2_p4_pd
endif

libswitchapi_la_CFLAGS = -I$(srcdir)/inc
libswitchapi_la_CFLAGS += -I$(srcdir)/src/gen-cpp
libswitchapi_la_CFLAGS += -I$(srcdir)/third-party/tommyds/include
libswitchapi_la_CFLAGS += -I$(srcdir)/../p4src/includes
libswitchapi_la_CFLAGS += $(TARGET_CFLAGS)
libswitchapi_la_CXXFLAGS = $(libswitchapi_la_CFLAGS)
libswitchapi_a_CFLAGS = $(libswitchapi_la_CFLAGS)
libswitchapi_a_CXXFLAGS = $(libswitchapi_a_CFLAGS)

BUILT_SOURCES = \
src/gen-cpp/switch_api_constants.cpp \
src/gen-cpp/switch_api_constants.h \
src/gen-cpp/switch_api_rpc.cpp \
src/gen-cpp/switch_api_rpc.h \
src/gen-cpp/switch_api_types.cpp \
src/gen-cpp/switch_api_types.h

$(BUILT_SOURCES): src/switch_api.thrift
	$(THRIFT) -o $(srcdir)/src/ --gen cpp -r $(srcdir)/src/switch_api.thrift

#lib_LIBRARIES = libswitchapi.a
noinst_LTLIBRARIES = libswitchapi.la

libswitchapi_la_SOURCES = \
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
src/switch_sflow_int.h \
src/switch_sflow.c \
src/thrift_cache.h \
inc/switchapi/switch_acl.h \
inc/switchapi/switch_base_types.h \
inc/switchapi/switch_capability.h \
inc/switchapi/switchapi/switch_config.h \
inc/switchapi/switch_handle.h \
inc/switchapi/switchapi/switch_hostif.h \
inc/switchapi/switch_id.h \
inc/switchapi/switch_interface.h \
inc/switchapi/switch_l2.h \
inc/switchapi/switch_l3.h \
inc/switchapi/switch_lag.h \
inc/switchapi/switch_mcast.h \
inc/switchapi/switchapi/switch_meter.h \
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
inc/switchapi/switch_vrf.h \
inc/switchapi/switch_sflow.h

#libswitchapi_a_SOURCES = $(libswitchapi_la_SOURCES)
libswitchapi_la_LIBADD = third-party/tommyds/libtommyds.la
