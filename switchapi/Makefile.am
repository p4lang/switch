ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = third-party/tommyds


if TARGET_BMV2
TARGET_CFLAGS = -D BMV2
TARGET_CFLAGS += $(P4C_LIBPDFIXED_CFLAGS)
TARGET_CFLAGS += -I $(srcdir)/../p4src/bmv2_p4_pd
endif

libswitchapi_la_CFLAGS = -I$(srcdir)/include
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
src/switch_buffer.c \
src/switch_buffer_int.h \
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
src/switch_log_int.h \
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
src/switch_pd_mcast.c \
src/switch_pd_nat.c \
src/switch_pd_ppg.c \
src/switch_pd_qos.c \
src/switch_pd_queue.c \
src/switch_pd_types.h \
src/switch_port.c \
src/switch_port_int.h \
src/switch_qos.c \
src/switch_qos_int.h \
src/switch_queue.c \
src/switch_queue_int.h \
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
src/switch_scheduler.c \
src/switch_scheduler_int.h \
src/switch_sflow_int.h \
src/switch_sflow.c \
src/thrift_cache.h \
include/switchapi/switch_acl.h \
include/switchapi/switch_base_types.h \
include/switchapi/switch_capability.h \
include/switchapi/switchapi/switch_config.h \
include/switchapi/switch_handle.h \
include/switchapi/switchapi/switch_hostif.h \
include/switchapi/switch_id.h \
include/switchapi/switch_interface.h \
include/switchapi/switch_l2.h \
include/switchapi/switch_l3.h \
include/switchapi/switch_lag.h \
include/switchapi/switch_mcast.h \
include/switchapi/switchapi/switch_meter.h \
include/switchapi/switch_neighbor.h \
include/switchapi/switch_nhop.h \
include/switchapi/switch_port.h \
include/switchapi/switch_porting.h \
include/switchapi/switch_protocol.h \
include/switchapi/switch_qos.h \
include/switchapi/switch_queue.h \
include/switchapi/switch_rmac.h \
include/switchapi/switch_status.h \
include/switchapi/switch_stp.h \
include/switchapi/switch_tunnel.h \
include/switchapi/switch_utils.h \
include/switchapi/switch_vlan.h \
include/switchapi/switch_INT.h \
include/switchapi/switch_vrf.h \
include/switchapi/switch_sflow.h

#libswitchapi_a_SOURCES = $(libswitchapi_la_SOURCES)
libswitchapi_la_LIBADD = third-party/tommyds/libtommyds.la
