ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

libswitchlink_la_CFLAGS = -I$(SUBMODULE_SWITCHSAI)/submodules/ocpsai/sai/inc
libswitchlink_la_CFLAGS += $(shell pkg-config --cflags libnl-3.0)
libswitchlink_a_CFLAGS = $(libswitchlink_la_CFLAGS)

lib_LIBRARIES = libswitchlink.a

libswitchlink_la_SOURCES = \
src/switchlink_address.c \
src/switchlink_db.c \
src/switchlink_db.h \
src/switchlink_db_int.h \
src/switchlink.h \
src/switchlink_int.h \
src/switchlink_link.c \
src/switchlink_link.h \
src/switchlink_main.c \
src/switchlink_neigh.c \
src/switchlink_neigh.h \
src/switchlink_packet.c \
src/switchlink_packet.h \
src/switchlink_route.c \
src/switchlink_route.h \
src/switchlink_sai.c \
src/switchlink_sai.h

libswitchlink_a_SOURCES = $(libswitchlink_la_SOURCES)
