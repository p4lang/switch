ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = third-party/xxhash

AM_CPPFLAGS += -I$(srcdir)/third-party/xxhash/include
AM_CPPFLAGS += -I$(top_srcdir)/switchsai/submodules/SAI/inc
AM_CPPFLAGS += -I$(top_srcdir)/switchapi/third-party/tommyds/include
# TODO: could this be done in configure?
AM_CPPFLAGS += $(shell pkg-config --cflags libnl-3.0)

switchlink_sources = \
src/switchlink_address.c \
src/switchlink_db.c \
src/switchlink_db.h \
src/switchlink_db_int.h \
src/switchlink.h \
src/switchlink_int.h \
src/switchlink_link.c \
src/switchlink_link.h \
src/switchlink_main.c \
src/switchlink_mdb.c \
src/switchlink_neigh.c \
src/switchlink_neigh.h \
src/switchlink_netconf.c \
src/switchlink_packet.c \
src/switchlink_packet.h \
src/switchlink_route.c \
src/switchlink_route.h \
src/switchlink_sai.c \
src/switchlink_sai.h

noinst_LTLIBRARIES =
lib_LIBRARIES =
lib_LTLIBRARIES =

if WITH_BMV2
# has the advantage of avoiding "created both with libtool and without" error
libswitchlink_la_CPPFLAGS = $(AM_CPPFLAGS)
libswitchlink_la_CPPFLAGS += -DBMV2
noinst_LTLIBRARIES += libswitchlink.la
libswitchlink_la_SOURCES = $(switchlink_sources)
libswitchlink_la_LIBADD = third-party/xxhash/libxxhash.la
libswitchlink_la_LIBADD += $(NETLINK_LIBS)
endif

# FIXME: legacy support, relies on p4factory
if WITH_P4FACTORY
lib_LIBRARIES += libswitchlink.a
libswitchlink_a_SOURCES = $(switchlink_sources)
# FIXME: this also creates shared libraries for p4factory, needs to be
# deprecated
lib_LTLIBRARIES += libswitchlink.la
# has the advantage of avoiding "created both with libtool and without" error
libswitchlink_la_CPPFLAGS = $(AM_CPPFLAGS)
libswitchlink_la_SOURCES = $(switchlink_sources)
endif

# FIXME: dos this really serve a purpose?
switch-local: all
switch-install-local: install
