ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

if WITH_BMV2
MAYBE_BMV2 = bmv2
endif

if WITH_SWITCHAPI
MAYBE_SWITCHAPI = switchapi
endif

if WITH_SWITCHSAI
MAYBE_SWITCHSAI = switchsai
endif

if WITH_SWITCHLINK
MAYBE_SWITCHLINK = switchlink
endif

SUBDIRS = $(MAYBE_BMV2) $(MAYBE_SWITCHAPI) $(MAYBE_SWITCHSAI) $(MAYBE_SWITCHLINK) .

bin_PROGRAMS =
lib_LTLIBRARIES =

if WITH_BMV2
AM_CPPFLAGS += -DBMV2
AM_CPPFLAGS += -I$(top_builddir)/bmv2/p4_pd
AM_CPPFLAGS += -I$(BM_PDFIXED_PATH)

lib_LTLIBRARIES += libbmswitchp4.la
libbmswitchp4_la_CPPFLAGS = $(AM_CPPFLAGS)
libbmswitchp4_la_LIBADD =
if WITH_SWITCHLINK
libbmswitchp4_la_LIBADD += @builddir@/switchlink/libswitchlink.la
endif
if WITH_SWITCHSAI
libbmswitchp4_la_LIBADD += @builddir@/switchsai/libbmswitchsai.la
endif
if WITH_SWITCHAPI
libbmswitchp4_la_LIBADD += @builddir@/switchapi/libbmswitchapi.la
endif
libbmswitchp4_la_LIBADD += \
@builddir@/bmv2/libbmpd.la \
@builddir@/bmv2/libbmpdthrift.la \
-lbmpdfixed -lbmpdfixedthrift $(THRIFT_LIB) 
libbmswitchp4_la_SOURCES = \
@srcdir@/bmv2/bmv2_init.c

bin_PROGRAMS += bmswitchp4_drivers
bmswitchp4_drivers_CPPFLAGS = $(AM_CPPFLAGS)
bmswitchp4_drivers_LDADD = \
libbmswitchp4.la
bmswitchp4_drivers_SOURCES = \
@srcdir@/bmv2/main.c
endif

@DX_RULES@
MOSTLYCLEANFILES = $(DX_CLEANFILES)

# AM_DISTCHECK_CONFIGURE_FLAGS = --with-bmv2 --with-switchlink
