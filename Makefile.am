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

if WITH_BMV2
bin_PROGRAMS += bmswitchp4_drivers
bmswitchp4_drivers_CPPFLAGS = $(AM_CPPFLAGS)
bmswitchp4_drivers_CPPFLAGS += -DBMV2
bmswitchp4_drivers_CPPFLAGS += -I$(top_srcdir)/bmv2/p4_pd
bmswitchp4_drivers_CPPFLAGS += -I$(BM_PDFIXED_PATH)/
bmswitchp4_drivers_LDADD = \
@builddir@/switchlink/libswitchlink.la \
@builddir@/switchsai/libbmswitchsai.la \
@builddir@/switchapi/libbmswitchapi.la \
@builddir@/bmv2/libbmpd.la \
@builddir@/bmv2/libbmpdthrift.la \
-lbmpdfixed -lbmpdfixedthrift -lthrift
bmswitchp4_drivers_SOURCES = \
@srcdir@/bmv2/bmv2_init.c \
@srcdir@/bmv2/main.c
endif
