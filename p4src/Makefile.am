ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

prog_CFLAGS = $(AM_CFLAGS)

p4_files = $(shell ls *.p4)
p4_files += $(shell ls includes/*.p4)
p4_name = switch
p4_prg = $(p4_name).p4

PFX ?=
if TARGET_BMV2
TARGET=bmv2
libbmv2pd_la_CXXFLAGS = -I $(srcdir)/bmv2_p4_pd
libbmv2pd_la_CXXFLAGS += \
	-I $(PFX)$(includedir)/pdfixed \
	-I $(PFX)$(includedir)/pdfixed/pd \
	-I $(PFX)$(includedir)/pdfixed/src \
	-std=c++11

# take all the pd files created by the compiler
# pd_file = $(shell ls p4_pd/src/*.cpp)
bmv2_pd_files = \
bmv2_p4_pd/src/pd.cpp \
bmv2_p4_pd/src/pd_learning.cpp \
bmv2_p4_pd/src/pd_meters.cpp \
bmv2_p4_pd/src/pd_counters.cpp \
bmv2_p4_pd/src/pd_tables.cpp \
bmv2_p4_pd/src/pd_ageing.cpp \
bmv2_p4_pd/src/pd_mirroring.cpp

bmv2_pd_headers = \
bmv2_p4_pd/pd/pd.h \
bmv2_p4_pd/pd/pd_learning.h \
bmv2_p4_pd/pd/pd_meters.h \
bmv2_p4_pd/pd/pd_counters.h \
bmv2_p4_pd/pd/pd_tables.h \
bmv2_p4_pd/pd/pd_types.h \
bmv2_p4_pd/pd/pd_mirroring.h

noinst_LTLIBRARIES = libbmv2pd.la
BUILT_SOURCES = $(bmv2_pd_files) $(bmv2_pd_headers)

libbmv2pd_la_SOURCES = $(BUILT_SOURCES)

P4CC_BM = $(PFX)$(bindir)/p4c_bm/p4c-bmv2

# target specific definitions - each target may require different output files
p4_bmv2_output = $(p4_name)_bmv2.json

bmv2_pd_files.ts : $(p4_bmv2_output)

$(p4_bmv2_output) : $(p4_files)
	@mkdir -p bmv2_p4_pd
	$(P4CC_BM) --pd bmv2_p4_pd --p4-prefix dc --json $@ $(p4_prg)

pkgdata_DATA = $(p4_bmv2_output)

endif

# TARGETs are bmv2, tofino, bm-tofino ...
$(BUILT_SOURCES) : $(TARGET)_pd_files.ts
	@touch $(TARGET)_pd_files.ts

_pd_files.ts:
	@echo "Error"
	exit

CLEANFILES = bmv2_pd_files.ts $(p4_bmv2_output) $(BUILT_SOURCES)
