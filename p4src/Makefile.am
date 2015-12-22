ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

prog_CFLAGS = $(AM_CFLAGS)

libbmv2pd_la_CXXFLAGS = -I $(srcdir)/bmv2_p4_pd
libbmv2pd_la_CXXFLAGS += -I /usr/local/include/p4c_bm \
	-I /usr/local/include/p4c_bm/pd \
	-I /usr/local/include/bm_sim -std=c++11

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

lib_LTLIBRARIES = libbmv2pd.la

BUILT_SOURCES = $(bmv2_pd_files) $(bmv2_pd_headers)

# TARGETs are bmv2, tofino, bm-tofino ...
$(BUILT_SOURCES) : $(TARGET)_pd_files.ts
	@touch $(TARGET)_pd_files.ts

libbmv2pd_la_SOURCES = $(BUILT_SOURCES)

p4_files = $(shell ls *.p4)
p4_files += $(shell ls includes/*.p4)
p4_name = switch
p4_prg = $(p4_name).p4

pd_files_.ts:
	@echo "Error"
	exit

P4CC_BM = p4c-bmv2

# target specific definitions - each target may require different output files
p4_bmv2_output = $(p4_name)_bmv2.json

bmv2_pd_files.ts : $(p4_bmv2_output)

$(p4_bmv2_output) : $(p4_files)
	@mkdir -p bmv2_p4_pd
	$(P4CC_BM) --pd bmv2_p4_pd --p4-prefix dc --json $@ $(p4_prg)

CLEANFILES = bmv2_pd_files.ts $(p4_bmv2_output)
