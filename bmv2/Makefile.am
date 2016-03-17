ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

pd_files = \
p4_pd/src/pd.cpp \
p4_pd/src/pd_learning.cpp \
p4_pd/src/pd_meters.cpp \
p4_pd/src/pd_counters.cpp \
p4_pd/src/pd_tables.cpp \
p4_pd/src/pd_ageing.cpp \
p4_pd/src/pd_mirroring.cpp

pd_headers = \
p4_pd/pd/pd.h \
p4_pd/pd/pd_learning.h \
p4_pd/pd/pd_meters.h \
p4_pd/pd/pd_counters.h \
p4_pd/pd/pd_tables.h \
p4_pd/pd/pd_types.h \
p4_pd/pd/pd_mirroring.h

pd_p4_IDL = p4_pd/thrift/p4_pd_rpc.thrift
pd_p4_src = \
$(builddir)/p4_pd/thrift-src/p4_pd_rpc_server.ipp \
$(builddir)/p4_pd/thrift-src/pd_rpc_server.cpp \
$(builddir)/p4_pd/thrift-src/pd_rpc_server.h

P4_PATH = $(top_srcdir)/p4src/switch.p4
P4_PREFIX = dc
P4_NAME = switch
P4_JSON_OUTPUT = $(P4_NAME).json

# TODO: improve
include $(top_srcdir)/p4src/p4_files.am

pd_files.ts : $(p4_files)
	@rm -f pd_files.tmp
	@touch pd_files.tmp
	PYTHONPATH=$(PYTHONPATH) $(P4C_BM) --pd $(builddir)/p4_pd/ --p4-prefix $(P4_PREFIX) --json $(builddir)/$(P4_JSON_OUTPUT) $(P4_PATH)
	@mv -f pd_files.tmp $@
$(pd_files) $(pd_p4_IDL) $(pd_p4_src) : pd_files.ts
## Recover from the removal of $@
	@if test -f $@; then :; else \
	  trap 'rm -rf pd_files.lock pd_files.ts' 1 2 13 15; \
## mkdir is a portable test-and-set
	if mkdir pd_files.lock 2>/dev/null; then \
## This code is being executed by the first process.
	  rm -f pd_files.ts; \
	  $(MAKE) $(AM_MAKEFLAGS) pd_files.ts; \
	  result=$$?; rm -rf pd_files.lock; exit $$result; \
	else \
## This code is being executed by the follower processes.
## Wait until the first process is done.
	  while test -d pd_files.lock; do sleep 1; done; \
## Succeed if and only if the first process succeeded.
	    test -f pd_files.ts; \
	  fi; \
	fi

pd_p4_thrift_files = \
pd_thrift_gen/gen-cpp/p4_prefix0.cpp \
pd_thrift_gen/gen-cpp/p4_prefix1.cpp \
pd_thrift_gen/gen-cpp/p4_prefix2.cpp \
pd_thrift_gen/gen-cpp/p4_prefix.h \
pd_thrift_gen/gen-cpp/p4_pd_rpc_constants.cpp \
pd_thrift_gen/gen-cpp/p4_pd_rpc_constants.h \
pd_thrift_gen/gen-cpp/p4_pd_rpc_types.cpp \
pd_thrift_gen/gen-cpp/p4_pd_rpc_types.h

pd_thrift_files = $(pd_p4_thrift_files)

pd_p4_py = pd_thrift_gen/gen-py/p4_pd_rpc/constants.py

pd_thrift_files.ts: $(pd_files) $(pd_p4_IDL) $(pd_res_IDL)
	@rm -f pd_thrift_files.tmp
	@touch pd_thrift_files.tmp
	$(THRIFT) -o $(builddir)/pd_thrift_gen/ -I $(BM_PDFIXED_PATH)/thrift/ --gen cpp -r $(pd_p4_IDL)
	$(THRIFT) -o $(builddir)/pd_thrift_gen/ -I $(BM_PDFIXED_PATH)/thrift/ --gen py -r $(pd_p4_IDL)
	mv -f pd_thrift_gen/gen-cpp/$(P4_PREFIX).h pd_thrift_gen/gen-cpp/p4_prefix.h
	sed --in-place 's/include "$(P4_PREFIX).h"/include "p4_prefix.h"/' pd_thrift_gen/gen-cpp/$(P4_PREFIX).cpp
	$(PYTHON) $(srcdir)/split_pd_thrift.py pd_thrift_gen/gen-cpp/$(P4_PREFIX).cpp pd_thrift_gen/gen-cpp/ 3
	@mv -f pd_thrift_files.tmp $@
$(pd_thrift_files): pd_thrift_files.ts
## Recover from the removal of $@
	@if test -f $@; then :; else \
	  trap 'rm -rf pd_thrift_files.lock pd_thrift_files.ts' 1 2 13 15; \
## mkdir is a portable test-and-set
	if mkdir pd_thrift_files.lock 2>/dev/null; then \
## This code is being executed by the first process.
	  rm -f pd_thrift_files.ts; \
	  $(MAKE) $(AM_MAKEFLAGS) pd_thrift_files.ts; \
	  result=$$?; rm -rf pd_thrift_files.lock; exit $$result; \
	else \
## This code is being executed by the follower processes.
## Wait until the first process is done.
	  while test -d pd_thrift_files.lock; do sleep 1; done; \
## Succeed if and only if the first process succeeded.
	    test -f pd_thrift_files.ts; \
	  fi; \
	fi

thrift_py_lzma = gen-py.tar.lz

$(thrift_py_lzma) : $(pdfixed_thrift_files) $(pd_thrift_files)
	tar --create -C pd_thrift_gen/ gen-py/ | lzma > $(thrift_py_lzma)

nobase_data_DATA = $(thrift_py_lzma)

# See
# http://stackoverflow.com/questions/6395148/install-data-directory-tree-with-massive-number-of-files-using-automake

install-data-hook:
	cp $(P4_JSON_OUTPUT) $(DESTDIR)$(datadir)
	cd $(DESTDIR)$(datadir); \
	cat $(thrift_py_lzma) | unlzma | tar --list > uninstall_manifest.txt; \
	cat $(thrift_py_lzma) | unlzma | tar --no-same-owner --extract; \
	rm -f $(thrift_py_lzma); \
	cat uninstall_manifest.txt | sed --expression='s/^\|$$/"/g' | xargs chmod a=rX,u+w

uninstall-local:
	rm $(DESTDIR)$(datadir)/$(P4_JSON_OUTPUT)
	cd $(DESTDIR)$(datadir); \
	cat uninstall_manifest.txt | sed --expression='s/ /\\ /g' | xargs rm -f; \
	rm -f uninstall_manifest.txt


BUILT_SOURCES = \
$(pd_files) \
$(pd_thrift_files) \
$(thrift_py_lzma)

nobase_pkginclude_HEADERS = \
$(pd_headers) \
p4_pd/thrift-src/pd_rpc_server.h

noinst_LTLIBRARIES = libbmpd.la libbmpdthrift.la

libbmpd_la_SOURCES = \
$(pd_files)

libbmpdthrift_la_SOURCES = \
$(pd_thrift_files) \
p4_pd/thrift-src/pd_rpc_server.cpp

AM_CPPFLAGS += -I$(BM_PDFIXED_PATH)/
AM_CPPFLAGS += -I$(BM_PDFIXED_PATH)/src/
AM_CPPFLAGS += -I$(BM_THRIFT_PATH)/
AM_CPPFLAGS += -I$(builddir)/p4_pd/
AM_CPPFLAGS += -I$(builddir)/pd_thrift_gen/gen-cpp/
AM_CPPFLAGS += -DHOST_BYTE_ORDER_CALLER

AM_CXXFLAGS = --std=c++11

CLEANFILES = $(BUILT_SOURCES) \
pd_files.ts pd_thrift_files.ts \
.bmv2-pd-sane
