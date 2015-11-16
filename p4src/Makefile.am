ACLOCAL_AMFLAGS = $(ACLOCAL_FLAGS) -I m4

P4_NAME := switch
P4_MAIN = $(srcdir)/switch.p4
P4_DEPS = $(srcdir)/acl.p4 $(srcdir)/egress_filter.p4 $(srcdir)/ipv6.p4 
P4_DEPS += $(srcdir)/l3.p4 $(srcdir)/multicast.p4 $(srcdir)/nexthop.p4
P4_DEPS += $(srcdir)/port.p4 $(srcdir)/security.p4 $(srcdir)/tunnel.p4
P4_DEPS += $(srcdir)/fabric.p4 $(srcdir)/ipv4.p4 $(srcdir)/l2.p4
P4_DEPS += $(srcdir)/mirror.p4 $(srcdir)/nat.p4 $(srcdir)/rewrite.p4
P4_DEPS += $(srcdir)/includes/defines.p4 $(srcdir)/includes/headers.p4
P4_DEPS += $(srcdir)/includes/p4features.h $(srcdir)/includes/parser.p4
P4_DEPS += $(srcdir)/includes/p4_table_sizes.h $(srcdir)/includes/tofino.p4
P4_PREFIX := dc
include $(srcdir)/p4program.am
libpd_include_HEADERS += $(srcdir)/includes/p4features.h
#AM_P4FLAGS += --placement-order=ingress_before_egress

clean-local:
	$(MAKE) $(AM_MAKEFLAGS) clean AM_MAKEFLAGS="$(AM_MAKEFLAGS)"
