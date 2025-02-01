###############################################################################
# Copyright (c) 2015-2016 Barefoot Networks, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# $Id: $
#
###############################################################################

thisdir := $(shell pwd)

base-docker-image:
	@sudo docker build -f Dockerfile -t p4dockerswitch .
