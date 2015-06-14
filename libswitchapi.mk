# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
#
# This file compiles switchapi.a and switchapi_thrift.a
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ifndef P4FACTORY
  $(error P4FACTORY not defined)
endif
MAKEFILES_DIR := $(P4FACTORY)/makefiles

ifndef SUBMODULE_SWITCHAPI
  SUBMODULE_SWITCHAPI := ${THIS_DIR}/../..
endif

# This variable is set to ${BUILD_DIR}/lib/switchapi.a when called from p4factory.
ifndef SWITCHAPI_LIB
  $(error Compiled archive filename not defined in SWITCHAPI_LIB)
endif

# This variable is set to ${BUILD_DIR}/lib/switchapi_thrift.a when called from p4factory.
ifndef SWITCHAPI_THRIFT_LIB
  $(error Compiled thrift archive filename not defined in SWITCHAPI_THRIFT_LIB)
endif

ifndef BUILD_DIR
  $(error Build directory not defined in BUILD_DIR)
endif

SWITCHAPI_SRC_DIR := $(SUBMODULE_SWITCHAPI)/src
SWITCHAPI_INC_DIR := $(SUBMODULE_SWITCHAPI)/inc
SWITCHAPI_SOURCES_C := $(wildcard $(SWITCHAPI_SRC_DIR)/*.c)
SWITCHAPI_SOURCES_CPP := $(wildcard $(SWITCHAPI_SRC_DIR)/*.cpp)

SWITCHAPI_BUILD_DIR := $(BUILD_DIR)/switchapi
SWITCHAPI_BUILD_SRC_DIR := $(SWITCHAPI_BUILD_DIR)/src
SWITCHAPI_OBJ_DIR := $(SWITCHAPI_BUILD_DIR)/obj
MAKE_DIR := $(SWITCHAPI_BUILD_DIR)
include $(MAKEFILES_DIR)/makedir.mk

MAKE_DIR := $(SWITCHAPI_BUILD_SRC_DIR)
include $(MAKEFILES_DIR)/makedir.mk

MAKE_DIR := $(SWITCHAPI_OBJ_DIR)
include $(MAKEFILES_DIR)/makedir.mk

MAKE_DIR := $(dir ${SWITCHAPI_THRIFT_LIB})
include ${MAKEFILES_DIR}/makedir.mk

# Rules for generating thrift files.
SWITCHAPI_THRIFT_OUTPUT_BASENAMES := switch_api_constants switch_api_rpc switch_api_types
SWITCHAPI_THRIFT_OUTPUT_BASENAMES_CPP := $(addsuffix .cpp, $(SWITCHAPI_THRIFT_OUTPUT_BASENAMES))
SWITCHAPI_THRIFT_OUTPUT_BASENAMES_H := $(addsuffix .h, $(SWITCHAPI_THRIFT_OUTPUT_BASENAMES))
SWITCHAPI_THRIFT_OUTPUT_CPP := $(addprefix ${SWITCHAPI_BUILD_SRC_DIR}/, $(SWITCHAPI_THRIFT_OUTPUT_BASENAMES_CPP))
SWITCHAPI_THRIFT_OUTPUT_H := $(addprefix ${SWITCHAPI_BUILD_SRC_DIR}/, $(SWITCHAPI_THRIFT_OUTPUT_BASENAMES_H))
${SWITCHAPI_THRIFT_OUTPUT_CPP} ${SWITCHAPI_THRIFT_OUTPUT_H} : ${SWITCHAPI_SRC_DIR}/switch_api.thrift
	thrift --gen cpp --out ${SWITCHAPI_BUILD_SRC_DIR} $<

ifdef COVERAGE
COVERAGE_FLAGS := --coverage
endif

SWITCHAPI_THRIFT_OBJS := $(addprefix $(SWITCHAPI_OBJ_DIR)/, $(addsuffix .o, $(SWITCHAPI_THRIFT_OUTPUT_BASENAMES)))
$(SWITCHAPI_THRIFT_OBJS) : $(SWITCHAPI_OBJ_DIR)/%.o : $(SWITCHAPI_BUILD_SRC_DIR)/%.cpp
	$(VERBOSE)g++ -o $@ $(COVERAGE_FLAGS) $(DEBUG_FLAGS) $(GLOBAL_INCLUDES) -I . -std=c++11 -MD -c $<

THRIFT_INPUT_FILES := ${SWITCHAPI_SRC_DIR}/switch_api.thrift
THRIFT_DEP_FILES := ${SWITCHAPI_SRC_DIR}/switch_api.thrift
THRIFT_SERVICE_NAMES := switch_api_rpc
include ${MAKEFILES_DIR}/thrift-py.mk

$(SWITCHAPI_THRIFT_LIB) : ${SWITCHAPI_THRIFT_OBJS}
	$(VERBOSE)ar -rc $@ $(SWITCHAPI_THRIFT_OBJS)

MODULE := switchapi
MODULE_LIB := $(SWITCHAPI_LIB)
MODULE_INFO := switchapi
switchapi_DIR := $(SUBMODULE_SWITCHAPI)
$(MODULE)_PREREQ := $(SWITCHAPI_THRIFT_LIB)
include $(MAKEFILES_DIR)/module.mk
$(MODULE_LIB) : MODULE_INCLUDES += -I $(SWITCHAPI_BUILD_SRC_DIR)
