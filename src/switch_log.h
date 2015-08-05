/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "p4features.h"
#include <switchapi/switch_base_types.h>

#define SWITCH_API_ERROR printf
#define SWITCH_API_WARN printf
#define SWITCH_API_INFO printf
#define SWITCH_API_VERBOSE printf
#define SWITCH_API_TRACE printf

char * switch_print_error(switch_status_t status);
