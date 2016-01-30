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

#ifndef SWITCH_VER_H
#define SWITCH_VER_H

#include "switch_bld_ver.h"

#define SWITCH_REL_VER "0.1.0"
#define SWITCH_VER SWITCH_REL_VER "-" SWITCH_BLD_VER

#define SWITCH_INTERNAL_VER SWITCH_VER "(" SWITCH_GIT_VER ")"

#endif /* BF_DRV_VER_H */
