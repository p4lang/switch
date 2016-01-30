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
#include "switch_log.h"

char * switch_print_error(switch_status_t status)
{
    switch (status) {
        case SWITCH_STATUS_INVALID_HANDLE:
            return "err: invalid handle";
            break;
        case SWITCH_STATUS_ITEM_NOT_FOUND:
            return "err: entry not found";
            break;
        case SWITCH_STATUS_FAILURE:
            return "err: general failure";
            break;
        default:
            return "err: unknown failure";
            break;
    }
}
