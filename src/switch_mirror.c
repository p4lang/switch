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

#include <Judy.h>
#include "switchapi/switch_mirror.h"
#include "switchapi/switch_status.h"
#include "switch_mirror_int.h"
#include "switch_nhop_int.h"
#include "switch_pd.h"

static void *switch_mirror_sessions = NULL;

static switch_mirror_session_t *
switch_mirror_session_get(switch_mirror_id_t id)
{
    void                        *temp = NULL;
    switch_mirror_session_t     *mirror_info = NULL;

    JLG(temp, switch_mirror_sessions, id);
    if(!temp) {
        return NULL;
    }
    mirror_info = (switch_mirror_session_t *)(*(unsigned long *)temp);
    return mirror_info;
}

switch_status_t
switch_mirror_session_create(switch_device_t device, switch_mirror_id_t id,
                            switch_direction_t direction, switch_port_t eg_port,
                            switch_mirror_type_t type, switch_cos_t cos,
                            unsigned int length, unsigned int timeout)
{
    switch_mirror_session_t           *mirror_info = NULL;
    void                              *temp = NULL;
    switch_status_t                   status;

    mirror_info = switch_mirror_session_get(id);
    if(mirror_info) {
        return SWITCH_STATUS_ITEM_ALREADY_EXISTS;
    }
    // create new mirror session
    mirror_info = switch_malloc(sizeof(switch_mirror_session_t), 1);
    if(!mirror_info) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    JLI(temp, switch_mirror_sessions, id);
    if(!temp) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    *(unsigned long *)temp = (unsigned long)mirror_info;
    status = switch_mirror_session_update(device, id, direction, eg_port,
                                          type, cos,
                                          length, timeout, 1/*enable*/);
    if (status != SWITCH_STATUS_SUCCESS) {
        // delete the session
        JLD(status, switch_mirror_sessions, id);
        switch_free(mirror_info);
    }
    return status;
}

switch_status_t
switch_mirror_session_update(switch_device_t device, switch_mirror_id_t id,
                            switch_direction_t direction, switch_port_t eg_port,
                            switch_mirror_type_t type, switch_cos_t cos,
                            unsigned int length, unsigned int timeout,
                            int enable)
{
    switch_status_t                   status=SWITCH_STATUS_SUCCESS;
    switch_mirror_session_t           *mirror_info = NULL;
    switch_mirror_session_t           tmp_info;

    mirror_info = switch_mirror_session_get(id);
    if (!mirror_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    memset(&tmp_info, 0, sizeof(tmp_info));
    tmp_info.id = id;
    tmp_info.eg_port = eg_port;
    tmp_info.type = type;
    tmp_info.dir = direction;
    tmp_info.cos = cos;
    tmp_info.max_pkt_len = length;
    tmp_info.pd_mirror_nhop_hdl = 0;

    switch (type) {
        case SWITCH_MIRROR_TYPE_SIMPLE:
            status = switch_pd_mirror_session_update(device, &tmp_info, enable);
            break;
        case SWITCH_MIRROR_TYPE_TRUNCATE:
        case SWITCH_MIRROR_TYPE_COALESCE:
            break;
        default:
            break;
    }
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    *mirror_info = tmp_info;
    return status;
}

switch_status_t
switch_mirror_session_delete(switch_device_t device, switch_mirror_id_t id)
{
    unsigned int                       status=0;
    switch_mirror_session_t            *mirror_info = NULL;

    mirror_info = switch_mirror_session_get(id);
    if (!mirror_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    switch (mirror_info->type) {
        case SWITCH_MIRROR_TYPE_SIMPLE:
            switch_pd_mirror_session_delete(device, id);
            break;
        case SWITCH_MIRROR_TYPE_TRUNCATE:
        case SWITCH_MIRROR_TYPE_COALESCE:
            break;
        default:
            break;
    }
    JLD(status, switch_mirror_sessions, id);
    switch_free(mirror_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_mirror_nhop_create(switch_device_t device, switch_mirror_id_t id, switch_handle_t nhop_hdl)
{
    switch_mirror_session_t     *mirror_info = NULL;
    int32_t                     nhop_idx;

    mirror_info = switch_mirror_session_get(id);
    if (!mirror_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    if (switch_nhop_get(nhop_hdl) == NULL) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    if (mirror_info->pd_mirror_nhop_hdl) {
        return SWITCH_STATUS_ITEM_ALREADY_EXISTS;
    }
    nhop_idx = handle_to_id(nhop_hdl);
    return switch_pd_mirror_nhop_create(device, mirror_info, nhop_idx);
}

switch_status_t
switch_mirror_nhop_delete(switch_device_t device, switch_mirror_id_t id)
{
    switch_mirror_session_t     *mirror_info = NULL;

    mirror_info = switch_mirror_session_get(id);
    if (!mirror_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    if (!mirror_info->pd_mirror_nhop_hdl) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    return switch_pd_mirror_nhop_delete(device, mirror_info);
}

