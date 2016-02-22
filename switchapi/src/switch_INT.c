/*
Copyright 2015-present Barefoot Networks, Inc.

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
#include "switchapi/switch_base_types.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_INT.h"
#include "switch_pd.h"

#ifdef P4_INT_TRANSIT_ENABLE
static void *switch_int_proto_entry_handles = NULL;

static bool
switch_int_entry_hdl_get(switch_device_t device, p4_pd_entry_hdl_t *hdl)
{
    void *temp = NULL;
    // check if already created
    JLG(temp, switch_int_proto_entry_handles, device);
    if(temp) {
        *hdl = (p4_pd_entry_hdl_t)*(p4_pd_entry_hdl_t *)temp;
        return true;
    }
    return false;
}
#endif

switch_status_t
switch_int_transit_enable(switch_device_t device, int32_t switch_id, int32_t enable)
{
    switch_status_t  status = SWITCH_STATUS_SUCCESS;
#ifdef P4_INT_TRANSIT_ENABLE
    p4_pd_entry_hdl_t entry_hdl;
    if (enable) {
        void *temp = NULL;
        // check if already created
        if (switch_int_entry_hdl_get(device, &entry_hdl)) {
            return SWITCH_STATUS_ITEM_ALREADY_EXISTS;
        }
        // use the lowest priority entry for transit
        status = switch_pd_int_transit_enable(device, switch_id, 1, &entry_hdl);
        if (status == SWITCH_STATUS_SUCCESS) {
            JLI(temp, switch_int_proto_entry_handles, device);
            if(!temp) {
                return SWITCH_STATUS_NO_MEMORY;
            }
            *(p4_pd_entry_hdl_t *)temp = entry_hdl;
        }
    } else {
        // disable
        int rc;
        if (!switch_int_entry_hdl_get(device, &entry_hdl)) {
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }
        status = switch_pd_int_transit_disable(device, entry_hdl);
        if (status == SWITCH_STATUS_SUCCESS) {
            JLD(rc, switch_int_proto_entry_handles, device);
        }
    }
#else
    (void)device, (void)switch_id, (void)enable;
#endif
    return status;
}

switch_status_t
switch_int_src_enable(switch_device_t device, int32_t switch_id,
            switch_ip_addr_t *src,
            switch_ip_addr_t *dst,
            uint8_t max_hop, uint16_t ins_mask
            )
{
    switch_status_t  status = SWITCH_STATUS_SUCCESS;
#ifdef P4_INT_EP_ENABLE
    p4_pd_entry_hdl_t entry_hdl;
    status = switch_pd_int_src_enable(device, switch_id,
                                        src, dst,
                                        max_hop, ins_mask,
                                        0, &entry_hdl, false/*vtep_src*/);
    // INT and VTEP src together is not supported yet
#else
    (void)device, (void)switch_id,
    (void) src, (void) dst,
    (void) max_hop, (void) ins_mask;
#endif
    return status;
}

switch_status_t
switch_int_src_disable(switch_device_t device,
            switch_ip_addr_t *src,
            switch_ip_addr_t *dst)
{
    switch_status_t  status = SWITCH_STATUS_SUCCESS;
#ifdef P4_INT_EP_ENABLE
    // TBD
#else
    (void)device, (void)dst, (void)src, (void)dst;
#endif
    return status;
}

switch_status_t
switch_int_sink_enable(switch_device_t device,
            switch_ip_addr_t *dst,
            int32_t mirror_id
            )
{
    switch_status_t  status = SWITCH_STATUS_SUCCESS;
#ifdef P4_INT_EP_ENABLE
    p4_pd_entry_hdl_t entry_hdl;
    status = switch_pd_int_sink_enable(device, dst,
            mirror_id,
            0, &entry_hdl, true/*use_client_ip*/);
    // INT sink based on tunnel IP is not supported yet.
#else
    (void)device, (void)dst, (void)mirror_id;
#endif
    return status;
}

switch_status_t
switch_int_sink_disable(switch_device_t device, switch_ip_addr_t *dst)
{
    switch_status_t  status = SWITCH_STATUS_SUCCESS;
#ifdef P4_INT_EP_ENABLE
    // TBD
#else
    (void)device, (void)dst;
#endif
    return status;
}
