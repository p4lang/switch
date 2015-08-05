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

#ifndef _SWITCH_MIRROR_INT_H_
#define _SWITCH_MIRROR_INT_H_

typedef struct switch_mirror_session_ {
    // local span and common params
    switch_mirror_id_t      id;
    switch_mirror_type_t    type;
    switch_port_t           eg_port;
    switch_direction_t      dir;
    switch_cos_t            cos;
    uint32_t                max_pkt_len; // 0 = do not truncate
    // rspan params
    // erspan params
    // pd handle for mirror nhop table entry
    p4_pd_entry_hdl_t       pd_mirror_nhop_hdl;
    // coal params - can these be here? also typedefs ?
    uint32_t                header[4];
    uint32_t                header_len;
    uint32_t                timeout;
    uint32_t                min_pkt_len;
    uint32_t                extract_len;
    uint32_t                ver;
    bool                    extract_len_by_p4;
} switch_mirror_session_t;

#endif /* _SWITCH_MIRROR_INT_H_ */
