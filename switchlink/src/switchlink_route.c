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

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_route.h"
#include "switchlink_db.h"
#include "switchlink_sai.h"

static void
ecmp_delete(switchlink_handle_t ecmp_h) {
    int32_t ref_count;
    switchlink_db_status_t status;
    status  = switchlink_db_ecmp_ref_dec(ecmp_h, &ref_count);
    assert(status == SWITCHLINK_DB_STATUS_SUCCESS);

    if (ref_count == 0) {
        switchlink_db_ecmp_info_t ecmp_info;
        memset(&ecmp_info, 0, sizeof(switchlink_db_ecmp_info_t));
        status = switchlink_db_ecmp_handle_get_info(ecmp_h, &ecmp_info);
        assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
        switchlink_ecmp_delete(&ecmp_info);
        switchlink_db_ecmp_delete(ecmp_h);
    }
}

void
route_create(switchlink_handle_t vrf_h, switchlink_ip_addr_t *dst,
             switchlink_ip_addr_t *gateway, switchlink_handle_t ecmp_h,
             switchlink_handle_t intf_h) {
    if (!dst || (!gateway && !ecmp_h)) {
        if (ecmp_h) {
            ecmp_delete(ecmp_h);
        }
        return;
    }

    bool ecmp_valid = false;
    switchlink_handle_t nhop_h = 0;
    if (!ecmp_h) {
        switchlink_db_neigh_info_t neigh_info;
        memset(&neigh_info, 0, sizeof(switchlink_db_neigh_info_t));
        memcpy(&(neigh_info.ip_addr), gateway, sizeof(switchlink_ip_addr_t));
        neigh_info.intf_h = intf_h;
        neigh_info.vrf_h = vrf_h;
        switchlink_db_status_t status;
        status = switchlink_db_neighbor_get_info(&neigh_info);
        if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
            nhop_h = neigh_info.nhop_h;
        } else {
            nhop_h = g_cpu_rx_nhop_h;
        }
        ecmp_valid = false;
    } else {
        ecmp_valid = true;
        nhop_h = ecmp_h;
    }

    // get the route from the db (if it already exists)
    switchlink_db_route_info_t route_info;
    memset(&route_info, 0, sizeof(switchlink_db_route_info_t));
    route_info.vrf_h = vrf_h;
    memcpy(&(route_info.ip_addr), dst, sizeof(switchlink_ip_addr_t));
    switchlink_db_status_t status = switchlink_db_route_get_info(&route_info);
    if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
        if ((route_info.ecmp == ecmp_valid) && (route_info.nhop_h == nhop_h)) {
            // no change
            return;
        }
        // nexthop has change, delete the current route
        route_delete(vrf_h, dst);
    }

    memset(&route_info, 0, sizeof(switchlink_db_route_info_t));
    route_info.vrf_h = vrf_h;
    memcpy(&(route_info.ip_addr), dst, sizeof(switchlink_ip_addr_t));
    route_info.ecmp = ecmp_valid;
    route_info.nhop_h = nhop_h;

    // add the route
    if (switchlink_route_create(&route_info) == -1) {
        if (route_info.ecmp) {
            ecmp_delete(route_info.nhop_h);
        }
        return;
    }

    // add the route to the db
    if (switchlink_db_route_add(&route_info) == SWITCHLINK_DB_STATUS_SUCCESS) {
        if (route_info.ecmp) {
            switchlink_db_ecmp_ref_inc(route_info.nhop_h);
        }
    }
}

void
route_delete(switchlink_handle_t vrf_h, switchlink_ip_addr_t *dst) {
    if (!dst) {
        return;
    }

    switchlink_db_status_t status;
    switchlink_db_route_info_t route_info;
    memset(&route_info, 0, sizeof(switchlink_db_route_info_t));
    route_info.vrf_h = vrf_h;
    memcpy(&(route_info.ip_addr), dst, sizeof(switchlink_ip_addr_t));
    status = switchlink_db_route_get_info(&route_info);
    if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
        return;
    }

    if (switchlink_route_delete(&route_info) == -1) {
        return;
    }

    status = switchlink_db_route_delete(&route_info);
    if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
        if (route_info.ecmp) {
            ecmp_delete(route_info.nhop_h);
        }
    }
}

static switchlink_handle_t
process_ecmp_attribute(uint8_t family, struct nlattr *attr,
                       switchlink_handle_t vrf_h) {

    if ((family != AF_INET) && (family != AF_INET6)) {
        return 0;
    }

    switchlink_db_ecmp_info_t ecmp_info;
    memset(&ecmp_info, 0, sizeof(switchlink_db_ecmp_info_t));
    switchlink_db_status_t status;

    struct rtnexthop *rnh = (struct rtnexthop *)nla_data(attr);
    int attrlen = nla_len(attr);
    while (RTNH_OK(rnh, attrlen)) {
        struct rtattr *rta = RTNH_DATA(rnh);
        if (rta->rta_type == RTA_GATEWAY) {
            switchlink_ip_addr_t gateway;
            memset(&gateway, 0, sizeof(switchlink_ip_addr_t));
            gateway.family = family;
            if (family == AF_INET) {
                gateway.ip.v4addr.s_addr = ntohl(*((uint32_t *)RTA_DATA(rta)));
                gateway.prefix_len = 32;
            } else {
                gateway.prefix_len = 128;
            }

            switchlink_db_interface_info_t ifinfo;
            memset(&ifinfo, 0, sizeof(switchlink_db_interface_info_t));
            status = switchlink_db_interface_get_info(rnh->rtnh_ifindex,
                                                      &ifinfo);
            if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
                switchlink_db_neigh_info_t neigh_info;
                memset(&neigh_info, 0, sizeof(switchlink_db_neigh_info_t));
                memcpy(&(neigh_info.ip_addr), &gateway,
                       sizeof(switchlink_ip_addr_t));
                neigh_info.intf_h = ifinfo.intf_h;
                neigh_info.vrf_h = vrf_h;
                status = switchlink_db_neighbor_get_info(&neigh_info);
                if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
                    ecmp_info.nhops[ecmp_info.num_nhops] = neigh_info.nhop_h;
                } else {
                    ecmp_info.nhops[ecmp_info.num_nhops] = g_cpu_rx_nhop_h;
                }
                ecmp_info.num_nhops++;
                assert(ecmp_info.num_nhops < SWITCHLINK_ECMP_NUM_MEMBERS_MAX);
            }
        }
        rnh = RTNH_NEXT(rnh);
    }

    if (!ecmp_info.num_nhops) {
        return 0;
    }

    status = switchlink_db_ecmp_get_info(&ecmp_info);
    if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
        switchlink_ecmp_create(&ecmp_info);
        switchlink_db_ecmp_add(&ecmp_info);
    }

    return ecmp_info.ecmp_h;
}

static void
process_mroute_msg(struct nlmsghdr *nlmsg, int type) {
}

void
process_route_msg(struct nlmsghdr *nlmsg, int type) {
    int hdrlen, attrlen;
    struct nlattr *attr;
    struct rtmsg *rmsg;
    bool dst_valid = false;
    bool gateway_valid = false;
    switchlink_handle_t ecmp_h = 0;
    switchlink_ip_addr_t dst_addr;
    switchlink_ip_addr_t gateway_addr;
    switchlink_db_interface_info_t ifinfo;
    bool oif_valid = false;
    uint32_t oif = 0;

    assert((type == RTM_NEWROUTE) || (type == RTM_DELROUTE));
    rmsg = nlmsg_data(nlmsg);
    hdrlen = sizeof(struct rtmsg);
    NL_LOG_DEBUG(("%sroute: family = %d, dst_len = %d, src_len = %d, tos = %d, "
                  "table = %d, proto = %d, scope = %d, type = %d, "
                  "flags = 0x%x\n",
                  ((type == RTM_NEWROUTE) ? "new" : "del"),
                  rmsg->rtm_family, rmsg->rtm_dst_len, rmsg->rtm_src_len,
                  rmsg->rtm_tos, rmsg->rtm_table, rmsg->rtm_protocol,
                  rmsg->rtm_scope, rmsg->rtm_type, rmsg->rtm_flags));

    if ((rmsg->rtm_family != AF_INET) && (rmsg->rtm_family != AF_INET6)) {
        return;
    }

    if ((rmsg->rtm_family == RTNL_FAMILY_IPMR) ||
        (rmsg->rtm_family == RTNL_FAMILY_IP6MR)) {
        process_mroute_msg(nlmsg, type);
        return;
    }

    memset(&dst_addr, 0, sizeof(switchlink_ip_addr_t));
    memset(&gateway_addr, 0, sizeof(switchlink_ip_addr_t));

    attrlen = nlmsg_attrlen(nlmsg, hdrlen);
    attr = nlmsg_attrdata(nlmsg, hdrlen);
    while (nla_ok(attr, attrlen)) {
        int attr_type = nla_type(attr);
        switch (attr_type) {
            case RTA_DST:
                dst_valid = true;
                memset(&dst_addr, 0, sizeof(switchlink_ip_addr_t));
                dst_addr.family = rmsg->rtm_family;
                dst_addr.prefix_len = rmsg->rtm_dst_len;
                if (rmsg->rtm_family == AF_INET) {
                    dst_addr.ip.v4addr.s_addr = ntohl(nla_get_u32(attr));
                } else {
                    memcpy(&(dst_addr.ip.v6addr), nla_data(attr),
                           nla_len(attr));
                }
                break;
            case RTA_GATEWAY:
                gateway_valid = true;
                memset(&gateway_addr, 0, sizeof(switchlink_ip_addr_t));
                gateway_addr.family = rmsg->rtm_family;
                if (rmsg->rtm_family == AF_INET) {
                    gateway_addr.ip.v4addr.s_addr = ntohl(nla_get_u32(attr));
                    gateway_addr.prefix_len = 32;
                } else {
                    memcpy(&(gateway_addr.ip.v6addr), nla_data(attr),
                           nla_len(attr));
                    gateway_addr.prefix_len = 128;
                }
                break;
            case RTA_MULTIPATH:
                ecmp_h = process_ecmp_attribute(rmsg->rtm_family, attr,
                                                g_default_vrf_h);
                break;
            case RTA_OIF:
                oif_valid = true;
                oif = nla_get_u32(attr);
                break;
            default:
                NL_LOG_DEBUG(("route: skipping attr(%d)\n", attr_type));
                break;
        }
        attr = nla_next(attr, &attrlen);
    }

    if (rmsg->rtm_dst_len == 0) {
        // default route
        dst_valid = true;
        memset(&dst_addr, 0, sizeof(switchlink_ip_addr_t));
        dst_addr.family = rmsg->rtm_family;
        dst_addr.prefix_len = 0;
    }

    if (oif_valid) {
        switchlink_db_status_t status;
        status = switchlink_db_interface_get_info(oif, &ifinfo);
        if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
            NL_LOG_DEBUG(("route: switchlink_db_interface_get_info failed\n"));
            return;
        }
    }

    if (type == RTM_NEWROUTE) {
        route_create(g_default_vrf_h, (dst_valid ? &dst_addr : NULL),
                     (gateway_valid ? &gateway_addr : NULL),
                     ecmp_h, ifinfo.intf_h);
    } else {
        route_delete(g_default_vrf_h, (dst_valid ? &dst_addr : NULL));
    }
}
