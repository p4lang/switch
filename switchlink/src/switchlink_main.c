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
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include "switchlink.h"
#include "switchlink_int.h"

static struct nl_sock *g_nlsk = NULL;
static pthread_t switchlink_thread;
uint8_t g_log_level = SWITCHLINK_LOG_ERR;

static void
nl_sync_state() {
    int msg_array[] = {
        RTM_GETLINK,
        RTM_GETADDR,
        RTM_GETNEIGH,
        RTM_GETNEIGHTBL,
        RTM_GETROUTE
    };

    static uint16_t msg_idx = 0;
    if (msg_idx < sizeof(msg_array)/sizeof(int)) {
        struct rtgenmsg rt_hdr = {
            .rtgen_family = AF_UNSPEC,
        };

        // fixups a.k.a hacks
        // using GETNEIGH to denote bridge macs and GETNEIGHTBL to denote
        // regular neighbor entries (arp, nd)
        int msg_type = msg_array[msg_idx];
        if (msg_type == RTM_GETNEIGH) {
            rt_hdr.rtgen_family = AF_BRIDGE;
        }
        if (msg_type == RTM_GETNEIGHTBL) {
            msg_type = RTM_GETNEIGH;
        }

        nl_send_simple(g_nlsk, msg_type, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
        msg_idx++;
    }
}

static void
process_nl_message(struct nlmsghdr *nlmsg) {
    switch(nlmsg->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            process_link_msg(nlmsg, nlmsg->nlmsg_type);
            break;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            process_address_msg(nlmsg, nlmsg->nlmsg_type);
            break;
        case RTM_NEWROUTE:
        case RTM_DELROUTE:
            process_route_msg(nlmsg, nlmsg->nlmsg_type);
            break;
        case RTM_NEWNEIGH:
        case RTM_DELNEIGH:
            process_neigh_msg(nlmsg, nlmsg->nlmsg_type);
            break;
        case NLMSG_DONE:
            nl_sync_state();
            break;
        default:
            printf("Unknown netlink message(%d). Ignoring\n",
                   nlmsg->nlmsg_type);
            break;
    }
}

static int
nl_sock_recv_msg(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nl_msg = nlmsg_hdr(msg);
    int nl_msg_sz = nlmsg_get_max_size(msg);
    while (nlmsg_ok(nl_msg, nl_msg_sz)) {
        process_nl_message(nl_msg);
        nl_msg = nlmsg_next(nl_msg, &nl_msg_sz);
    }

    return 0;
}

static void
cleanup_nl_sock() {
    // free the socket
    nl_socket_free(g_nlsk);
    g_nlsk = NULL;
}

static void
init_nl_sock_intf() {
    int nlsk_fd, sock_flags;

    // allocate a new socket
    g_nlsk = nl_socket_alloc();
    if (g_nlsk == NULL) {
        perror("nl_socket_alloc");
        return;
    }

    nl_socket_set_local_port(g_nlsk, 0);

    // disable sequence number checking
    nl_socket_disable_seq_check(g_nlsk);

    // set the callback function
    nl_socket_modify_cb(g_nlsk, NL_CB_VALID, NL_CB_CUSTOM, nl_sock_recv_msg,
                        NULL);
    nl_socket_modify_cb(g_nlsk, NL_CB_FINISH, NL_CB_CUSTOM, nl_sock_recv_msg,
                        NULL);

    // connect to the netlink route socket
    if (nl_connect(g_nlsk, NETLINK_ROUTE) < 0) {
        perror("nl_connect:NETLINK_ROUTE");
        cleanup_nl_sock();
        return;
    }

    // register for the following messages
    nl_socket_add_memberships(g_nlsk, RTNLGRP_LINK, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_NOTIFY, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_NEIGH, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_IFADDR, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_MROUTE, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_ROUTE, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_RULE, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_IFADDR, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_MROUTE, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_ROUTE, 0);
    nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_RULE, 0);

    // set socket to be non-blocking
    nlsk_fd = nl_socket_get_fd(g_nlsk);
    if (nlsk_fd < 0) {
        perror("nl_socket_get_fd");
        cleanup_nl_sock();
        return;
    }
    sock_flags = fcntl(nlsk_fd, F_GETFL, 0);
    if (fcntl(nlsk_fd, F_SETFL, sock_flags | O_NONBLOCK) < 0) {
        perror("fcntl");
        cleanup_nl_sock();
        return;
    }

    // start building state from the kernel
    nl_sync_state();
}

static void
process_nl_event_loop() {
    int nlsk_fd;
    nlsk_fd = nl_socket_get_fd(g_nlsk);
    assert(nlsk_fd > 0);

    while(1) {
        int ret, num_fds;
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(nlsk_fd, &read_fds);
        num_fds = nlsk_fd + 1;

        ret = select(num_fds, &read_fds, NULL, NULL, NULL);
        if (ret == -1) {
            perror("pselect");
            return;
        } else if (ret == 0) {
        } else {
            if (FD_ISSET(nlsk_fd, &read_fds)) {
                nl_recvmsgs_default(g_nlsk);
            }
        }
    }
}

static void *
switchlink_main(void *args) {
    init_nl_sock_intf();

    if (!g_nlsk) {
        return NULL;
    }

    switchlink_db_init();
    switchlink_api_init();
    switchlink_link_init();
    switchlink_packet_driver_init();

    process_nl_event_loop();
    cleanup_nl_sock();

    return NULL;
}

int
switchlink_init() {
    return pthread_create(&switchlink_thread, NULL, switchlink_main, NULL);
}
