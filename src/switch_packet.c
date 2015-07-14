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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include "switch_packet_int.h"
#include "switch_sup_int.h"
#include "switch_log.h"
#include <switchapi/switch_status.h>

pthread_t packet_driver_thread;

static char *sup_intf_name = "veth251";
static uint32_t sup_ifindex = 0;
static int sup_sock_fd = -1;
static void *switch_intf_fd_array;


void
switch_packet_tx_to_hw(switch_packet_header_t *packet_header, char *packet, int packet_size)
{
    static char                       out_packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
    struct sockaddr_ll                addr;
    switch_cpu_header_t              *cpu_header = NULL;
    switch_fabric_header_t           *fabric_header = NULL;
    int                               current_offset = 0;

    fabric_header = &packet_header->fabric_header;
    cpu_header = &packet_header->cpu_header;
    memset(&addr, 0, sizeof(addr));
    addr.sll_ifindex = sup_ifindex;

    fabric_header->ether_type = htons(fabric_header->ether_type);
    fabric_header->dst_port_or_group = htons(fabric_header->dst_port_or_group);
    cpu_header->sup_code = htons(cpu_header->sup_code);

    memcpy(out_packet, packet, SWITCH_PACKET_HEADER_OFFSET);
    current_offset += SWITCH_PACKET_HEADER_OFFSET;

    memcpy((out_packet + current_offset), packet_header, sizeof(switch_packet_header_t));
    current_offset += sizeof(switch_packet_header_t);

    memcpy((out_packet + current_offset), packet + SWITCH_PACKET_HEADER_OFFSET,
           (packet_size - SWITCH_PACKET_HEADER_OFFSET));
    packet_size = packet_size + sizeof(switch_packet_header_t);

    if (sendto(sup_sock_fd, out_packet, packet_size, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("packet send failed");
    }
    SWITCH_API_TRACE("Sent packet to hw port %d\n",
                     packet_header->fabric_header.dst_port_or_group);
}

static void
switch_packet_rx_from_hw()
{
    int                               packet_size = 0;
    switch_packet_header_t           *packet_header = NULL;
    static char                       in_packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
    static char                       packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
    switch_status_t                   status = SWITCH_STATUS_SUCCESS;

    // read packet from cpu port
    while((packet_size = read(sup_sock_fd, in_packet, sizeof(in_packet))) > 0) {
        packet_header = (switch_packet_header_t *)
            (in_packet + SWITCH_PACKET_HEADER_OFFSET);
        packet_size = packet_size - sizeof(switch_packet_header_t);
        memcpy(packet, in_packet, SWITCH_PACKET_HEADER_OFFSET);
        memcpy(packet + SWITCH_PACKET_HEADER_OFFSET,
               in_packet + SWITCH_PACKET_HEADER_OFFSET +
               sizeof(switch_packet_header_t),
               packet_size - SWITCH_PACKET_HEADER_OFFSET);
        packet_header->fabric_header.ingress_ifindex =
            ntohs(packet_header->fabric_header.ingress_ifindex);
        packet_header->cpu_header.sup_code =
            ntohl(packet_header->cpu_header.sup_code);
        SWITCH_API_TRACE("Received packet from hw ifindex %x\n",
                         packet_header->fabric_header.ingress_ifindex);
        status = switch_api_sup_rx_packet_from_hw(packet_header, packet, packet_size);
        if (status != SWITCH_STATUS_SUCCESS) {
            return;
        }
    }
}

void
switch_packet_tx_to_host(switch_sup_interface_info_t *sup_intf_info, char *packet, int packet_size)
{
    int intf_fd = sup_intf_info->intf_fd;
    if (write(intf_fd, packet, packet_size < 0)) {
        perror("sendto host interface failed");
        return;
    }
    SWITCH_API_TRACE("Sent packet to host interface %lu\n",
                     sup_intf_info->sup_interface.handle);
    return;
}

void
switch_packet_rx_from_host(int intf_fd)
{
    switch_sup_interface_info_t       *sup_intf_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                packet_size = 0;
    static char                        in_packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
    void                              *temp = NULL;

    while ((packet_size = read(intf_fd, in_packet, sizeof(in_packet))) > 0) {
        JLG(temp, switch_intf_fd_array, intf_fd);
        sup_intf_info = (switch_sup_interface_info_t *) (*(unsigned long *)temp);
        if (!sup_intf_info) {
            perror("invalid hostif fd");
            return;
        }
        SWITCH_API_TRACE("Received packet from host interface %lu\n",
                         sup_intf_info->sup_interface.handle);
        status = switch_api_sup_rx_packet_from_host(sup_intf_info, in_packet, packet_size);
        if (status != SWITCH_STATUS_SUCCESS) {
        }
    }
}

static void
switch_packet_sup_hw_interface_create()
{
    struct ifreq                       ifr;
    struct sockaddr_ll                 addr;
    int                                sockflags = 0;

    // initialize raw socket
    if ((sup_sock_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("failed to open raw socket");
        exit(1);
    }

    // initialize cpu port
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, sup_intf_name, IFNAMSIZ);
    if (ioctl(sup_sock_fd, SIOCGIFINDEX, (void *)&ifr) < 0) {
        perror("failed to get ifindex of cpu interface");
        exit(1);
    }

    // bind to cpu port
    sup_ifindex = ifr.ifr_ifindex;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = sup_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sup_sock_fd, (struct sockaddr *)&addr,
             sizeof(struct sockaddr_ll)) < 0) {
        perror("bind to cpu interface failed");
        exit(1);
    }

    // set cpu port to be non-blocking
    sockflags = fcntl(sup_sock_fd, F_GETFL, 0);
    if (fcntl(sup_sock_fd, F_SETFL, sockflags | O_NONBLOCK) < 0) {
        perror("f_setfl on cpu interface failed");
        exit(1);
    }
}

switch_status_t
switch_packet_sup_host_interface_create(switch_sup_interface_info_t *sup_intf_info)
{
    int                               intf_fd = 0;
    struct ifreq                      ifr;
    int                               sock_flags = 0;
    char                             *intf_name = NULL;
    void                             *temp = NULL;

    if ((intf_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return SWITCH_STATUS_FAILURE;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    intf_name = sup_intf_info->sup_interface.intf_name;
    strncpy(ifr.ifr_name, intf_name, IFNAMSIZ);
    if ((ioctl(intf_fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("tunsetiff failed");
        close(intf_fd);
        return SWITCH_STATUS_FAILURE;
    }

    // set connection to be non-blocking
    sock_flags = fcntl(intf_fd, F_GETFL, 0);
    if ((fcntl(intf_fd, F_SETFL, sock_flags | O_NONBLOCK)) < 0) {
        perror("f_setfl failed");
        close(intf_fd);
        return SWITCH_STATUS_FAILURE;
    }

    // fetch the mac address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, intf_name, IFNAMSIZ);
    if ((ioctl(intf_fd, SIOCGIFHWADDR, (void *)&ifr)) < 0) {
        perror("ioctl failed");
        close(intf_fd);
        return SWITCH_STATUS_FAILURE;
    }
    sup_intf_info->intf_fd = intf_fd;
    JLG(temp, switch_intf_fd_array, intf_fd);
    if (!temp) {
        JLI(temp, switch_intf_fd_array, intf_fd);
        *(unsigned long *)temp = (unsigned long) (sup_intf_info);
    }
    return SWITCH_STATUS_SUCCESS;
}

static int
switch_packet_select_fd_get()
{
    switch_sup_interface_info_t       *sup_intf_info = NULL;
    void                              *temp = NULL;
    int                                nfds;
    int                                index = 0;

    nfds = sup_sock_fd;
    JLF(temp, switch_intf_fd_array, *((Word_t *) &index));
    if (!temp) {
        return nfds + 1;
    }
    sup_intf_info = (switch_sup_interface_info_t *) (*(unsigned long *) temp);
    while (sup_intf_info != NULL) {
        if (sup_intf_info->intf_fd > nfds) {
            nfds = sup_intf_info->intf_fd;
        }
        JLF(temp, switch_intf_fd_array, *((Word_t *) &index));
        sup_intf_info = (switch_sup_interface_info_t *) (*(unsigned long *) temp);
    }
    return nfds + 1;
}

static void
switch_packet_rx_from_hosts(fd_set read_fds)
{
    switch_sup_interface_info_t       *sup_intf_info = NULL;
    void                              *temp = NULL;
    int                                index = 0;

    JLF(temp, switch_intf_fd_array, *((Word_t *) &index));
    sup_intf_info = (switch_sup_interface_info_t *) (*(unsigned long *) temp);
    while (sup_intf_info != NULL) {
        JLF(temp, switch_intf_fd_array, *((Word_t *) &index));
        sup_intf_info = (switch_sup_interface_info_t *) (*(unsigned long *) temp);
        if (FD_ISSET(sup_intf_info->intf_fd, &read_fds)) {
            switch_packet_rx_from_host(sup_intf_info->intf_fd);
        }
    }
}

static void * switch_packet_driver_thread(void *args)
{
    fd_set                             read_fds;
    int                                nfds = -1;
    int                                ret = 0;

    switch_packet_sup_hw_interface_create();
    assert(sup_sock_fd != -1);

    while (TRUE) {
        FD_ZERO(&read_fds);
        FD_SET(sup_sock_fd, &read_fds);
        nfds = switch_packet_select_fd_get();
        ret = select(nfds, &read_fds, NULL, NULL, NULL);
        if (ret == -1) {
            perror("select called failed");
            return NULL;
        } else if (ret) {
            if (FD_ISSET(sup_sock_fd, &read_fds)) {
                switch_packet_rx_from_hw();
            } else {
                switch_packet_rx_from_hosts(read_fds);
            }
        }
    }
}

int start_switch_api_packet_driver()
{
    pthread_create(&packet_driver_thread, NULL,
                   switch_packet_driver_thread, NULL);
    return SWITCH_STATUS_SUCCESS;
}
