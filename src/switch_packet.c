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
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include "switch_packet_int.h"
#include "switch_hostif_int.h"
#include "switch_log.h"
#include <switchapi/switch_status.h>
#include <switchapi/switch_capability.h>

pthread_t packet_driver_thread;

static char *cpu_intf_name = "veth251";
static uint32_t cpu_ifindex = 0;
static int cpu_sock_fd = -1;
static void *switch_intf_fd_array;
static int pipe_fd[2];

static void
switch_packet_create_pipe() {
    int                                ret = 0;
    int                                sockflags = 0;

    // create a pipe to wake up the main thread from select
    ret = pipe(pipe_fd);
    assert(ret == 0);

    // set fd to be non-blocking
    sockflags = fcntl(pipe_fd[0], F_GETFL, 0);
    if (fcntl(pipe_fd[0], F_SETFL, sockflags | O_NONBLOCK) < 0) {
        perror("f_setfl on cpu interface failed");
        exit(1);
    }
}

static void
switch_packet_read_from_pipe() {
    int                                ret = 0;
    char                               buf[1];

    ret = read(pipe_fd[0], buf, 1);
    assert(ret == 1);
    assert(buf[0] = 'A');
}

static void
switch_packet_write_to_pipe() {
    int                                ret = 0;
    char                               buf[1];

    buf[0] = 'A';
    ret = write(pipe_fd[1], buf, 1);
    assert(ret == 1);
}

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
    addr.sll_ifindex = cpu_ifindex;

    fabric_header->ether_type = htons(fabric_header->ether_type);
    fabric_header->dst_port_or_group = htons(fabric_header->dst_port_or_group);
    cpu_header->reason_code = htons(cpu_header->reason_code);

    memcpy(out_packet, packet, SWITCH_PACKET_HEADER_OFFSET);
    current_offset += SWITCH_PACKET_HEADER_OFFSET;

    memcpy((out_packet + current_offset), packet_header, sizeof(switch_packet_header_t));
    current_offset += sizeof(switch_packet_header_t);

    memcpy((out_packet + current_offset), packet + SWITCH_PACKET_HEADER_OFFSET,
           (packet_size - SWITCH_PACKET_HEADER_OFFSET));
    packet_size = packet_size + sizeof(switch_packet_header_t);

    if (sendto(cpu_sock_fd, out_packet, packet_size, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("packet send failed");
    }
//    SWITCH_API_TRACE("Sent packet to hw port %d\n",
//                     packet_header->fabric_header.dst_port_or_group);
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
    while((packet_size = read(cpu_sock_fd, in_packet, sizeof(in_packet))) > 0) {
        uint16_t ethType = *(uint16_t *)(in_packet + 12);
        if(ntohs(ethType) != 0x9000)
            continue;
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
        packet_header->cpu_header.reason_code =
            ntohs(packet_header->cpu_header.reason_code);
        if(packet_header->cpu_header.reason_code == SWITCH_HOSTIF_REASON_CODE_NULL_DROP)
            continue;
        packet_header->cpu_header.ingress_port =
            ntohs(packet_header->cpu_header.ingress_port);
//         SWITCH_API_TRACE("Received packet from hw ifindex %x\n",
//                          packet_header->fabric_header.ingress_ifindex);
        status = switch_api_hostif_rx_packet_from_hw(packet_header, packet, packet_size);
        if (status != SWITCH_STATUS_SUCCESS) {
            return;
        }
    }
}

void
switch_packet_tx_to_host(switch_hostif_info_t *hostif_info, char *packet, int packet_size)
{
    int intf_fd = hostif_info->intf_fd;
    if (write(intf_fd, packet, packet_size) < 0) {
        perror("sendto host interface failed");
        return;
    }
//     SWITCH_API_TRACE("Sent packet to host interface %lu\n",
//                      hostif_info->hostif.handle);
    return;
}

void
switch_packet_rx_from_host(int intf_fd)
{
    switch_hostif_info_t              *hostif_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                packet_size = 0;
    static char                        in_packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
    void                              *temp = NULL;

    while ((packet_size = read(intf_fd, in_packet, sizeof(in_packet))) > 0) {
        JLG(temp, switch_intf_fd_array, intf_fd);
        hostif_info =
            (switch_hostif_info_t *) (*(unsigned long *)temp);
        if (!hostif_info) {
            perror("invalid hostif fd");
            return;
        }
//         SWITCH_API_TRACE("Received packet from host interface %lu\n",
//                          hostif_info->hostif.handle);
        status = switch_api_hostif_rx_packet_from_host(hostif_info, in_packet,
                                                    packet_size);
        if (status != SWITCH_STATUS_SUCCESS) {
        }
    }
}

static void
switch_packet_cpu_interface_create()
{
    struct ifreq                       ifr;
    struct sockaddr_ll                 addr;
    int                                sockflags = 0;

    // initialize raw socket
    if ((cpu_sock_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("failed to open raw socket");
        exit(1);
    }

    // initialize cpu port
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, cpu_intf_name, IFNAMSIZ);
    if (ioctl(cpu_sock_fd, SIOCGIFINDEX, (void *)&ifr) < 0) {
        perror("failed to get ifindex of cpu interface");
        exit(1);
    }

    // bind to cpu port
    cpu_ifindex = ifr.ifr_ifindex;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = cpu_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(cpu_sock_fd, (struct sockaddr *)&addr,
             sizeof(struct sockaddr_ll)) < 0) {
        perror("bind to cpu interface failed");
        exit(1);
    }

    // set cpu port to be non-blocking
    sockflags = fcntl(cpu_sock_fd, F_GETFL, 0);
    if (fcntl(cpu_sock_fd, F_SETFL, sockflags | O_NONBLOCK) < 0) {
        perror("f_setfl on cpu interface failed");
        exit(1);
    }
}

switch_status_t
switch_packet_hostif_create(switch_device_t device, switch_hostif_info_t *hostif_info)
{
    int                               intf_fd = 0;
    struct ifreq                      ifr;
    int                               sock_flags = 0;
    char                             *intf_name = NULL;
    void                             *temp = NULL;
    switch_api_capability_t api_switch_info;
    switch_mac_addr_t mac;

    switch_api_capability_get(device, &api_switch_info);

    if ((intf_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return SWITCH_STATUS_FAILURE;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    intf_name = hostif_info->hostif.intf_name;
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


    memset(&mac, 0, sizeof(switch_mac_addr_t));
    if (memcmp(&api_switch_info.switch_mac, &mac, ETH_LEN) != 0) {
        // set the mac address
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, intf_name, IFNAMSIZ);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_addr.sa_data,  &api_switch_info.switch_mac, ETH_LEN);
        if ((ioctl(intf_fd, SIOCSIFHWADDR, (void *)&ifr)) < 0) {
            perror("ioctl failed");
            close(intf_fd);
            return SWITCH_STATUS_FAILURE;
        }
    }
    // bring the interface up
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, intf_name, IFNAMSIZ);
    if ((ioctl(cpu_sock_fd, SIOCGIFFLAGS, (void *)&ifr)) < 0) {
        perror("ioctl get failed");
        //        close(intf_fd);
        //        return SWITCH_STATUS_FAILURE;
    }
    else {
        ifr.ifr_flags |= IFF_UP;
        if ((ioctl(cpu_sock_fd, SIOCSIFFLAGS, (void *)&ifr)) < 0) {
            perror("ioctl set failed");
            //        close(intf_fd);
            //        return SWITCH_STATUS_FAILURE;
        }
    }

    hostif_info->intf_fd = intf_fd;
    JLG(temp, switch_intf_fd_array, intf_fd);
    if (!temp) {
        JLI(temp, switch_intf_fd_array, intf_fd);
        *(unsigned long *)temp = (unsigned long) (hostif_info);
    }

    switch_packet_write_to_pipe();

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_packet_hostif_delete(switch_device_t device, switch_hostif_info_t *hostif_info)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    void                              *temp = NULL;

    JLG(temp, switch_intf_fd_array, hostif_info->intf_fd);
    if (!temp) {
        return SWITCH_STATUS_FAILURE;
    }
    JLD(status, switch_intf_fd_array, hostif_info->intf_fd);

    switch_packet_write_to_pipe();

    return status;
}

static int
switch_packet_select_fd_get(fd_set *read_fds)
{
    switch_hostif_info_t              *hostif_info = NULL;
    void                              *temp = NULL;
    int                                nfds;
    Word_t                             index = 0;

    nfds = (cpu_sock_fd > pipe_fd[0]) ? cpu_sock_fd : pipe_fd[0];

    JLF(temp, switch_intf_fd_array, index);
    while (temp) {
        hostif_info =
            (switch_hostif_info_t *) (*(unsigned long *) temp);
        FD_SET(hostif_info->intf_fd, read_fds);
        if (hostif_info->intf_fd > nfds) {
            nfds = hostif_info->intf_fd;
        }
        JLN(temp, switch_intf_fd_array, index);
    }
    return nfds + 1;
}

static void
switch_packet_rx_from_hosts(fd_set read_fds)
{
    switch_hostif_info_t              *hostif_info = NULL;
    void                              *temp = NULL;
    Word_t                             index = 0;

    JLF(temp, switch_intf_fd_array, index);
    while (temp) {
        hostif_info =
            (switch_hostif_info_t *) (*(unsigned long *) temp);
        if (FD_ISSET(hostif_info->intf_fd, &read_fds)) {
            switch_packet_rx_from_host(hostif_info->intf_fd);
        }
        JLN(temp, switch_intf_fd_array, index);
    }
}

static void *
switch_packet_driver_thread(void *args)
{
    fd_set                             read_fds;
    int                                nfds = -1;
    int                                ret = 0;

    switch_packet_cpu_interface_create();
    assert(cpu_sock_fd != -1);

    switch_packet_create_pipe();

    while (TRUE) {
        FD_ZERO(&read_fds);
        FD_SET(cpu_sock_fd, &read_fds);
        FD_SET(pipe_fd[0], &read_fds);
        nfds = switch_packet_select_fd_get(&read_fds);
        ret = select(nfds, &read_fds, NULL, NULL, NULL);
        if (ret == -1) {
            perror("select called failed");
            return NULL;
        } else if (ret) {
            if (FD_ISSET(cpu_sock_fd, &read_fds)) {
                switch_packet_rx_from_hw();
            } else if (FD_ISSET(pipe_fd[0], &read_fds)) {
                switch_packet_read_from_pipe();
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
