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
#include "switch_interface_int.h"
#include "switch_vlan_int.h"
#include "switch_port_int.h"
#include "switch_lag_int.h"
#include "switch_log_int.h"
#include <switchapi/switch_status.h>
#include <switchapi/switch_capability.h>
#include "switchapi/switch_utils.h"

pthread_t packet_driver_thread;
static pthread_mutex_t packet_driver_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t packet_driver_cond = PTHREAD_COND_INITIALIZER;
static bool packet_driver_done = false;

static tommy_list packet_rx_filter_list;
static tommy_list packet_tx_filter_list;

static char *cpu_intf_name = "veth251";
static uint32_t cpu_ifindex = 0;
static int cpu_sock_fd = -1;
static void *switch_intf_fd_array;
static int pipe_fd[2];

switch_status_t switch_packet_init(switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  tommy_list_init(&packet_rx_filter_list);
  tommy_list_init(&packet_tx_filter_list);
  return status;
}

switch_status_t switch_packet_done(switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  return status;
}

static void switch_packet_create_pipe() {
  int ret = 0;
  int sockflags = 0;

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

static void switch_packet_read_from_pipe() {
  int ret = 0;
  char buf[1];

  ret = read(pipe_fd[0], buf, 1);
  assert(ret == 1);
  assert(buf[0] = 'A');
}

static void switch_packet_write_to_pipe() {
  int ret = 0;
  char buf[1];

  buf[0] = 'A';
  ret = write(pipe_fd[1], buf, 1);
  assert(ret == 1);
}

void switch_packet_tx_to_hw(switch_packet_header_t *packet_header,
                            char *packet,
                            int packet_size) {
  static char out_packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
  struct sockaddr_ll addr;
  switch_cpu_header_t *cpu_header = NULL;
  switch_fabric_header_t *fabric_header = NULL;
  int current_offset = 0;

  fabric_header = &packet_header->fabric_header;
  cpu_header = &packet_header->cpu_header;
  memset(&addr, 0, sizeof(addr));
  addr.sll_ifindex = cpu_ifindex;

  fabric_header->ether_type = htons(fabric_header->ether_type);
  fabric_header->dst_port_or_group = htons(fabric_header->dst_port_or_group);
  cpu_header->reason_code = htons(cpu_header->reason_code);

  memcpy(out_packet, packet, SWITCH_PACKET_HEADER_OFFSET);
  current_offset += SWITCH_PACKET_HEADER_OFFSET;

  memcpy((out_packet + current_offset),
         packet_header,
         sizeof(switch_packet_header_t));
  current_offset += sizeof(switch_packet_header_t);

  memcpy((out_packet + current_offset),
         packet + SWITCH_PACKET_HEADER_OFFSET,
         (packet_size - SWITCH_PACKET_HEADER_OFFSET));
  packet_size = packet_size + sizeof(switch_packet_header_t);

  if (sendto(cpu_sock_fd,
             out_packet,
             packet_size,
             0,
             (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
    perror("packet send failed");
  }
  //    SWITCH_API_TRACE("Sent packet to hw port %d\n",
  //                     packet_header->fabric_header.dst_port_or_group);
}

static void switch_packet_extract_optional_header(
    switch_packet_header_t *packet_header,
    switch_opt_header_t **opt_header,
    uint16_t *opt_length) {
  *opt_length = 0;
  if (packet_header->cpu_header.reason_code ==
      SWITCH_HOSTIF_REASON_CODE_SFLOW_SAMPLE) {
    *opt_header = (switch_opt_header_t *)(((char *)packet_header) +
                                          sizeof(switch_packet_header_t));
    (*opt_header)->sflow_header.sflow_session_id =
        ntohs((*opt_header)->sflow_header.sflow_session_id);
    (*opt_header)->sflow_header.sflow_egress_ifindex =
        ntohs((*opt_header)->sflow_header.sflow_egress_ifindex);
    *opt_length = sizeof(switch_sflow_header_t);
  }
}

static void switch_packet_rx_from_hw() {
  int packet_size = 0;
  switch_packet_header_t *packet_header = NULL;
  switch_opt_header_t *opt_header = NULL;
  static char in_packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
  static char packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  uint16_t opt_length = 0;

  // read packet from cpu port
  while ((packet_size = read(cpu_sock_fd, in_packet, sizeof(in_packet))) > 0) {
    uint16_t ethType = *(uint16_t *)(in_packet + 12);
    if (ntohs(ethType) != 0x9000) continue;
    packet_header =
        (switch_packet_header_t *)(in_packet + SWITCH_PACKET_HEADER_OFFSET);
    memcpy(packet, in_packet, SWITCH_PACKET_HEADER_OFFSET);
    packet_header->cpu_header.reason_code =
        ntohs(packet_header->cpu_header.reason_code);
    if (packet_header->cpu_header.reason_code ==
        SWITCH_HOSTIF_REASON_CODE_NULL_DROP)
      continue;

    switch_packet_extract_optional_header(
        packet_header, &opt_header, &opt_length);
    packet_size = packet_size - sizeof(switch_packet_header_t) - opt_length;
    memcpy(packet + SWITCH_PACKET_HEADER_OFFSET,
           in_packet + SWITCH_PACKET_HEADER_OFFSET +
               sizeof(switch_packet_header_t) + opt_length,
           packet_size - SWITCH_PACKET_HEADER_OFFSET);

    packet_header->cpu_header.ingress_port =
        ntohs(packet_header->cpu_header.ingress_port);
    packet_header->cpu_header.ingress_ifindex =
        ntohs(packet_header->cpu_header.ingress_ifindex);
    packet_header->cpu_header.ingress_bd =
        ntohs(packet_header->cpu_header.ingress_bd);
    status = switch_api_hostif_rx_packet_from_hw(
        packet_header, opt_header, packet, packet_size);
    if (status != SWITCH_STATUS_SUCCESS) {
      return;
    }
  }
}

void switch_packet_rx_transform(switch_packet_header_t *packet_header,
                                char *transformed_packet,
                                char *packet,
                                int *packet_size) {
  switch_cpu_header_t *cpu_header = NULL;
  switch_packet_rx_info_t *rx_info = NULL;
  switch_ethernet_header_t *eth_header = NULL;
  switch_vlan_header_t *vlan_header = NULL;
  switch_packet_rx_entry_t rx_entry;
  uint16_t offset = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  cpu_header = &packet_header->cpu_header;

  memset(&rx_entry, 0x0, sizeof(rx_entry));
  rx_entry.port = cpu_header->ingress_port;
  rx_entry.ifindex = cpu_header->ingress_ifindex;
  rx_entry.bd = cpu_header->ingress_bd;
  rx_entry.reason_code = cpu_header->reason_code;

  status = switch_packet_rx_info_get(&rx_entry, &rx_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("failed to find filter. packet not transformed");
    memcpy(transformed_packet, packet, *packet_size);
    return;
  }

  if (rx_info->vlan_action == SWITCH_PACKET_VLAN_ADD) {
    eth_header = (switch_ethernet_header_t *)packet;
    if (ntohs(eth_header->ether_type) != SWITCH_ETHERTYPE_DOT1Q &&
        rx_info->vlan_id) {
      offset = 2 * ETH_LEN;
      memcpy(transformed_packet, packet, offset);
      vlan_header = (switch_vlan_header_t *)(transformed_packet + offset);
      vlan_header->tpid = htons(SWITCH_ETHERTYPE_DOT1Q);
      uint16_t *vlan_h = (uint16_t *)(vlan_header) + 1;
      *vlan_h = htons(rx_info->vlan_id);
      memcpy(transformed_packet + offset + sizeof(switch_vlan_header_t),
             packet + offset,
             *packet_size - offset);
      *packet_size += sizeof(switch_vlan_header_t);
    } else {
      memcpy(transformed_packet, packet, *packet_size);
    }
  } else if (rx_info->vlan_action == SWITCH_PACKET_VLAN_REMOVE) {
    eth_header = (switch_ethernet_header_t *)packet;
    if (ntohs(eth_header->ether_type) == SWITCH_ETHERTYPE_DOT1Q) {
      offset = 2 * ETH_LEN;
      memcpy(transformed_packet, packet, offset);
      memcpy(transformed_packet, packet + offset, *packet_size - offset);
      *packet_size -= sizeof(switch_vlan_header_t);
    } else {
      memcpy(transformed_packet, packet, *packet_size);
    }
  } else if (rx_info->vlan_action == SWITCH_PACKET_VLAN_SWAP) {
    eth_header = (switch_ethernet_header_t *)packet;
    if (ntohs(eth_header->ether_type) == SWITCH_ETHERTYPE_DOT1Q &&
        rx_info->vlan_id) {
      offset = 2 * ETH_LEN;
      vlan_header = (switch_vlan_header_t *)(transformed_packet + offset);
      vlan_header->vid = htons(rx_info->vlan_id);
    } else {
      memcpy(transformed_packet, packet, *packet_size);
    }
  } else {
    memcpy(transformed_packet, packet, *packet_size);
  }
}

void switch_packet_rx_to_host(switch_packet_header_t *packet_header,
                              char *packet,
                              int packet_size) {
  switch_cpu_header_t *cpu_header = NULL;
  switch_packet_rx_info_t *rx_info = NULL;
  static char in_packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
  switch_packet_rx_entry_t rx_entry;
  int intf_fd = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  cpu_header = &packet_header->cpu_header;

  memset(&rx_entry, 0x0, sizeof(rx_entry));
  rx_entry.port = cpu_header->ingress_port;
  rx_entry.ifindex = cpu_header->ingress_ifindex;
  rx_entry.bd = cpu_header->ingress_bd;
  rx_entry.reason_code = cpu_header->reason_code;

  status = switch_packet_rx_info_get(&rx_entry, &rx_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("failed to find fd. dropping packet");
    return;
  }

  SWITCH_API_INFO("Rx packet reason_code 0x%x - send to fd %d, action %d\n",
                  rx_entry.reason_code,
                  rx_info->intf_fd,
                  rx_info->vlan_action);

  switch_packet_rx_transform(packet_header, in_packet, packet, &packet_size);

  intf_fd = rx_info->intf_fd;

  if (write(intf_fd, in_packet, packet_size) < 0) {
    perror("sendto host interface failed");
    return;
  }
  return;
}

void switch_packet_tx_bd_transform(char *in_packet,
                                   int in_packet_size,
                                   char *out_packet,
                                   int *out_packet_size,
                                   switch_packet_tx_info_t *tx_info) {
  switch_ethernet_header_t *eth_header = NULL;
  switch_vlan_header_t *vlan_header = NULL;
  switch_vlan_t vlan_id1 = 0;
  switch_vlan_t vlan_id2 = 0;
  uint16_t ether_type = 0;
  uint16_t offset = 0;
  uint16_t vlan_offset = 0;

  /*
   * In order to perform a fastpath lookup, bd has to be
   * added as vlan tag(s) to the packet from host.
   * bd is a 16 bit field whereas the vlan id is a 12 bit field.
   * packets has to be double tagged when the bd value is more
   * than 12 bits.
   */
  vlan_id1 = tx_info->bd & 0xFFF;
  vlan_id2 = (tx_info->bd & 0xF000) >> 12;

  eth_header = (switch_ethernet_header_t *)in_packet;
  ether_type = htons(eth_header->ether_type);

  if (ether_type != SWITCH_ETHERTYPE_DOT1Q) {
    vlan_offset += sizeof(switch_vlan_header_t);
  }

  if (vlan_id2) {
    vlan_offset += sizeof(switch_vlan_header_t);
  }

  memcpy(out_packet, in_packet, 2 * ETH_LEN);
  memcpy(out_packet + 2 * ETH_LEN + vlan_offset,
         in_packet + 2 * ETH_LEN,
         (in_packet_size - 2 * ETH_LEN));
  *out_packet_size = in_packet_size;
  *out_packet_size += vlan_offset;

  vlan_header = (switch_vlan_header_t *)(out_packet + 2 * ETH_LEN);
  vlan_header->vid = ntohs(vlan_id1);
  vlan_header->tpid = ntohs(SWITCH_ETHERTYPE_DOT1Q);
  vlan_header->dei = 0;
  vlan_header->pcp = 0;

  if (vlan_id2) {
    offset = 2 * ETH_LEN + sizeof(switch_vlan_header_t);
    vlan_header = (switch_vlan_header_t *)(out_packet + offset);
    vlan_header->vid = ntohs(vlan_id2);
    vlan_header->tpid = ntohs(SWITCH_ETHERTYPE_DOT1Q);
    vlan_header->dei = 0;
    vlan_header->pcp = 0;
  }
}

void switch_packet_tx_switched(switch_packet_header_t *packet_header,
                               char *in_packet,
                               int in_packet_size) {
  int packet_size = 0;
  static char packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
  switch_ethernet_header_t *eth_header = NULL;
  switch_vlan_header_t *vlan_header = NULL;
  switch_vlan_t vlan_id1 = 0;
  switch_packet_tx_entry_t tx_entry;
  switch_packet_tx_info_t *tx_info = NULL;
  switch_status_t status;

  eth_header = (switch_ethernet_header_t *)in_packet;
  if (ntohs(eth_header->ether_type) == SWITCH_ETHERTYPE_DOT1Q) {
    vlan_header = (switch_vlan_header_t *)(in_packet + 2 * ETH_LEN);
    uint16_t *vlan_h = (uint16_t *)(vlan_header) + 1;
    vlan_id1 = ntohs(*vlan_h);
  }

  tx_entry.fd_valid = false;
  tx_entry.vlan_id = vlan_id1;
  status = switch_packet_tx_info_get(&tx_entry, &tx_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("net filter tx not found. dropping packet");
    return;
  }

  memset(packet, 0x0, SWITCH_PACKET_MAX_BUFFER_SIZE);
  switch_packet_tx_bd_transform(
      in_packet, in_packet_size, packet, &packet_size, tx_info);
  switch_packet_tx_to_hw(packet_header, packet, packet_size);
}

void switch_packet_tx_from_host(int intf_fd) {
  switch_hostif_info_t *hostif_info = NULL;
  int packet_size = 0;
  int in_packet_size = 0;
  static char in_packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
  static char packet[SWITCH_PACKET_MAX_BUFFER_SIZE];
  void *temp = NULL;
  switch_packet_header_t packet_header;
  switch_fabric_header_t *fabric_header = NULL;
  switch_cpu_header_t *cpu_header = NULL;
  switch_ethernet_header_t *eth_header = NULL;
  switch_vlan_header_t *vlan_header = NULL;
  switch_vlan_t vlan_id1 = 0;
  switch_packet_tx_entry_t tx_entry;
  switch_packet_tx_info_t *tx_info = NULL;
  switch_device_t device = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  memset(in_packet, 0x0, SWITCH_PACKET_MAX_BUFFER_SIZE);
  memset(packet, 0x0, SWITCH_PACKET_MAX_BUFFER_SIZE);

  while ((in_packet_size = read(intf_fd, in_packet, sizeof(in_packet))) > 0) {
    JLG(temp, switch_intf_fd_array, intf_fd);
    hostif_info = (switch_hostif_info_t *)(*(unsigned long *)temp);
    if (!hostif_info) {
      perror("invalid hostif fd");
      return;
    }
    SWITCH_API_TRACE("Received packet from host port %s through netdev\n",
                     hostif_info->hostif.intf_name);

    eth_header = (switch_ethernet_header_t *)in_packet;
    if (ntohs(eth_header->ether_type) == SWITCH_ETHERTYPE_DOT1Q) {
      vlan_header = (switch_vlan_header_t *)(in_packet + 2 * ETH_LEN);
      uint16_t *vlan_h = (uint16_t *)(vlan_header) + 1;
      vlan_id1 = ntohs(*vlan_h);
    }

    tx_entry.intf_fd = intf_fd;
    tx_entry.vlan_id = vlan_id1;
    status = switch_packet_tx_info_get(&tx_entry, &tx_info);
    if (status != SWITCH_STATUS_SUCCESS) {
      SWITCH_API_ERROR("net filter tx not found. dropping packet");
      continue;
    }

    memset(&packet_header, 0x0, sizeof(packet_header));
    cpu_header = &packet_header.cpu_header;
    fabric_header = &packet_header.fabric_header;

    if (tx_info->bypass_flags == SWITCH_BYPASS_ALL) {
      cpu_header->tx_bypass = TRUE;
      cpu_header->reason_code = tx_info->bypass_flags;
      fabric_header->dst_port_or_group = tx_info->port;
      memcpy(packet, in_packet, in_packet_size);
      packet_size = in_packet_size;
    } else {
      cpu_header->tx_bypass = FALSE;
      cpu_header->reason_code = tx_info->bypass_flags;
      switch_packet_tx_bd_transform(
          in_packet, in_packet_size, packet, &packet_size, tx_info);
    }

    fabric_header = &packet_header.fabric_header;
    cpu_header = &packet_header.cpu_header;
    fabric_header->dst_device = device;
    fabric_header->packet_type = SWITCH_FABRIC_HEADER_TYPE_CPU;
    fabric_header->ether_type = SWITCH_FABRIC_HEADER_ETHTYPE;

    switch_packet_tx_to_hw(&packet_header, packet, packet_size);
  }
}

static void switch_packet_cpu_interface_create() {
  struct ifreq ifr;
  struct sockaddr_ll addr;
  int sockflags = 0;

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
  if (bind(cpu_sock_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) <
      0) {
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

switch_status_t switch_packet_hostif_create(switch_device_t device,
                                            switch_hostif_info_t *hostif_info) {
  int intf_fd = 0;
  struct ifreq ifr;
  int sock_flags = 0;
  char *intf_name = NULL;
  void *temp = NULL;
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
    memcpy(ifr.ifr_addr.sa_data, &api_switch_info.switch_mac, ETH_LEN);
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
  } else {
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
    *(unsigned long *)temp = (unsigned long)(hostif_info);
  }

  switch_packet_write_to_pipe();

  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_packet_hostif_delete(switch_device_t device,
                                            switch_hostif_info_t *hostif_info) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  void *temp = NULL;

  JLG(temp, switch_intf_fd_array, hostif_info->intf_fd);
  if (!temp) {
    return SWITCH_STATUS_FAILURE;
  }
  JLD(status, switch_intf_fd_array, hostif_info->intf_fd);

  switch_packet_write_to_pipe();

  return status;
}

static int switch_packet_select_fd_get(fd_set *read_fds) {
  switch_hostif_info_t *hostif_info = NULL;
  void *temp = NULL;
  int nfds;
  Word_t index = 0;

  nfds = (cpu_sock_fd > pipe_fd[0]) ? cpu_sock_fd : pipe_fd[0];

  JLF(temp, switch_intf_fd_array, index);
  while (temp) {
    hostif_info = (switch_hostif_info_t *)(*(unsigned long *)temp);
    FD_SET(hostif_info->intf_fd, read_fds);
    if (hostif_info->intf_fd > nfds) {
      nfds = hostif_info->intf_fd;
    }
    JLN(temp, switch_intf_fd_array, index);
  }
  return nfds + 1;
}

static void switch_packet_tx_from_hosts(fd_set read_fds) {
  switch_hostif_info_t *hostif_info = NULL;
  void *temp = NULL;
  Word_t index = 0;

  JLF(temp, switch_intf_fd_array, index);
  while (temp) {
    hostif_info = (switch_hostif_info_t *)(*(unsigned long *)temp);
    if (FD_ISSET(hostif_info->intf_fd, &read_fds)) {
      switch_packet_tx_from_host(hostif_info->intf_fd);
    }
    JLN(temp, switch_intf_fd_array, index);
  }
}

static void *switch_packet_driver_thread(void *args) {
  fd_set read_fds;
  int nfds = -1;
  int ret = 0;

  switch_packet_cpu_interface_create();
  assert(cpu_sock_fd != -1);

  switch_packet_create_pipe();

  // Signal parent to continue
  pthread_mutex_lock(&packet_driver_mutex);
  packet_driver_done = true;
  pthread_cond_signal(&packet_driver_cond);
  pthread_mutex_unlock(&packet_driver_mutex );

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
        switch_packet_tx_from_hosts(read_fds);
      }
    }
  }
}

int start_switch_api_packet_driver() {

  pthread_create(
      &packet_driver_thread, NULL, switch_packet_driver_thread, NULL);

  // Let switch_packet_driver_thread to finish initializing
  pthread_mutex_lock(&packet_driver_mutex);
  while(packet_driver_done == false) {
    pthread_cond_wait(&packet_driver_cond, &packet_driver_mutex);
  }
  pthread_mutex_unlock(&packet_driver_mutex);

  return SWITCH_STATUS_SUCCESS;
}

static bool switch_packet_tx_filter_match(switch_packet_tx_entry_t *tx_entry1,
                                          switch_packet_tx_entry_t *tx_entry2) {
  /*
   * entry1 is the one stored in the filter list
   * entry2 represents incoming packet, therefore all the valid
   * bits and masks are used from entry1
   */
  if ((!tx_entry1->fd_valid || (tx_entry1->intf_fd == tx_entry2->intf_fd)) &&
      (!tx_entry1->vlan_valid || (tx_entry1->vlan_id == tx_entry2->vlan_id))) {
    return TRUE;
  }
  return FALSE;
}

int32_t switch_packet_tx_filter_priority_compare(const void *key1,
                                                 const void *key2) {
  switch_packet_tx_entry_t *tx_entry1 = NULL;
  switch_packet_tx_entry_t *tx_entry2 = NULL;

  if (!key1 || !key2) {
    return 0;
  }

  tx_entry1 = (switch_packet_tx_entry_t *)key1;
  tx_entry2 = (switch_packet_tx_entry_t *)key2;

  return (int32_t)tx_entry1->priority - (int32_t)tx_entry2->priority;
}

switch_status_t switch_api_packet_net_filter_tx_create(
    switch_device_t device,
    switch_packet_tx_key_t *tx_key,
    switch_packet_tx_action_t *tx_action) {
  switch_packet_tx_entry_t tx_entry;
  switch_packet_tx_info_t *tx_info = NULL;
  switch_hostif_info_t *hostif_info = NULL;
  switch_handle_t bd_handle = 0;
  switch_interface_info_t *intf_info = NULL;
  switch_handle_type_t handle_type = 0;
  switch_bd_info_t *bd_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!tx_key || !tx_action) {
    SWITCH_API_ERROR("filter tx create failed. invalid params");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  if (tx_key->handle_valid) {
    hostif_info = switch_hostif_get(tx_key->hostif_handle);
    if (!hostif_info) {
      SWITCH_API_ERROR("invalid hostif handle");
      return SWITCH_STATUS_INVALID_HANDLE;
    }
  }

  memset(&tx_entry, 0x0, sizeof(tx_entry));
  if (tx_key->handle_valid) {
    tx_entry.intf_fd = hostif_info->intf_fd;
  }
  tx_entry.fd_valid = tx_key->handle_valid;
  tx_entry.vlan_id = tx_key->vlan_id;
  tx_entry.vlan_valid = tx_key->vlan_valid;
  tx_entry.priority = tx_key->priority;

  tx_info = switch_malloc(sizeof(switch_packet_tx_info_t), 0x1);
  if (!tx_info) {
    SWITCH_API_ERROR("hif %lx vlan %x malloc failure",
                     tx_key->hostif_handle,
                     tx_key->vlan_id);
    return SWITCH_STATUS_NO_MEMORY;
  }

  if (tx_action->bypass_flags != SWITCH_BYPASS_ALL) {
    bd_handle = tx_action->handle;

    handle_type = switch_handle_get_type(tx_action->handle);
    if (handle_type == SWITCH_HANDLE_TYPE_INTERFACE) {
      intf_info = switch_api_interface_get(tx_action->handle);
      if (!intf_info) {
        SWITCH_API_ERROR("intf_handle %lx is invalid", tx_action->handle);
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
        SWITCH_API_ERROR("intf_handle %lx is not l3", tx_action->handle);
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      bd_handle = intf_info->bd_handle;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
      SWITCH_API_ERROR(
          "hif %lx vlan %x invalid bd", tx_key->hostif_handle, tx_key->vlan_id);
      return SWITCH_STATUS_INVALID_HANDLE;
    }
  }

  memcpy(&tx_info->tx_entry, &tx_entry, sizeof(tx_entry));
  tx_info->bd = handle_to_id(bd_handle);
  tx_info->bypass_flags = tx_action->bypass_flags;
  tx_info->port = handle_to_id(tx_action->port_handle);

  SWITCH_API_INFO(
      "net_filter_tx_create: hostif 0x%lx, vlan_id = %d, fd 0x%x, bypass "
      "0x%x\n",
      tx_key->hostif_handle,
      tx_key->vlan_valid ? tx_key->vlan_id : 0xFFF,
      tx_entry.intf_fd,
      tx_info->bypass_flags);

  tommy_list_insert_head(&packet_tx_filter_list, &(tx_info->node), tx_info);
  tommy_list_sort(&packet_tx_filter_list,
                  switch_packet_tx_filter_priority_compare);
  return status;
}

switch_status_t switch_api_packet_net_filter_tx_delete(
    switch_device_t device, switch_packet_tx_key_t *tx_key) {
  switch_packet_tx_entry_t *tmp_tx_entry = NULL;
  switch_packet_tx_info_t *tmp_tx_info = NULL;
  switch_packet_tx_entry_t tx_entry;
  tommy_node *node = NULL;
  switch_hostif_info_t *hostif_info = NULL;
  bool node_found = FALSE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!tx_key) {
    SWITCH_API_ERROR("filter tx delete failed. invalid params");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  memset(&tx_entry, 0x0, sizeof(tx_entry));
  if (tx_key->handle_valid) {
    hostif_info = switch_hostif_get(tx_key->hostif_handle);
    if (!hostif_info) {
      SWITCH_API_ERROR("invalid hostif handle");
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    tx_entry.intf_fd = hostif_info->intf_fd;
  }

  if (tx_key->vlan_valid) {
    tx_entry.vlan_id = tx_key->vlan_id;
  }

  node = tommy_list_head(&packet_tx_filter_list);
  while (node) {
    tmp_tx_info = (switch_packet_tx_info_t *)node->data;
    tmp_tx_entry = &tmp_tx_info->tx_entry;

    if (switch_packet_tx_filter_match(tmp_tx_entry, &tx_entry)) {
      node_found = TRUE;
      break;
    }
    node = node->next;
  }

  if (!node_found) {
    SWITCH_API_ERROR("tx filter delete failed. node find failed");
    return SWITCH_STATUS_ITEM_NOT_FOUND;
  }

  tommy_list_remove_existing(&packet_tx_filter_list, node);
  switch_free(tmp_tx_info);
  return status;
}

int32_t switch_packet_rx_filter_priority_compare(const void *key1,
                                                 const void *key2) {
  switch_packet_rx_entry_t *rx_entry1 = NULL;
  switch_packet_rx_entry_t *rx_entry2 = NULL;

  if (!key1 || !key2) {
    return 0;
  }

  rx_entry1 = (switch_packet_rx_entry_t *)key1;
  rx_entry2 = (switch_packet_rx_entry_t *)key2;

  return (int32_t)rx_entry1->priority - (int32_t)rx_entry2->priority;
}

static bool switch_packet_rx_filter_match(switch_packet_rx_entry_t *rx_entry1,
                                          switch_packet_rx_entry_t *rx_entry2) {
  // entry1 is the one stored in the filter list
  // entry2 represents incoming packet, therefore all the valid
  // bits and masks are used from entry1
  if ((!rx_entry1->port_valid || rx_entry1->port == rx_entry2->port) &&
      (!rx_entry1->ifindex_valid || rx_entry1->ifindex == rx_entry2->ifindex) &&
      (!rx_entry1->bd_valid || rx_entry1->bd == rx_entry2->bd) &&
      (!rx_entry1->reason_code_valid ||
       (rx_entry1->reason_code & rx_entry1->reason_code_mask) ==
           (rx_entry2->reason_code & rx_entry1->reason_code_mask))) {
    // priority is not be compared so matching entry can be found
    // use reason_code mask from entry1
    return TRUE;
  }
  return FALSE;
}

switch_status_t switch_api_packet_net_filter_rx_create(
    switch_device_t device,
    switch_packet_rx_key_t *rx_key,
    switch_packet_rx_action_t *rx_action) {
  switch_hostif_info_t *hostif_info = NULL;
  switch_lag_info_t *lag_info = NULL;
  switch_port_info_t *port_info = NULL;
  switch_packet_rx_entry_t rx_entry;
  switch_packet_rx_info_t *rx_info = NULL;
  switch_handle_type_t handle_type = 0;
  switch_interface_info_t *intf_info = NULL;
  switch_handle_t bd_handle = 0;
  switch_bd_info_t *bd_info = NULL;
  switch_ifindex_t ifindex = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!rx_key || !rx_action) {
    SWITCH_API_ERROR("filter rx create failed. invalid params");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  memset(&rx_entry, 0x0, sizeof(rx_entry));

  if (rx_key->port_lag_valid) {
    handle_type = switch_handle_get_type(rx_key->port_lag_handle);
    if (handle_type == SWITCH_HANDLE_TYPE_LAG) {
      lag_info = switch_api_lag_get_internal(rx_key->port_lag_handle);
      if (!lag_info) {
        SWITCH_API_ERROR("invalid lag handle");
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      ifindex = lag_info->ifindex;
    } else {
      port_info = switch_api_port_get_internal(rx_key->port_lag_handle);
      if (!port_info) {
        SWITCH_API_ERROR("invalid port handle");
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      ifindex = port_info->ifindex;
    }
    rx_entry.ifindex_valid = TRUE;
  }

  if (rx_key->handle_valid) {
    bd_handle = rx_key->handle;
    handle_type = switch_handle_get_type(rx_key->handle);
    if (handle_type == SWITCH_HANDLE_TYPE_INTERFACE) {
      intf_info = switch_api_interface_get(rx_key->handle);
      if (!intf_info) {
        SWITCH_API_ERROR("intf_handle %lx is invalid", rx_key->handle);
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
        SWITCH_API_ERROR("intf_handle %lx is not l3", rx_key->handle);
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      bd_handle = intf_info->bd_handle;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
      SWITCH_API_ERROR("bd derivation failed %lx", rx_key->handle);
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    rx_entry.bd_valid = TRUE;
  }

  if (rx_action->hostif_handle) {
    hostif_info = switch_hostif_get(rx_action->hostif_handle);
    if (!hostif_info) {
      SWITCH_API_ERROR("invalid hostif handle");
      return SWITCH_STATUS_INVALID_HANDLE;
    }
  }

  rx_entry.bd = handle_to_id(bd_handle);
  rx_entry.ifindex = ifindex;
  rx_entry.port_valid = rx_key->port_valid;
  rx_entry.port = handle_to_id(rx_key->port_handle);
  rx_entry.reason_code_valid = rx_key->reason_code_valid;
  rx_entry.reason_code = rx_key->reason_code;
  rx_entry.reason_code_mask = rx_key->reason_code_mask;
  rx_entry.priority = rx_key->priority;

  rx_info = switch_malloc(sizeof(switch_packet_rx_info_t), 0x1);
  if (!rx_info) {
    SWITCH_API_ERROR("port %lx port_lag %lx handle %lx malloc failed",
                     rx_key->port_handle,
                     rx_key->port_lag_handle,
                     rx_key->handle);
    return SWITCH_STATUS_NO_MEMORY;
  }

  memset(rx_info, 0x0, sizeof(switch_packet_rx_info_t));
  memcpy(&rx_info->rx_entry, &rx_entry, sizeof(rx_entry));
  rx_info->vlan_id = rx_action->vlan_id;
  rx_info->vlan_action = rx_action->vlan_action;
  if (hostif_info) {
    rx_info->intf_fd = hostif_info->intf_fd;
  }

  SWITCH_API_INFO(
      "net_filter_rx_create: port 0x%lx, port_lag_hdl = 0x%lx, "
      "if_bd_hdl 0x%lx, rcode 0x%x, rcode_mask 0x%x "
      "vlan_id %d, fd %d, action %d\n",
      rx_key->port_valid ? rx_key->port_handle : 0,
      rx_key->port_lag_valid ? rx_key->port_lag_handle : 0,
      rx_key->handle_valid ? rx_key->handle : 0,
      rx_key->reason_code_valid ? rx_key->reason_code : 0,
      rx_key->reason_code_mask,
      rx_info->vlan_id,
      rx_info->vlan_action,
      rx_info->intf_fd);
  /*
   * Adding an element to the list results in sorting the list.
   * tommy does not have a way to compare and insert the elements
   */
  tommy_list_insert_head(&packet_rx_filter_list, &(rx_info->node), rx_info);
  tommy_list_sort(&packet_rx_filter_list,
                  switch_packet_rx_filter_priority_compare);
  return status;
}

switch_status_t switch_api_packet_net_filter_rx_delete(
    switch_device_t device, switch_packet_rx_key_t *rx_key) {
  switch_lag_info_t *lag_info = NULL;
  switch_port_info_t *port_info = NULL;
  switch_packet_rx_entry_t *tmp_rx_entry = NULL;
  switch_packet_rx_entry_t rx_entry;
  switch_packet_rx_info_t *tmp_rx_info = NULL;
  switch_handle_type_t handle_type = 0;
  switch_interface_info_t *intf_info = NULL;
  switch_handle_t bd_handle = 0;
  switch_bd_info_t *bd_info = NULL;
  tommy_node *node = NULL;
  bool node_found = FALSE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!rx_key) {
    SWITCH_API_ERROR("filter rx delete failed. invalid params");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  memset(&rx_entry, 0, sizeof(switch_packet_rx_entry_t));

  if (rx_key->port_lag_valid && rx_key->port_lag_handle) {
    handle_type = switch_handle_get_type(rx_key->port_lag_handle);
    if (handle_type == SWITCH_HANDLE_TYPE_LAG) {
      lag_info = switch_api_lag_get_internal(rx_key->port_lag_handle);
      if (!lag_info) {
        SWITCH_API_ERROR("invalid lag handle");
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      rx_entry.ifindex = lag_info->ifindex;
    } else {
      port_info = switch_api_port_get_internal(rx_key->port_lag_handle);
      if (!port_info) {
        SWITCH_API_ERROR("invalid port handle");
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      rx_entry.ifindex = port_info->ifindex;
    }
  }

  if (rx_key->handle_valid) {
    bd_handle = rx_key->handle;
    handle_type = switch_handle_get_type(rx_key->handle);
    if (handle_type == SWITCH_HANDLE_TYPE_INTERFACE) {
      intf_info = switch_api_interface_get(rx_key->handle);
      if (!intf_info) {
        SWITCH_API_ERROR("intf_handle %lx is invalid", rx_key->handle);
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
        SWITCH_API_ERROR("intf_handle %lx is not l3", rx_key->handle);
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      bd_handle = intf_info->bd_handle;
    }
    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
      SWITCH_API_ERROR("bd derivation failed %lx", rx_key->handle);
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    rx_entry.bd = handle_to_id(bd_handle);
  }

  if (rx_entry.port_valid) {
    rx_entry.port = handle_to_id(rx_key->port_handle);
  }
  rx_entry.bd_valid = rx_key->handle_valid;
  rx_entry.reason_code = rx_key->reason_code;

  node = tommy_list_head(&packet_rx_filter_list);
  while (node) {
    tmp_rx_info = (switch_packet_rx_info_t *)node->data;
    tmp_rx_entry = &tmp_rx_info->rx_entry;
    if (switch_packet_rx_filter_match(tmp_rx_entry, &rx_entry)) {
      node_found = TRUE;
      break;
    }
    node = node->next;
  }

  if (!node_found) {
    SWITCH_API_ERROR("tx filter delete failed. node find failed");
    return SWITCH_STATUS_ITEM_NOT_FOUND;
  }

  tommy_list_remove_existing(&packet_rx_filter_list, node);

  switch_free(tmp_rx_info);
  return status;
}

switch_status_t switch_packet_rx_info_get(switch_packet_rx_entry_t *rx_entry,
                                          switch_packet_rx_info_t **rx_info) {
  switch_packet_rx_info_t *tmp_rx_info = NULL;
  tommy_node *node = NULL;
  switch_packet_rx_entry_t *tmp_rx_entry = NULL;
  switch_status_t status = SWITCH_STATUS_ITEM_NOT_FOUND;

  *rx_info = NULL;

  node = tommy_list_head(&packet_rx_filter_list);
  while (node) {
    tmp_rx_info = (switch_packet_rx_info_t *)node->data;
    tmp_rx_entry = &tmp_rx_info->rx_entry;

    if (switch_packet_rx_filter_match(tmp_rx_entry, rx_entry)) {
      *rx_info = tmp_rx_info;
      status = SWITCH_STATUS_SUCCESS;
      break;
    }
    node = node->next;
  }

  return status;
}

switch_status_t switch_packet_tx_info_get(switch_packet_tx_entry_t *tx_entry,
                                          switch_packet_tx_info_t **tx_info) {
  switch_packet_tx_info_t *tmp_tx_info = NULL;
  tommy_node *node = NULL;
  switch_packet_tx_entry_t *tmp_tx_entry = NULL;
  switch_status_t status = SWITCH_STATUS_ITEM_NOT_FOUND;

  *tx_info = NULL;

  node = tommy_list_head(&packet_tx_filter_list);
  while (node) {
    tmp_tx_info = (switch_packet_tx_info_t *)node->data;
    tmp_tx_entry = &tmp_tx_info->tx_entry;
    if (switch_packet_tx_filter_match(tmp_tx_entry, tx_entry)) {
      *tx_info = tmp_tx_info;
      status = SWITCH_STATUS_SUCCESS;
      break;
    }
    node = node->next;
  }

  return status;
}
