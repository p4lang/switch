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

#ifdef SAI_BMLIB

#include "saiinternal.h"
#include <p4_sim/rmt.h>
#include <BMI/bmi_port.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static unsigned int initialized = 0;
static int log_level = P4_LOG_LEVEL_NONE;
static bmi_port_mgr_t *port_mgr;
static sai_api_t api_id = SAI_API_UNSPECIFIED;

extern int start_switch_api_packet_driver(void);

const char *
sai_profile_get_value(_In_ sai_switch_profile_id_t profile_id,
                      _In_ const char* variable)
{
    return NULL;
}


/*
 * Enumerate all the K/V pairs in a profile.
 * Pointer to NULL passed as variable restarts enumeration.
 * Function returns 0 if next value exists, -1 at the end of the list.
 */
int
sai_profile_get_next_value(_In_ sai_switch_profile_id_t profile_id,
                           _Out_ const char** variable,
                           _Out_ const char** value)
{
    return -1;
}

const service_method_table_t sai_services = {
    .profile_get_value = sai_profile_get_value,
    .profile_get_next_value = sai_profile_get_next_value
};

static void sai_log_packet(
        _In_ int port_num,
        _In_ const char *buffer,
        _In_ int length)
{
    static char log_pkt[512];
    int i = 0;

    sprintf(log_pkt, "Packet in on port %d length %d; first bytes:\n",
            port_num, length);
    for (i = 0; i < 32; i++) {
        if (i && ((i % 4) == 0)) {
            sprintf(log_pkt, "%s ", log_pkt);
        }
        sprintf(log_pkt, "%s%02x", log_pkt, (uint8_t) buffer[i]);
    }
    printf("%s\n", log_pkt);
}

static void sai_transmit_packet(
        _In_ p4_port_t egress,
        _In_ void *pkt,
        _In_ int len) {
    if (log_level >= P4_LOG_LEVEL_TRACE) {
        sai_log_packet(egress, pkt, len);
    }
    if (bmi_port_send(port_mgr, egress, pkt, len) < 0) {
        printf("Error sending packet\n");
    }
}

static void sai_receive_packet(
        _In_ int port_num,
        _In_ const char *buffer,
        _In_ int length)
{
    if (log_level >= P4_LOG_LEVEL_TRACE) {
        sai_log_packet(port_num, buffer, length);
    }
    rmt_process_pkt(port_num, (char*)buffer, length);
}

static sai_status_t sai_load_config(
        _In_ char *fname,
        _In_ unsigned int *num_ports,
        _In_ int *log_level)
{
    sai_status_t status = SAI_STATUS_SUCCESS;
    char s[256];
    int port;
    char veth[32];
    char pcap[36];
    char tmp[32];
    char *pcap_file = NULL;
    int r = 0;
    FILE *fp = NULL;
    
    fp = fopen(fname, "r");
    if (!fp) {
        SAI_LOG_ERROR("failed to open config file: %s",
                      sai_status_to_string(status));
        return status;
    }

    while (fgets(s, 256, fp)) {
        pcap[0] = 0;
        pcap_file = NULL;
        if (s[0] == '#') {
            continue;
        }

        if (!strncmp(s, "num_ports", 9)) {
            sscanf(s, "%s = %d", tmp, num_ports);
        } else if (!strncmp(s, "log_level", 9)) {
            sscanf(s, "%s = %d", tmp, log_level);
        } else {
            if ((r= sscanf(s, "%d:%s %s", &port, veth, pcap)) >= 2) {
                pcap_file = pcap;
            }
            if (bmi_port_interface_add(port_mgr, veth, port, pcap_file)) {
                fclose(fp);
                status = SAI_STATUS_FAILURE;
                SAI_LOG_ERROR("failed to add port to bmi: %s",
                              sai_status_to_string(status));
                return status;
            }
        }
    }
    fclose(fp);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_api_initialize(_In_ uint64_t flags,
                   _In_ const service_method_table_t* services) {
    sai_status_t status =  SAI_STATUS_SUCCESS;
    unsigned int num_ports = 32;
    UNUSED(services);
    if(!initialized) {
        SAI_LOG_WARN("Initializing device");
        bmi_port_create_mgr(&port_mgr);
        rmt_init();
        rmt_logger_set((p4_logging_f) printf);
        status = sai_load_config("port.cfg", &num_ports, &log_level);
        if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to load port config");
            return status;
        }
        rmt_log_level_set(log_level);
        rmt_transmit_register(sai_transmit_packet);
        switch_api_init(0, num_ports);
        start_switch_api_packet_driver();
        initialized = 1;
        sai_initialize();
        bmi_set_packet_handler(port_mgr, sai_receive_packet);
    }

    services = &sai_services;
    return status;
}

sai_status_t
sai_api_uninitialize(void) {
    sai_status_t status =  SAI_STATUS_SUCCESS;
    return status;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SAI_BMLIB */
