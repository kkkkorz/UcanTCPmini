#ifndef UDP_H
#define UDP_H
#include "header.h"
#include "config.h"

void udp_send_data(uint8_t *dest_ip, uint16_t src_port, uint16_t dst_port, char *payload_data, uint32_t data_len);
void add_udp_header(base_packet *udp_packet, UDP_HEADER *header, base_packet *data);
base_packet* udp_process(base_packet* data);
#endif