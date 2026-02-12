#ifndef IP_H
#define IP_H
#include "packet.h"
#include "header.h"



base_packet* ip_process(base_packet* packet_receive);
void add_ip_header(base_packet* data, uint8_t protocol, uint8_t* dest_ip);
void ip_send(uint8_t* data,uint8_t protocol,uint8_t* dest_ip);

#endif