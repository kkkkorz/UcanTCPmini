#ifndef IP_H
#define IP_H
#include "packet.h"



void ip_process(packet* packet_receive);
void ip_send(uint8_t* data,uint8_t* protocol,uint8_t* dest_ip,uint32_t len);

#endif