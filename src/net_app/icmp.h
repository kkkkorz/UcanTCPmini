#ifndef ICMP_H
#define ICMP_H
#include"packet.h"
#include "header.h"

base_packet* icmp_process(ip_packet* data);
void icmp_send(uint8_t* distination_ip_uint8);
#endif