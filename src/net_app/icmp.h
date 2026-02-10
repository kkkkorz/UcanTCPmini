#ifndef ICMP_H
#define ICMP_H
#include"packet.h"

void icmp_process(ip_packet* packet_receive);
void icmp_send(uint8_t* distination_ip_uint8);
#endif