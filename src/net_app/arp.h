#ifndef ARP_h
#define ARP_h

#include <stdint.h>
#include "tiny_net.h"

//ARP数据包结构体



void arp_init();
arp_packet* arp_process(packet* packet);//解析为ARP数据包
void arp_send(uint8_t* ip,uint8_t* mac);//发送ARP数据包

#endif