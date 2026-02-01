#ifndef ARP_h
#define ARP_h

#include <stdint.h>
#include "tiny_net.h"

//ARP数据包结构体



void arp_init();
void arp_process(packet* packet);//解析为ARP数据包
void arp_reply(packet* packet);//回应ARP数据包
void arp_request(uint8_t* ip,uint8_t* mac);//发送ARP请求
//打印arp数据包
void arp_print(arp_packet* arp);

#endif