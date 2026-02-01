#ifndef ARP_h
#define ARP_h

#include <stdint.h>
#include "tiny_net.h"

//ARP数据包结构体
typedef struct arp_packet
{
    uint16_t htype;//硬件类型
    uint16_t ptype;//协议类型
    uint8_t hlen;//硬件长度
    uint8_t plen;//协议长度
    uint16_t operation;//操作类型
}arp_packet;

void arp_init();
arp_packet* arp_process(packet* packet);//解析为ARP数据包
void arp_send(uint8_t* ip,uint8_t* mac);//发送ARP数据包

#endif