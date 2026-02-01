#ifndef PACKET_DEFINE_H
#define PACKET_DEFINE_H

#include <stdint.h>
#pragma pack(1)
//网卡收到的数据包结构体
typedef struct packet
{
    uint8_t data[2048];//数据
    uint32_t  size;//数据长度

}packet;
typedef struct arp_packet
{
    uint16_t htype;//硬件类型
    uint16_t ptype;//协议类型
    uint8_t hlen;//硬件长度
    uint8_t plen;//协议长度
    uint16_t operation;//操作类型
}arp_packet;

#endif
