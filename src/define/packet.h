#ifndef PACKER_H
#define PACKER_H

#include <stdint.h>
#pragma pack(1)//告诉编译器，结构体成员不进行字节对齐
//网卡收到的数据包结构体
typedef struct packet
{
    //Ethernet帧头
    uint8_t destination_mac[6];//目的MAC地址
    uint8_t source_mac[6];//源MAC地址
    uint16_t ether_type;//协议类型

    uint8_t data[1518];//数据
}packet;
typedef struct arp_packet
{
    uint16_t htype;//硬件类型
    uint16_t ptype;//协议类型
    uint8_t hlen;//硬件长度
    uint8_t plen;//协议长度
    uint16_t operation;//操作类型
    uint8_t sender_mac[6];//发送方MAC地址
    uint8_t sender_ip[4];//发送方IP地址
    uint8_t target_mac[6];//目标方MAC地址
    uint8_t target_ip[4];//目标方IP地址
}arp_packet;
#pragma pack()

#endif
