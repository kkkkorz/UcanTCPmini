#ifndef HEADER_H
#define HEADER_H

#include <stdint.h>
#pragma pack(1)//告诉编译器，结构体成员不进行字节对齐
typedef struct ETH_HEADER
{
    //Ethernet帧头
    uint8_t destination_mac[6];//目的MAC地址
    uint8_t source_mac[6];//源MAC地址
    uint16_t ether_type;//协议类型
} ETH_HEADER;
typedef struct IP_HEADER
{
    uint8_t header_len;//版本和头部长度
    uint8_t service_type;//服务类型
    uint16_t total_len;//总长度
    uint16_t identification;//标识
    uint16_t flag_fragment;//标志和分片
    uint8_t ttl;//生存时间
    uint8_t protocol;//协议
    uint16_t checksum;//校验和
    uint8_t source_ip[4];//源IP地址
    uint8_t destination_ip[4];//目的IP地址
} IP_HEADER;
typedef struct ICMP_HEADER
{
    uint8_t type;//类型
    uint8_t code;//代码
    uint16_t checksum;//校验和
    uint16_t id;//标识
    uint16_t seq;//序列号
} ICMP_HEADER;
typedef struct ARP_HEADER
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
} ARP_HEADER;
typedef struct base_packet
{
    uint8_t *buffer;
    uint32_t len;
    uint32_t offset;
} base_packet;
#pragma pack()
#endif