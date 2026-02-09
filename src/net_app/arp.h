#ifndef ARP_h
#define ARP_h

#include <stdint.h>
#include "tiny_net.h"
#include "config.h"


void arp_init();
void arp_process(packet *packet);                                       // 解析为ARP数据包
void arp_reply(packet *packet_receive, arp_packet *arp_packet_receive); // 回应ARP数据包
uint8_t *arp_request(uint8_t *ip, uint8_t *mac);                        // 发送ARP请求
void arp_insert(uint8_t *ip, uint8_t *mac);                             // 插入ARP缓存表
uint8_t *get_mac_by_ip(uint8_t *ip);                                    // 通过ip地址获取mac地址
void clear_arp_table();                                                 // 清空ARP缓存表
void write_arp_table(uint8_t *ip, uint8_t *mac, uint32_t index);        // 写入ARP缓存表
void arp_process_reply(packet *packet_receive);                         // 处理ARP应答

#pragma pack(1)
// ARP缓存表
typedef struct arp_cache_node
{
    
    uint8_t ip[4];  // ip地址
    uint8_t mac[6]; // mac地址
    uint32_t time;  // 最后更新时间
    uint8_t valid;  // 是否有效
    struct arp_cache_node* next;
} arp_cache_node;
#pragma pack()
// arp 缓存表
static  arp_cache_node arp_cache[ARP_CACHE_SIZE];

#endif