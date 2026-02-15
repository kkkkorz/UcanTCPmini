#include "arp.h"
#include "stdlib.h"
#include "config.h"
#include "tiny_net.h"
#include "util.h"
#include "header.h"
void arp_init() // todo
{
    // memset(arp_cache, 0, sizeof(arp_cache));
    //  初始化ARP缓存表
}
void arp_insert(uint8_t *ip, uint8_t *mac)
{
    uint32_t ip_num = IP_TO_UINT32(ip);
    uint32_t index = ip_num % ARP_CACHE_SIZE;
    if (arp_cache[index].valid == 0) // 空桶或过期节点直接插入
    {
        memcpy(arp_cache[index].ip, ip, 4);
        memcpy(arp_cache[index].mac, mac, 6);
        arp_cache[index].time = time(NULL);
        arp_cache[index].valid = 1;
    }
    else // 冲突
    {
        if (memcmp(arp_cache[index].ip, ip, 4) == 0) // 冲突，但是ip地址相同则更新
        {
            memcpy(arp_cache[index].mac, mac, 6); // 更新mac地址
            arp_cache[index].time = time(NULL);   // 更新时间
        }
        else // 冲突，ip地址不同 则插入链表
        {
            arp_cache_node *cur = &arp_cache[index]; // 获取链表头
            arp_cache_node *node = (arp_cache_node *)malloc(sizeof(arp_cache_node));
            memcpy(node->ip, ip, 4);
            memcpy(node->mac, mac, 6);
            node->time = time(NULL);
            node->valid = 1;
            node->next = cur->next; // 插入链表
            cur->next = node;       // 插入链表
        }
    }
}

uint8_t *get_mac_by_ip(uint8_t *ip)
{
    uint32_t ip_num = IP_TO_UINT32(ip);
    uint32_t index = ip_num % ARP_CACHE_SIZE;
    if (arp_cache[index].valid == 1)
    {
        if (memcmp(arp_cache[index].ip, ip, 4) == 0) // ip地址相同则未冲突，直接返回mac地址
        {
            return arp_cache[index].mac;
        }
        else // 冲突，ip地址不同
        {
            arp_cache_node *cur = &arp_cache[index]; // 获取链表头
            while (cur->next != NULL)
            {
                if (memcmp(cur->next->ip, ip, 4) == 0 && cur->valid == 1) // ip地址相同则未冲突且有效，直接返回mac地址
                {
                    return cur->next->mac;
                }
                cur = cur->next;
            }
        }
    }
    return NULL;
}
base_packet *arp_process(base_packet *packet_receive)
{
    ARP_HEADER *arp = (ARP_HEADER *)(packet_receive->buffer + packet_receive->offset); // 解析为ARP数据包
    base_packet *reply = NULL;
    if (memcmp(arp->target_ip, host_ip_addr, 4) == 0)
    {
        uint16_t operation = arp->operation;
        operation = SWAP_UINT16(operation);

        if (operation == ARP_OP_REQUEST) // ARP请求
        {
            // 处理ARP请求：发送ARP应答
            reply = arp_reply(arp);
            return reply;
        }
        else if (operation == ARP_OP_REPLY)
        { // 处理ARP应答
            arp_process_reply(arp);
            return reply;
        }
    }
    return reply;
}

base_packet *arp_reply(ARP_HEADER *arp_header_receive) // 发送ARP数据包
{
    // 更新缓存表
    arp_insert(arp_header_receive->sender_ip, arp_header_receive->sender_mac);
    // 封装ARP数据包
    base_packet *send_packet = malloc(sizeof(base_packet));
    ARP_HEADER *arp = (ARP_HEADER *)malloc(sizeof(ARP_HEADER));
    arp->htype = SWAP_UINT16(HTYPE);
    arp->ptype = SWAP_UINT16(PTYPE);
    arp->hlen = HLEN;
    arp->plen = PLEN;
    arp->operation = SWAP_UINT16(ARP_OP_REPLY);                 // 设置操作类型为应答
    memcpy(arp->sender_mac, host_mac, 6);                       // 设置发送方MAC地址为当前主机的MAC地址
    memcpy(arp->sender_ip, host_ip_addr, 4);                    // 设置发送方IP地址为当前主机的IP地址
    memcpy(arp->target_mac, arp_header_receive->sender_mac, 6); // 设置目标方MAC地址为发送方MAC地址
    memcpy(arp->target_ip, arp_header_receive->sender_ip, 4);   // 设置目标方IP地址为发送方IP地址
    send_packet->buffer = (uint8_t *)arp;
    send_packet->len = sizeof(ARP_HEADER);
    return send_packet;
}
void arp_process_reply(ARP_HEADER *arp)
{
    arp_insert(arp->sender_ip, arp->sender_mac); // 更新缓存表
}
// 发送ARP请求
uint8_t *arp_request(uint8_t *ip, uint8_t *mac)
{
    ARP_HEADER *arp_packet_request = malloc(sizeof(ARP_HEADER)); // 构建数据包

    arp_packet_request->hlen = HLEN;
    arp_packet_request->htype = SWAP_UINT16(HTYPE);
    arp_packet_request->plen = PLEN;
    arp_packet_request->ptype = SWAP_UINT16(PTYPE);
    arp_packet_request->operation = SWAP_UINT16(ARP_OP_REQUEST); // int赋值给uint16_t
    memcpy(arp_packet_request->sender_mac, host_mac, 6);         // 源MAC地址
    memcpy(arp_packet_request->sender_ip, host_ip_addr, 4);      // 源IP地址
    memcpy(arp_packet_request->target_mac, broadcast_mac, 6);    // 目标MAC地址
    memcpy(arp_packet_request->target_ip, ip, 4);                // 目标IP地址

    base_packet *send_data = malloc(sizeof(base_packet));
    send_data->buffer = (uint8_t *)arp_packet_request;
    send_data->len = sizeof(ARP_HEADER);

    add_ethernet_header(send_data, broadcast_mac, host_mac, ARP_TYPE);
    send_packet(send_data);
    return NULL;
}