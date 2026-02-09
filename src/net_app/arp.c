#include "arp.h"
#include "stdlib.h"
#include "config.h"
#include "tiny_net.h"
#include "util.h"
void arp_init() // todo
{
    //memset(arp_cache, 0, sizeof(arp_cache));
    // 初始化ARP缓存表
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
                if (memcmp(cur->next->ip, ip, 4) == 0 && cur->valid == 1)// ip地址相同则未冲突且有效，直接返回mac地址
                {
                    return cur->next->mac;
                }
                cur = cur->next;
            }
        }
    }
    return NULL;
}
void arp_process(packet *packet_receive) // 解析为ARP数据包
{

    arp_packet *arp = (arp_packet *)malloc(sizeof(arp_packet));
    // print_packet(packet_receive,sizeof(packet));
    // 输出arp数据包的大小
    memcpy(arp, packet_receive->data, sizeof(arp_packet));
    if (memcmp(arp->target_ip, host_ip_addr, 4) == 0)
    {
        uint16_t operation = arp->operation;
        operation = SWAP_UINT16(operation);

        if (operation == ARP_OP_REQUEST)// ARP请求
        { 
            // 处理ARP请求：发送ARP应答
            arp_reply(packet_receive, arp);
        }
        else if (operation == ARP_OP_REPLY)
        {  // 处理ARP应答
            arp_process_reply(packet_receive);
        }
    }
    free(arp);
}

void arp_reply(packet *packet_receive, arp_packet *arp_packet_receive) // 发送ARP数据包
{
    // 封装数据链路层数据包头
    packet *packet_reply = malloc(sizeof(packet));
    memcpy(packet_reply->destination_mac, packet_receive->source_mac, 6);
    memcpy(packet_reply->source_mac, host_mac, 6);
    packet_reply->ether_type = SWAP_UINT16(ARP_TYPE); // 设置协议类型为ARP

    // 封装ARP数据包
    arp_packet *arp = (arp_packet *)malloc(sizeof(arp_packet));
    arp->htype = SWAP_UINT16(HTYPE);
    arp->ptype = SWAP_UINT16(PTYPE);
    arp->hlen = HLEN;
    arp->plen = PLEN;
    arp->operation = SWAP_UINT16(ARP_OP_REPLY);               // 设置操作类型为应答
    memcpy(arp->sender_mac, host_mac, 6);                     // 设置发送方MAC地址为当前主机的MAC地址
    memcpy(arp->sender_ip, host_ip_addr, 4);                  // 设置发送方IP地址为当前主机的IP地址
    memcpy(arp->target_mac, packet_receive->source_mac, 6);   // 设置目标方MAC地址为发送方MAC地址
    memcpy(arp->target_ip, arp_packet_receive->sender_ip, 4); // 设置目标方IP地址为发送方IP地址
    // 更新缓存表
    arp_insert(arp->sender_ip, arp->sender_mac);

    // 将ARP数据包写入数据包
    memcpy(packet_reply->data, arp, sizeof(arp_packet));
    net_send(packet_reply, 14 + sizeof(arp_packet)); // 发送数据包 长度为帧头加ARP数据包大小
    free(arp);
    free(packet_reply);
}
void arp_process_reply(packet* packet_receive){
    arp_packet *arp = (arp_packet *)packet_receive->data;//取出ARP数据包
    arp_insert(arp->sender_ip, arp->sender_mac);//更新缓存表
}
//发送ARP请求
uint8_t* arp_request(uint8_t* ip,uint8_t* mac){
    packet *packet_request = malloc(sizeof(packet));//构建数据包
    arp_packet *arp_packet_request = (arp_packet *)packet_request->data;//获取ARP数据包结构体

    arp_packet_request->hlen = HLEN;
    arp_packet_request->htype = SWAP_UINT16(HTYPE);
    arp_packet_request->plen = PLEN;
    arp_packet_request->ptype = SWAP_UINT16(PTYPE);
    arp_packet_request->operation = SWAP_UINT16(ARP_OP_REQUEST);//int赋值给uint16_t
    //SWAP_UINT16(arp_packet_request->operation);//改变字节序
    memcpy(arp_packet_request->sender_mac, host_mac, 6);//源MAC地址
    memcpy(arp_packet_request->sender_ip, host_ip_addr, 4);//源IP地址
    memcpy(arp_packet_request->target_mac, broadcast_mac, 6);//目标MAC地址
    memcpy(arp_packet_request->target_ip, ip, 4);//目标IP地址
    net_data_send(arp_packet_request, broadcast_mac, host_mac, ARP_TYPE, sizeof(arp_packet));//向下传递
    free(packet_request);
    //开始计时
    time_t start = time(NULL);
    time_t now = start;
    while (now - start < 1000) // 等待arp表更新，这里是否合适？
    {
       uint8_t* dest_mac =  get_mac_by_ip(ip);
       if(dest_mac != NULL) return dest_mac;
       now = time(NULL);
    }
    return NULL;
    
    
}