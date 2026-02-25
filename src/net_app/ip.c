#include "ip.h"
#include "config.h"
#include "icmp.h"
#include "util.h"
#include "tiny_net.h"
#include "arp.h"
#include "tcp.h"
#include "udp.h"
#include "header.h"
base_packet *ip_process(base_packet *data)
{
    IP_HEADER *ip_header_receive = (IP_HEADER *)(data->buffer + data->offset);
    data->offset += sizeof(IP_HEADER);
    uint16_t total_len = SWAP_UINT16(ip_header_receive->total_len);
    data->len = total_len - sizeof(IP_HEADER);
    uint8_t prpotocol = ip_header_receive->protocol;
    base_packet *reply = NULL;
    // 白嫖arp缓存
    // arp_insert(ip_header_receive->source_ip, ((ETH_HEADER *)(data->buffer))->source_mac);
    switch (prpotocol)
    {
    case ICMP_TYPE: // ICMP
        reply = icmp_process(data);
        if (reply != NULL)
        {
            add_ip_header(reply, ICMP_TYPE, ip_header_receive->source_ip);
        }
        return reply;
        break;
    case TCP_TYPE: // TCP
        reply = tcp_process(data, IP_TO_UINT32(ip_header_receive->source_ip), IP_TO_UINT32(ip_header_receive->destination_ip));
        if (reply != NULL)
        {
            pseudo_header_checksum(reply, ip_header_receive);
            add_ip_header(reply, TCP_TYPE, ip_header_receive->source_ip);
            return reply;
        }
        break;
    case UDP_TYPE: // UDP
        reply = udp_process(data);
        if(reply != NULL){

        }
        break;

    default:
        break;
    }
    return reply;
}
void ip_send(base_packet *data, uint8_t protocol, uint8_t *dest_ip) //这里判断是不是tcp，来判断要不要加虚拟头是不是更好
{
    // 调用 add_ip_header 构造 IP 包
    add_ip_header(data, protocol, dest_ip);

    // 获取目标 MAC 地址
    uint8_t *dest_mac = get_mac_by_ip(dest_ip);
    if (dest_mac == NULL)
    {
        // 发送 ARP 请求后立即返回，交给后续报文或对端重传使用缓存的 MAC
        // 不能在这里阻塞等待，否则当前处理线程无法去处理 ARP 应答包
        arp_request(dest_ip, NULL);
        return;
    }

    // 向下传递数据包
    add_ethernet_header(data, dest_mac, host_mac, IP_TYPE);
    net_data_send(data);
}

void add_ip_header(base_packet *data, uint8_t protocol, uint8_t *dest_ip)
{
    // 分配新的缓冲区，用于存储 IP 头部和上层数据
    IP_HEADER *ip_packet_send = malloc(sizeof(IP_HEADER) + data->len);

    // 填充 IP 头部字段
    ip_packet_send->header_len = 0x45;                                      // 固定值：IPv4 头部长度为 20 字节（5 * 4）
    ip_packet_send->service_type = 0;                                       // 服务类型（ToS），通常设置为 0
    ip_packet_send->total_len = SWAP_UINT16(sizeof(IP_HEADER) + data->len); // 总长度（头部 + 数据）
    ip_packet_send->identification = SWAP_UINT16(0x1234);                   // 标识符，用于分片重组
    ip_packet_send->flag_fragment = SWAP_UINT16(0x4000);                    // 标志位和分片偏移量（不分片）
    ip_packet_send->ttl = 128;                                              // 生存时间（TTL）
    ip_packet_send->protocol = protocol;                                    // 上层协议类型（如 ICMP、TCP、UDP）
    memcpy(ip_packet_send->source_ip, host_ip_addr, 4);                     // 源 IP 地址
    memcpy(ip_packet_send->destination_ip, dest_ip, 4);                     // 目标 IP 地址

    // 计算校验和
    ip_packet_send->checksum = 0;
    ip_packet_send->checksum = calculate_checksum(ip_packet_send, sizeof(IP_HEADER));

    // 将上层数据复制到 IP 包中
    memcpy((uint8_t *)ip_packet_send + sizeof(IP_HEADER), data->buffer, data->len);

    // 更新 base_packet 结构体
    free(data->buffer);                       // 释放旧的缓冲区
    data->buffer = (uint8_t *)ip_packet_send; // 替换为新的缓冲区
    data->len += sizeof(IP_HEADER);           // 更新数据长度
}
// 计算伪首部计算校验和
void pseudo_header_checksum(base_packet *tcp_reply_packet, IP_HEADER *ip_header_receive)
{
    TCP_HEADER *tcp_reply = (TCP_HEADER *)(tcp_reply_packet->buffer);
    tcp_reply->checksum = 0;
    uint8_t *pseudo_header = malloc(12 + tcp_reply_packet->len);
    memcpy(pseudo_header, ip_header_receive->source_ip, 4);
    memcpy(pseudo_header + 4, ip_header_receive->destination_ip, 4);
    pseudo_header[8] = 0;
    pseudo_header[9] = 6;
    pseudo_header[10] = (uint8_t)(tcp_reply_packet->len >> 8);   // 填充高 8 位
    pseudo_header[11] = (uint8_t)(tcp_reply_packet->len & 0xFF); // 填充低 8 位
    memcpy(pseudo_header + 12, tcp_reply, tcp_reply_packet->len);
    tcp_reply->checksum = calculate_checksum(pseudo_header, 12 + tcp_reply_packet->len);
    free(pseudo_header);
}