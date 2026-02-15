/**
 * 用1500行代码从0开始实现TCP/IP协议栈+WEB服务器
 *
 * 本源码旨在用最简单、最易懂的方式帮助你快速地了解TCP/IP以及HTTP工作原理的主要核心知识点。
 * 所有代码经过精心简化设计，避免使用任何复杂的数据结构和算法，避免实现其它无关紧要的细节。
 *
 * 作者：李述铜
 * 微信公众号：李述铜的嵌入式内功修炼
 * 网址：https://zw8ls.xetlk.com/s/1pF4qg
 *
 * 版权声明：源码仅供学习参考，请勿用于商业产品，不保证可靠性。二次开发或其它商用前请联系作者。
 *
 * 注意：本课程提供的tcp/ip实现很简单，只能够用于演示基本的协议运行机制。我还开发了另一套更加完整的课程，
 * 展示了一个更加完成的TCP/IP协议栈的实现。功能包括：
 * 1. IP层的分片与重组
 * 2. Ping功能的实现
 * 3. TCP的流量控制等
 * 4. 基于UDP的TFTP服务器实现
 * 5. DNS域名接触
 * 6. HTTP服务器
 * 7. 提供socket接口供应用程序使用
 * 8、代码可移植，可移植到arm和x86平台上
 * ..... 更多功能开发中...........
 * 如果你有兴趣的话，请扫仓库中的二维码，或者点击以上面的链接可找到该课程。
 */

#include "tiny_net.h"
#include "pcap_device.h"
#include "arp.h"
#include "ip.h"
#include "config.h"
#include "util.h"
#include "header.h"
#include "tcp.h"
base_packet *packet_queue_send[PACKET_QUEUE_SIZE] = {NULL}; // 发送队列
int packet_queue_send_index = -1;                           // 队尾

base_packet *packet_queue_receive[PACKET_QUEUE_SIZE]; // 接收队列
int packet_queue_receive_index = -1;                  // 队尾

void load_config()
{
    // 这里直接使用了全局变量，简化代码设计
    // get_host_ip(real_host_ip);
    // get_host_mac(host_mac);
}

void net_init()
{
    device = pcap_device_open(real_host_ip, host_mac, 1); // 打开物理网卡
    if (!device)
    {
        printf("打开网卡失败\n");
    }
    tcp_init();
}
// 接收数据包
void net_recv()
{
    uint8_t *buffer = malloc(MAX_PACKET_LEN);
    uint32_t len = pcap_device_read(device, buffer);
    if (len > 0)
    {
        base_packet *data = malloc(sizeof(base_packet));
        data->buffer = malloc(len); // 只保留数据部分
        data->len = len;
        data->offset = 0;
        memcpy(data->buffer, buffer, len);
        packet_queue_receive[++packet_queue_receive_index >= PACKET_QUEUE_SIZE ? 0 : packet_queue_receive_index] = data;
    }
    else if (len < 0)
    {
        printf("接收数据包出错\n");
    }
    free(buffer);
}

// 添加数据链路层包头
void add_ethernet_header(base_packet *data, uint8_t *destination, uint8_t *source, uint16_t ether_type)
{
    if (data == NULL)
        return;
    ETH_HEADER *packet_send = malloc(sizeof(ETH_HEADER) + data->len);
    // 填充以太网帧头部
    memcpy(packet_send->destination_mac, destination, 6);
    memcpy(packet_send->source_mac, source, 6);
    packet_send->ether_type = SWAP_UINT16(ether_type); // 处理字节序
    // 连接上层数据
    memcpy((uint8_t *)packet_send + sizeof(ETH_HEADER), data->buffer, data->len);
    // 更新 base_packet 结构体
    free(data->buffer);
    data->buffer = (uint8_t *)packet_send;
    data->len += sizeof(ETH_HEADER);
}

// 数据链路层发送，上层调用无需关心数据包头
void net_data_send(base_packet *data)
{
    // 封装为消息队列的节点
    packet_queue_send[++packet_queue_send_index >= PACKET_QUEUE_SIZE ? 0 : packet_queue_send_index] = data;
}

// 处理数据包

void packet_process(base_packet *packet_receive)
{
    // 判断数据包类型
    ETH_HEADER *header = (ETH_HEADER *)(packet_receive->buffer + packet_receive->offset);

    uint16_t type = SWAP_UINT16(header->ether_type);
    base_packet *echo_data = NULL;
    printf("数据包类型：%d\n", type);
    packet_receive->len -= sizeof(ETH_HEADER);    // 减去数据包头
    packet_receive->offset += sizeof(ETH_HEADER); // 移动数据包指针
    switch (type)
    {
    case ARP_TYPE:
        echo_data = arp_process(packet_receive);
        if (echo_data != NULL)
        {                                                                           // 直接使用这里的mac地址
            add_ethernet_header(echo_data, header->source_mac, host_mac, ARP_TYPE); // 封装为以太网帧
            net_data_send(echo_data);
        }
        break;
    case IP_TYPE:
        echo_data = ip_process(packet_receive);
        if (echo_data != NULL)
        {

            add_ethernet_header(echo_data, header->source_mac, host_mac, IP_TYPE); // 封装为以太网帧
            net_data_send(echo_data);
        }

        break;
    default:
        break;
    }
}

// 打印数据包
void print_packet(packet *packet_receive, uint32_t len)
{
    printf("数据包结构体大小：%d\n", sizeof(packet));
    uint8_t *pointer = (uint8_t *)packet_receive;
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", *(pointer + i));
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}
void send_packet(base_packet *packet)
{
    uint32_t res = pcap_device_send(device, packet->buffer, packet->len);
    if (res >= 0)
    {
        printf("发送数据包成功\n");
    }
    else
    {
        printf("发送数据包失败\n");
    }
}
// 持续运行
void net_run()
{
    while (1)
    {
        net_recv();
    }
}
