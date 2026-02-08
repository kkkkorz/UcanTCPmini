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
#include "config.h"
#include "util.h"

void net_init()
{
    device = pcap_device_open(real_host_ip, real_host_mac, 0); // 打开物理网卡
    if (!device)
    {
        printf("打开网卡失败\n");
    }
    // 数据链路层
    memcpy(packet_template.source_mac, host_mac, 6); // 填充源MAC地址
    // 网络层
    arp_packet_template.htype = SWAP_UINT16((uint16_t)1);
    arp_packet_template.ptype = SWAP_UINT16((uint16_t)0x0800);
    arp_packet_template.hlen = (uint8_t)6;
    arp_packet_template.plen = (uint8_t)4;
    memcpy(arp_packet_template.sender_mac, host_mac, 6);
    memcpy(arp_packet_template.sender_ip, host_ip_addr, 4);
}
// 接收数据包
void net_recv()
{
    packet *packet_receive = malloc(sizeof(packet));
    uint32_t len = pcap_device_read(device, packet_receive, sizeof(packet));
    // print_packet(packet_receive,len);
    if (len > 0)
    {
        // print_packet(packet_receive,len);
        packet_process(packet_receive);
    }
    else if (len < 0)
    {
        printf("接收数据包出错\n");
    }
    free(packet_receive);
}

// 发送数据包
void net_send(packet *packet_send, uint32_t len)
{

    uint32_t res = pcap_device_send(device, packet_send, len);
    if (res >= 0)
    {
        printf("发送数据包成功\n");
    }
    else
    {
        printf("发送数据包失败\n");
    }
}

// 数据链路层发送，上层调用无需关心数据包头
void net_data_send(packet *up_packet_send, uint8_t *destination, uint8_t *source, uint16_t ether_type, uint32_t len)
{
    packet *packet_send = (packet *)malloc(len + 14);
    // 这里增加数据链路层的包头
    memcpy(packet_send->destination_mac, destination, 6);
    memcpy(packet_send->source_mac, source, 6);
    packet_send->ether_type =SWAP_UINT16(ether_type);//处理UINT16
    // 连接数据
    memcpy(packet_send->data, up_packet_send, len);
    uint32_t res = pcap_device_send(device, packet_send, len + 14); // 14是数据链路层头
    if (res >= 0)
    {
        printf("发送数据包成功\n");
    }
    else
    {
        printf("发送数据包失败\n");
    }
}

// 处理数据包
void packet_process(packet *packet_receive)
{
    // 判断数据包类型
    uint16_t type = packet_receive->ether_type;
    type = SWAP_UINT16(type);
    printf("数据包类型：%d\n", type);
    switch (type)
    {
    case ARP_TYPE:
        arp_process(packet_receive);
        break;
    case IP_TYPE:
        // arp_process(packet_receive);
        break;
    default:
        break;
    }
}
// 持续运行
void net_run()
{
    while (1)
    {
        net_recv();
        Sleep(10);
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