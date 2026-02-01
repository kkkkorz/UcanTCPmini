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
 * 如果你有兴趣的话，请扫仓库中的d二维码，或者点击以上面的链接可找到该课程。
 */
#ifndef TINE_NET_H
#define TINE_NET_H
#include <stdint.h>
#include "pcap/pcap.h"
#include "packet_define.h"
//主机的IP地址和MAC地址
static char* host_ip = "192.168.254.1";//模拟一个IP地址
//0A:00:27:00:00:13
static uint8_t host_mac[6] = {0x0A,0x00,0x27,0x00,0x00,0x13};
//设备控制器
static pcap_t* device = NULL;

//数据包默认大小
static unsigned int packet_default_size = 2048;

//0806 ARP
#define ARP_TYPE  0x0806
//0800 IP
#define IP_TYPE  0x0800



//数据包初始化

packet* packet_creator(uint32_t size);



//初始化协议栈
void net_init();

//设置主机的IP地址和MAC地址
void net_set_host_info(uint8_t* ip,uint8_t* mac);

//接收数据包
void net_recv(packet* packet);

//发送数据包
void net_send(packet* packet);

//处理数据包
void packet_process(packet* packet);

//运行协议栈
void net_run();

//打印数据包
void print_packet(packet* packet);


#endif // XNET_TINY_H

