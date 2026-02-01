#ifndef CONFIG_H
#define CONFIG_H
#include <stdint.h>
#include "pcap/pcap.h"
#include "packet.h"
//主机的IP地址和MAC地址
static char* host_ip = "192.168.254.1";//模拟一个IP地址
static uint8_t host_ip_addr[4] = {192,168,254,1};
//0A:00:27:00:00:13
static uint8_t host_mac[6] = {0xFF,0x00,0x00,0x00,0x00,0x00};
//设备控制器
static pcap_t* device = NULL;
//数据包默认大小
static unsigned int packet_default_size = 2048;
//packet 模板
static packet packet_template;
static arp_packet arp_packet_template;
//0806 ARP
#define ARP_TYPE  0x0806
//0800 IP
#define IP_TYPE  0x0800
//APR 操作类型
#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY  2
#endif