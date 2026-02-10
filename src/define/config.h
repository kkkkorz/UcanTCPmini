#ifndef CONFIG_H
#define CONFIG_H
#include <stdint.h>
#include "pcap/pcap.h"
#include "packet.h"

//主机的IP地址和MAC地址
//static char* real_host_ip = "192.168.254.1";//模拟一个IP地址
static char* real_host_ip = "192.168.254.1";
//0A:00:27:00:00:13
//static uint8_t real_host_mac[6] = {0x0a,0x00,0x27,0x00,0x00,0x13};
// 00-1C-42-6E-B5-C4
static uint8_t real_host_mac[6] = {0x00,0x1c,0x42,0x6e,0xb5,0xc4};
//模拟一个IP地址和MAC地址
static uint8_t host_ip_addr[4] = {192,168,254,254};
static uint8_t host_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
//设备控制器
static pcap_t* device = NULL;
//数据包默认大小
static unsigned int packet_default_size = 2048;
//广播地址
static uint8_t broadcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
//packet 模板
static packet packet_template;
static arp_packet arp_packet_template;
//消息队列 暂时使用轮询
#define PACKET_QUEUE_SIZE 100
extern  packet_node* packet_queue[PACKET_QUEUE_SIZE];
extern  int  packet_queue_index;//队尾



//arp缓存表大小
#define ARP_CACHE_SIZE 10
#define HTYPE 1
#define PTYPE  0x0800
#define HLEN 6
#define PLEN 4

//0806 ARP
#define ARP_TYPE  0x0806
//0800 IP
#define IP_TYPE  0x0800
//APR 操作类型
#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY  2
//IP 协议类型
#define ICMP_TYPE  1
#define IPV4  4


//ICMP 类型
#define ICMP_ECHO_REQUEST  8
#define ICMP_ECHO_REPLY  0
//ICMP数据填充
static uint8_t icmp_data[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
//icmp包全局id
#define ICMP_ID 0x1234
//icmp包序列号
static uint16_t icmp_seq = 0;
//时间戳
static uint32_t icmp_timestamp[1<<16];
//超时时间
static uint32_t icmp_timeout = 1000;


#endif