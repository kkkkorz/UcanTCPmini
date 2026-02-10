#include"ping.h"
#include "arp.h"
#include "util.h"
#include "icmp.h"
#include "config.h"

void send_ping(char* ip) { 
    uint8_t* distination_ip_uint8  = malloc(4);
    ip_str_to_uint8(distination_ip_uint8,ip);//转为数字
    uint8_t times = 4;//发送ping请求的次数
    for (int i = 0; i < times; i++)
    {
        icmp_send(distination_ip_uint8);//发送ping请求
    }
    free(distination_ip_uint8);
    return;
}