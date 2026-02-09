#include"ping.h"
#include "arp.h"
#include "util.h"
#include "icmp.h"

void send_ping(char* ip) { 
    uint8_t* distination_ip_uint8  = malloc(4);
    ip_str_to_uint8(distination_ip_uint8,ip);//转为数字
    uint8_t* distination_mac_uint8 = get_mac_by_ip(distination_ip_uint8); //从arp缓存表中获取目的ip的mac地址
    if (distination_mac_uint8 == NULL) { //目的ip的mac地址为空则发送arp请求
        distination_mac_uint8 = arp_request(distination_ip_uint8,NULL);
    }
    free(distination_ip_uint8);
    //构建ping数据包
    return;
}