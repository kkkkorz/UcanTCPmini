#include"ping.h"
#include "arp.h"
#include "util.h"

void send_ping(char* ip) { 
    uint8_t* distination_ip_uint8 = ip_str_to_uint8(ip);//转为数字
    uint8_t* distination_mac =  arp_request(distination_ip_uint8,NULL);//获取目的ip的mac地址
    //构建ping数据包
    return;
}