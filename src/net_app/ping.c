#include"ping.h"
#include "arp.h"


void send_ping(uint8_t* ip) { 
    uint8_t* distination_mac =  arp_request(ip,NULL);//获取目的ip的mac地址
    //构建ping数据包
    return;
}