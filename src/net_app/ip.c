#include"ip.h"
#include"config.h"
#include "icmp.h"
#include "util.h"
#include "tiny_net.h"
#include "arp.h"
void ip_process(packet* packet_receive){
    ip_packet* ip_packet_receive = (ip_packet*)packet_receive->data;//获取ip数据包结构体
    uint8_t prpotocol = ip_packet_receive->protocol;
    switch (prpotocol)
    {
    case ICMP_TYPE: // ICMP
        icmp_process(packet_receive);
        break;
    
    default:
        break;
    }
}
            //上层数据      上层协议             目的ip地址     上层数据长度
void ip_send(uint8_t* data,uint8_t* protocol,uint8_t* dest_ip,uint32_t len){ //IP层发送数据包
    ip_packet* ip_packet_send = malloc(sizeof(ip_packet)+len);
    //添加头部01000101
    ip_packet_send->header_len = 0x45;
    ip_packet_send->service_type = 0;//？？
    ip_packet_send->total_len = SWAP_UINT16(sizeof(ip_packet) + sizeof(icmp_packet));
    ip_packet_send->identification = SWAP_UINT16(0x1234);//？？
    ip_packet_send->flag_fragment = SWAP_UINT16(0x4000);//？？
    ip_packet_send->ttl = 128;
    ip_packet_send->protocol = protocol;
    memcpy(ip_packet_send->source_ip, host_ip_addr, 4);
    memcpy(ip_packet_send->destination_ip, dest_ip, 4);
    ip_packet_send->checksum = 0;
    ip_packet_send->checksum = calculate_checksum(ip_packet_send, sizeof(ip_packet));
    //ip_packet_send->checksum = SWAP_UINT16(checksum(ip_packet_send, sizeof(ip_packet) + ip_packet_send->header_len * 4));
    //拼接data
    memcpy(ip_packet_send + 1, data, len);
    uint8_t* dest_mac = get_mac_by_ip(dest_ip);
    if(dest_mac == NULL){
       arp_request(dest_ip, NULL);
       //等待arp请求完成
       uint32_t wait_time = 0;
       while(get_mac_by_ip(dest_ip) == NULL){
           Sleep(100);
           wait_time+= 100;
           if(wait_time > 1000){
               printf("Timeout when arp\n");
               return;
           }
       }
       dest_mac = get_mac_by_ip(dest_ip);
    }
    net_data_send(ip_packet_send, dest_mac,host_mac, IP_TYPE, len + sizeof(ip_packet));//向下传递
    free(ip_packet_send);
}