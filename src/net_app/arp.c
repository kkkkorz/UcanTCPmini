#include"arp.h"
#include "stdlib.h"
#include "config.h"
 
void arp_init()
{



    //初始化ARP缓存表
}

void arp_process(packet* packet_receive)//解析为ARP数据包
{ 
    arp_packet *arp = (arp_packet*)malloc(sizeof(arp_packet));
    memcpy(arp,packet_receive->data + 14,sizeof(arp_packet));
    if(memcmp(arp->target_ip,host_ip_addr,4) == 0){
        if(arp->operation == 1){//ARP请求
            //发送ARP应答
            arp_reply(packet_receive);
        }
        else if(arp->operation == 2){//ARP应答
            //保存在ARP缓存表
        }
    }
    free(arp);
}

void arp_reply(packet* packet_receive)//发送ARP数据包
{ 
    //封装数据链路层数据包头
    packet* packet_reply = malloc(sizeof(arp_packet));
    memcpy(packet_reply, &packet_template, sizeof(packet_template));//复制模板填充源mac地址
    memcpy(packet_reply, packet_receive+6, 6);//复制源mac地址作为目的mac地址
    packet_reply->ether_type = ARP_TYPE;//设置协议类型为ARP



    //封装ARP数据包
    arp_packet *arp = (arp_packet*)malloc(sizeof(arp_packet));
    memcpy(arp,&arp_packet_template,sizeof(arp_packet));//复制模板填充各种信息
    arp->operation = ARP_OP_REPLY;//设置操作类型为应答
    memcpy(arp->sender_mac,host_mac,6);//设置发送方MAC地址为当前主机的MAC地址
    memcpy(arp->sender_ip,host_ip_addr,4);//设置发送方IP地址为当前主机的IP地址
    memcpy(arp->target_mac,packet_receive->data+6,6);//设置目标方MAC地址为发送方MAC地址
    memcpy(arp->target_ip,packet_receive->data+26,4);//设置目标方IP地址为发送方IP地址

    //将ARP数据包写入数据包
    memcpy(packet_reply->data,arp,sizeof(arp_packet));
    net_send(packet_reply);//发送数据包
    free(arp);
    free(packet_reply);

}

void arp_print(arp_packet* arp)
{ 
    printf("ARP: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",arp->sender_mac[0],arp->sender_mac[1],arp->sender_mac[2],arp->sender_mac[3],arp->sender_mac[4],arp->sender_mac[5],arp->sender_mac[6],arp->sender_mac[7],arp->sender_mac[8]);
    printf("ARP: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",arp->target_mac[0],arp->target_mac[1],arp->target_mac[2],arp->target_mac[3],arp->target_mac[4],arp->target_mac[5],arp->target_mac[6],arp->target_mac[7],arp->target_mac[8]);
    printf("ARP: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",arp->sender_ip[0],arp->sender_ip[1],arp->sender_ip[2],arp->sender_ip[3],arp->target_ip[0],arp->target_ip[1],arp->target_ip[2],arp->target_ip[3]);
    printf("ARP: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",arp->target_ip[0],arp->target_ip[1],arp->target_ip[2],arp->target_ip[3]);
    printf("ARP: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",arp->htype,arp->ptype,arp->hlen,arp->plen,arp->operation);
    printf("\n");

}