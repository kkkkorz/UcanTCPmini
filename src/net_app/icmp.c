#include "icmp.h"
#include "config.h"
#include "util.h"
#include "ip.h"



void icmp_process(packet* packet_receive){ //传入ip层数据包
    //拆封数据包
    ip_packet* ip_packet_receive = (ip_packet*)packet_receive->data;//获取ip数据包
    icmp_packet* icmp_packet_receive = (icmp_packet*)(ip_packet_receive+1);//获取icmp数据包
    if(icmp_packet_receive->type == ICMP_ECHO_REQUEST){//类型为8则ping请求
        //构建ping应答数据包
        icmp_packet* icmp_packet_reply = malloc(sizeof(icmp_packet));
        icmp_packet_reply->type = ICMP_ECHO_REPLY;  //设置类型为0 回复
        icmp_packet_reply->code = 0; //无错误
        icmp_packet_reply->checksum = 0;
        icmp_packet_reply->id = icmp_packet_receive->id;
        icmp_packet_reply->seq = icmp_packet_receive->seq;
        memcpy(icmp_packet_reply->data,icmp_packet_receive->data,sizeof(icmp_packet_receive->data));//拷贝数据
        icmp_packet_reply->checksum = calculate_checksum(icmp_packet_reply,sizeof(icmp_packet));
        ip_send(icmp_packet_reply, ICMP_TYPE, ip_packet_receive->source_ip,sizeof(icmp_packet));
        free(icmp_packet_reply);
    }
}