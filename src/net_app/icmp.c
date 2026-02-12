#include "icmp.h"
#include "config.h"
#include "util.h"
#include "ip.h"
#include "header.h"
#include "time.h"

base_packet* icmp_process(base_packet *data)
{ // 传入ip层数据包
    // 拆封数据包
    ICMP_HEADER* icmp_packet_receive = (ICMP_HEADER *)(data->buffer+data->offset);
  //  icmp_packet *icmp_packet_receive = (icmp_packet *)(ip_packet_receive + 1); // 获取icmp数据包
    if (icmp_packet_receive->type == ICMP_ECHO_REQUEST)
    { // 类型为8则ping请求
        // 构建ping应答数据包
        ICMP_HEADER *icmp_packet_reply = malloc(data->len);//回应数据包的长度和对方的数据包长度一致
        icmp_packet_reply->type = ICMP_ECHO_REPLY; // 设置类型为0 回复
        icmp_packet_reply->code = 0;               // 无错误
        icmp_packet_reply->checksum = 0;
        icmp_packet_reply->id = icmp_packet_receive->id;
        icmp_packet_reply->seq = icmp_packet_receive->seq;
        memcpy(icmp_packet_reply+1, icmp_packet_receive+1, data->len-sizeof(ICMP_HEADER)); // 拷贝数据
        icmp_packet_reply->checksum = calculate_checksum((uint16_t*)icmp_packet_reply,data->len);

        base_packet* reply_packet = malloc(sizeof(base_packet));
        reply_packet->buffer = (uint8_t*)icmp_packet_reply;
        reply_packet->len = data->len;
        return reply_packet;
    }
    else if (icmp_packet_receive->type == ICMP_ECHO_REPLY && icmp_packet_receive->id == ICMP_ID)
    { // 类型为0则ping应答且是发给自己的
        if (time(NULL) - icmp_timestamp[icmp_packet_receive->seq]  < icmp_timeout && icmp_timestamp[icmp_packet_receive->seq] && memcmp(icmp_data, icmp_packet_receive+1, sizeof(icmp_data))==0)
        {                                                                                                           // 时间未超时且id有效且数据一致
            printf("[%d] %dms\n", icmp_packet_receive->seq, (int)(time(NULL) - icmp_timestamp[icmp_packet_receive->seq])); // 打印延迟

            icmp_timestamp[icmp_packet_receive->seq] = 0; // 释放seq
        }
        else
        { // 时间超时或seq无效：丢弃
        }
        return NULL;
    }
}

void icmp_send(uint8_t* distination_ip_uint8)
{
    // 构建icmp数据包
    ICMP_HEADER *icmp_packet_send = malloc(sizeof(ICMP_HEADER)+sizeof(icmp_data));
    icmp_packet_send->type = ICMP_ECHO_REQUEST;
    icmp_packet_send->code = 0;
    icmp_packet_send->checksum = 0;
    icmp_packet_send->id = ICMP_ID;                               // 设置id
    icmp_packet_send->seq = icmp_seq;                             // 设置seq
    memcpy(icmp_packet_send+1, icmp_data, sizeof(icmp_data)); // 填充数据
    icmp_packet_send->checksum = calculate_checksum(icmp_packet_send, sizeof(ICMP_HEADER)+sizeof(icmp_data));
    
    // 构建数据包
    base_packet* icmp_packet = malloc(sizeof(base_packet));
    icmp_packet->buffer = icmp_packet_send;
    icmp_packet->len = sizeof(ICMP_HEADER)+sizeof(icmp_data);
    
    
    
    ip_send(icmp_packet, ICMP_TYPE, distination_ip_uint8);

    icmp_timestamp[icmp_seq] = time(NULL);
    Sleep(1000);
    if (icmp_timestamp[icmp_seq]) // 如果seq有效则说明没有收到应答或超时
    {
        printf("Request timeout for icmp_seq %d\n", icmp_seq);
        icmp_timestamp[icmp_seq] = 0; // 释放seq
    }
    icmp_seq++;
}