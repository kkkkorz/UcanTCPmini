#include "icmp.h"
#include "config.h"
#include "util.h"
#include "ip.h"

void icmp_process(packet *packet_receive)
{ // 传入ip层数据包
    // 拆封数据包
    ip_packet *ip_packet_receive = (ip_packet *)packet_receive->data;          // 获取ip数据包
    icmp_packet *icmp_packet_receive = (icmp_packet *)(ip_packet_receive + 1); // 获取icmp数据包
    if (icmp_packet_receive->type == ICMP_ECHO_REQUEST)
    { // 类型为8则ping请求
        // 构建ping应答数据包
        icmp_packet *icmp_packet_reply = malloc(sizeof(icmp_packet));
        icmp_packet_reply->type = ICMP_ECHO_REPLY; // 设置类型为0 回复
        icmp_packet_reply->code = 0;               // 无错误
        icmp_packet_reply->checksum = 0;
        icmp_packet_reply->id = icmp_packet_receive->id;
        icmp_packet_reply->seq = icmp_packet_receive->seq;
        memcpy(icmp_packet_reply->data, icmp_packet_receive->data, sizeof(icmp_packet_receive->data)); // 拷贝数据
        icmp_packet_reply->checksum = calculate_checksum(icmp_packet_reply, sizeof(icmp_packet));
        ip_send(icmp_packet_reply, ICMP_TYPE, ip_packet_receive->source_ip, sizeof(icmp_packet));
        free(icmp_packet_reply);
    }
    else if (icmp_packet_receive->type == ICMP_ECHO_REPLY && icmp_packet_receive->id == ICMP_ID)
    { // 类型为0则ping应答且是发给自己的
        if (time(NULL) - icmp_timestamp[icmp_packet_receive->seq]  < icmp_timeout && icmp_timestamp[icmp_packet_receive->seq] && memcmp(icmp_data, icmp_packet_receive->data, sizeof(icmp_data))==0)
        {                                                                                                           // 时间未超时且id有效且数据一致
            printf("[%d] %dms\n", icmp_packet_receive->seq, time(NULL) - icmp_timestamp[icmp_packet_receive->seq]); // 打印延迟

            icmp_timestamp[icmp_packet_receive->seq] = 0; // 释放seq
        }
        else
        { // 时间超时或seq无效：丢弃
        }
    }
}

void icmp_send(uint8_t* distination_ip_uint8)
{
    // 构建icmp数据包
    icmp_packet *icmp_packet_send = malloc(sizeof(icmp_packet));
    icmp_packet_send->type = ICMP_ECHO_REQUEST;
    icmp_packet_send->code = 0;
    icmp_packet_send->checksum = 0;
    icmp_packet_send->id = ICMP_ID;                               // 设置id
    icmp_packet_send->seq = icmp_seq;                             // 设置seq
    memcpy(icmp_packet_send->data, icmp_data, sizeof(icmp_data)); // 填充固定数据
    icmp_packet_send->checksum = calculate_checksum(icmp_packet_send, sizeof(icmp_packet));
    ip_send(icmp_packet_send, ICMP_TYPE, distination_ip_uint8, sizeof(icmp_packet));
    icmp_timestamp[icmp_seq] = time(NULL);
    Sleep(1000);
    if (icmp_timestamp[icmp_seq]) // 如果seq有效则说明没有收到应答或超时
    {
        printf("Request timeout for icmp_seq %d\n", icmp_seq);
        icmp_timestamp[icmp_seq] = 0; // 释放seq
    }
    icmp_seq++;

    free(icmp_packet_send);
}