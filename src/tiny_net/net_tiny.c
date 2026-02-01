/**
 * 用1500行代码从0开始实现TCP/IP协议栈+WEB服务器
 *
 * 本源码旨在用最简单、最易懂的方式帮助你快速地了解TCP/IP以及HTTP工作原理的主要核心知识点。
 * 所有代码经过精心简化设计，避免使用任何复杂的数据结构和算法，避免实现其它无关紧要的细节。
 *
 * 作者：李述铜
 * 微信公众号：李述铜的嵌入式内功修炼
 * 网址：https://zw8ls.xetlk.com/s/1pF4qg
 *
 * 版权声明：源码仅供学习参考，请勿用于商业产品，不保证可靠性。二次开发或其它商用前请联系作者。
 *
 * 注意：本课程提供的tcp/ip实现很简单，只能够用于演示基本的协议运行机制。我还开发了另一套更加完整的课程，
 * 展示了一个更加完成的TCP/IP协议栈的实现。功能包括：
 * 1. IP层的分片与重组
 * 2. Ping功能的实现
 * 3. TCP的流量控制等
 * 4. 基于UDP的TFTP服务器实现
 * 5. DNS域名接触
 * 6. HTTP服务器
 * 7. 提供socket接口供应用程序使用
 * 8、代码可移植，可移植到arm和x86平台上
 * ..... 更多功能开发中...........
 * 如果你有兴趣的话，请扫仓库中的二维码，或者点击以上面的链接可找到该课程。
 */
#include "tiny_net.h"
#include "pcap_device.h"
#include "arp.h"


void net_init()
{ 
    device =  pcap_device_open(host_ip,host_mac,0);//打开网卡的模拟IP地址
    if(!device){
        printf("打开网卡失败\n");
    }

    
}
void net_set_host_info(uint8_t* ip,uint8_t* mac){
     device =  pcap_device_open(ip,mac,0);
}

//创建数据包
packet* packet_creator(uint32_t size)
{
    packet* target =  malloc(sizeof(packet));
    target->data = malloc(size);
    target->size = size;
    return target;
}



//接收数据包
void net_recv(){
    packet* packet = packet_creator(packet_default_size);
    uint32_t len = pcap_device_read(device,packet->data,packet->size);
    if(len > 0){
        packet->size = len;
        print_packet(packet);
        packet_process(packet);//给协议栈解析处理
    }
    free(packet->data);
    free(packet);
    

}

//发送数据包
void net_send(packet* packet){
    pcap_device_send(device,packet->data,packet->size);
}

//处理数据包
void packet_process(packet* packet){
    //打印数据包
    printf("接收数据包：%d\n",packet->size);
    //判断数据包类型
    uint8_t typeH = packet->data[12],typeL = packet->data[13];
    uint16_t type = (typeH << 8) | typeL;  
    switch (type)
    {
    case ARP_TYPE:
        arp_process(packet);
        break;
    case IP_TYPE:
        arp_process(packet);
        break;
    default:
        break;
    } 


}
//持续运行
void net_run(){
    while(1){
        net_recv();
    }
}

//打印数据包
void print_packet(packet* packet){
    printf("接收数据包：%d\n",packet->size);
    for(int i = 0;i < packet->size;i++){
        printf("%02x ",packet->data[i]);
        if((i+1)%16 == 0){
            printf("\n");
        }
    }
    printf("\n");
}