#include "tcp_conversation.h"
#include "util.h"
#include "stdio.h"
#include "tcp.h"

void tcp_conversation(char *ip, uint16_t port)
{
    printf("ip: %s\n", ip);
    printf("port: %d\n", port);
    uint8_t *distination_ip_uint8 = malloc(4);
    ip_str_to_uint8(distination_ip_uint8, ip); // 转为数字
    uint16_t src_port = 8888;
    tcb_node *tcb_node_res = tcp_connect(distination_ip_uint8, src_port, port);
    if(tcb_node_res == NULL)
    {
        printf("tcp_connect error\n");
        return;
    }
    //输入并发送数据
    while (1)
    {
        char buf[1024];
        printf(">");
        scanf("%s", buf);
        tcp_send_data(tcb_node_res, buf, strlen(buf));
    }

    free(distination_ip_uint8);
}