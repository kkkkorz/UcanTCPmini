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
    tcp_connect(distination_ip_uint8, src_port, port);

    free(distination_ip_uint8);
}