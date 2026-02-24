#include "udp_conversation.h"
#include "udp.h"

void udp_conversation(char *ip, uint32_t port)
{
    printf("--- UDP Mode ---\n");
    printf("Target IP: %s, Port: %d\n", ip, port);

    uint8_t *destination_ip_uint8 = malloc(4);
    ip_str_to_uint8(destination_ip_uint8, ip);
    
    uint16_t src_port = 8887;

    while (1)
    {
        char buf[1024];
        printf("UDP > ");
        if (scanf("%s", buf) == EOF) break;

        // 直接调用发送函数，无需建立连接
        udp_send_data(destination_ip_uint8, src_port, (uint16_t)port, buf, strlen(buf));
        printf("Sent %zu bytes to %s:%d\n", strlen(buf), ip, port);
    }

    free(destination_ip_uint8);
}