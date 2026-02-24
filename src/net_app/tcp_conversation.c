#include "tcp_conversation.h"
#include "util.h"
#include "stdio.h"
#include "tcp.h"

void tcp_conversation(char *ip, uint16_t port)
{
    printf("Connecting to %s:%d...\n", ip, port);

    uint8_t *distination_ip_uint8 = malloc(4);
    ip_str_to_uint8(distination_ip_uint8, ip);

    uint16_t src_port = 8888;

    // 1. 发起握手
    tcb_node *tcb_node_res = tcp_connect(distination_ip_uint8, src_port, port);
    if (tcb_node_res == NULL)
    {
        printf("tcp_connect error\n");
        free(distination_ip_uint8);
        return;
    }

    // 2. 交互循环
    while (1)
    {
        char buf[1024];
        printf("\n(Type 'exit' to close) > ");
        scanf("%s", buf);

        // 检查用户是否想要断开连接
        if (strcmp(buf, "exit") == 0 || strcmp(buf, "quit") == 0)
        {
            printf("[System] Closing TCP connection...\n");

            // 3. 调用主动关闭函数（发送第一个 FIN）
            tcp_close(tcb_node_res);

            // 注意：在真实的协议栈中，这里不该直接 break，
            // 应该继续循环等待对方的 ACK 和 FIN。
            // 但作为简单的控制台演示，我们可以退出输入循环。
            break;
        }

        // 正常发送数据
        tcp_send_data(tcb_node_res, buf, strlen(buf));
    }

    // 4. 清理资源
    // 这里的 free 比较微妙，如果 tcp_process 还会用到这个 TCB，
    // 建议由协议栈的状态机在检测到 TCP_STATE_CLOSED 后统一清理。
    free(distination_ip_uint8);
    printf("[System] Conversation loop ended.\n");
}