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

#include <stdio.h>
#include <string.h>
#include "tiny_net.h"
#include "ping.h"
#include "thread_utils.h"
#include "config.h"
#include "header.h"
#include "tcp_conversation.h"
#include "udp_conversation.h"
#include "webserver.h"
#include "tcp.h"
static void *net_run_thread(void *arg)
{
    (void)arg;
    net_run();
    return NULL;
}

static void *net_cmd_thread(void *arg)
{
    printf("支持的命令：\n");
    printf("ping <ip地址> - 发送ping请求\n");
    printf("socket <ip地址> <端口号> - 与指定IP和端口建立TCP连接\n");
    printf("ifconfig - 显示主机IP和MAC地址\n");
    printf("arp -a - 显示ARP缓存表\n");
    printf("exit - 退出程序\n");
    (void)arg;
    while (1)
    {
        printf(">");
        char cmd[1024];
        if (scanf("%s", cmd) != 1)
            continue;
        if (strcmp(cmd, "ping") == 0)
        {
            char ip[16];

            if (scanf("%15s", ip) == 1)
                send_ping(ip);
        }
        else if (strcmp(cmd, "socket") == 0)
        {
            char ip[16];
            uint32_t port;
            if (scanf("%15s", ip) == 1)
            {
                scanf("%d", &port);
                tcp_conversation(ip, port);
            }
        }
        else if (strcmp(cmd, "netstat") == 0)
        {
            tcp_show_netstat();
        }
        else if (strcmp(cmd, "udp") == 0)
        {
            char ip[16];
            uint32_t port;
            if (scanf("%15s", ip) == 1)
            {
                scanf("%d", &port);
                udp_conversation(ip, port);
            }
        }
        else if (strcmp(cmd, "exit") == 0)
        {
            printf("退出程序\n");
            exit(0);
        }
        else if (strcmp(cmd, "ifconfig") == 0)
        {
            printf("主机IP地址: %d.%d.%d.%d\n", host_ip_addr[0], host_ip_addr[1], host_ip_addr[2], host_ip_addr[3]);
            printf("主机MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n", host_mac[0], host_mac[1], host_mac[2], host_mac[3], host_mac[4], host_mac[5]);
        }
        else if (strcmp(cmd, "arp -a") == 0)
        {
         //   print_arp_cache();
        }
        else if (strcmp(cmd, "help") == 0)
        {
            printf("支持的命令：\n");
            printf("ping <ip地址> - 发送ping请求\n");
            printf("socket <ip地址> <端口号> - 与指定IP和端口建立TCP连接\n");
            printf("ifconfig - 显示主机IP和MAC地址\n");
            printf("arp -a - 显示ARP缓存表\n");
            printf("exit - 退出程序\n");
        }
        else
        {
            printf("未知命令\n");
        }
    }
    return NULL;
}
static void *net_send_thread(void *arg) // 发送数据包的线程
{
    (void)arg;
    while (1)
    {
        // 轮询队列中的数据包发送出去
        for (int i = 0; i < PACKET_QUEUE_SIZE; i++)
        {
            if (packet_queue_send[i] != NULL)
            {
                send_packet(packet_queue_send[i]);
                free(packet_queue_send[i]->buffer);
                free(packet_queue_send[i]);
                packet_queue_send[i] = NULL;
            }
        }

        // 定期检查是否有需要重传的 TCP 报文
        check_retransmit();

        Sleep(1);
    }
    return NULL;
}

static void *net_process_thread(void *arg) // 处理数据包的线程
{
    (void)arg;
    while (1)
    {
        // 一直取队列中的数据包处理
        for (int i = 0; i < PACKET_QUEUE_SIZE; i++)
        {
            if (packet_queue_receive[i] != NULL)
            {
                packet_process(packet_queue_receive[i]);
                free(packet_queue_receive[i]->buffer);
                free(packet_queue_receive[i]);
                packet_queue_receive[i] = NULL;
            }
        }
        Sleep(1);
    }

    return NULL;
}

int main(void)
{
    // 初始化协议栈
    net_init();

    // 启动 Web 服务器（监听默认端口 80）
    webserver_listen(WEBSERVER_DEFAULT_PORT);
    webserver_print_banner();

    thread_create(net_run_thread, NULL);
    thread_create(net_cmd_thread, NULL);
    thread_create(net_send_thread, NULL);
    thread_create(net_process_thread, NULL);

    // 主线程保持运行
    while (1)
        thread_sleep(1);

    return 0;
}
