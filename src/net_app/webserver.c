#include <stdio.h>

#include "webserver.h"
#include "config.h"

static uint16_t g_listen_port = WEBSERVER_DEFAULT_PORT;

void webserver_listen(uint16_t port)
{
    if (port == 0)
    {
        port = WEBSERVER_DEFAULT_PORT;
    }
    g_listen_port = port;
}

uint16_t webserver_get_listen_port(void)
{
    return g_listen_port;
}

void webserver_print_banner(void)
{
    printf("HTTP 服务器已启动，监听 %d.%d.%d.%d:%u\n",
           host_ip_addr[0], host_ip_addr[1], host_ip_addr[2], host_ip_addr[3],
           g_listen_port);
}
