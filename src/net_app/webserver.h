#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <stdint.h>

// 默认 HTTP 监听端口
#define WEBSERVER_DEFAULT_PORT 80

// 设置 HTTP 服务监听端口
void webserver_listen(uint16_t port);

// 获取当前 HTTP 服务监听端口
uint16_t webserver_get_listen_port(void);

// 在控制台打印 WebServer 启动信息
void webserver_print_banner(void);

#endif