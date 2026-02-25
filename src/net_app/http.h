#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

// 前向声明，避免在头文件中引入过多依赖
typedef struct tcb_node tcb_node;

// 应用层分发，目前只处理 HTTP 请求
void app_layer_dispatch(tcb_node *tcb, char *data, uint32_t len);

// 处理单个 HTTP 请求
void handle_http_request(tcb_node *tcb, const char *request_data, uint32_t request_len);

#endif