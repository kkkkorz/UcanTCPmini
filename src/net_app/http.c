#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "http.h"
#include "tcp.h"

// 假设 HTML/CSS/JS/图片等静态资源都放在工程目录下的 www 目录
// 由于可执行程序的工作目录可能是 build/ 或 build/Debug/，这里同时尝试多个相对路径
static const char *HTTP_STATIC_ROOTS[] = {
    "./www",
    "../www",
    "../../www"};

// 根据文件扩展名推断简单的 Content-Type
static const char *http_get_content_type(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path)
    {
        return "application/octet-stream";
    }

    if (strcmp(dot, ".html") == 0 || strcmp(dot, ".htm") == 0)
        return "text/html; charset=utf-8";
    if (strcmp(dot, ".css") == 0)
        return "text/css; charset=utf-8";
    if (strcmp(dot, ".js") == 0)
        return "application/javascript; charset=utf-8";
    if (strcmp(dot, ".png") == 0)
        return "image/png";
    if (strcmp(dot, ".jpg") == 0 || strcmp(dot, ".jpeg") == 0)
        return "image/jpeg";
    if (strcmp(dot, ".gif") == 0)
        return "image/gif";

    return "application/octet-stream";
}

// 根据不同的相对根目录尝试打开静态文件，兼容从项目根目录或 build 目录启动的情况
static FILE *http_try_open_file(const char *path, char *full_path, size_t full_path_size)
{
    for (size_t i = 0; i < sizeof(HTTP_STATIC_ROOTS) / sizeof(HTTP_STATIC_ROOTS[0]); ++i)
    {
        snprintf(full_path, full_path_size, "%s%s", HTTP_STATIC_ROOTS[i], path);
        FILE *file = fopen(full_path, "rb");
        if (file != NULL)
        {
            return file;
        }
    }

    // 全部尝试失败时，返回 NULL，full_path 中保留最后一次尝试的路径用于日志打印
    return NULL;
}

void app_layer_dispatch(tcb_node *tcb, char *data, uint32_t len)
{
    if (tcb == NULL || data == NULL || len < 3)
    {
        return;
    }

    // 简单判断：如果前 3 个字节是 "GET"，说明是 HTTP 请求
    if (strncmp(data, "GET", 3) == 0)
    {
        printf("[HTTP] 收到 GET 请求\n");
        handle_http_request(tcb, data, len);
    }
}

void handle_http_request(tcb_node *tcb, const char *request_data, uint32_t request_len)
{
    if (tcb == NULL || request_data == NULL || request_len == 0)
    {
        return;
    }

    // 复制一份请求首行到本地缓冲区，确保以 '\0' 结尾，避免越界
    char line[512] = {0};
    uint32_t copy_len = request_len < (sizeof(line) - 1) ? request_len : (uint32_t)(sizeof(line) - 1);
    memcpy(line, request_data, copy_len);
    line[copy_len] = '\0';

    char method[10] = {0};
    char path[256] = {0};
    char protocol[20] = {0};

    // 解析请求行：方法 路径 协议
    if (sscanf(line, "%9s %255s %19s", method, path, protocol) < 3)
    {
        const char *bad_request =
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        tcp_send_data(tcb, (char *)bad_request, (uint32_t)strlen(bad_request));
        return;
    }

    // 目前只处理 GET，其它方法直接返回 405
    if (strcmp(method, "GET") != 0)
    {
        const char *method_not_allowed =
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        tcp_send_data(tcb, (char *)method_not_allowed, (uint32_t)strlen(method_not_allowed));
        return;
    }

    // 访问根目录时，默认跳转到 /index.html
    if (strcmp(path, "/") == 0)
    {
        strcpy(path, "/index.html");
    }

    // 拼接真实文件路径并尝试打开（兼容不同工作目录）
    char full_path[512];
    FILE *file = http_try_open_file(path, full_path, sizeof(full_path));
    if (file == NULL)
    {
        printf("[HTTP] 文件未找到: %s\n", full_path);
        const char *not_found_body = "<h1>404 Not Found</h1>";
        char header[256];
        int header_len = snprintf(header, sizeof(header),
                                  "HTTP/1.1 404 Not Found\r\n"
                                  "Content-Type: text/html; charset=utf-8\r\n"
                                  "Content-Length: %zu\r\n"
                                  "Connection: close\r\n"
                                  "\r\n",
                                  strlen(not_found_body));
        tcp_send_data(tcb, header, (uint32_t)header_len);
        tcp_send_data(tcb, (char *)not_found_body, (uint32_t)strlen(not_found_body));
        return;
    }

    // 获取文件大小
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        const char *server_error =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        tcp_send_data(tcb, (char *)server_error, (uint32_t)strlen(server_error));
        return;
    }

    long file_size = ftell(file);
    if (file_size < 0)
    {
        fclose(file);
        const char *server_error =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        tcp_send_data(tcb, (char *)server_error, (uint32_t)strlen(server_error));
        return;
    }

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        const char *server_error =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        tcp_send_data(tcb, (char *)server_error, (uint32_t)strlen(server_error));
        return;
    }

    size_t content_len = (size_t)file_size;
    char *file_buf = (char *)malloc(content_len);
    if (!file_buf)
    {
        fclose(file);
        const char *server_error =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        tcp_send_data(tcb, (char *)server_error, (uint32_t)strlen(server_error));
        return;
    }

    size_t read_len = fread(file_buf, 1, content_len, file);
    fclose(file);

    if (read_len != content_len)
    {
        free(file_buf);
        const char *server_error =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        tcp_send_data(tcb, (char *)server_error, (uint32_t)strlen(server_error));
        return;
    }

    const char *content_type = http_get_content_type(path);

    // 构造并发送响应头
    char header[256];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: %s\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              content_type, content_len);

    tcp_send_data(tcb, header, (uint32_t)header_len);

    // 将文件内容分块发送，避免单个以太网帧过大导致发送失败
    const uint32_t CHUNK_SIZE = 1024;
    size_t offset = 0;
    while (offset < content_len)
    {
        uint32_t to_send = (uint32_t)((content_len - offset) > CHUNK_SIZE
                                          ? CHUNK_SIZE
                                          : (content_len - offset));
        tcp_send_data(tcb, file_buf + offset, to_send);
        offset += to_send;
    }

    free(file_buf);

    // 当前实现采用 Connection: close，每次完成一个 HTTP 响应后，
    // 主动发起 TCP 关闭，避免浏览器长时间复用旧连接导致的等待。
    tcp_close(tcb);

    printf("[HTTP] 已发送文件: %s (%zu bytes, %s)\n", full_path, content_len, content_type);
}

