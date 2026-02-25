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
#include "ip.h"
#include "config.h"
#include "util.h"
#include "header.h"
#include "tcp.h"
#include "cJSON.h"
base_packet *packet_queue_send[PACKET_QUEUE_SIZE] = {NULL}; // 发送队列
int packet_queue_send_index = -1;                           // 队尾

base_packet *packet_queue_receive[PACKET_QUEUE_SIZE]; // 接收队列
int packet_queue_receive_index = -1;                  // 队尾

// 读取文件内容到字符串
char *read_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        printf("无法打开文件: %s\n", filename);
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        printf("读取文件失败（fseek 出错）: %s\n", filename);
        fclose(file);
        return NULL;
    }

    long file_size = ftell(file);
    if (file_size < 0)
    {
        printf("读取文件大小失败: %s\n", filename);
        fclose(file);
        return NULL;
    }

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        printf("读取文件失败（fseek 出错）: %s\n", filename);
        fclose(file);
        return NULL;
    }

    char *buffer = (char *)malloc((size_t)file_size + 1);
    if (!buffer)
    {
        printf("内存分配失败，无法读取文件: %s\n", filename);
        fclose(file);
        return NULL;
    }

    size_t read_len = fread(buffer, 1, (size_t)file_size, file);
    if (read_len != (size_t)file_size)
    {
        printf("读取文件内容不完整: %s\n", filename);
        // 这里仍然返回已经读取的内容，方便调试使用
    }
    buffer[read_len] = '\0';
    fclose(file);

    return buffer;
}

void load_config()
{
    char *json_data = read_file("..\\src\\config.json");
    if (json_data == NULL)
    {
        printf("配置文件读取失败，使用默认配置\n");
        return;
    }

    cJSON *config = cJSON_Parse(json_data);
    if (config == NULL)
    {
        printf("配置文件解析失败，JSON 格式错误\n");
        free(json_data);
        return;
    }
    cJSON *hi = cJSON_GetObjectItem(config, "host_ip");
    cJSON *hm = cJSON_GetObjectItem(config, "host_mac");
    cJSON *rhi = cJSON_GetObjectItem(config, "real_host_ip");
    cJSON *rhm = cJSON_GetObjectItem(config, "real_host_mac");
    if (hi && hm && rhi && rhm &&
        cJSON_IsString(hi) && cJSON_IsString(hm) &&
        cJSON_IsString(rhi) && cJSON_IsString(rhm))
    {
        // 解析主机 IP
        if (sscanf(hi->valuestring, "%hhu.%hhu.%hhu.%hhu",
                   &host_ip_addr[0], &host_ip_addr[1],
                   &host_ip_addr[2], &host_ip_addr[3]) != 4)
        {
            printf("host_ip 解析失败，保持默认值\n");
        }

        // 解析物理网卡 IP 字符串，拷贝到全局缓冲区
        strncpy(real_host_ip, rhi->valuestring, sizeof(real_host_ip) - 1);
        real_host_ip[sizeof(real_host_ip) - 1] = '\0';

        // 解析 MAC 地址
        if (sscanf(hm->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &host_mac[0], &host_mac[1], &host_mac[2],
                   &host_mac[3], &host_mac[4], &host_mac[5]) != 6)
        {
            printf("host_mac 解析失败，保持默认值\n");
        }

        if (sscanf(rhm->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &real_host_mac[0], &real_host_mac[1], &real_host_mac[2],
                   &real_host_mac[3], &real_host_mac[4], &real_host_mac[5]) != 6)
        {
            printf("real_host_mac 解析失败，保持默认值\n");
        }
    }
    else
    {
        printf("配置文件字段缺失或类型错误，使用默认配置\n");
    }

    cJSON_Delete(config);
    free(json_data);
}

void net_init()
{
    load_config();                                        // 加载配置文件
    device = pcap_device_open(real_host_ip, host_mac, 1); // 打开物理网卡
    if (!device)
    {
        printf("打开网卡失败\n");
    }
    tcp_init();
}
// 接收数据包
void net_recv()
{
    uint8_t *buffer = (uint8_t *)malloc(MAX_PACKET_LEN);
    if (!buffer)
    {
        printf("内存分配失败，无法接收数据包\n");
        return;
    }

    uint32_t len = pcap_device_read(device, buffer);
    if (len > 0)
    {
        base_packet *data = (base_packet *)malloc(sizeof(base_packet));
        if (!data)
        {
            printf("内存分配失败，丢弃接收到的数据包\n");
            free(buffer);
            return;
        }

        data->buffer = (uint8_t *)malloc(len); // 只保留数据部分
        if (!data->buffer)
        {
            printf("内存分配失败，丢弃接收到的数据包\n");
            free(data);
            free(buffer);
            return;
        }

        data->len = len;
        data->offset = 0;
        memcpy(data->buffer, buffer, len);

        // 简单的循环队列，下标安全取模
        packet_queue_receive_index = (packet_queue_receive_index + 1) % PACKET_QUEUE_SIZE;
        if (packet_queue_receive[packet_queue_receive_index] != NULL)
        {
            // 队列满时简单丢弃最旧的数据包，避免内存泄漏
            free(packet_queue_receive[packet_queue_receive_index]->buffer);
            free(packet_queue_receive[packet_queue_receive_index]);
        }
        packet_queue_receive[packet_queue_receive_index] = data;
    }
    else if ((int32_t)len < 0)
    {
        printf("接收数据包出错\n");
    }
    free(buffer);
}

// 添加数据链路层包头
void add_ethernet_header(base_packet *data, uint8_t *destination, uint8_t *source, uint16_t ether_type)
{
    if (data == NULL)
        return;
    ETH_HEADER *packet_send = malloc(sizeof(ETH_HEADER) + data->len);
    // 填充以太网帧头部
    memcpy(packet_send->destination_mac, destination, 6);
    memcpy(packet_send->source_mac, source, 6);
    packet_send->ether_type = SWAP_UINT16(ether_type); // 处理字节序
    // 连接上层数据
    memcpy((uint8_t *)packet_send + sizeof(ETH_HEADER), data->buffer, data->len);
    // 更新 base_packet 结构体
    free(data->buffer);
    data->buffer = (uint8_t *)packet_send;
    data->len += sizeof(ETH_HEADER);
}

// 数据链路层发送，上层调用无需关心数据包头
void net_data_send(base_packet *data)
{
    if (data == NULL)
    {
        return;
    }

    // 简单的循环队列，下标安全取模
    packet_queue_send_index = (packet_queue_send_index + 1) % PACKET_QUEUE_SIZE;
    if (packet_queue_send[packet_queue_send_index] != NULL)
    {
        // 队列满时丢弃旧数据，避免内存泄漏
        free(packet_queue_send[packet_queue_send_index]->buffer);
        free(packet_queue_send[packet_queue_send_index]);
    }
    packet_queue_send[packet_queue_send_index] = data;
}

// 处理数据包

void packet_process(base_packet *packet_receive)
{
    if (packet_receive == NULL || packet_receive->buffer == NULL || packet_receive->len < sizeof(ETH_HEADER))
    {
        return;
    }

    // 判断数据包类型
    ETH_HEADER *header = (ETH_HEADER *)(packet_receive->buffer + packet_receive->offset);

    uint16_t type = SWAP_UINT16(header->ether_type);
    base_packet *echo_data = NULL;
    packet_receive->len -= sizeof(ETH_HEADER);    // 减去数据包头
    packet_receive->offset += sizeof(ETH_HEADER); // 移动数据包指针
    switch (type)
    {
    case ARP_TYPE:
        echo_data = arp_process(packet_receive);
        if (echo_data != NULL)
        {                                                                           // 直接使用这里的mac地址
            add_ethernet_header(echo_data, header->source_mac, host_mac, ARP_TYPE); // 封装为以太网帧
            net_data_send(echo_data);
        }
        break;
    case IP_TYPE:
        echo_data = ip_process(packet_receive);
        if (echo_data != NULL)
        {

            add_ethernet_header(echo_data, header->source_mac, host_mac, IP_TYPE); // 封装为以太网帧
            net_data_send(echo_data);
        }

        break;
    default:
        break;
    }
}

// 打印数据包
void print_packet(packet *packet_receive, uint32_t len)
{
    printf("数据包结构体大小：%d\n", sizeof(packet));
    uint8_t *pointer = (uint8_t *)packet_receive;
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", *(pointer + i));
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}
void send_packet(base_packet *packet)
{
    uint32_t res = pcap_device_send(device, packet->buffer, packet->len);
    if (res >= 0)
    {
       
    }
    else
    {
        printf("发送数据包失败\n");
    }
}
// 持续运行
void net_run()
{
    while (1)
    {
        net_recv();
    }
}
