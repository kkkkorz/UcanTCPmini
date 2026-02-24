
#include "udp.h"
#include "ip.h"
#include "header.h"
#include "util.h"
// 仿照 add_tcp_header，实现 add_udp_header
void add_udp_header(base_packet *udp_packet, UDP_HEADER *header, base_packet *data)
{
    uint32_t header_len = sizeof(UDP_HEADER);
    uint32_t data_len = data ? data->len : 0;

    udp_packet->buffer = malloc(header_len + data_len);
    udp_packet->len = header_len + data_len;
    udp_packet->offset = 0;

    // 拷贝头部
    memcpy(udp_packet->buffer, header, header_len);
    // 拷贝数据
    if (data_len > 0)
    {
        memcpy(udp_packet->buffer + header_len, data->buffer, data_len);
    }
}

// 封装发送函数，模仿 tcp_send_data
void udp_send_data(uint8_t *dest_ip, uint16_t src_port, uint16_t dst_port, char *payload_data, uint32_t data_len)
{
    // 1. 构造 UDP 首部
    UDP_HEADER udp_header;
    udp_header.source_port = SWAP_UINT16(src_port);
    udp_header.destination_port = SWAP_UINT16(dst_port);
    udp_header.length = SWAP_UINT16(sizeof(UDP_HEADER) + data_len);
    udp_header.checksum = 0; // 预留位置用于校验

    // 2. 准备 payload
    base_packet payload = {(uint8_t *)payload_data, data_len, 0};
    base_packet *full_packet = malloc(sizeof(base_packet));

    // 3. 封装包头和数据
    add_udp_header(full_packet, &udp_header, &payload);

    // 4. 校验和计算 (UDP 同样需要伪首部校验)
    // 仿照你在 TCP 中的校验逻辑
    IP_HEADER ip_info;
    memcpy(ip_info.destination_ip, dest_ip, 4);
    memcpy(ip_info.source_ip, host_ip_addr, 4); // 假设 host_ip_addr 全局可用

    // 调用你已有的伪首部校验函数
    pseudo_header_checksum(full_packet, &ip_info);

    // 5. 调用 IP 层发送
    ip_send(full_packet, 17, dest_ip); // 17 是 UDP 的协议号

    // 6. 清理内存 (注意：这取决于你的 ip_send 是否会自行 free buffer)
    // free(full_packet->buffer);
    // free(full_packet);
}

base_packet *udp_process(base_packet *data)
{
    // 1. 获取 UDP 首部指针
    // 注意：进入此函数时，data->offset 应当已经由 ip_process 调整为指向 UDP 头部起始位置
    UDP_HEADER *udp_hdr = (UDP_HEADER *)(data->buffer + data->offset);

    // 2. 提取并转换字节序 (网络字节序 -> 主机字节序)
    uint16_t src_port = SWAP_UINT16(udp_hdr->source_port);
    uint16_t dst_port = SWAP_UINT16(udp_hdr->destination_port);
    uint16_t udp_len = SWAP_UINT16(udp_hdr->length);

    // 3. 安全校验：确保包长度合法（UDP 首部固定 8 字节）
    if (udp_len < sizeof(UDP_HEADER))
    {
        return NULL;
    }

    // 4. 计算有效载荷 (Payload) 的长度
    uint32_t payload_len = udp_len - sizeof(UDP_HEADER);

    // 5. 更新 base_packet 状态
    // 将 offset 移动到数据区起始位置，并将 len 更新为纯数据的长度
    data->offset += sizeof(UDP_HEADER);
    data->len = payload_len;

    // 6. 显示收到的 UDP 消息
    printf("\n[UDP Received] %u -> %u | Length: %u\n", src_port, dst_port, payload_len);

    // 打印数据内容（以字符串形式展示，处理不可见字符）
    printf("Content: ");
    uint8_t *payload_ptr = data->buffer + data->offset;
    for (uint32_t i = 0; i < payload_len; i++)
    {
        if (payload_ptr[i] >= 32 && payload_ptr[i] <= 126)
        {
            printf("%c", payload_ptr[i]);
        }
        else
        {
            printf("."); // 不可打印字符显示为点
        }
    }
    printf("\n----------------------------------\n");

    // 7. 返回值
    // UDP 是无连接协议，接收方通常不需要像 TCP 那样自动回复 ACK
    // 如果你后续要实现 DNS 或 TFTP 服务，可以在这里构造回复包并返回
    return NULL;
}