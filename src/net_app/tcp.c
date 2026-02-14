#include "tcp.h"
#include "packet.h"
#include "config.h"
#include "util.h"
#include "ip.h"

base_packet *tcp_process(base_packet *data, uint32_t src_ip, uint32_t des_ip)
{
    // 拆封数据包
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(data->buffer + data->offset);
    uint8_t flags = tcp_packet_receive->flags;
    base_packet *data_send = NULL;
    // 根据标志位进行分发处理、

    // 收到对方的强制重置包
    if (flags & (1 << TCP_FLAG_RST))
    {
        // handle_tcp_reset(ip_packet_receive, tcp_packet_receive);
    }

    // 握手响应
    else if ((flags & (1 << TCP_FLAG_SYN)) && (flags & (1 << TCP_FLAG_ACK)))
    {
    }
    // 握手请求处理
    else if (flags & (1 << TCP_FLAG_SYN))
    {
        data_send = handle_tcp_syn(data, src_ip, des_ip);
    }

    // 挥手处理
    else if (flags & (1 << TCP_FLAG_FIN))
    {
    }

    // 第三次确认或数据传输处理
    else if (flags & (1 << TCP_FLAG_ACK))
    {
        data_send = handle_tcp_ack(data, src_ip, des_ip);
    }
    return data_send;
    // 这里计算校验和
}
// 处理 SYN：回应第一次握手，标志位设置为 SYN+ACK
base_packet *handle_tcp_syn(base_packet *data, uint32_t src_ip, uint32_t dst_ip)
{
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(data->buffer + data->offset);

    // 1. 准备 TCB 节点
    tcb_node *node = malloc(sizeof(tcb_node));
    memset(node, 0, sizeof(tcb_node));

    // 2. 填充连接基本信息 (注意视角：对方的源是我们的远程)
    node->tcb.local_ip = dst_ip;
    node->tcb.remote_ip = src_ip;
    node->tcb.local_port = tcp_packet_receive->destination_port;
    node->tcb.remote_port = tcp_packet_receive->source_port;

    // 3. 序列号同步
    // 对方的 Seq
    uint32_t guest_seq = SWAP_UINT32(tcp_packet_receive->seq);
    // 我们期望收到：对方 Seq + 1 (SYN 占用 1 字节)
    node->tcb.rcv_nxt = guest_seq + 1;
    // 初相对始序列号
    node->tcb.snd_nxt = (uint32_t)time(NULL);

    // 设置状态
    node->tcb.state = TCP_STATE_SYN_RECV;

    // 插入tcb表
    if (insert_tcb(node) != SUCCESS)
    {
        free(node);
        return NULL;
    }

    // 构造 SYN+ACK 响应包
    TCP_HEADER *tcp_packet_send = malloc(sizeof(TCP_HEADER));
    memset(tcp_packet_send, 0, sizeof(TCP_HEADER));

    tcp_packet_send->source_port = node->tcb.local_port;
    tcp_packet_send->destination_port = node->tcb.remote_port;
    tcp_packet_send->seq = SWAP_UINT32(node->tcb.snd_nxt);
    tcp_packet_send->ack = SWAP_UINT32(node->tcb.rcv_nxt);
    tcp_packet_send->flags = (1 << TCP_FLAG_SYN) | (1 << TCP_FLAG_ACK);
    tcp_packet_send->header_len = 0x50;
    tcp_packet_send->window = SWAP_UINT16(65535);

    // 回复SYN消耗一个序列号
    node->tcb.snd_nxt++;
    // 封装返回
    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = (uint8_t *)tcp_packet_send;
    data_send->len = sizeof(TCP_HEADER);
    data_send->offset = 0;

    return data_send;
}

// 处理 ACK：三次握手的最后一步和数据传输一同处理
base_packet *handle_tcp_ack(base_packet *receive_data, uint32_t src_ip, uint32_t des_ip) // 数据解析
{

    // 构建tcb_key拿对应的TCB
    tcp_key *key = malloc(sizeof(tcp_key));
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(receive_data->buffer + receive_data->offset);
    key->local_ip = des_ip;
    key->local_port = tcp_packet_receive->destination_port;
    key->remote_ip = src_ip;
    key->remote_port = tcp_packet_receive->source_port;

    tcb_node *tcb = get_tcb(key);
    free(key);
    if (tcb == NULL)
    {
        tcb->tcb.state = TCP_STATE_ESTABLISHED;
        return NULL;
    }

    remov_tcp_header(receive_data);
    if (receive_data->len <= 0)
    {
        printf("no data");
        return NULL;
    }
    else
    {
        for (uint32_t i = 0; i < receive_data->len; i++)
        {
            printf("%c", *(receive_data->buffer + (receive_data->offset + i)));
        }
        printf("\n");

        // transfer to http

        TCP_HEADER *tcp_header = malloc(sizeof(TCP_HEADER));
        base_packet *data = malloc(sizeof(base_packet));
        data->buffer = malloc(receive_data->len);
        base_packet *tcp_packet = malloc(sizeof(base_packet));

        data->len = receive_data->len; // 回显数据
        memcpy(data->buffer, receive_data->buffer + receive_data->offset, receive_data->len);

        // 更新本地的发送序列
        tcp_header->ack = SWAP_UINT32(SWAP_UINT32(tcp_packet_receive->seq) + data->len); // 更新确认ack
        tcp_header->checksum = 0;
        tcp_header->source_port = tcp_packet_receive->destination_port;
        tcp_header->destination_port = tcp_packet_receive->source_port;
        tcp_header->seq = SWAP_UINT32(tcb->tcb.snd_nxt); // 本地的seq
        tcp_header->flags = (1 << TCP_FLAG_PSH | 1 << TCP_FLAG_ACK);
        tcp_header->window = tcp_packet_receive->window;
        tcp_header->urgent_pointer = 0;
        tcp_header->header_len = 0x50; // len:0101 res:0000
        // 本地消耗
        (tcb->tcb.snd_nxt) += (data->len);
        add_tcp_header(tcp_packet, tcp_header, data);
        free(data);
        free(tcp_header);
        return tcp_packet;
    }
}
void remov_tcp_header(base_packet *data)
{
    TCP_HEADER *tcp_header = (TCP_HEADER *)(data->buffer + data->offset);
    data->offset += (tcp_header->header_len >> 4) * 4;
    data->len -= (tcp_header->header_len >> 4) * 4;
}
void add_tcp_header(base_packet *tcp_packet, TCP_HEADER *header, base_packet *data) // 为数据添加tcp包头
{
    uint8_t header_len = (header->header_len >> 4) * 4;
    uint32_t data_len = data->len;
    tcp_packet->buffer = malloc(header_len + data_len);
    tcp_packet->len = header_len + data_len;
    memcpy(tcp_packet->buffer, header, header_len);
    memcpy(tcp_packet->buffer + header_len, data->buffer, data_len);
}
Status insert_tcb(tcb_node *node)
{
    if (node == NULL)
        return FAILURE;

    // 构造查找键，先检查是否已经存在（防止重复插入）
    tcp_key key = {
        node->tcb.local_ip,
        node->tcb.remote_ip,
        node->tcb.local_port,
        node->tcb.remote_port};

    if (get_tcb(&key) != NULL)
    {
        printf("TCB conflict: Connection already exists.\n");
        return FAILURE;
    }

    uint32_t index = calculate_hash(&key);

    // --- 优雅的头插法 ---
    // 1. 让新节点的 next 指向当前桶的头（可能是 NULL，也可能是旧节点）
    node->next = tcb_table[index];
    node->valid = 1;

    // 2. 让桶的头指针指向新节点
    tcb_table[index] = node;

    return SUCCESS;
}
tcb_node *get_tcb(tcp_key *key)
{
    if (key == NULL)
        return NULL;

    uint32_t index = calculate_hash(key);
    tcb_node *curr = tcb_table[index];

    // 遍历该哈希桶下的链表
    while (curr != NULL)
    {
        if (curr->valid &&
            curr->tcb.local_ip == key->local_ip &&
            curr->tcb.remote_ip == key->remote_ip &&
            curr->tcb.local_port == key->local_port &&
            curr->tcb.remote_port == key->remote_port)
        {
            return curr; // 找到了匹配的 TCB
        }
        curr = curr->next;
    }
    return NULL; // 未找到对应连接
}
static uint32_t calculate_hash(tcp_key *key)
{
    // 使用异或运算确保每一个字节的变化都能影响到哈希值
    return (key->local_ip ^ key->remote_ip ^
            (uint32_t)key->local_port ^ (uint32_t)key->remote_port) %
           TCB_TABLE_MAX_SIZE;
}

// 主动发起tcp连接
void tcp_connect(uint8_t *destination_ip, uint16_t source_port, uint16_t destination_port)
{
    // 1. 准备 TCB 节点
    tcb_node *node = malloc(sizeof(tcb_node));
    memset(node, 0, sizeof(tcb_node));
    // 2. 填充连接基本信息
    node->tcb.local_ip = IP_TO_UINT32(host_ip_addr);
    node->tcb.remote_ip = IP_TO_UINT32(destination_ip);
    node->tcb.local_port = source_port;
    node->tcb.remote_port = destination_port;
    // 3. 序列号同步
    // 我们期望收到：对方 Seq + 1 (SYN 占用 1 字节)
    node->tcb.rcv_nxt = 0;
    // 初相对始序列号
    node->tcb.snd_nxt = (uint32_t)time(NULL);

    // 设置状态
    node->tcb.state = TCP_STATE_SYN_SENT;
    // 插入tcb表
    if (insert_tcb(node) != SUCCESS)
    {
        free(node);
        return NULL;
    }

    // 构造 SYN+ACK 响应包
    TCP_HEADER *tcp_packet_send = malloc(sizeof(TCP_HEADER));
    memset(tcp_packet_send, 0, sizeof(TCP_HEADER));

    tcp_packet_send->source_port = SWAP_UINT16(node->tcb.local_port);
    tcp_packet_send->destination_port = SWAP_UINT16(node->tcb.remote_port);
    tcp_packet_send->seq = SWAP_UINT32(node->tcb.snd_nxt); // 这个不重要，直接置为0
    tcp_packet_send->ack = SWAP_UINT32(node->tcb.rcv_nxt);
    tcp_packet_send->flags = (1 << TCP_FLAG_SYN);
    tcp_packet_send->header_len = 0x50;
    tcp_packet_send->window = SWAP_UINT16(65535);

    // 回复SYN消耗一个序列号
    node->tcb.snd_nxt++;
    // 封装返回
    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = (uint8_t *)tcp_packet_send;
    data_send->len = sizeof(TCP_HEADER);
    data_send->offset = 0;
    // 校验暂时写在这里 //TODO
    IP_HEADER *ip_header = malloc(sizeof(IP_HEADER));
    memcpy(ip_header->destination_ip, destination_ip, 4);
    memcpy(ip_header->source_ip, host_ip_addr, 4);
    pseudo_header_checksum(data_send, ip_header);
    free(ip_header);
    ip_send(data_send, TCP_TYPE, destination_ip);
}
void tcp_init()
{
}