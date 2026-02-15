#include "tcp.h"
#include "packet.h"
#include "config.h"
#include "util.h"
#include "ip.h"
// 函数名重构为handle_sencond_shake这种形式

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

    // 第二次握手
    else if ((flags & (1 << TCP_FLAG_SYN)) && (flags & (1 << TCP_FLAG_ACK)))
    {
        data_send = handle_sencond_shake(data, src_ip, des_ip);
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
        return NULL;
    }
    else
    {
        printf("receive data: ");
        for (uint32_t i = 0; i < receive_data->len; i++)
        {
            printf("%c", *(receive_data->buffer + (receive_data->offset + i)));
        }
        printf("\n");

        // transfer to http

        TCP_HEADER *tcp_header = malloc(sizeof(TCP_HEADER));
        base_packet *data = malloc(sizeof(base_packet));
        data->buffer = NULL;
        data->len = 0; // 单纯确认
        base_packet *tcp_packet = malloc(sizeof(base_packet));
        // 更新本地的发送序列
        tcp_header->ack = SWAP_UINT32(SWAP_UINT32(tcp_packet_receive->seq) + receive_data->len); // 更新确认ack
        tcp_header->checksum = 0;
        tcp_header->source_port = tcp_packet_receive->destination_port;
        tcp_header->destination_port = tcp_packet_receive->source_port;
        tcp_header->seq = SWAP_UINT32(tcb->tcb.snd_nxt); // 本地的seq
        tcp_header->flags = (1 << TCP_FLAG_PSH | 1 << TCP_FLAG_ACK);
        tcp_header->window = tcp_packet_receive->window;
        tcp_header->urgent_pointer = 0;
        tcp_header->header_len = 0x50; // len:0101 res:0000
        // 本地消耗
       // (tcb->tcb.snd_nxt) += (data->len);
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

// 发起第一次握手
tcb_node *tcp_connect(uint8_t *destination_ip, uint32_t source_port, uint32_t destination_port)
{
    // 1. 准备并填充 TCB 节点
    tcb_node *node = malloc(sizeof(tcb_node));
    memset(node, 0, sizeof(tcb_node));
    set_tcb_node(node, source_port, destination_ip, destination_port);

    // 2. 序列号同步与状态设置
    node->tcb.rcv_nxt = 0;
    node->tcb.snd_nxt = (uint32_t)time(NULL);
    node->tcb.state = TCP_STATE_SYN_SENT;

    if (insert_tcb(node) != SUCCESS)
    {
        free(node);
        return NULL;
    }

    // 3. 构造并发送 SYN 包
    TCP_HEADER *tcp_header = malloc(sizeof(TCP_HEADER));
    memset(tcp_header, 0, sizeof(TCP_HEADER));

    set_tcp_header(node, tcp_header);        // 使用封装函数
    tcp_header->flags = (1 << TCP_FLAG_SYN); // 单独设置标志位

    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = (uint8_t *)tcp_header;
    data_send->len = sizeof(TCP_HEADER);
    data_send->offset = 0;

    // 4. 校验与发送
    IP_HEADER ip_info; // 临时结构用于校验
    memcpy(ip_info.destination_ip, destination_ip, 4);
    memcpy(ip_info.source_ip, host_ip_addr, 4);
    pseudo_header_checksum(data_send, &ip_info);

    ip_send(data_send, TCP_TYPE, destination_ip);

    node->tcb.snd_nxt++; // SYN 消耗一个序列号
    return node;
}
// 接收第二次握手，发送第三次握手
base_packet *handle_sencond_shake(base_packet *receive_data, uint32_t src_ip, uint32_t des_ip)
{
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(receive_data->buffer + receive_data->offset);

    // 1. 获取 TCB
    tcp_key key = {des_ip, src_ip, tcp_packet_receive->destination_port, tcp_packet_receive->source_port};
    tcb_node *tcb = get_tcb(&key);

    if (tcb == NULL)
        return NULL;

    // 2. 更新状态与序列号
    tcb->tcb.state = TCP_STATE_ESTABLISHED;
    tcb->tcb.rcv_nxt = SWAP_UINT32(tcp_packet_receive->seq) + 1;

    // 3. 构造 ACK 响应包
    TCP_HEADER *tcp_header = malloc(sizeof(TCP_HEADER));
    memset(tcp_header, 0, sizeof(TCP_HEADER));

    set_tcp_header(tcb, tcp_header); // 使用封装函数
    tcp_header->flags = (1 << TCP_FLAG_ACK);

    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = (uint8_t *)tcp_header;
    data_send->len = sizeof(TCP_HEADER);
    data_send->offset = 0;

    return data_send;
}
// 发送数据
void tcp_send_data(tcb_node *node, char *payload_data, uint32_t data_len)
{
    if (node == NULL || node->tcb.state != TCP_STATE_ESTABLISHED)
    {
        printf("Connection not established.\n");
        return;
    }

    // 1. 构造 TCP 首部
    TCP_HEADER tcp_header;
    set_tcp_header(node, &tcp_header); // 使用封装函数
    tcp_header.flags = (1 << TCP_FLAG_ACK) | (1 << TCP_FLAG_PSH);

    // 2. 准备 payload 与封装
    base_packet payload = {(uint8_t *)payload_data, data_len, 0};
    base_packet *full_packet = malloc(sizeof(base_packet));
    add_tcp_header(full_packet, &tcp_header, &payload);

    // 3. 发送
    uint8_t dest_ip[4];
    UINT32_TO_IP(dest_ip, node->tcb.remote_ip);

    // 临时结构用于校验
    IP_HEADER ip_info;
    memcpy(ip_info.destination_ip, dest_ip, 4);
    memcpy(ip_info.source_ip, host_ip_addr, 4);
    pseudo_header_checksum(full_packet, &ip_info);
    ip_send(full_packet, TCP_TYPE, dest_ip);

    // 4. 更新序列号
    node->tcb.snd_nxt += data_len;
    // 注意：full_packet 的释放取决于你的 ip_send 是否会拷贝数据
}
// 设置tcp头部通用信息
void set_tcp_header(tcb_node *node, TCP_HEADER *tcp_header)
{
    tcp_header->source_port = node->tcb.local_port; //这个就是存的网络端序
    tcp_header->destination_port = node->tcb.remote_port;
    tcp_header->seq = SWAP_UINT32(node->tcb.snd_nxt); // 当前发送序列号
    tcp_header->ack = SWAP_UINT32(node->tcb.rcv_nxt); // 确认对方的序列号
                                                      //  tcp_header->flags = (1 << TCP_FLAG_ACK) | (1 << TCP_FLAG_PSH); // PSH 表示立即推送到应用层
    tcp_header->header_len = 0x50;
    tcp_header->window = SWAP_UINT16(65535);
}

// 设置tcb节点信息
void set_tcb_node(tcb_node *node, uint16_t local_port, uint8_t *remote_ip, uint16_t remote_port)
{
    node->tcb.local_ip = IP_TO_UINT32(host_ip_addr);
    node->tcb.remote_ip = IP_TO_UINT32(remote_ip);
    node->tcb.local_port =SWAP_UINT16( local_port);
    node->tcb.remote_port =SWAP_UINT16(remote_port);
}

void tcp_init()
{
}