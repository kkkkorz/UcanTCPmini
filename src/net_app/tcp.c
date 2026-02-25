#include "tcp.h"
#include "packet.h"
#include "config.h"
#include "util.h"
#include "ip.h"
#include "http.h"
#include "webserver.h"

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
        data_send = handle_tcp_fin(data, src_ip, des_ip);
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

    // 仅接受当前 WebServer 监听端口上的连接请求
    uint16_t dst_port_host = SWAP_UINT16(tcp_packet_receive->destination_port);
    if (dst_port_host != webserver_get_listen_port())
    {
        return NULL;
    }

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

    // 初始化窗口相关字段
    node->tcb.snd_wnd = 65535;
    node->tcb.rcv_wnd = 65535;
    node->tcb.snd_una = node->tcb.snd_nxt;

    // 设置状态
    node->tcb.state = TCP_STATE_SYN_RECV;

    // 插入tcb表

    node = insert_tcb(node);

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
base_packet *handle_tcp_ack(base_packet *receive_data, uint32_t src_ip, uint32_t des_ip)
{
    // 1. 获取 TCP 头部和 TCB 节点
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(receive_data->buffer + receive_data->offset);

    tcp_key key = {des_ip, src_ip, tcp_packet_receive->destination_port, tcp_packet_receive->source_port};
    tcb_node *tcb = get_tcb(&key);

    if (tcb == NULL)
        return NULL;

    // 更新对端窗口大小和已确认序列号，供发送端进行简单流量控制
    tcb->tcb.snd_wnd = SWAP_UINT16(tcp_packet_receive->window);
    tcb->tcb.snd_una = SWAP_UINT32(tcp_packet_receive->ack);

    // 2. 状态机迁移：处理挥手过程中的 ACK
    // -----------------------------------------------------------
    if (tcb->tcb.state == TCP_STATE_SYN_RECV)
    {
        // 三次握手的最后一步：收到对方对 SYN+ACK 的确认
        tcb->tcb.state = TCP_STATE_ESTABLISHED;
        printf("[TCP] Three-way handshake complete: ESTABLISHED\n");
    }
    else if (tcb->tcb.state == TCP_STATE_FIN_WAIT_1)
    {
        // 主动关闭阶段 1：收到对方对我方 FIN 的确认
        tcb->tcb.state = TCP_STATE_FIN_WAIT_2;
        printf("[TCP] State -> FIN_WAIT_2\n");
    }
    else if (tcb->tcb.state == TCP_STATE_LAST_ACK)
    {
        // 被动关闭阶段：收到对方对我方最后一个 FIN 的确认
        tcb->tcb.state = TCP_STATE_CLOSED;
        tcb->valid = 0; // 实际项目中这里应从哈希表删除节点并 free
        printf("[TCP] Connection CLOSED.\n");
        return NULL;
    }

    // 3. 数据载荷处理
    // -----------------------------------------------------------
    remov_tcp_header(receive_data); // 此时 data->len 变为 Payload 长度

    if (receive_data->len > 0)
    {
        // 收到数据，更新 TCB 中的接收序列号 (重要！)
        // rcv_nxt = 对方当前的 Seq + 对方发送的数据长度
        tcb->tcb.rcv_nxt = SWAP_UINT32(tcp_packet_receive->seq) + receive_data->len;

        printf("[TCP] Receive Data (%d bytes): ", receive_data->len);
        for (uint32_t i = 0; i < receive_data->len; i++)
        {
            printf("%c", receive_data->buffer[receive_data->offset + i]);
        }
        printf("\n");
        // 判断是否是http请求
        app_layer_dispatch(tcb, (char *)(receive_data->buffer + receive_data->offset), receive_data->len);

        // 4. 构造 ACK 回复
        // -----------------------------------------------------------
        TCP_HEADER ack_header;
        memset(&ack_header, 0, sizeof(TCP_HEADER));

        // 填充头部信息
        ack_header.source_port = tcp_packet_receive->destination_port;
        ack_header.destination_port = tcp_packet_receive->source_port;
        ack_header.seq = SWAP_UINT32(tcb->tcb.snd_nxt);
        ack_header.ack = SWAP_UINT32(tcb->tcb.rcv_nxt); // 确认收到的所有数据
        ack_header.flags = (1 << TCP_FLAG_ACK);
        ack_header.header_len = 0x50;
        ack_header.window = SWAP_UINT16(65535);

        base_packet empty_payload = {NULL, 0, 0};
        base_packet *ack_packet = malloc(sizeof(base_packet));

        add_tcp_header(ack_packet, &ack_header, &empty_payload);

        // 发送数据包：作为生产者放入待确认队列

        return ack_packet;
    }

    // 如果只是一个纯 ACK 包（无数据），直接结束
    return NULL;
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
tcb_node *insert_tcb(tcb_node *node)
{
    if (node == NULL)
        return NULL;

    // 构造查找键，先检查是否已经存在（防止重复插入）
    tcp_key key = {
        node->tcb.local_ip,
        node->tcb.remote_ip,
        node->tcb.local_port,
        node->tcb.remote_port};

    tcb_node *cache = get_tcb(&key);
    if (cache != NULL)
    {
        printf("TCB conflict: Connection already exists.\n");
        free(node); // 释放内存
        return cache;
    }

    uint32_t index = calculate_hash(&key);

    // --- 优雅的头插法 ---
    // 1. 让新节点的 next 指向当前桶的头（可能是 NULL，也可能是旧节点）
    node->next = tcb_table[index];
    node->valid = 1;

    // 2. 让桶的头指针指向新节点
    tcb_table[index] = node;

    return node;
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
    node = insert_tcb(node);
    // 2. 序列号同步与状态设置
    node->tcb.rcv_nxt = 0;
    node->tcb.snd_nxt = (uint32_t)time(NULL);
    node->tcb.snd_wnd = 65535;
    node->tcb.rcv_wnd = 65535;
    node->tcb.snd_una = node->tcb.snd_nxt;
    node->tcb.state = TCP_STATE_SYN_SENT;

    // 3. 构造并发送 SYN 包
    TCP_HEADER *tcp_header = malloc(sizeof(TCP_HEADER));
    memset(tcp_header, 0, sizeof(TCP_HEADER));

    set_tcp_header(node, tcp_header);        // 根据 TCB 填充头部
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
// 完善：发送数据函数，增加滑动窗口逻辑
void tcp_send_data(tcb_node *node, char *payload_data, uint32_t data_len)
{
    if (node == NULL || payload_data == NULL || data_len == 0)
        return;

    if (node->tcb.state != TCP_STATE_ESTABLISHED)
        return;

    // 1. 流量控制：检查对方窗口空间
    // 可用窗口 = snd_una + snd_wnd - snd_nxt
    uint32_t usable_wnd = node->tcb.snd_una + node->tcb.snd_wnd - node->tcb.snd_nxt;
    if (data_len > usable_wnd)
    {
        printf("[TCP] Window Full! Waiting for ACK...\n");
        return; // 简单起见，这里直接丢弃，实际应存入等待队列
    }

    // 2. 存入重传缓冲区 (仅演示单包重传)
    if (node->tcb.retrans_buf)
        free(node->tcb.retrans_buf);
    node->tcb.retrans_buf = malloc(data_len);
    memcpy(node->tcb.retrans_buf, payload_data, data_len);
    node->tcb.retrans_len = data_len;
    node->tcb.last_send_time = clock();

    // 3. 封装并发送
    TCP_HEADER header;
    memset(&header, 0, sizeof(TCP_HEADER));
    set_tcp_header(node, &header);
    header.flags = (1 << TCP_FLAG_ACK) | (1 << TCP_FLAG_PSH);

    base_packet payload = {(uint8_t *)payload_data, data_len, 0};
    base_packet *full_packet = malloc(sizeof(base_packet));
    add_tcp_header(full_packet, &header, &payload);

    uint8_t dest_ip[4];
    UINT32_TO_IP(dest_ip, node->tcb.remote_ip);

    // 伪头部校验与发送
    IP_HEADER ip_info;
    memcpy(ip_info.destination_ip, dest_ip, 4);
    memcpy(ip_info.source_ip, host_ip_addr, 4);
    pseudo_header_checksum(full_packet, &ip_info);
    ip_send(full_packet, TCP_TYPE, dest_ip);

    // 4. 更新 snd_nxt
    node->tcb.snd_nxt += data_len;
}
// 设置tcp头部通用信息
void set_tcp_header(tcb_node *node, TCP_HEADER *tcp_header)
{
    tcp_header->source_port = node->tcb.local_port; // 这个就是存的网络端序
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
    node->tcb.local_port = SWAP_UINT16(local_port);
    node->tcb.remote_port = SWAP_UINT16(remote_port);
}

// 处理FIN
base_packet *handle_tcp_fin(base_packet *receive_data, uint32_t src_ip, uint32_t des_ip)
{
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(receive_data->buffer + receive_data->offset);

    tcp_key key = {des_ip, src_ip, tcp_packet_receive->destination_port, tcp_packet_receive->source_port};
    tcb_node *tcb = get_tcb(&key);
    if (tcb == NULL)
        return NULL;

    // FIN 占用一个序列号，期望下一位从对方 seq + 1 开始
    tcb->tcb.rcv_nxt = SWAP_UINT32(tcp_packet_receive->seq) + 1;

    if (tcb->tcb.state == TCP_STATE_ESTABLISHED)
    {
        // 对方主动关，我方进入被动关闭状态
        tcb->tcb.state = TCP_STATE_CLOSE_WAIT;
        printf("[TCP] State: CLOSE_WAIT (Remote side wants to close)\n");
    }
    else if (tcb->tcb.state == TCP_STATE_FIN_WAIT_2)
    {
        // 我方发过 FIN 且对方已 ACK，现在收到对方 FIN，进入 TIME_WAIT
        tcb->tcb.state = TCP_STATE_TIME_WAIT;
        printf("[TCP] State: TIME_WAIT (Both sides closed)\n");
    }

    // 无论哪种情况，收到 FIN 必须回 ACK
    TCP_HEADER *tcp_header = malloc(sizeof(TCP_HEADER));
    memset(tcp_header, 0, sizeof(TCP_HEADER));
    set_tcp_header(tcb, tcp_header);
    tcp_header->flags = (1 << TCP_FLAG_ACK);

    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = (uint8_t *)tcp_header;
    data_send->len = sizeof(TCP_HEADER);
    data_send->offset = 0;

    return data_send;
}

// 主动断开
void tcp_close(tcb_node *node)
{
    if (node == NULL)
        return;

    if (node->tcb.state == TCP_STATE_ESTABLISHED)
    {
        // 场景 A: 主动关闭，发送第一个 FIN
        node->tcb.state = TCP_STATE_FIN_WAIT_1;
        printf("[TCP] Active Close: Sending FIN, State -> FIN_WAIT_1\n");
    }
    else if (node->tcb.state == TCP_STATE_CLOSE_WAIT)
    {
        // 场景 B: 被动关闭的后半段，应用层准备好了，发送我方的 FIN
        node->tcb.state = TCP_STATE_LAST_ACK;
        printf("[TCP] Passive Close: Sending FIN, State -> LAST_ACK\n");
    }
    else
    {
        return;
    }

    TCP_HEADER *tcp_header = malloc(sizeof(TCP_HEADER));
    memset(tcp_header, 0, sizeof(TCP_HEADER));
    set_tcp_header(node, tcp_header);
    tcp_header->flags = (1 << TCP_FLAG_FIN) | (1 << TCP_FLAG_ACK);

    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = (uint8_t *)tcp_header;
    data_send->len = sizeof(TCP_HEADER);
    data_send->offset = 0;

    // 校验并发送
    uint8_t dest_ip[4];
    UINT32_TO_IP(dest_ip, node->tcb.remote_ip);
    IP_HEADER ip_info;
    memcpy(ip_info.destination_ip, dest_ip, 4);
    memcpy(ip_info.source_ip, host_ip_addr, 4);
    pseudo_header_checksum(data_send, &ip_info);

    ip_send(data_send, TCP_TYPE, dest_ip);

    // 发送 FIN 消耗一个序列号
    node->tcb.snd_nxt++;
}

// 查看所有tcb
void tcp_show_netstat()
{
    printf("\n%-25s %-25s %-15s\n", "Local Address", "Remote Address", "State");
    printf("--------------------------------------------------------------------------------\n");

    const char *state_names[] = {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED",
        "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT"};

    for (int i = 0; i < TCB_TABLE_MAX_SIZE; i++)
    {
        tcb_node *curr = tcb_table[i];
        while (curr != NULL)
        {
            if (curr->valid && curr->tcb.state >= 0 && curr->tcb.state <= 10)
            {
                char local_addr[64], remote_addr[64];

                // 1. 使用位移提取 IP 字节 (处理 32 位整数)
                // 假设存储的是主机序（如果你存的是大端序，则字节顺序需微调）
                uint32_t l_ip = curr->tcb.local_ip;
                uint32_t r_ip = curr->tcb.remote_ip;

                // 2. 统一端口转换逻辑
                // 如果你之前的截图显示 1200... 那么说明 SWAP 可能被重复调用了
                // 这里我们直接从 TCB 取值，如果不对，尝试去掉 SWAP_UINT16
                uint16_t l_p = SWAP_UINT16(curr->tcb.local_port);
                uint16_t r_p = SWAP_UINT16(curr->tcb.remote_port);

                // 3. 格式化输出 (手动按 192.168.254.x 顺序排列)
                // 注意：这里取决于你存储 IP 的方式，通常 uint32 存储 192 在最高位
                snprintf(local_addr, sizeof(local_addr), "%d.%d.%d.%d:%u",
                         (l_ip >> 24) & 0xFF, (l_ip >> 16) & 0xFF,
                         (l_ip >> 8) & 0xFF, l_ip & 0xFF, l_p);

                snprintf(remote_addr, sizeof(remote_addr), "%d.%d.%d.%d:%u",
                         (r_ip >> 24) & 0xFF, (r_ip >> 16) & 0xFF,
                         (r_ip >> 8) & 0xFF, r_ip & 0xFF, r_p);

                printf("%-25s %-25s %-15s\n", local_addr, remote_addr, state_names[curr->tcb.state]);
            }
            curr = curr->next;
        }
    }
}

// 检查重传
void check_retransmit()
{
    for (int i = 0; i < TCB_TABLE_MAX_SIZE; i++)
    {
        tcb_node *curr = tcb_table[i];
        while (curr)
        {
            if (curr->valid && curr->tcb.retrans_buf)
            {
                // 如果超过 500ms 未收到 ACK
                if ((clock() - curr->tcb.last_send_time) > 500)
                {
                    printf("[TCP] Timeout! Retransmitting Seq: %u\n", curr->tcb.snd_una);
                    // 重新调用底层发送逻辑，这里为了简洁只做示意

                    // 实际应重发 snd_una 对应的数据
                    curr->tcb.last_send_time = clock();
                }
            }
            curr = curr->next;
        }
    }
}

void tcp_init()
{
}