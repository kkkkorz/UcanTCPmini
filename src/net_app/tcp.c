#include "tcp.h"
#include "packet.h"
#include "config.h"
#include "util.h"

void tcp_send(ip_packet *pkt, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window_size, uint16_t urgent_pointer)
{
}

base_packet *tcp_process(base_packet *data, uint32_t src_ip, uint32_t des_ip)
{
    // 拆封数据包
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(data->buffer + data->offset);

    // 校验和
    //  if (calculate_checksum(tcp_packet_receive, sizeof(tcp_packet)) != 0)
    //  {
    //      return;
    //  }
    // switch语句判断tcp标志位的类型
    uint8_t flags = tcp_packet_receive->flags;
    base_packet *data_send = NULL;
    // 3. 根据标志位进行分发处理
    if (flags & (1 << TCP_FLAG_RST))
    {
        // 场景：收到对方的强制重置包。
        // 逻辑：你应该立即释放本地的 TCB (控制块)，停止该连接的所有任务。
        //    handle_tcp_reset(ip_packet_receive, tcp_packet_receive);
    }

    // --- 握手响应处理 (客户端收到服务器的回应) ---
    else if ((flags & (1 << TCP_FLAG_SYN)) && (flags & (1 << TCP_FLAG_ACK)))
    {
        // 场景：你作为客户端发起了 SYN，现在收到了服务器发回的确认。
        // 逻辑：这是三次握手的第二步。你需要提取服务器的 Seq，并回一个最终的 ACK。
        // handle_tcp_syn_ack(tcp_packet_receive);
    }

    // --- 握手请求处理 (服务器收到客户端的请求) ---
    else if (flags & (1 << TCP_FLAG_SYN))
    {
        // 场景：Windows Telnet 客户端向你发起连接。
        // 逻辑：这是三次握手的第一步。你需要记录对方的 Seq，并回复 SYN+ACK。
        data_send = handle_tcp_syn(data, src_ip, des_ip);
    }

    // --- 挥手处理 (断开连接) ---
    else if (flags & (1 << TCP_FLAG_FIN))
    {
        // 场景：对方发出了“我要断开连接”的信号。
        // 逻辑：你需要进入 CLOSE_WAIT 状态，回 ACK，并通知应用层连接即将关闭。
        //    handle_tcp_fin(ip_packet_receive, tcp_packet_receive);
    }

    // --- 数据确认或数据传输处理 ---
    else if (flags & (1 << TCP_FLAG_ACK))
    {
        /*
         * 在连接建立后，几乎所有的包都会带有 ACK 标志位。
         * 我们需要区分这仅仅是一个空确认，还是带有载荷（Payload）的数据包。
         */
        //  if (tcp_has_payload(ip_packet_receive, tcp_packet_receive)) {
        // 场景：收到 Telnet 发来的数据（如你敲的一个字母）。
        // 逻辑：提取数据并交给上层 Telnet 逻辑处理。
        //    handle_tcp_data(ip_packet_receive, tcp_packet_receive);
        //  } else {
        // 场景：纯确认包。
        // 逻辑：通常用于完成三次握手的最后一步，或者单纯确认你发出的数据已被收到。
        data_send = handle_tcp_ack(data, src_ip, des_ip);
        // }
    }
    if (data_send == NULL)
        return NULL;
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

    printf("%d--------", tcp_packet_receive->destination_port);

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
        return NULL; // 可能是连接冲突或内存不足
    }

    // 构造 SYN+ACK 响应包
    TCP_HEADER *tcp_packet_send = malloc(sizeof(TCP_HEADER));
    memset(tcp_packet_send, 0, sizeof(TCP_HEADER));

    tcp_packet_send->source_port = node->tcb.local_port;
    tcp_packet_send->destination_port = node->tcb.remote_port;
    tcp_packet_send->seq = SWAP_UINT32(node->tcb.snd_nxt);
    tcp_packet_send->ack = SWAP_UINT32(node->tcb.rcv_nxt);
    tcp_packet_send->flags = (1 << TCP_FLAG_SYN) | (1 << TCP_FLAG_ACK);
    tcp_packet_send->header_len = 0x50; // 20 字节
    tcp_packet_send->window = SWAP_UINT16(65535);

    // 回复SYN消耗一个序列号
    node->tcb.snd_nxt++;
    // 封装返回
    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = (uint8_t *)tcp_packet_send;
    data_send->len = sizeof(TCP_HEADER);
    data_send->offset = 0;

    printf("TCB Created: [%d -> %d] State: SYN_RECV\n",
           SWAP_UINT16(node->tcb.local_port), SWAP_UINT16(node->tcb.remote_port));

    return data_send;
}
// 处理 SYN+ACK：接受第二次握手
void handle_tcp_syn_ack(base_packet *data)
{
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(data->buffer + data->offset);

    // 读取对方的Seq
    uint32_t seq = tcp_packet_receive->seq;

    // 计算ack，表示自己已经收到对方的数据
    uint32_t ack = SWAP_UINT32(SWAP_UINT32(seq) + 1); // 消耗一个字节

    // 创建tcp包
    TCP_HEADER *tcp_packet_send = malloc(sizeof(TCP_HEADER));
    tcp_packet_send->checksum = 0;
    tcp_packet_send->source_port = tcp_packet_receive->destination_port;
    tcp_packet_send->destination_port = tcp_packet_receive->source_port;
    tcp_packet_send->seq = local_seq; // 本地的seq
    tcp_packet_send->ack = ack;
    tcp_packet_send->flags = (1 << TCP_FLAG_SYN) | (1 << TCP_FLAG_ACK);
    tcp_packet_send->window = tcp_packet_receive->window;
    tcp_packet_send->urgent_pointer = 0;
    tcp_packet_send->header_len = 0x50; // len:0101 res:0000

    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = tcp_packet_send;
    data_send->len = sizeof(TCP_HEADER);
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
        memcpy(data->buffer, receive_data->buffer, receive_data->len);

                                                     // 更新本地的发送序列
        tcp_header->ack = SWAP_UINT32(SWAP_UINT32(tcp_packet_receive->seq) + data->len); // 更新确认ack
        tcp_header->checksum = 0;
        tcp_header->source_port = tcp_packet_receive->destination_port;
        tcp_header->destination_port = tcp_packet_receive->source_port;
        tcp_header->seq = SWAP_UINT32(tcb->tcb.snd_nxt); // 本地的seq
        tcp_header->flags = (1 << TCP_FLAG_ACK);
        tcp_header->window = tcp_packet_receive->window;
        tcp_header->urgent_pointer = 0;
        tcp_header->header_len = 0x50; // len:0101 res:0000
        //本地消耗
        (tcb->tcb.snd_nxt) += (data->len);  
        add_tcp_header(tcp_packet, tcp_header, data);
        free(data);
        free(tcp_header);
        return tcp_packet;
    }
}
base_packet *make_reply_data(base_packet *receive_data)
{

    for (uint32_t i = 0; i < receive_data->len; i++)
    {
        printf("%c", *(receive_data->buffer + receive_data->offset + i));
    }
    base_packet *data = malloc(sizeof(base_packet));
    printf("\n");
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
void set_flag(uint8_t *flags, uint8_t value, uint8_t target)
{
    if (target)
    {
        *flags |= (1 << value); // 设置标志位
    }
    else
    {
        *flags &= ~(1 << value); // 取消标志位
    }
}
void set_flags(uint8_t *flags, uint8_t CWR, uint8_t ECE, uint8_t URG, uint8_t ACK, uint8_t PSH, uint8_t RST, uint8_t SYN, uint8_t FIN)
{
    *flags = CWR | ECE | URG | ACK | PSH | RST | SYN | FIN;
}
void tcp_init()
{
    local_seq = time(NULL);
}
tcp_tcb *create_tcb()
{ // 头插法建立新的tcb
    tcb_node *new_tcb_node = malloc(sizeof(tcb_node));
    if (insert_tcb(new_tcb_node) == SUCCESS)
        return new_tcb_node;
    else
    {
        INFO("新建TCB失败");
        free(new_tcb_node);
        return NULL;
    }
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