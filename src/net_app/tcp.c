#include "tcp.h"
#include "packet.h"
#include "config.h"
#include "util.h"

void tcp_send(ip_packet *pkt, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window_size, uint16_t urgent_pointer)
{
}

base_packet *tcp_process(base_packet *data)
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
    base_packet* data_send = NULL;
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
        data_send = handle_tcp_syn( data);
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
       // return handle_tcp_ack(tcp_packet_receive);
        // }
    }
    return data_send;
    // 这里计算校验和
}
// 处理 SYN：回应第一次握手，标志位设置为 SYN+ACK
base_packet *handle_tcp_syn(base_packet *data)
{
    TCP_HEADER *tcp_packet_receive = (TCP_HEADER *)(data->buffer + data->offset);

    // 读取对方的Seq
    uint32_t seq = tcp_packet_receive->seq;

    // 计算ack，表示自己已经收到对方的数据
    uint32_t ack = SWAP_UINT32(SWAP_UINT32(seq) + 1); // 消耗一个字节
    // 生成自己的Seq：表示自己想要收到的数据的序号
    uint32_t my_seq = time(NULL) % 1000;

    // 创建tcp包
    TCP_HEADER *tcp_packet_send = malloc(sizeof(TCP_HEADER));
    tcp_packet_send->checksum = 0;
    tcp_packet_send->source_port = tcp_packet_receive->destination_port;
    tcp_packet_send->destination_port = tcp_packet_receive->source_port;
    tcp_packet_send->seq = my_seq;
    tcp_packet_send->ack = ack;
    tcp_packet_send->flags = (1 << TCP_FLAG_SYN) | (1 << TCP_FLAG_ACK);
    tcp_packet_send->window = tcp_packet_receive->window;
    tcp_packet_send->urgent_pointer = 0;
    tcp_packet_send->header_len = 0x50; // len:0101 res:0000

    base_packet *data_send = malloc(sizeof(base_packet));
    data_send->buffer = tcp_packet_send;
    data_send->len = sizeof(TCP_HEADER);
    return data_send;
    //  ip_send(&tcp_packet_send, TCP_TYPE , ip_packet_receive->source_ip, 20);
    //  free(tcp_packet_send);
}
// 处理 SYN+ACK：接受第二次握手
void handle_tcp_syn_ack(ip_packet *ip_packet_receive, tcp_packet *tcp_packet_receive)
{
    // 读取对方的Seq
    uint32_t seq = tcp_packet_receive->seq;

    // 计算ack，表示自己已经收到对方数据
    uint32_t ack = SWAP_UINT32(SWAP_UINT32(seq) + 1); // 消耗一个字节
    // 生成自己的Seq：表示自己想要收到数据的序号
    uint32_t my_seq = time(NULL) % 1000;
    // 创建tcp包
    tcp_packet tcp_packet_send;
    memset(&tcp_packet_send, 0, sizeof(tcp_packet));
    tcp_packet_send.source_port = tcp_packet_receive->destination_port;
    tcp_packet_send.destination_port = tcp_packet_receive->source_port;
    tcp_packet_send.seq = my_seq;
    tcp_packet_send.ack = ack;
    tcp_packet_send.flags = (1 << TCP_FLAG_ACK);
    tcp_packet_send.window = tcp_packet_receive->window;
    tcp_packet_send.urgent_pointer = 0;
    tcp_packet_send.header_len = 5;
    // 伪首部
    uint8_t *pseudo_header = malloc(TCP_HEADER_LEN + 12); // 伪首部+tcp包

    memcpy(pseudo_header, ip_packet_receive->destination_ip, 4);
    memcpy(pseudo_header + 4, ip_packet_receive->source_ip, 4);
    pseudo_header[8] = 0;
    pseudo_header[9] = 6;
    pseudo_header[10] = 0;
    pseudo_header[11] = 0x14;
    memcpy(pseudo_header + 12, &tcp_packet_send, TCP_HEADER_LEN);                      // 拼接在一起
    tcp_packet_send.checksum = calculate_checksum(pseudo_header, TCP_HEADER_LEN + 12); // 校验和
    free(pseudo_header);
    ip_send(&tcp_packet_send, TCP_TYPE, ip_packet_receive->source_ip, TCP_HEADER_LEN);
    Sleep(1000);
}

// 处理 ACK：三次握手的最后一步和数据传输一同处理
base_packet* handle_tcp_ack(base_packet *data)
{

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
