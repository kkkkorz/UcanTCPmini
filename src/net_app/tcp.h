#ifndef TCP_H
#define TCP_H

#include "packet.h"
#include "header.h"
#include "stdint.h"

#define TCB_TABLE_MAX_SIZE 100
#define TCP_FLAG_FIN 0
#define TCP_FLAG_SYN 1
#define TCP_FLAG_RST 2
#define TCP_FLAG_PSH 3
#define TCP_FLAG_ACK 4
#define TCP_FLAG_URG 5
#define TCP_FLAG_ECE 6
#define TCP_FLAG_CWR 7


typedef struct tcp_tcb
{
    uint32_t local_ip, remote_ip;
    uint16_t local_port, remote_port;
    uint32_t snd_nxt; // 下一个要发的 Seq
    uint32_t rcv_nxt; // 期望收到的下一个 Ack (即对方的 Seq + Len)
    int state;        // ESTABLISHED, etc.
    // 未来可以挂载应用层数据，比如 http_context
} tcp_tcb;
typedef struct
{
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
} tcp_key;
typedef struct tcb_node
{
    uint8_t valid;
    tcp_tcb tcb;
    struct tcb_node *next;
} tcb_node;
typedef enum
{
    SUCCESS,
    FAILURE
} Status;
static tcb_node *tcb_table[TCB_TABLE_MAX_SIZE];
tcb_node *get_tcb(tcp_key *key);
int insert_tcb(tcb_node *node);
tcb_node *get_tcb(tcp_key *key);
Status insert_tcb(tcb_node *node);
tcp_tcb *create_tcb();

// tcp seq
static uint32_t local_seq;

void tcp_send(ip_packet *pkt, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window_size, uint16_t urgent_pointer);
base_packet *tcp_process(base_packet *data, uint32_t src_ip, uint32_t des_ip);
base_packet *handle_tcp_syn(base_packet *data, uint32_t src_ip, uint32_t dst_ip);
void set_flags(uint8_t *flags, uint8_t CWR, uint8_t ECE, uint8_t URG, uint8_t ACK, uint8_t PSH, uint8_t RST, uint8_t SYN, uint8_t FIN);
void handle_tcp_syn_ack(ip_packet *ip_packet_receive, tcp_packet *tcp_packet_receive);
base_packet *handle_tcp_ack(base_packet *receive_data, uint32_t src_ip, uint32_t des_ip); // 处理ACK包
void set_flag(uint8_t *flags, uint8_t value, uint8_t target);
void remov_tcp_header(base_packet *data);
void tcp_init();

tcb_node *tcp_connect(uint8_t *destination_ip, uint32_t source_port, uint32_t destination_port);
base_packet *handle_sencond_shake(base_packet *receive_data, uint32_t src_ip, uint32_t des_ip);
void tcp_send_data(tcb_node *node, char *payload_data, uint32_t data_len);
void set_tcb_node(tcb_node *node, uint16_t local_port, uint8_t *remote_ip, uint16_t remote_port);
void set_tcp_header(tcb_node *node, TCP_HEADER *tcp_header);
void add_tcp_header(base_packet *tcp_packet, TCP_HEADER *header, base_packet *data);
// TCB定义
/* TCP 状态定义 (符合 RFC 793 标准) */

#define TCP_STATE_CLOSED 0      // 初始状态，没有任何连接
#define TCP_STATE_LISTEN 1      // 服务器等待连接请求
#define TCP_STATE_SYN_SENT 2    // 客户端发送 SYN 后，等待匹配的 SYN+ACK
#define TCP_STATE_SYN_RECV 3    // 服务器收到 SYN 并回复 SYN+ACK 后，等待最后的 ACK
#define TCP_STATE_ESTABLISHED 4 // 连接已建立，可以正常传输数据 (HTTP 在此状态运行)

/* --- 断开连接相关的状态 (挥手阶段) --- */
#define TCP_STATE_FIN_WAIT_1 5 // 本地发送 FIN，等待对方确认
#define TCP_STATE_FIN_WAIT_2 6 // 本地收到对方对 FIN 的 ACK，等待对方发来的 FIN
#define TCP_STATE_CLOSE_WAIT 7 // 收到对方 FIN 并回了 ACK，等待本地应用层关闭
#define TCP_STATE_CLOSING 8    // 两端同时发送 FIN，进入交叉关闭状态
#define TCP_STATE_LAST_ACK 9   // 服务器发完最后的 FIN，等待对方最后的 ACK
#define TCP_STATE_TIME_WAIT 10 // 等待足够时间以确保对方收到最后的 ACK (通常是 2MSL)





#endif