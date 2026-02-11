#ifndef TCP_H
#define TCP_H

#include "packet.h"


#define TCP_FLAG_FIN  0
#define TCP_FLAG_SYN  1
#define TCP_FLAG_RST  2
#define TCP_FLAG_PSH  3
#define TCP_FLAG_ACK  4
#define TCP_FLAG_URG  5
#define TCP_FLAG_ECE  6
#define TCP_FLAG_CWR  7



void tcp_send(ip_packet *pkt, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window_size, uint16_t urgent_pointer);



void tcp_process(packet *pkt);

void handle_tcp_syn(ip_packet *ip_packet_receive, tcp_packet *tcp_packet_receive);
void set_flags(uint8_t *flags,uint8_t CWR,uint8_t ECE,uint8_t URG,uint8_t ACK,uint8_t PSH,uint8_t RST,uint8_t SYN,uint8_t FIN);
void handle_tcp_syn_ack(ip_packet *ip_packet_receive, tcp_packet *tcp_packet_receive);

void set_flag(uint8_t *flags, uint8_t value,uint8_t target);
#endif