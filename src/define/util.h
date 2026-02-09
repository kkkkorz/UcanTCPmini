#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

//将两个字节转换为一个无符号数
uint16_t bytes_to_uint16(uint8_t* bytes);
//将一个无符号数转换为两个字节
void uint16_to_bytes(uint16_t value,uint8_t* bytes);
//将四个字节转换为一个无符号数
uint32_t bytes_to_uint32(uint8_t* bytes);

//处理uint16_t大小端问题
#define SWAP_UINT16(x) (((x) >> 8) | ((x) << 8))
//将ip地址转为数字

#define IP_TO_UINT32(ip) (((uint32_t)(ip[0]) << 24) | ((uint32_t)(ip[1]) << 16) | ((uint32_t)(ip[2]) << 8) | ((uint32_t)(ip[3])))

//将数字转为ip地址
#define UINT32_TO_IP(ip,num) ip[0] = (num >> 24) & 0xff; ip[1] = ()

//将点分十进制的ip字符串转为uint8_t数组
inline void   ip_str_to_uint8(uint8_t* ip,char* ip_str){
    char* token = strtok(ip_str,".");
    int i = 0;
    while(token != NULL){
        ip[i] = atoi(token);
        token = strtok(NULL,".");
        i++;
    }
    return;
}
//校验ip地址是否合法

//校验mac地址是否合法


//计算校验和
 inline uint16_t  calculate_checksum(uint16_t *addr, int count) {
    uint32_t sum = 0;
    uint16_t *ptr = addr;
    // 将所有 16 位字相加
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }

    // 处理可能的最后一个字节（如果总字节数为奇数）
    if (count > 0) {
        sum += *(uint8_t *)ptr; // 将最后一个字节视为高8位，低8位为0
    }

    // 将进位加到低16位
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // 返回反码
    return (uint16_t)(~sum);
}




#endif
