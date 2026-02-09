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
inline uint8_t*   ip_str_to_uint8(char* ip_str){
    uint8_t* ip = malloc(4);
    char* token = strtok(ip_str,".");
    int i = 0;
    while(token != NULL){
        ip[i] = atoi(token);
        token = strtok(NULL,".");
        i++;
    }
    return ip;
}
//校验ip地址是否合法

//校验mac地址是否合法

#endif
