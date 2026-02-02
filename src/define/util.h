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

#endif
