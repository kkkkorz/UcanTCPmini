# 从零手写TCP/IP协议栈

## 前言

我是一名研二在读研究生，正在为即将到来的实习招聘季做准备。和很多计算机专业的同学一样，我匆匆忙忙地做了两个所谓的"外卖加点评"项目，背了一堆八股文就开始投递简历。

面试过程中我发现一个有趣的现象：面试官对应届生似乎更看重**基础**，几乎没有怎么问我关于项目的细节。这让我开始反思：我的简历上那两个"全栈项目"真的能体现我的技术实力吗？

答案显然是否定的。

于是我决定沉下心来，真正去啃一些计算机科学的基础知识。TCP/IP协议栈作为计算机网络的核心，自然成了我的首选目标。

## 为什么选择手写TCP/IP？

在B站上搜索"手写TCP"，我发现了李述铜老师的课程。正准备兴致勃勃地跟着视频敲代码，却发现他的代码风格我实在不太习惯——可能是太久没有写C语言了。

与其纠结于代码风格，不如**完全从零开始**！

我决定：
- **不看视频教程**，只通过理论知识和实践来实现
- **借助AI工具**作为编程辅助
- **使用WireShark抓包**来验证和调试
- **复用李述铜老师的网卡操作接口**（毕竟我不是驱动专家）

这将是一场真正的"从0到1"的挑战。

---

## 项目结构

```
UCanTCPmini/
├── lib/
│   ├── npcap/          # npcap库（第三方）
│   └── xnet/           # 网卡操作封装
├── src/
│   ├── define/         # 配置和数据结构定义
│   ├── net_app/        # ARP、IP、ICMP等协议实现
│   ├── tiny_net/       # 协议栈核心
│   └── app.c           # 主程序
└── CMakeLists.txt
```

---

## 开发历程

### 2026-01-30：项目启动

fork了李述铜老师的工程，获得了npcap库的基本操作接口。

```c
// 网卡打开接口
device = pcap_device_open(real_host_ip, host_mac, 1);
```

---

### 2026-02-03 至 2026-02-08：ARP协议

从ARP协议开始，因为它是数据链路层和网络层的桥梁。

**数据包结构定义：**

```c
// packet.h
#pragma pack(1)
typedef struct arp_packet {
    uint16_t htype;      // 硬件类型
    uint16_t ptype;      // 协议类型
    uint8_t hlen;        // 硬件长度
    uint8_t plen;        // 协议长度
    uint16_t operation;  // 操作类型
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} arp_packet;
#pragma pack()
```

**ARP缓存表设计（哈希表+链表解决冲突）：**

```c
// arp.h
typedef struct arp_cache_node {
    uint8_t ip[4];
    uint8_t mac[6];
    uint32_t time;
    uint8_t valid;
    struct arp_cache_node* next;
} arp_cache_node;

static arp_cache_node arp_cache[ARP_CACHE_SIZE];
```

**插入缓存表：**

```c
void arp_insert(uint8_t *ip, uint8_t *mac) {
    uint32_t ip_num = IP_TO_UINT32(ip);
    uint32_t index = ip_num % ARP_CACHE_SIZE;
    
    if (arp_cache[index].valid == 0) {
        // 空桶，直接插入
        memcpy(arp_cache[index].ip, ip, 4);
        memcpy(arp_cache[index].mac, mac, 6);
        arp_cache[index].time = time(NULL);
        arp_cache[index].valid = 1;
    } else if (memcmp(arp_cache[index].ip, ip, 4) == 0) {
        // IP相同，更新
        memcpy(arp_cache[index].mac, mac, 6);
        arp_cache[index].time = time(NULL);
    } else {
        // 冲突，插入链表
        arp_cache_node *node = malloc(sizeof(arp_cache_node));
        memcpy(node->ip, ip, 4);
        memcpy(node->mac, mac, 6);
        node->next = arp_cache[index].next;
        arp_cache[index].next = node;
    }
}
```

---

### 2026-02-09：ICMP协议与Ping实现

ARP完成后，开始实现ICMP协议。

**IP头结构：**

```c
typedef struct ip_packet {
    uint8_t header_len;      // 版本+头部长度
    uint8_t service_type;    // 服务类型
    uint16_t total_len;      // 总长度
    uint16_t identification; // 标识
    uint16_t flag_fragment;  // 标志+分片
    uint8_t ttl;             // 生存时间
    uint8_t protocol;        // 协议
    uint16_t checksum;       // 校验和
    uint8_t source_ip[4];
    uint8_t destination_ip[4];
} ip_packet;
```

**ICMP结构：**

```c
typedef struct icmp_packet {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
    uint8_t data[32];
} icmp_packet;
```

**校验和计算（踩过的坑）：**

```c
uint16_t calculate_checksum(uint16_t *addr, int count) {
    uint32_t sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(uint8_t *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}
```

> **Bug记录**：一开始WireShark能抓到包但Windows显示超时，原因是IP校验和计算时没有先置0！

```c
// 正确做法
ip_packet_send->checksum = 0;
ip_packet_send->checksum = calculate_checksum(ip_packet_send, sizeof(ip_packet));
```

---

### 2026-02-10：多线程架构重构

随着功能增多，单线程架构遇到瓶颈，进行了重构。

**消息队列设计：**

```c
// config.h
#define PACKET_QUEUE_SIZE 100

packet_node* packet_queue_send[PACKET_QUEUE_SIZE];
int packet_queue_send_index = -1;

packet* packet_queue_receive[PACKET_QUEUE_SIZE];
int packet_queue_receive_index = -1;
```

**发送线程：**

```c
static void *net_send_thread(void *arg) {
    while (1) {
        for(int i = 0; i < PACKET_QUEUE_SIZE; i++){
            if(packet_queue_send[i] != NULL){
                send_packet(packet_queue_send[i]);
                free(packet_queue_send[i]);
                packet_queue_send[i] = NULL;
            }
        }
        Sleep(1);
    }
    return NULL;
}
```

**处理线程（为每个数据包创建独立线程处理，防止阻塞）：**

```c
static void *net_process_thread(void *arg) {
    while (1) {
        for(int i = 0; i < PACKET_QUEUE_SIZE; i++){
            if(packet_queue_receive[i] != NULL){
                // 创建独立线程处理，防止类似死锁的情况
                thread_create(packet_process, packet_queue_receive[i]);
                packet_queue_receive[i] = NULL;
            }
        }
        Sleep(1);
    }
    return NULL;
}
```

---

### 2026-02-10：ARP缓存优化

**问题**：第一次ping回复总是发不出去，需要先"预热"一下ARP表。

**解决**：从经过的IP数据包中"偷取"MAC地址信息。

```c
void ip_process(packet* packet_receive){
    ip_packet* ip_packet_receive = (ip_packet*)packet_receive->data;//获取ip数据包结构体
    uint8_t prpotocol = ip_packet_receive->protocol;
    //白嫖arp缓存
    arp_insert(ip_packet_receive->source_ip, packet_receive->source_mac);
    switch (prpotocol)
    {
    case ICMP_TYPE: // ICMP
        icmp_process(packet_receive);
        break;
    
    default:
        break;
    }
}
```

---

## 工具函数

**字节序转换（网络是大端，x86是小端）：**

```c
#define SWAP_UINT16(x) (((x) >> 8) | ((x) << 8))

#define IP_TO_UINT32(ip) \
    (((uint32_t)(ip[0]) << 24) | ((uint32_t)(ip[1]) << 16) | \
     ((uint32_t)(ip[2]) << 8) | ((uint32_t)(ip[3])))
```

**IP字符串转数组：**

```c
void ip_str_to_uint8(uint8_t* ip, char* ip_str){
    char* token = strtok(ip_str, ".");
    int i = 0;
    while(token != NULL){
        ip[i] = atoi(token);
        token = strtok(NULL, ".");
        i++;
    }
}
```

---

## 技术总结

### 已实现功能

- ✅ 数据链路层：Ethernet帧处理
- ✅ ARP协议：请求、应答、缓存表
- ✅ IP协议：基本转发、校验和
- ✅ ICMP协议：Echo请求/应答
- ✅ Ping功能：互ping、延迟计算

### 学习到的知识点

1. **网络字节序**：大端 vs 小端
2. **校验和计算**：IP、ICMP的校验和算法
3. **哈希表设计**：冲突解决策略
4. **多线程编程**：生产者-消费者模式
5. **调试技巧**：WireShark抓包分析

### 下一步计划

- [ ] UDP协议
- [ ] TCP协议（三次握手、四次挥手）
- [ ] HTTP服务器
- [ ] 代码优化

---

## 心得体会

1. **基础真的很重要**：面试不问项目细节，不代表基础不重要
2. **Debug是一门艺术**：WireShark救了我无数次
3. **不要害怕从零开始**：一步步拆解后发现其实没那么难
4. **代码风格很重要**：写代码要写出自己的风格
5. **实践出真知**：看书百遍，不如手写一遍

---

## 关于我

一个正在努力提升自己的研二学生，希望通过手写TCP/IP协议栈来夯实计算机网络基础。

**项目地址**: https://github.com/yourusername/UCanTCPmini

如果你觉得这篇文章对你有帮助，欢迎Star！

---

*最后更新：2026-02-10*
