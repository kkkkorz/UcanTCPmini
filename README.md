# 从零手写TCP/IP协议栈

## 为什么选择手写TCP/IP？

本人对计算机网络有一定的了解，但是不满足于浅尝辄止，纸上谈兵的感觉，对计算机网络的底层的实现十分好奇，于是在B站上搜索"手写TCP"的教程，我发现了李述铜老师的课程。正准备兴致勃勃地跟着视频敲代码，却发现他的代码风格我实在不太习惯——可能是太久没有写C语言了。

与其纠结于代码风格，不如**完全从零开始**！

我决定：
- **不看视频教程**，只通过理论知识和实践来实现
- **借助AI工具**作为编程辅助
- **使用WireShark抓包**来验证和调试
- **复用李述铜老师的网卡操作接口**（毕竟我不是驱动专家）

---

## 项目结构

```
UCanTCPmini/
├── lib/
│   ├── npcap/          # npcap库（第三方）
│   └── xnet/           # 网卡操作封装
├── src/
│   ├── define/         # 配置和数据结构定义
│   ├── net_app/        # ARP、IP、ICMP、TCP、UDP、HTTP等协议实现
│   ├── tiny_net/       # 协议栈核心
│   └── app.c           # 主程序
└── CMakeLists.txt
```

---

## 功能特性

- **ARP协议**：实现地址解析，支持ARP缓存表管理
- **IP协议**：网络层数据包处理
- **ICMP协议**：实现ping命令功能
- **TCP协议**：实现TCP三次握手、数据传输、四次挥手等完整流程
- **UDP协议**：实现UDP数据包收发
- **HTTP协议**：实现HTTP服务器，支持静态网页部署
- **Telnet支持**：支持基本的远程连接
- **多线程命令输入**：支持并发处理多个网络请求
- **配置文件**：支持IP地址和MAC地址的动态配置
- **Web服务器**：内置HTTP服务器，可部署静态网页

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
    }
}
```

---

### 2026-02-09 至 2026-02-10：ICMP与Ping实现

实现了ping命令，能够正确响应ping请求，通过消息队列分离了发送和接收数据包的线程。

**关键改进：**
- 解决了因IP层校验和未正确计算导致的ping命令超时问题
- 实现了多线程消息队列处理机制

---

### 2026-02-11 至 2026-02-13：TCP协议初步实现

**被动连接实现：**
- 成功实现被动接受TCP连接握手请求（接受对方的telnet命令的连接）
- 大量重构代码，采用分层模型进行编写
- 使用零拷贝（长度+偏移量）解析接收到的数据包
- 将packet结构体统一为header结构体

**TCB连接管理：**
- 加入TCB管理TCP连接，使用数组加链表存储TCB表
- 解决了计算校验和需要IP地址的问题

---

### 2026-02-14 至 2026-02-15：TCP连接完善

**主动连接实现：**
- 实现TCP第一次握手请求
- 完善TCP主动连接功能
- 实现客户端向服务端发送数据
- 初步完成基于TCP的聊天功能

**系统优化：**
- 修复因返回值错误导致闪退的bug
- 完成数据回显的功能

---

### 2026-02-15 至 2026-02-16：配置与命令增强

**配置管理：**
- 添加配置文件
- 实现IP地址和MAC地址可配置
- 添加ifconfig命令

**Bug修复：**
- 测试配置文件，修复ping命令的bug

---

### 2026-02-24：UDP与HTTP协议实现

**UDP协议：**
- 完成UDP数据包的收发

**HTTP协议：**
- 使用AI重构部分代码
- 实现HTTP协议，能够部署静态网页
- 修复了首次ARP超时的bug

---

### 2026-02-25：最终完善

**功能增强：**
- 初步测试了HTTP请求，浏览器成功请求到HTML文件
- 使用AI重构代码，增加代码可读性、健壮性
- 实现Web服务器功能，支持静态网页部署
- 进一步优化TCP连接处理

---

## 编译与运行

1. 确保安装了Npcap库
2. 配置好CMake环境
3. 执行以下命令编译：

```bash
mkdir build
cd build
cmake ..
make
```

4. 运行程序并根据提示配置网络参数

---

## 技术特点

1. **分层架构**：严格按照TCP/IP五层模型实现各协议
2. **零拷贝技术**：使用长度+偏移量方式解析数据包，提高性能
3. **多线程处理**：支持并发处理多个网络请求
4. **内存管理**：合理分配和释放内存，避免内存泄漏
5. **错误处理**：完善的错误处理机制，提高程序稳定性
6. **协议扩展**：模块化设计，易于添加新协议支持

---

## 项目贡献者

- laptop-pc (2250503470@qq.com)
- silence3322 (1916756072@qq.com)
- kkkkorz (99013530+kkkkorz@users.noreply.github.com)

---

## 学习价值

本项目展示了如何从零开始构建一个完整的TCP/IP协议栈，涵盖了网络编程的各个方面：

- 数据链路层的帧处理
- 网络层的路由与转发
- 传输层的可靠传输
- 应用层的服务实现
- 多线程并发处理
- 内存管理与资源释放
- 网络调试与抓包分析

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

### 2026-02-11：实现被动接受tcp握手请求

**问题**：虚拟机总是不认我的第二次握手发送的数据包，但是抓包抓得到。

**解决**：校验和有问题，需要使用伪首部进行校验和。

**说明**：还有很多问题，例如不能使用malloc，暂时还没弄明白，还有各种硬编码问题，还需要重构项目结构之类的。道阻且长~

```c
void handle_tcp_syn(ip_packet *ip_packet_receive, tcp_packet *tcp_packet_receive){
    //读取对方的Seq
    uint32_t seq = tcp_packet_receive->seq;


    //计算ack，表示自己已经收到对方的数据
    uint32_t ack =SWAP_UINT32( SWAP_UINT32(seq) + 1);//消耗一个字节
    //生成自己的Seq：表示自己想要收到的数据的序号
    uint32_t my_seq = time(NULL)%1000;

    //创建tcp包
    tcp_packet tcp_packet_send ;
    tcp_packet_send.checksum = 0;
    memset(&tcp_packet_send,0,sizeof(tcp_packet));
    tcp_packet_send.source_port = tcp_packet_receive->destination_port;
    tcp_packet_send.destination_port = tcp_packet_receive->source_port;
    tcp_packet_send.seq = my_seq;
    tcp_packet_send.ack = ack;
    tcp_packet_send.flags = (1<<TCP_FLAG_SYN) |(1<< TCP_FLAG_ACK);
    tcp_packet_send.window = tcp_packet_receive->window;
    tcp_packet_send.urgent_pointer = 0;
    tcp_packet_send.header_len = 0x50;
     //伪首部
    uint8_t* pseudo_header = malloc(32);
    memcpy(pseudo_header, ip_packet_receive->destination_ip, 4);
    memcpy(pseudo_header + 4, ip_packet_receive->source_ip, 4);
    pseudo_header[8] = 0;
    pseudo_header[9] = 6;
    pseudo_header[10] = 0;
    pseudo_header[11] = 0x14;
    memcpy(pseudo_header + 12, &tcp_packet_send, 20);
    tcp_packet_send.checksum = calculate_checksum(pseudo_header, 32);
    free(pseudo_header);
    //发送tcp包
    ip_send(&tcp_packet_send, TCP_TYPE , ip_packet_receive->source_ip, 20);
    Sleep(1000);
  //  free(tcp_packet_send);
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

一个正在努力提升自己的研二学生

**项目地址**: [[kkkkorz/UcanTCPmini](https://github.com/kkkkorz/UcanTCPmini)](https://github.com/kkkkorz/UcanTCPmini)

如果你觉得这篇文章对你有帮助，欢迎Star！

---

