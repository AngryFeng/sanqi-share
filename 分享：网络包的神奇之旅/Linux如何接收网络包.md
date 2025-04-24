# Linux如何接收网络包

## 0.应用层接收网络包

```c
int main(){
    int serverSocketFd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(serverSocketFd, ...);

    char buff[BUFFSIZE];
    int readCount = recvfrom(serverSocketFd, buff, BUFFSIZE, 0, ...);
    buff[readCount] = '\0';
    printf("Receive from client:%s\n", buff);
}
```

`recvfrom`之下隐藏了哪些技术细节？

## 1.开局两张图：Linux接受网络包总览

1.1.网络分层话事人

![image-20250324153629800](.\素材库\image-20250324153629800.png)

在TCP/IP网络分层模型里，整个协议栈被分成了物理层、链路层、网络层、传输层以及应用层。物理层对应的时网卡、网线；链路层对应的时网络设备驱动；应用层是在用户进程里一般有Http、FTP等应用（游戏服务器也在改层）；其中`Linux`内核和网卡驱动主要实现链路层+网络层+传输层这三层功能。内核为更上层的应用层提供Socket接口来支持用户访问。

1.2.数据包进入内核身体的全过程



![微信截图_20250324154221](.\素材库\微信截图_20250324154221.png)

1.2.1.处理方式：一个标记+两个中断+事后处理

```c
/**
名词概念解释

**硬中断（Hard IRQ）**：硬件设备触发中断信号，CPU 立即暂停当前任务，执行中断处理程序（ISR）。

**软中断（Soft IRQ）**：ISR 将非紧急任务标记为软中断，交由 `ksoftirqd` 在适当时机处理。

**DMA（Direct Memory Access，直接内存访问）**：一种让硬件设备无需通过CPU中转直接访问计算机内存的技术，**DMA**控制器接管总线，完成外设与内存之间的数据搬运，传输完成后向CPU发起硬中断信号
**/
```

当网卡设备上有数据到达时，会给CPU的相关引脚出发一个电压变化，以通知CPU来处理数据。对应网络模块来说，由于处理过程复杂和耗时，若此次硬中断处理完整个过程，会导致中断处理函数优先级过高从而存在过度占用CPU的情况（鼠标、键盘等响应无法及时响应）。因此Linux中断处理函数上下部分，上半部只进行最简单的工作，快速处理后释放CPU，剩下的绝大部分工作放到下一步“慢慢”处理。

硬中断是通过给CPU物理引脚施加电压变化实现的，软中断是内核通过给内存中的⼀个变量赋予⼆进制值以标记有软中断发生，接下来由`ksoftirqd内核线程`全权处理。

1. 当⽹卡收到数据以后，以`DMA`的⽅式把⽹卡收到的帧写到内存⾥，再向CPU发起⼀ 个中断，以通知CPU有数据到达。
2. 当CPU收到中断请求后，会去调⽤⽹络设备驱动注册的中断处理函数。
3. ⽹卡的中断处理函数并不做过多⼯作，发出软中断请求，然后尽快释放CPU资源。
4. `ksoftirqd内核线程`检测到有软中断请求到达，调⽤``poll``开始轮询收包，收到后交由各级协议栈处理。对于TCP包来说，会被放到⽤户`socket`的接收队列中。

## 2.为迎接网络包的到来，内核事先的准备

### 2.1.创建异步任务载体--ksoftirqd内核线程

**ksoftirqd** 是 Linux 内核中用于处理 **软中断（softirq）** 的守护线程，每个线程对应一个核心，其核心职责包括：

- **异步处理中断下半部**：在硬件中断（硬中断）处理完成后，将耗时较长的任务（如网络数据包处理、定时器回调）延迟到软中断中执行。
- **防止中断处理阻塞系统**：避免高负载下软中断积累导致内核无法调度其他任务。
- **多核负载均衡**：每个 CPU 核心对应一个 `ksoftirqd/<N>` 线程（如 `ksoftirqd/0`、`ksoftirqd/1`）。

创建流程

![微信截图_20250324164313](.\素材库\微信截图_20250324164313.png)

当**ksoftirqd** 被创建出来后，进入线程循环函数`ksoftirqd_should_run`和`run_ksoftirqd`中，会一直判断有没有软中断需要处理。其中软中断会有多种类型

```c
/* include/linux/interrupt.h */

enum {
    HI_SOFTIRQ=0,          /* 高优先级 tasklet */
    TIMER_SOFTIRQ,         /* 定时器回调 */
    NET_TX_SOFTIRQ,         /* 网络数据包发送 */
    NET_RX_SOFTIRQ,         /* 网络数据包接收 */
    BLOCK_SOFTIRQ,          /* 块设备 I/O 完成 */
    IRQ_POLL_SOFTIRQ,       /* 中断轮询混合处理 */
    TASKLET_SOFTIRQ,        /* 普通优先级 tasklet */
    SCHED_SOFTIRQ,          /* 调度器任务 */
    HRTIMER_SOFTIRQ,        /* 高精度定时器 */
    RCU_SOFTIRQ,            /* RCU 同步回调 */
    NR_SOFTIRQS              /* 软中断类型总数 */
};

```

`NET_TX_SOFTIRQ`和`NET_RX_SOFTIRQ`分别对应网络包的发送和接受两种类型。

### 2.2.链路层干的话--*网络子系统初始化*

![微信截图_20250326151201](.\素材库\微信截图_20250326151201.png)

Linux内核通过调⽤`subsys initcall`来初始化各个⼦系统，⽹络⼦系统的初始化，会执⾏`net_dev_init`函数

```c
//file: net/core/dev.c
static int __init net_dev_init(void)
{
    ......

    for_each_possible_cpu(i) {
        struct softnet_data *sd = &per_cpu(softnet_data, i);

        memset(sd, 0, sizeof(*sd));
        skb_queue_head_init(&sd->input_pkt_queue);
        skb_queue_head_init(&sd->process_queue);
        sd->completion_queue = NULL;
        INIT_LIST_HEAD(&sd->poll_list);

        ......
    }

    ......

    open_softirq(NET_TX_SOFTIRQ, net_tx_action);
    open_softirq(NET_RX_SOFTIRQ, net_rx_action);
}
subsys_initcall(net_dev_init);
```

在⽹络⼦系统的初始化过程中，会为每个CPU初始化`softnet_data`，`open_softirq`注册了每一种软中断都注册一个处理函数

- `softnet _ data`数据结构中的`poll_list`字段，用于各个存储驱动程序的`poll`函数，下面网卡驱动初始化时会把对应`poll`函数注册进来
- `NET_TX_SOFTIRQ`类型对应`net_tx_action`函数
- `NET_RX_SOFTIRQ`类型对应`net_rx_action`函数

继续跟踪`open_softirq`后发现这个注册的方式是记录在`softirq_vec`变量里的。后面`ksoftirqd`线程收到软中断的时候，也会使用这个变量来找到每一种软中断对应的处理函数。

```c
//file: kernel/softirq.c
void open_softirq(int nr, void (*action)(struct softirq_action *))
{
    softirq_vec[nr].action = action;
}
```

### 2.3.传输层和网络层干的活--*协议栈注册*

内核实现了网络层的ip协议，也实现了传输层的**tcp**协议和**udp**协议。 这些协议对应的实现函数分别是`ip_rcv()`,`tcp_v4_rcv()`和`udp_rcv()`。是通过注册的方式来实现的。 Linux内核中的`fs_initcall`和`subsys_initcall`类似，也是初始化模块的入口。`fs_initcall`调用`inet_init`后开始网络协议栈注册。 通过`inet_init`，将这些函数注册到了`inet_protos`和`ptype_base`数据结构中了



![微信截图_20250326203805](.\素材库\微信截图_20250326203805.png)

**inet_protos记录着udp，tcp的处理函数地址，**

**ptype_base存储着ip_rcv()函数的处理地址**。

软中断中会通过`ptype_base`找到`ip_rcv`函数地址，进而将ip包正确地送到`ip_rcv()`中执行。在`ip_rcv`中将会通过`inet_protos`找到**tcp**或者**udp**的处理函数，再而把包转发给`udp_rcv()`或`tcp_v4_rcv()`函数。

拓展：`ip_rcv`中会处理**netfilter**和**iptable**过滤，如果你有很多或者很复杂的 **netfilter** 或 **iptables** 规则，这些规则都是在软中断的上下文中执行的，会加大网络延迟。

### 2.4.接口设计~可插拔，物理层实现--网卡驱动初始化

每一个驱动程序（不仅仅只是网卡驱动）会使用 `module_init `向内核注册一个初始化函数，当驱动被加载时，内核会调用这个函数。比如igb网卡驱动的代码位于`drivers/net/ethernet/intel/igb/igb_main.c`

```c
//file: drivers/net/ethernet/intel/igb/igb_main.c
static struct pci_driver igb_driver = {
    .name     = igb_driver_name,
    .id_table = igb_pci_tbl,
    .probe    = igb_probe,
    .remove   = igb_remove,
    ......
};

static int __init igb_init_module(void)
{
    ......
    ret = pci_register_driver(&igb_driver);
    return ret;
}
```

驱动的`pci_register_driver`调用完成后，Linux内核就知道了该驱动的相关信息，比如igb网卡驱动的`igb_driver_name`和`igb_probe`函数地址等等。当网卡设备被识别以后，内核会调用其驱动的probe方法（igb_driver的probe方法是igb_probe）。驱动probe方法执行的目的就是让设备ready，对于igb网卡，其`igb_probe`位于drivers/net/ethernet/intel/igb/igb_main.c下。主要执行的操作如下：



![微信截图_20250326204842](.\素材库\微信截图_20250326204842.png)





- 第5步中我们看到，网卡驱动实现了ethtool所需要的接口，也在这里注册完成函数地址的注册。网卡实现了ethool的所有接口，ethool命令能查看网卡收发包统计，调整RX队列数量和大小，最终都是通过调用ethool接口调用了网卡驱动的相应方法
- 第6步注册的igb_netdev_ops中包含的是`igb_open`等函数，该函数在网卡被启动的时候会被调用。
- 第7步中，在`igb_probe`初始化过程中，还调用到了`igb_alloc_q_vector`。他注册了一个NAPI机制所必须的poll函数(NAPI就是优化网络数据包接收处理的一种机制，**中断触发** 与 **轮询处理**，避免中断风暴，高吞吐量)

### 2.5.串联打通各层软硬件--启动网卡

当上面的初始化都完成以后，就可以启动网卡了。回忆前面网卡驱动初始化时，我们提到了驱动向内核注册了 structure `net_device_ops`变量，它包含着网卡启用、发包、设置mac 地址等回调函数（函数指针）。当启用一个网卡时（例如，通过 ifconfig eth0 up），`net_device_ops` 中的` igb_open`方法会被调用



![微信截图_20250326210137](.\素材库\微信截图_20250326210137.png)

```c
//file: drivers/net/ethernet/intel/igb/igb_main.c
static int __igb_open(struct net_device *netdev, bool resuming)
{
    /* allocate transmit descriptors */
    err = igb_setup_all_tx_resources(adapter);

    /* allocate receive descriptors */
    err = igb_setup_all_rx_resources(adapter);

    /* 注册中断处理函数 */
    err = igb_request_irq(adapter);
    if (err)
        goto err_req_irq;

    /* 启用NAPI */
    for (i = 0; i < adapter->num_q_vectors; i++)
        napi_enable(&(adapter->q_vector[i]->napi));

    ......
}
```

- `igb_setup_all_rx_resources`分配了RingBuffer(环形数组，接受数据包)，并建立内存和Rx队列的映射关系（Rx Tx 队列的数量和大小可以通过 ethtool 进行配置）
- `igb_request_irq`给网卡的的每一个队列注册中断函数`igb_msix_ring`（多队列网卡可以在硬中断是提高CPU的亲和性）

## 3.万事俱备只欠东风，迎接数据的到来

### 3.1.硬中断处理

首先当数据帧从网线到达网卡上的时候，第一站是网卡的接收队列。网卡在分配给自己的RingBuffer中寻找可用的内存位置，找到后DMA引擎会把数据DMA到网卡之前关联的内存里，这个时候CPU都是无感的。当DMA操作完成以后，网卡会像CPU发起一个硬中断，通知CPU有数据到达。

![微信截图_20250326211507](.\素材库\微信截图_20250326211507.png)

调用网卡硬中断注册函数`igb_msix_ring`-->`____napi_schedule`

```c
//file: drivers/net/ethernet/intel/igb/igb_main.c
static irqreturn_t igb_msix_ring(int irq, void *data)
{
    struct igb_q_vector *q_vector = data;

    /* Write the ITR value calculated from the previous interrupt. */
    igb_write_itr(q_vector);

    napi_schedule(&q_vector->napi);

    return IRQ_HANDLED;
}

/* Called with irq disabled */
static inline void ____napi_schedule(struct softnet_data *sd,
                     struct napi_struct *napi)
{
    list_add_tail(&napi->poll_list, &sd->poll_list);
    __raise_softirq_irqoff(NET_RX_SOFTIRQ);
}
```

`list_add_tail`修改了CPU变量`softnet_data`里的`poll_list`,将驱动的`napi struct`加到里面；接下来触发了一个软中断`NET_RX_SOFTIRQ`

### 3.2.兜兜转转只为扒到数据包--ksoftirqd内核线程处理软中断

![微信截图_20250326212531](.\素材库\微信截图_20250326212531.png)

`ksoftirqd_should_run`函数会加载硬中断设置的中断类型`NET_RX_SOFTIRQ`

`ksoftirqd_should_run`通过加载到的中断类型`NET_RX_SOFTIRQ`，找到对应的action方法，网络子系统初始化时注册的处理函数`net_rx_action`会被执行

硬中断在哪个CPU上被响应，那么软中断也是在这个CPU上处理的。所以说，如果你发现你的Linux软中断CPU消耗都集中在一个核上的话，做法是要把调整硬中断的CPU亲和性，来将硬中断打散到不通的CPU核上去。

`net_rx_action`函数

```c
static void net_rx_action(struct softirq_action *h)
{
    struct softnet_data *sd = &__get_cpu_var(softnet_data);
    //计算方法执行时长 防止接收网络包过程过长霸占cpu过久
    unsigned long time_limit = jiffies + 2;
    int budget = netdev_budget;
    void *have;
	//调用该方法关闭该设备的硬中断 防止poll硬中断中将设备添加到poll lis
    local_irq_disable();

    while (!list_empty(&sd->poll_list)) {
        ......
        n = list_first_entry(&sd->poll_list, struct napi_struct, poll_list);

        work = 0;
        if (test_bit(NAPI_STATE_SCHED, &n->state)) {
            //执行⽹卡驱动注册到的pol函数
            work = n->poll(n, weight);
            trace_napi_poll(n);
        }

        budget -= work;
    }
}
```

对于igb网卡来说，就是igb驱动力的`igb_poll`函数了。

```c
/**
 *  igb_poll - NAPI Rx polling callback
 *  @napi: napi polling structure
 *  @budget: count of how many packets we should handle
 **/
static int igb_poll(struct napi_struct *napi, int budget)
{
    ...
    if (q_vector->tx.ring)
        clean_complete = igb_clean_tx_irq(q_vector);

    if (q_vector->rx.ring)
    	//igb_clean_rx_irq->igb_fetch_rx_buffer和igb_is_non_eop把数据帧从RingBuffer上取下来/napi_gro_receive合并数据包->netif_receive_skb数据包将被送到协议栈中
        clean_complete &= igb_clean_rx_irq(q_vector, budget);
    ...
}
```

### 3.3.星火传递把数据网上抛递--网络协议栈处理

`netif_receive_skb`函数会根据包的协议，假如是udp包，会将包依次送到`ip_rcv()`,`udp_rcv()`协议处理函数中进行处理。

![微信截图_20250326215240](.\素材库\微信截图_20250326215240.png)



### 3.4 在网上抛递--IP协议层处理

```c
//file: net/ipv4/ip_input.c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    ......

    return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, skb, dev, NULL,
               ip_rcv_finish);
}
```

这里`NF_HOOK`是一个钩子函数，它就是我们⽇常⼯作中经常⽤到的iptables netiter 过滤。如果你有很多或者很复杂的netiler规则，会在这⾥消耗过多的CPU资源，加⼤⽹络 延迟。

当执行完注册的钩子后就会执行到最后一个参数指向的函数`ip_rcv_finish`,该函数最后根据`inet_protos`结构找打的`tcp_rcv()`和`udp_rcv()`的函数地址。这里将会根据包中的协议类型选择进行分发,在这里skb包将会进一步被派送到更上层的协议中，**udp**和**tcp**。

## 4.总结

再次回到开局一张图，接收数据发生的点点滴滴

![微信截图_20250324154221](.\素材库\微信截图_20250324154221.png)

首先在开始收包之前，Linux要做许多的准备工作：

- 创建ksoftirqd线程，为它设置好它自己的线程函数，后面就指望着它来处理软中断呢。
-  协议栈注册，linux要实现许多协议，比如arp，icmp，ip，udp，tcp，每一个协议都会将自己的处理函数注册一下，方便包来了迅速找到对应的处理函数
- 网卡驱动初始化，每个驱动都有一个初始化函数，内核会让驱动也初始化一下。在这个初始化过程中，把自己的DMA准备好，把NAPI的poll函数地址告诉内核
- 启动网卡，分配RX，TX队列，注册中断对应的处理函数

当数据到来了以后，第一个迎接它的是网卡：

-  网卡将数据帧DMA到内存的RingBuffer中，然后向CPU发起中断通知
- CPU响应中断请求，调用网卡启动时注册的中断处理函数
- 中断处理函数几乎没干啥，就发起了软中断请求
- 内核线程ksoftirqd线程发现有软中断请求到来，先关闭硬中断
- ksoftirqd线程开始调用驱动的poll函数收包
- poll函数将收到的包送到协议栈注册的ip_rcv函数中
- ip_rcv函数再讲包送到udp_rcv函数中（对于tcp包就送到tcp_rcv）





























