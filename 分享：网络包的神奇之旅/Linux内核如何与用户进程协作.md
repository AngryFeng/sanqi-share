# Linux内核如何与用户进程协作

## 1.了解socket的创建

### 1.1.内核通过socket与用户进程协作的两种方式

了解了网络包如何从网卡送到协议栈后，在协议栈接收处理完网络包后，内核要如何通知用户进程，让用户进程收到并处理这些数据。进程和内核配合有多重方案，最经典的有两种：同步阻塞方案和多路IO复用方案。

>  同步阻塞方案

一般在客户端中应用，使用起来方便，符合人的思维方式；相对性能较差

```c
int main() {
    //创建socket
    int sk = socket(AF_INET,SOCK_STREAM,0);
    //建立连接
    connect(sk,...);
    //获取包-调用后同步阻塞等待直到获取到网络包
    recv(sk,...);
}
```

> 多路IO复用方案

在服务端应用较多，**Linux**上多路复用的方案有**select**、**poll**和**epoll**，其中**epoll**的性能最好；后续会对**epoll**做介绍

```c
int main() {
    //监听服务端口
    listen(lfd,...);
    //accept客户端连接1
    cfd1 = accept(...);
    //accept客户端连接2
    cfd2 = accept(...);
    //创建epoll对线
    efd = epoll_create(...);
    //把cfd1交给efd管理，监听特定类型事件
    epoll_ctl(efd, EPOLL_CTL_ADD, cfd1, ...);
    //把cfd2交给efd管理，监听特定类型事件
    epoll_ctl(efd, EPOLL_CTL_ADD, cfd1, ...);
    //获取efd对象中的就绪列表数量-调用后结果可以立即返回/可设置最大延迟返回时长阻塞等待
    epoll_wait(efd,...);
}
```

无论是阻塞或者**epoll**，需要先从认识**socket**内核结构开始

### 1.2.创建**socket**函数

```c
int main() {
    //调用后返回socket对象的fd 内部构建一些列内核对象
    int sk = scoket(AF_INET, SOCK_STREAM, 0);
}
```

AF_INET（IPV4）协议族下的SOCK STREAM对象（tcp **socket**内核对象）<a id="socket结构">结构图</a>

![socket内核结构图](.\素材库\socket内核结构图.png)

```c
//创建socket对象函数
//file:net/ socket.c
int __scok_create(struct net *net, int family,...) {
    struct socket *sock;
    const struct net_proto_family *pf;
    ......
    //分配socket对象
    sock = sock_alloc();
    //获取每个协议族的操作表
    pf = rcu_dereference(net_families[family]);
    //调⽤每个协议族的创建函数，对于AF_INET对应的是inet_create
    err = pf-create(net, sock, protocol, kern);
}

//file:net/ipv4/af_inet.c
int inet_create(struct net *net, struct socket *sock, int protocol, int kern) {
    struct sock *sk;
    // sock->ops 套接字层操作
    //将inet_stream_ops（定义了 INET 域（IPv4/IPv6）流式套接字（如 TCP）的通用操作接口） 赋到socket->ops
	sock->ops = answer->ops;
	//获得 tcp prot(tcp_prot 是一个 struct proto 类型的全局变量，对应tcp协议的操作方法)
	answer_prot = answer->prot;
    //sk->sk_prot 传输层协议操作
	//分配 sock对象，并把 tcp_prot 赋到sock->sk_prot上
	sk = sk_alloc(net, PF_INET， GFP_KERNEL, answer_prot);
	//对sock对象进⾏初始化
	sock_init_data(sock, sk);
}
```

为**socket**对象赋值网络层和传输层对应的协议操作

![socket协议操作集合函数和](.\素材库\socket协议操作集合函数和.png)

`sock_init_data`函数

```c
void sock_init_data(struct socket *sock, struct sock *sk) {
    // sk->sk_data_read 当软中断上收到数据包时会通过调⽤sk_data_ready函数指针（实际被设置成了 sock_def_readable(）来唤醒在sock上等待的进程。
    sk->sk_data_ready = sock_def_readabie;
    Sk->sk_write_space = sock_ def_write_space;
	sk->sK_error_report = sock_def_error_report;
}
```

## 2.内核和用户进程协作の阻塞方式

同步阻塞IO模型下，从用户进程创建scoket，到等待网络包到达流程

![同步阻塞接收网络包](.\素材库\同步阻塞接收网络包.png)

### 2.1.<a id="recv调用">等待接收消息</a>

用户进程调用`recv`后会执行`recoform`系统调用，用户进程进入内核态，执行一系列内核协议层函数，然后到**socket**对象接收队列中查看是否有数据，没有数据的话就把自己添加到**socket**的等待队列中，最后让出cpu

![recvform系统调用过程](.\素材库\recvform系统调用过程.png)

源码分析`recvform`最后是如何把用户进程阻塞掉（只分析没有使用`O_NONBLOCK`标记的情况）

从系统调用开始，到进程阻塞

```c
//系统调用
//SYSCALL_DEFINE6->sock_recvmsg->__sock_recvmsg->__sock_recvmsg_nosec
static inline int __sock_recvmsg_nosecec(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size, int flags) {
    ...
    //调用socket对象的ops的recvmsg方法
    return sock->ops->recvmsg(...);
}
```

`sock->ops->recvmsg`指向的时`inet_recvmsg`方法

```c
//file:net/ipv4/af_inet.c
//inet_recvmsg方法
int inet_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size, int flags) {
    ...
    //会调用sk->sk_prot->recvmsg方法
    err = sk->sk_prot->recvmsg(...);
}
```

`sk->sk_prot->recvmsg`函数指针指向`tcp_recvmsg`方法

```c
//file: net/ipv4/tcp.c
int tcp_recvmsg() {
    do{
        //遍历接收队列接收数据
		skb_queue_walk(&sk->sk_receive_queue, skb){
            ...
        }
    }
    if (copied >= target){
        release_sock(sk);
        1ock_sock(sk);
    }else {
        //没有收到⾜够数据，启⽤sk_wait_data阻塞当前进程
        sk_wait_data(sk, &timeo);
    }   
}
```

从系统调用到读取接收队列过程

![tcp读取sock接收队列](.\素材库\tcp读取sock接收队列.png)

如果接收队列中没有数据，或者数据不多，就会调用`sk_wait_data`把当前进程阻塞掉。

```c
//file: net/core/sock.c
int sk_wait_data(struct sock *sk, 1ong *timeo) {
    //当前进程（current）关联到所定义的等待队列上
    DEFINE_WAIT(wait);
    //调用sk_sleep获取sock对象下的wait，并准备挂起，将进程状态设置为可打断（INTERRUPTIBLE）
    prepare_to_wait(sk_sleep(sk), &wait, TASK, TASK_INTERRUPIBLE);
    set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
    //通过调用schedule_timeout让出cpu，然后进行睡眠
    rc = sk_wait_event(sk, timeo, !skb_queue_empty(&sk->sk_receive_queue));
}
```

进程进入**socket**等待队列并挂起

![进程进入socket等待队列并挂起](.\素材库\进程进入socket等待队列并挂起.png)

<a id="添加默认等待项">进程关联等待队列并添加到队列中：</a>

1.先在`DEFINE_WAIT`宏下，定义了一个等待队列项`wait`。

```c
//file: include/1inux/wait.h
#define DEFINE_ WAIT(name） DEFINE_WAIT_FUNC(name, autoremove_wake_function)
#define DEFINE_ WAIT_FUNC(name， function)
wait_queue_t name = {
    //关联当前进程
	.private = current,
    //回调函数 autoremove_wake_function
	. func = function,
	.task list = LIST_HEAD_ INIT((name).task_list)
}
```

2.调用`sk_sleep`获取sock对象下等待队列的队列头`wait_queue_head`

```c
//file: include/net/ sock.h
static inline wait_queue head_t *sk_sleep(struct sock *sk)
{
    BUILD_BUG_ON(offsetof(struct socket_ wa, wait) !=0);
	return &rcu_dereference_raw(sk->sk_wg)->wait;
}    
```

3.调⽤`prepare_to_wait`来把新定义的等待队列项`wait`插⼊`sock`对象的等待队列。

```c
//file: kernel/wait.c
void prepare_to_wait(wait_queue_head *q, wait_queue_t *wait, int state) {
    ...
    if (list_empty (&wait->task_1ist)）
        _add_wait_queue(q, wait);
    ...
}
```

当内核收到完整数据产生就绪事件时，就可以查找**socket**等待队列上的等待项，进而可以找到回调函数和在等待该scoket就绪事件的进程了。

最后调用`sk_wait_event`让出cpu执行权，进程将进入睡眠状态（这会导致一次进程上下文切换，对于cpu来讲是一次不小的花销）

### 2.2.网络包到来，软中断模块内核与用户进程协作

当网络包到来后，网卡接收后触发硬中断，再进入下半部分软中断处理，数据包进入协议栈处理，从TCP协议接收函数`tcp_v4_rcv`开始，总体接收流程

![软中断中网络包接收方法调用栈](.\素材库\软中断中网络包接收方法调用栈.png)

软中断里收到啊网络包，判断是TCP包会执行`tcp_v4_rcv`函数，如果是**ESTABLISH**状态下的数据包，最终会把数据包解析拆包放到对应socket的接收队列中，然后调用`sk_data_ready`来唤醒用户进程。

```c
// file: net/ ipv4/tcp_ipv4.c
int tcp_v4_rcv(struct sk_buff *skb)
{
    ...
    //获取tcp header
	th = tcp_hdr(skb);
    //获取ip header
	iph = ip_hdr(skb);
	//根据数据包 header中的⼯P、端⼜信息查找到对应的socket
	sk =__inet_1ookup_skb (&tcp_hashinfo, skb, th->source, th-sdest);
    ...
    //继续调用tcp_v4_do_rcv
    ret = tcp_v4_do_rcv(sk, skb);
    ...
}
```

在`tcp_v4_rcv`函数中通过拆包获取到**source**和**dest**信息，从而在本机上查到对应的**socket**，继续调用`tcp_v4_do_rcv`

```c
//file: net/ipv4/tcp ipv4.c
int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
    ...
    if (sk->sk_state == TCP_ESTABL ISHED){
          //执⾏连接状态下的数据处理
		if (tcp_rcv_established(sk, skb, tcp_hdr(skb), skb->len)）{
			rsk =sk;
			goto reset;
			return 0;
		}
    }
    ...
}
```

假设处理的是`ESTABLISH`状态下的包，这样就又进⼊`tcp_rcv_ established`函数进行

```c
int tcp_rev_established(struct sock *sk, struct sk buff *skb,
						const struct tcphdr *th, unsigned int len)
{
    ...
    //接收数据放到队列中
	eaten = tcp_queue_rev(sk, skb, tcp_header_1en, &fragstolen);
	//数据准备好，唤醒socket上阻塞掉的进程
	sk->sk_data_ready(sk, a);
}
```

`tcp_queue_rev`函数将接受到的数据放到`socket`的接收队列上

![tcp协议处理将数据包放到socket接收队列](.\素材库\tcp协议处理将数据包放到socket接收队列.png)

调用`tcp_queue_rev`接收完成后，接着调用`sk_data_ready`来唤醒在socket上等待的用户进程。这个函数指针，指向了在创建socket流程中设置的<a id="sock_def_readable函数">`sock_def_readable`</a>函数（也是默认的数据就绪处理函数）。

```c
//file: net/core/sock.c
static void (struct sock *sk, int len)
{
    struct socket wq *Wq:
	rcu_read_1ock();
	wq = rcu_dereference(sk->sk_wq);
	//有进程在此socket的等待队列
	if (wq_has_sleeper(wq))
			//唤醒等待队列上的进程
			wake_up_interruptible_sync_po11(&wq->wait, POLLIN | POLLPRI |
												POLLRDNORM | POLLRDBAND);
		sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN)；
		rcu_read_ unlock();
}
```

在`sock_def_readable`中访问`sock->sk_wq`队列中的`wait`项。在`wait`项中的`.private`字段关联了等待数据的用户进程。

获取到用户进程，接着就是调用`wake_up_interruptible_sync_po11`来唤醒该进程。

![同步阻塞模式下唤醒socket上的等待进程](.\素材库\同步阻塞模式下唤醒socket上的等待进程.png)

```c
//file: include/1inux/wait.h
#define wake_up_interruptible_sync_po11(x, m)
__wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, (void *) (m))
//file:krnel/scned/core.c
void wake_up_sync_key (wait_queue_head_t *as unsigned int mode,
						int nr_exclusive, void *key)
{
    ...
    //此处实现唤醒
    //nr_exclusive=1  意味着即使有多个进程都阻塞在同一socket上，也只唤醒一个进程
    __wake_up_common (g, mode, nr_exclusive, wake_flags, key);
    ...
}

//file:kernel/sched/core.c
static void __wake_up_common (wait_queue_head_t *q, unsigned int mode,
							int nr_exclusive, int wake_flags, void *key)
{
    wait_queue_t *curr, *next;
	list_for_each_entry_safe(curr, next, &q->task_list, task_1ist) {
		unsigned flags = curr->flags;
        
        //curr->func 调用当前等待项中的func
		if (curr->func(curr, mode, wake_flags, key) &&
					(flags & WQ_FLAG_EXCLUSIVE) 8& !--nr_exclusive)
			break;
	}
}
```

在`__wake_up_common`中找出一个等待项`curr`,然后调用其`curr->func`。该函数指针指向在[`recv`函数](# recv调用)执行时，使用[`DEFINE_WAIT()`](#添加默认等待项)定义等待队列项时传入的是`autoremove_wake_function`函数。

其中`autoremove_wake_function`中，调用`deault_wake_function`

```c
//file: kernel/sched/core. C
int default_wake_function(wait_queue_t *curr, unsigned mode, int wake_f1ags,
						void *key)
{
    return try_to_wake_up(curr->private, mode, wake_flags);
}
```

执行完`try_to_wake_up`后，`curr->private`上等待而被阻塞的进程被唤醒进入就绪状态，重新进入运行队列中，等待被执行（又会产生一次进程上下文切换开销）

### 2.3.内核与用户进程使用同步阻塞模型协作总结

同步阻塞⽅式接收⽹络包的整个过程分为两部分：

1. 用户进程调用`socket()`函数进入内核态创建内核对象。调用`recv()`函数进入内核态查看接收队列，在没有数据可处理时把当前进程阻塞，挂起，让出CPU
2. 网络包到来，经硬中断、软中断处理；将包处理完后放到socket的接收队列中。然后根据socket内核对象找到等到对象中正在等待数据而阻塞掉的进程，把它唤醒。

![获取不到数据进入等待+数据到来唤醒过程](.\素材库\获取不到数据进入等待+数据到来唤醒过程.png)

每个进程专门为了等**socket**上的数据就被从CPU上拿下来，然后换上另一个进程。等到数据准备好，睡眠的进程又会被唤醒，总共产生两次进程上下文切换开销。根据业界的测试，每次切换要花费 3-5微秒，在不同的服务器上会有出入，但上下浮动不会太大。从开发者角度来看，进程上下切换其实没有做有意义的作用。如果是**网络IO密集型**的应用，CPU就会被迫不停地做进程切换这种无用功。
在服务端角色上，这种模式完全没办法使用。因为这种简单模型的**socket**和进程 是一对一的。现在要在单台机器上承载成千上万，甚至十几万、上百万的用户连接请求。如果用上面的方式，就得为每个用户请求都创建一个进程。这就是所谓的**C10K**问题的典型表现。

## 3.内核和用户进程协作のepoll

上一节介绍的用户空间通过`recvfrom`调用获取网络包，当没有网络包时会导致当前进程进入阻塞，直到网络包到来重新唤醒，前后还额外产生了两次进程上下文切换开销。为了高效处理海量请求，必须要有一种让一个进程能同时处理多个连接的技术方案：一种方法是以非阻塞的方式调用`recvfrom`，for循环遍历查看所有**socket**，但是这种方式很低效；一种是用一个线程监控多个连接，当某个连接上有IO事件发生时直接快速把它找出来，也就是**IO多路复用**机制，复用指的是对进程的复用。

Linux系统中提供三种多路复用方法：select，poll和epoll，其中epoll性能表现最优异，能支持的并发量也最大。以下详细结构epoll的数据结构和工作流程。

epoll相关函数：

- epoll_create：创建一个epoll对象
- epoll_ctl：向epoll对象添加要管理的连接和它关注的IO类型、删除连接等
- epoll_wait：等待epoll对象管理的连接上的IO事件

### 3.1.epoll内核对象的创建

在用户进程调用`epoll_create`时，内核会创建一个`struct eventpoll`的内核对象，并把它关联到当前进程的已打开文件列表。对应`struct eventpoll`对象，简单的对象信息如下：

![eventpoll结构简图](.\素材库\eventpoll结构简图.png)

```c
// file: fs/eventpoll.c
SYSCALL_DEFINE1 (epo11_create1, int, f1ags)
{
	struct eventpo11 *ep = NULL;
	//创建⼀个eventpol1对象
	error = ep_a11oc(&ep);   
}

struct eventpoll {
    //sys_epoll_wait用到的等待队列
    wait_queue_head_t wq;
    //接收就绪的描述符存放链表
    struct list_head rdllist;
    //epoll对象中的红黑树
    struct rb_root rbr;
}
```

`eventpoll`结构中几个重要的成员含义：

- `wq`：等待队列链表，阻塞在`epoll`对象上的用户进程，软中断数据就绪时会通过`wq`找到进程做唤醒
- `rbr`：红黑树，管理用户进程添加的socket连接，对连接进行高效的查找、插入和删除；
- `rdllist`：就绪描述符链表，当连接就绪时，内核把就绪连接放到链表中；通过链表能够直接获取到所有的就绪连接

结构申请和字段初始化，在`ep_alloc`中完成

```c
// file: fs/eventpoll.c
static int ep_a11oc(struct eventpo11 **pep) 
{ 
    struct eventpo11 *ep;
	//申请eventpo11内存
	ep = kza11oc(sizeof(*ep), GFP_KERNEL);
	// 初始化等待队列头
	init_waitqueue_head(&ep->wq);
	//初始化就绪列表
	INIT_LIST_HEAD(&ep->rdllist);
	//初始化红⿊树指针
	ep->rbr = RB_ROOT;
}
```

### 3.2.为epoll添加socket

用户通过调用`epoll_ctl`函数管理socket，可以添加、删除和更新socket，接下来通过添加`EPOLL_CTL_ADD`连接过程，深入理解`epoll`的内部结构。

假设现在和客户端的多个socket连接都创建好，也创建好`epoll`对象，调用`epoll_ctl`注册每一个socket时处理流程如下：

1. 分配一个红黑树节点对象`epitem`
2. 将等待事件项添加到socket的等待队列中（该事件项的回调函数是`ep_poll_callback`）
3. 将`epitem`插入`epoll`对象的红黑树

以下是通过`epoll_ctl`添加两个socket以后，这些内核数据在进程中的关系图

![epoll添加socket内核对象结构](.\素材库\epoll添加socket内核对象结构.png)

#### 3.2.1`epoll_ctl`添加socket过程

```c
// file: fs/eventpoll.c
SYSCALL_DEFINE4(epoll_ct1, int, epfd, int, op, int, fd,
                struct epoll_event __user *, event)
{
    struct eventpoll *ep;
    struct file *file, xtfile;
	//根据epfd找到eventpoll内核对象
	file = fget(epfd);
	ep = file->private_data;
	//根据socket句柄号，找到其file内核对象
	file = fget(fd);
	switch (op) {
		case EPOLL_CTL_ADD:
            if (!epi) {
				epds.events |= POLLERR | POLLHUP;
                //插入红黑树
				error = ep_insert(ep, &epds, tfile, fd);
			}else
                error = -EEXIST;
            clear_tfile_check_1ist();
            break;
    }
}
```

在`epoll_ctl`首先根据传入的`fd`找到`epoll`和socket的内核对象；根据操作类型`EPOLL_CTL_ADD`执行添加连接操作`ep_insert`。

#### 3.2.2.`eq_insert`过程

```c
// file: fs/eventpoll.c
static int ep_insert(struct eventpo11 *ep,
                     struct epoll_event *event,
                     struct file *tfile, int fd)
	//1 分配并初始化epitem
	//分配⼀个epi对象
	struct epitem epi;
	if (!(epi = kmem_cache_a11oc(epi_cache, GFP_KERNEL)))
		return -ENOMEM;
	//对分配的epi对象进⾏初始化
	//epi->ffd中存了句柄号和struct file对象地址
	INIT_LIST_HEAD (&epi->pwqlist);
	epi->ep=ep;
	ep_set_ffd(&epi->ffd, tfile, fd);

	//2 设置socket等待队列
	//定义并初始化ep_pqueue对象
	struct ep_pqueue epq;
	epq.epi = epi;
	init_poll_funcptr(&epq.pt, ep_ptable_queue_proc);
	//调⽤ep_ptable_queue_proc注册回调函数
	//实际注⼊的两数为ep_po11_callback
	revents = ep_item_pol1(epi, &epq.pt);
	......
	//3 将epi插⼊eventpo11对象的红⿊树中
	ep_rbtree_insert(ep, epi);
	......
}
```

> 分配并初始化`epitem`

对于每一个socket，`epoll`会将其封装成`epitem`结构存储在红黑树中，`epitem`的数据结构如下

```c
// file: fs/eventpoll.c
struct epitem {
    //红黑树节点
    struct rb_node rbn;
    //socket文件描述符信息
    struct epoll_filefd ffd;
    //所归属的eventpoll对象
    struct eventpoll *ep;
    //等待队列
    struct list_head pwqlist;
}

static inline void ep_set_ffd(struct epol1_filefd *ffd,
                              struct file *file, int fd)
{ 
    fd->file = file;
	ffd->fd = fd;
}
```

`epitem`进行初始化时，`eqi->ep=ep`将`ep`指针指向`eventpoll`对象；`ep_set_ffd`函数将socket的`file`和`fd`填充到`epi->ffd`中。`epitem`结构关系图如下：

![epitem结构关系图](.\素材库\epitem结构关系图.png)

> 设置socket等待队列

回顾前面章节提到的[socket的数据结构](#socket结构)，在调用`recvfrom`后没有获取到网络包时，会创建等待队列项[放入到socket的等待队列中](#添加默认等待项),epoll在实现上也需要往socket等待队列添加队列项：

```c
//....前面做了一堆事情，根据socket的fd获取到socket的ops，从而获取到ipv4协议族映射的ops实现，执行sk_sleep(sk)获取到sock对象下的等待队列列表头wait queue head t，将等待队列项插入。

//file: fs/eventpol1.c
static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
								poll_table *pt)
{
    struct eppoll_entry *pwq;
	f (epi->nwait >= 0 && (pwq = kmem_cache_alloc(pwq_cache, GFP_KERNEL))) {
		//初始化回调⽅法
		init_waitqueue_func_entry(&pwg-swait, ep_po11_callback);
		//将ep_poll_callback放⼊socket的等待队列whead（注意不是epo1l的等待队列）
		add_wait_queue(whead, &pwq->wait);
	}
}

//file:include/linux/wait.h
static inline void init_waitqueue_func_entry(wait_queue_t *g, wait_queue_func_t func)
{
    q->flags = 0;
    //private被设置为NULL，在recvfrom调用时设置的时current当前进程
	q->private = NULL;
	//将ep_po11_callback注册到wait_queue_t对象上
	//有数据到达的时候调⽤q->func q->func = func;
    q->func = func;
}
```

等待队列项中仅将回调函数`q->func`设置为`ep_po11_callback`, 软中断将数据添加到socket的接收队列后，会通过注册的这个`ep_po11_callback`函数来回调，进而通知epoll对象。

![epoll创建等待队列项](.\素材库\epoll创建等待队列项.png)

> 插入红黑树

分配网`epitem`对象后会把它插入到红黑树中，结构关系图：

![epitem在红黑树中结构图](.\素材库\epitem在红黑树中结构图.png)

epoll使用红黑树数据结构存储`epitem`对象，是考虑查找效率、插入效率、内存开销等多个方面的均衡考量。

### 3.2.3.epoll_wait等待接收

`epoll_wait`被调用时，会观察`epoll->rdllists`链表里有没有数据。有数据就返回，没有就创建一个等待队列项，将其添加到`eventpoll`的等待队列中，然后阻塞当前进程。

![epoll_wait处理流程](.\素材库\epoll_wait处理流程.png)

<a id="epoll_wait添加等待队列项">`epoll_wait`处理流程</a>

```c
//file: fs/eventpol1.c
SYSCALL_DEFINE4(epo11_wait, int, epfd,...)
{
	error = ep_poll(ep, events, maxevents, timeout);    
}

static int ep_poll(struct eventpo11 *ep,...)
{ 
    wait_queue_t wait;
	fetch_events:
	//1 判断就绪队列上有没有事件就绪
	if (!ep_events_available(ep)){
        //2 定义等待事件并关联当前进程
		init_waitqueue_entry(&wait, current);
		//3 把新waitqueue添加到epo11->wq链表
		_add_wait_queue_exclusive(&ep->wq, &wait);
        for （;;){
        ......
		//4 让出CPU，主动进⼊睡眠状态
		set_current_state(TASK_INTERRUPTIBLE)；
		if (!schedule_hrtimeout_range(to, slack, HRTIMER_ MODE_ABS))
			timed_ out = 1;
       	......
        }
    }
}

//file: fs/eventpoll.c
//判断就绪队列上有没有事件就绪
static inline int ep_events_available (struct eventpo11 *ep) 
{ 
    return !list_empty(&ep->rdl1ist) || ep->ovflist != EP_UNACTIVE_ PTR;
}

//file: include/linux/wait.h
//定义等待事件并关联当前进程
static inline void init_waitqueue_entry(wait_queue_t *g, struct task_struct *p)
{
    q->flags = 0;
    q->private = p;
    //后续会关注到这个在epoll等待队列中的等待队列项的回调函数
    q->func = default_wake_function;
}
```

### 3.3.数据来了

执行`epoll_ctl`，内核为每一个socket都添加了一个等待队列项，在`epoll_wait`运行完后，又在`eventpoll`对象上添加了等待队列元素，得到新的epoll内核数据结构关系图：

![epoll内核数据结构关系图](.\素材库\epoll内核数据结构关系图.png)

- socket->sock->sk_data_ready设置就绪处理函数[`sock_def_readable`](#sock_def_readable函数)
- socket的等待队列项中，其回调函数是`ep_poll_callback`另外其`private` 没用了， 指向的是空指针null
- 在`eventpoll`的等待队列项中，其回调函数是`default_wake_function`。其private指向 的是等待该事件的⽤户进程。

当网络数据包被接收到socket的接收队列后，经过前面章节介绍最后会调用就绪处理函数`sock_def_readable`

```c
//file: net/core/sock.c
static void (struct sock *sk, int len)
{
    struct socket wq *Wq:
	rcu_read_1ock();
	wq = rcu_dereference(sk->sk_wq);
	//判断等待队列不为空
	if (wq_has_sleeper(wq))
			//执⾏等待队列项上的回调函数
			wake_up_interruptible_sync_po11(&wq->wait, POLLIN | POLLPRI |
												POLLRDNORM | POLLRDBAND);
		sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN)；
		rcu_read_ unlock();
}
```

- `wq_has_sleeper`对于简单的`recvfrom`系统调用来说，确实是判断是否有进程阳 塞。但是对于epoll下的socket只是判断等待队列是否不为空，不⼀定有进程阻塞。 
- `wake_up_interruptible_sync_po11` 只是会进⼊socket等待队列项上设置的回调函数，并不⼀定有唤醒进程的操作。

> `wake_up_interruptible_sync_poll`找到等待队列项注册的回调函数

```c
//fi1e: include/linux/wait.h
#define wake_up_interruptible_sync_po11(x，m)
__wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, (void *)(m))

//file: kernel/sched/core.c
void __wake_up_sync_key(wait_queue_head_t *q, unsigned int mode,
					int nr_exclusive, void *key)
{
    ......
    __wake_up_common(q, mode, nr_exclusive, wake_flags, key);
    ......
}

static void __wake_up_common(wait_queve_head_t *q, unsigned int mode,
							int nr_exclusives, int wake flags, void *key) 
{
    wait_queue_t *curr, *next;
    
	list_for_each_entry_safe(curr, next, &q->task_list, task_list) { 
        unsigned flags = curr->flags;
        //出等待队列⾥注册的某个元素curr，回调其curr->func,
        //也就是在ep_insert中设置的ep_poll_calloack
		if (curr->func(curr, mode, wake_f1ags, key) && 
            (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive）
				break; 
     }
}
```

> 执⾏socket就绪回调函数数`ep_poll_calloack`

```c
//file: fs/eventpol1.c
static int ep_po11_callback(wait_queue_t xwait, unsigned mode, int sync,
							void *key)
{
    //获取wait对应的epitem
	struct epitem *epi = ep_item_from_wait(wait);
	//获取epitem对应的eventpo11结构体
	struct eventpo11 *ep = epi->ep;
    
    //1 将当前epitem添加到eventpo11的就绪队列中
	list_add_tail(&epi->rdllink, &ep->rdllist);
    
    //2 查看eventpo11的等待队列上是否有等待
	if (waitqueue_active (&ep->wq)）
		wake_up_1ocked (&ep->wq)；
}
```

在`ep_poll_callback`中根据等待任务队列项上额外的`base`指针可以找到`epitem`，进⽽ 也可以找到`eventpoll`对象。

接下来第一件事就是把自己的`epitem`添加到`epoll`的就绪队列中，接着查看`eventpoll`对象的等待队列中是否有等待项（[调用`epoll_wait`设置](#epoll_wait添加等待队列项)），如果没有等待项，软中断的事情就做完了。如果有等待项，那就找到等待项里设置的回调函数

![ep_poll_callback获取等待队列项成员字段](.\素材库\ep_poll_callback获取等待队列项成员字段.png)



调用链`wake_up_locked()` => `__wake_up_locked()` => `__wake_up_common`，最后执行`curr->func`也就是调用`epoll_wait`时传入的[`default_wake_function`函数](#epoll_wait添加等待队列项)

> 执⾏epoll就绪通知`default_wake_function`

在`default_wake_function`中找到等待队列项里的进程描述符，然后唤醒它

```c
//file:kernel/sched/ core.c
int default_wake_function(wait_queue_t *curr, unsigned mode, int wake_flags,
							void *key)
{
    return try_to_wake_up(curr->private, mode, wake_flags);
}

```

![default_wake_fucntion唤醒等待项中的进程](.\素材库\default_wake_fucntion唤醒等待项中的进程.png)

唤醒进程后进入进程调度就绪队列，等待调度；后续进程接着从`epoll_wait`阻塞时暂停的代码处继续进行，把`rdllist`中就绪的事件返回给用户进程。

### 3.4.内核和用户进程协作のepoll总结

![epoll工作时序图](.\素材库\epoll工作时序图.png)

其中软中断回调时的回调函数调用关系整理如下： 

`sock_def_readable`：sock对象初始化时设置的。 

​		=＞ `ep_poll_callback`：调⽤`epoll_ctl`时添加到socket上的。 

​				=> `detault_wake_function`：调⽤`epoll_wait`时设置到epoll上的。

epoll相关的函数内核运行环境分两部分：

- 用户进程内核态。调⽤`epoll_wait`等函数时会将进程陷入内核态来执行。这部分代码负责查看接收队列，以及负责把当前进程阻塞掉，让出CPU。
- 硬、软中断上下文中。在这些组件中，将包从网卡接收过来进行处理，然后放到socket的接收队列。对于epoll来说，再找到socket关联的`epitem`，并且把它添加到`eventpoll`对象的就绪链表中，同时顺带检查一下`eventpoll`的`wq`等待队列上是否有阻塞的进程，如果有则唤醒。

调用`epoll_wait`后可能存让进程进入阻塞，但是在实践中，只要有源源不断的网络IO事件到来，`epoll_wait`根本就不会进入阻塞，直到实在没有事件后才进入阻塞让出CPU。

## 4.Q&A

阻塞到底是怎么⼀回事？

同步阻塞IO都需要哪些开销？

多路复用epoll为什么就能提高网络性能？

epoll也是阻塞的？







































































