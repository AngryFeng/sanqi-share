# Linux内核如何与用户进程协作

了解了网络包如何从网卡送到协议栈后，在协议栈接收处理完网络包后，内核要如何通知用户进程，让用户进程收到并处理这些数据。进程和内核配合有多重方案，最经典的有两种：同步阻塞方案和多路IO复用方案。

- 同步阻塞方案：一般在客户端中应用，使用起来方便，符合人的思维方式；相对性能较差

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

- 多路IO复用方案：在服务端应用较多，**Linux**上多路复用的方案有**select**、**poll**和**epoll**，其中**epoll**的性能最好；后续会对**epoll**做介绍

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

  ## 0.了解socket的创建

  无论是阻塞或者**epoll**，需要先从认识**socket**内核结构开始

  创建**socket**函数

  ```c
  int main() {
      //调用后返回socket对象的fd 内部构建一些列内核对象
      int sk = scoket(AF_INET, SOCK_STREAM, 0);
  }
  ```

  AF_INET（IPV4）协议族下的SOCK STREAM对象（tcp **socket**内核对象）机构图

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

## 1.内核和用户进程协作の阻塞方式

同步阻塞IO模型下，从用户进程创建scoket，到等待网络包到达流程

![同步阻塞接收网络包](.\素材库\同步阻塞接收网络包.png)

### 1.1.等待接收消息

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

进程关联等待队列并添加到队列中：

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

### 1.2.网络包到来，软中断模块内核与用户进程协作

当网络包到来后，网卡接收后触发硬中断，再进入下半部分软中断处理，数据包进入协议栈处理，从TCP协议接收函数`tcp_v4_rcv`开始，总体接收流程

![软中断中网络包接收方法调用栈](.\素材库\软中断中网络包接收方法调用栈.png)

软中断里收到啊网络包，判断是TCP包会执行`tcp_v4_rcv`函数，如果是ESTABLISH**状态下的数据包，最终会把数据包解析拆包放到对应socket的接收队列中，然后调用`sk_data_ready`来唤醒用户进程。

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

调用`tcp_queue_rev`接收完成后，接着调用`sk_data_ready`来唤醒在socket上等待的用户进程。这个函数指针，指向了在创建socket流程中设置的`sock_def_readable`函数（也是默认的数据就绪处理函数）。

```c
//file: net/ core/sock.c
static void sock_def_readable (struct sock *sk, int len)
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

在`__wake_up_common`中找出一个等待项`curr`,然后调用其`curr->func`。该函数指针指向在`recv`函数执行时，使用`DEFINE_WAIT()`定义等待队列项时传入的是`autoremove_wake_function`函数。

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

### 1.3.内核与用户进程使用同步阻塞模型协作总结

同步阻塞⽅式接收⽹络包的整个过程分为两部分：

1. 用户进程调用`socket()`函数进入内核态创建内核对象。调用`recv()`函数进入内核态查看接收队列，在没有数据可处理时把当前进程阻塞，挂起，让出CPU
2. 网络包到来，经硬中断、软中断处理；将包处理完后放到socket的接收队列中。然后根据socket内核对象找到等到对象中正在等待数据而阻塞掉的进程，把它唤醒。

![获取不到数据进入等待+数据到来唤醒过程](.\素材库\获取不到数据进入等待+数据到来唤醒过程.png)

每个进程专门为了等**socket**上的数据就被从CPU上拿下来，然后换上另一个进程。等到数据准备好，睡眠的进程又会被唤醒，总共产生两次进程上下文切换开销。根据业界的测试，每次切换要花费 3-5微秒，在不同的服务器上会有出入，但上下浮动不会太大。从开发者角度来看，进程上下切换其实没有做有意义的作用。如果是**网络IO密集型**的应用，CPU就会被迫不停地做进程切换这种无用功。
在服务端角色上，这种模式完全没办法使用。因为这种简单模型的**socket**和进程 是一对一的。现在要在单台机器上承载成千上万，甚至十几万、上百万的用户连接请求。如果用上面的方式，就得为每个用户请求都创建一个进程。这就是所谓的**C10K**问题的典型表现。























































