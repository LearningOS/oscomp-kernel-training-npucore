# 信号

## 简介

信号是Linux下常见的跨进程通信机制，特别是在父子进程之间应用很多，这篇文档用于教怎么从零开始搭建一套信号系统。

## 相关系统调用

有关的系统调用有4个,分别是:
+ `kill`,  负责给进程传递信号 
+ `sigaction`, 负责设定特定信号处理的方式  
+ `sigprocmask`, 负责建立特定进程的"信号掩码",从而过滤并忽略特定的信号  
+ `sigreturn`, 负责调用完成自定义信号处理函数后返回  

## 机理

信号是在软件层次上对中断机制的一种模拟。在原理上，一个进程收到一个信号与处理器收到一个中断请求可以说是一样的。信号是异步的，一个进程不必通过任何操作来等待信号的到达，事实上，进程也不知道信号到底什么时候到达。信号可以直接进行用户空间进程和内核进程之间的交互，内核进程也可以利用它来通知用户空间进程发生了哪些系统事件。信号因此可以处理进程间异步通信。

### 信号的发出

当特定时间发生,信号发出。其对应事件是系统硬编码且不可更改的,具体内容可见于manpage: signal(2)部分，或者本操作系统的function reference。

当进程发出信号的时候会调用`kill`系统调用，这个时候内核处理`kill`时会讲对应进程的信号置位，信号量的维护放在TCB里，在NPUCore里它用一个叫`SigInfo`的数据结构维护。

```rust
pub struct TaskControlBlockInner {
    pub siginfo: SigInfo,
}
```

`SigInfo`这个数据结构如下：

```rust
pub struct SigInfo {
    pub signal_pending: Signals,
    pub signal_handler: BTreeMap<Signals, SigAction>,
}
```

+ `signal_pending` 本质上是一个整型，维护信号标志位
+ `signal_handler` 维护用户自定义处理函数

内核在处理`kill`系统调用时会

### 默认处理函数



### 自定义处理函数

Ok. 这里是信号处理的重中之重,我们先介绍一下其基本原理和内容. Linux允许用户替换
