---
layout: post
title:  "eBPF在HIDS中的应用"
date:   2021-07-08 15:14:54
categories: HIDS
tags: eBPF HIDS
excerpt: 
mathjax: true
---

# eBPF在HIDS中的应用

## 一、 eBPF历史

 1. eBPF定义：eBPF是一套Linux内核运行信息的采集与控制框架。无需编写内核模块即可实现对内核信息的观测。提供了灵活的可定制性与高效的运行性能。

 2. 前身BPF出现，解决什么问题。

    BPF全称是**「Berkeley Packet Filter」**。作者描述了他们如何在 Unix 内核实现网络数据包过滤，这种新的技术比当时最先进的数据包过滤技术快 20 倍。

    ![udohbd0u3x](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/udohbd0u3x-1696044.png)

    

 3. eBPF出现背景，为了解决什么问题

    发展到现在名称升级为eBPF：**「extended Berkeley Packet Filter」**。它演进成为了一套通用执行引擎，提供可基于系统或程序事件高效安全执行特定代码的通用能力，通用能力的使用者不再局限于内核开发者。其使用场景不再仅仅是网络分析，可以基于eBPF开发性能分析、系统追踪、网络优化等多种类型的工具和平台。

    ![1334952-20200806131434176-1093013946](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/1334952-20200806131434176-1093013946-1696275.png)

    eBPF字节码指令在内核执行前必须通过 BPF 验证器的验证，同时在启用 BPF JIT 模式的内核中，会直接将字节码指令转成内核可执行的本地指令运行，具有很高的执行效率。

    原来的 BPF 就被称为cBPF（classic BPF），目前已基本废弃。当前Linux 内核只运行 eBPF，内核会将cBPF 透明转换成 eBPF 再执行。

    ![loader-7eec5ccd8f6fbaf055256da4910acd5a](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/loader-7eec5ccd8f6fbaf055256da4910acd5a-1696456.png)

    

 4. eBPF发展到现在的关键路标

    - 1992年：BPF全称Berkeley Packet Filter，诞生初衷提供一种内核中自定义报文过滤的手段（类汇编），提升抓包效率。（tcpdump）
    - 2011年：linux kernel 3.2版本对BPF进行重大改进，引入BPF JIT，使其性能得到大幅提升。
    - 2014年： linux kernel 3.15版本，BPF扩展成eBPF，其功能范畴扩展至：内核跟踪、性能调优、协议栈QoS等方面。与之配套改进包括：扩展BPF ISA指令集、提供高级语言（C）编程手段、提供MAP机制、提供Help机制、引入Verifier机制等。
    - 2016年：linux kernel 4.8版本，eBPF支持XDP，进一步拓展该技术在网络领域的应用。随后Netronome公司提出eBPF硬件卸载方案。
    - 2018年：linux kernel 4.18版本，引入BTF，将内核中BPF对象（Prog/Map）由字节码转换成统一结构对象，这有利于eBPF对象与Kernel版本的配套管理，为eBPF的发展奠定基础。
    - 2018年：从kernel 4.20版本开始，eBPF成为内核最活跃的项目之一，新增特性包括：sysctrl hook、flow dissector、struct_ops、lsm hook、ring buffer等。场景范围覆盖容器、安全、网络、跟踪等。

    ![image-20210522230951641](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/image-20210522230951641.png)



## 二、eBPF基础

 1. eBPF能干啥

    ​	当前内核支持的eBPF程序类型为：

    - `BPF_PROG_TYPE_SOCKET_FILTER`: a network packet filter
    - `BPF_PROG_TYPE_KPROBE`: determine whether a kprobe should fire or not
    - `BPF_PROG_TYPE_SCHED_CLS`: a network traffic-control classifier
    - `BPF_PROG_TYPE_SCHED_ACT`: a network traffic-control action
    - `BPF_PROG_TYPE_TRACEPOINT`: determine whether a tracepoint should fire or not
    - `BPF_PROG_TYPE_XDP`: a network packet filter run from the device-driver receive path
    - `BPF_PROG_TYPE_PERF_EVENT`: determine whether a perf event handler should fire or not
    - `BPF_PROG_TYPE_CGROUP_SKB`: a network packet filter for control groups
    - `BPF_PROG_TYPE_CGROUP_SOCK`: a network packet filter for control groups that is allowed to modify socket options
    - `BPF_PROG_TYPE_LWT_*`: a network packet filter for lightweight tunnels
    - `BPF_PROG_TYPE_SOCK_OPS`: a program for setting socket parameters
    - `BPF_PROG_TYPE_SK_SKB`: a network packet filter for forwarding packets between sockets
    - `BPF_PROG_CGROUP_DEVICE`: determine if a device operation should be permitted or not

    通过bpftrace查看支持的观测资源：

    ![image-20210522232638156](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/image-20210522232638156.png)

    <img src="/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/image-20210522232711532.png" alt="image-20210522232711532" style="zoom:67%;" />

 2. eBPF怎么用（工具、编码）

    早期BPF代码需要使用伪机器码编写对内核网络报文的处理代码，然后用socket将代码加载到内核。

    ![image-20210522233733622](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/image-20210522233733622.png)

    eBPF可使用C语言编写内核处理代码，通过llvm编译后，使用linux提供的一些帮助函数helper，最终通过syscall将编译后的伪机器码加载到内核。

    ![libbpf-f4991ee40f74df260dbb3e0541855044](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/libbpf-f4991ee40f74df260dbb3e0541855044.png)

    

    bcc之类的工具提供了更进一步的简化，减少了手动操作步骤：

    ![bcc-def942c66b8c7565f0cfeab1c1017a80](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/bcc-def942c66b8c7565f0cfeab1c1017a80.png)

    ``` go
    #include <linux/bpf.h>
    #include "bpf_helpers.h"
    
    #define SEC(NAME) __attribute__((section(NAME), used))
    
    struct bpf_map_def SEC("maps") taskname = {
    	.type        = BPF_MAP_TYPE_HASH,
    	.key_size    = sizeof("name"), 
    	.value_size  = 16, 
    	.max_entries = 256, 
    };
    
    SEC("tracepoint/syscalls/sys_enter_execve")
    int bpf_prog(void *ctx) {
        char comm[16];
        char key[] = "name";
        int result;
    
        bpf_get_current_comm(&comm, 16);
        bpf_map_update_elem(&taskname, &key, &comm, BPF_ANY);
        return 0;
    }
    
    char _license[] SEC("license") = "GPL";
    ```

    ``` shell
    ubuntu@ubuntu:~/projects/ebpf$ clang -O2 -target bpf -c bpf_hello.c -o bpf_hello.o -I/usr/include/x86_64-linux-gnu -I/home/ubuntu/projects/linux-source-5.4.0/tools/testing/selftests/bpf
    ```

    ``` go
    #include <stdio.h>
    #include <errno.h>
    #include <string.h>
    #include <unistd.h>
    #include "bpf_load.h"
    
    int main(int argc, char **argv) {
        int result;
        char key[] = "name";
        char comm[16];
    
        if (load_bpf_file("bpf_hello.o")) {
            printf("The kernel didn't load the BPF program\n");
            return -1;
        }
    
        while (1) {
            result = bpf_map_lookup_elem(map_fd[0], &key, &comm);
            if (result != 0) {
                sleep(1);
                continue;
            }
    
            printf("Get info: %s\n", comm);
        }
        return 0;
    }
    ```

    ``` shell
    ubuntu@ubuntu:~/projects/ebpf$ clang -DHAVE_ATTR_TEST=0 -o loader -lelf -I/home/ubuntu/projects/linux-source-5.4.0/samples/bpf -I/home/ubuntu/projects/linux-source-5.4.0/tools/lib -I/home/ubuntu/projects/linux-source-5.4.0/tools/perf -I /home/ubuntu/projects/linux-source-5.4.0/tools/include -L/usr/lib/x86_64-linux-gnu -lbcc_bpf /home/ubuntu/projects/linux-source-5.4.0/samples/bpf/bpf_load.c bpf_hello_user.c
    ```

    使用bcc更方便：

    ``` python
    from bcc import BPF
    
    bpf_source = """
    int trace_bpf_prog_load(void ctx) {
      char comm[16];
      bpf_get_current_comm(&comm, sizeof(comm));
    
      bpf_trace_printk("%s is loading a BPF program", comm);
      return 0;
    }
    """
    
    bpf = BPF(text = bpf_source)
    bpf.attach_tracepoint(tp = "bpf:bpf_prog_load", fn_name = "trace_bpf_prog_load")
    bpf.trace_print()
    
    ```

    

 3. eBPF的限制

## 三、eBPF在安全监控上的应用

 1. 简单使用介绍

    bpftrace带来了更易用的工具

    ![dfyjrg8q4abkcjgcsnp00vuuymg](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/dfyjrg8q4abkcjgcsnp00vuuymg.jpeg)

    简单使用演示：

    ![eBPF使用演示](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/eBPF使用演示.gif)

 2. 监控系统调用

    沿用文件访问，只不过用audit： sudo auditctl -w /home/ubuntu/projects/tmp/go.mod -p r

 3. 监控文件访问

    eBPF：监控tracepoint:syscalls:sys_enter_openat， 并用filter过滤进程名

    对比： inotify  ./listen_file /home/ubuntu/projects/tmp/go.mod

    ​	![readfile_cpuall](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/readfile_cpuall.png)

    |                   | 无监控  | audit   | inotify | ebpf    |
    | ----------------- | ------- | ------- | ------- | ------- |
    | 平均CPU占用（总） | 22.8505 | 39.6578 | 24.5449 | 24.7309 |
    | 用户态占用        | 8.99668 | 16.3887 | 7.55814 | 7.43522 |

    

 4. 监控进程启动

​		eBPF： sudo bpftrace -e 'tracepoint:syscalls:sys_enter_clone /pid == 2431053/{ printf("%s\n", comm); }'

​		对比： 使用 Netlink Connector： https://zhuanlan.zhihu.com/p/74555741

​		计算平均结果： awk 'BEGIN{sum=1;a=0;b=0;c=0}{a+=int($2);b+=int($3);c+=int($4);sum+=1;}END{print a/sum,b/sum,c/sum} ' allcpu_all.txt

​	![process_cpuall](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/process_cpuall.png)

|                   | 无监控  | netlink_connector | ebpf    |
| ----------------- | ------- | ----------------- | ------- |
| 平均CPU占用（总） | 15.7973 | 19.1694           | 19.3787 |
| 用户态占用        | 1.10631 | 1.97674           | 2.22259 |



## 四、eBPF使用相关资源

 1. 工具链

 2. 编程helper范围

    内核编码helper：

    > ​	man bpf-helpers
    >
    > ​	include/uapi/linux/bpf.h
    >
    > ​	sudo bpftrace -l

    代码参考：

    > ​	samples/bpf/

 3. 资料参考

    eBPF简史：https://linux.cn/article-9032-1.html

    ​	eBPF介绍：[https://openeuler.org/zh/blog/MrRlu/2021-01-04-openEuler%20eBPF%20introduce.html](https://openeuler.org/zh/blog/MrRlu/2021-01-04-openEuler eBPF introduce.html)

    ​	eBPF文档：https://ebpf.io/what-is-ebpf/

    ​	eBPF全面介绍：https://www.cnblogs.com/charlieroro/p/13403672.html#ebpf的演进

    ​	eBPF学习资料总结：https://github.com/DavadDi/bpf_study

    ​	eBPF完整学习总结：https://cloud.tencent.com/developer/article/1698426

    ​	工具链：http://www.brendangregg.com/ebpf.html



## 五、补充信息

1. perf event 有哪些类型bpf事件？

   主要是syscall 中的 sys_perf_event_open和kprobe中的perf event相关函数

2. xdp的事件

   tracepoint:**xdp**:**xdp**_exception

   tracepoint:**xdp**:**xdp**_bulk_tx

   tracepoint:**xdp**:**xdp**_redirect

   tracepoint:**xdp**:**xdp**_redirect_err

   tracepoint:**xdp**:**xdp**_redirect_map

   tracepoint:**xdp**:**xdp**_redirect_map_err

   tracepoint:**xdp**:**xdp**_cpumap_kthread

   tracepoint:**xdp**:**xdp**_cpumap_enqueue

   tracepoint:**xdp**:**xdp**_devmap_xmit

   tracepoint:**xdp**:mem_disconnect

   tracepoint:**xdp**:mem_connect

   tracepoint:**xdp**:mem_return_failed

   还有kprobe中的xdp

3. btf 的简单定义

4. bpf的单行编译脚本

   编译内核部分： clang -O2 -target bpf -c bpf_hello.c -o bpf_hello.o -I/usr/include/x86_64-linux-gnu -I/home/ubuntu/projects/linux-source-5.4.0/tools/testing/selftests/bpf

   用户部分：clang -DHAVE_ATTR_TEST=0 -o loader -lelf -I/home/ubuntu/projects/linux-source-5.4.0/samples/bpf -I/home/ubuntu/projects/linux-source-5.4.0/tools/lib -I/home/ubuntu/projects/linux-source-5.4.0/tools/perf -I /home/ubuntu/projects/linux-source-5.4.0/tools/include -L/usr/lib/x86_64-linux-gnu -lbcc_bpf /home/ubuntu/projects/linux-source-5.4.0/samples/bpf/bpf_load.c bpf_hello_user.c

5. inotify 代码截图

   ![image-20210602233732469](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/image-20210602233732469.png)

   ![image-20210602233913597](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/image-20210602233913597.png)

   ![image-20210602234033035](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/image-20210602234033035.png)

   

6. audit 基础用例截图

   ![image-20210602234606316](/tmpfile/_post/2021-07-08-ebpf-in-hids.assets/image-20210602234606316.png)

7. netlink connector 样例代码

8. 开发支撑资源补充

   每个类型能使用的helper 函数

   具体跟踪点的参考， bpftrace 和sample里面对不上？

   每个内核版本特性列表：https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md

9. 文件监控测试程序一句话描述，ebpf执行命令

   进程启动测试程序： 串行启动子进程，子进程睡眠1毫秒后退出。

   文件程序：顺序读取文件内容到内存，打开后不做动作，睡眠1微秒，关闭文件

   sudo **bpftrace** -e 'tracepoint:syscalls:sys_enter_openat /str(args->filename) == "go.mod"/{ printf("%s %s\n", comm, str(args->filename)); }'
