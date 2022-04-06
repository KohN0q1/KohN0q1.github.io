# Pwn环境搭建


# Pwn虚拟机搭建
虚拟机：Ubuntu16.04

## 换源
备份
```bash
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
```
换阿里云的源
sudo vim /etc/apt/sources.list

```bash
deb http://mirrors.aliyun.com/ubuntu/ xenial main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial main

deb http://mirrors.aliyun.com/ubuntu/ xenial-updates main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates main

deb http://mirrors.aliyun.com/ubuntu/ xenial universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial universe
deb http://mirrors.aliyun.com/ubuntu/ xenial-updates universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates universe

deb http://mirrors.aliyun.com/ubuntu/ xenial-security main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security main
deb http://mirrors.aliyun.com/ubuntu/ xenial-security universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security universe
```

更新
```bash
sudo apt-get update  #更新软件包列表
sudo apt-get -f install #休复损坏的软件包，尝试卸载出错的包，重新安装正确版本的。
sudo apt-get upgrade  #升级系统中的所有软件包
```

## pip
安装pip
```python
sudo apt-get install python-pip
sudo apt-get install python3-pip
```
临时换源
```bash
pip install 包名 -i https://pypi.tuna.tsinghua.edu.cn/simple
```
永久换源
vim ~/.pip/pip.conf 
```bash
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
```
升级pip
```bash
sudo pip install --upgrade pip
sudo pip3 install --upgrade pip
```

## pwntools
pwntools是一个CTF框架和漏洞利用开发库，用Python开发，由rapid设计，旨在让使用者简单快速的编写exploit。
```bash
sudo pip install pwntools
sudo pip3 install pwntools
```
验证pwntools是否安装成功，回显`b'1\xc0'`即成功安装
```python
python
>>> from pwn import *
>>> asm("xor eax,eax")
b'1\xc0'
```
安装pwntools会附带安装 `ROPgadget` 和 `checksec`

## pwndbg
用于动态调试的gdb插件
```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```
`vim ~/.gdbinit` 查看是否写入配置文件成功

## one_gadget
one-gadget会在libc里寻找execve('/bin/sh', NULL, NULL)的地址
```bash
sudo apt -y install ruby
sudo gem install one_gadget
```

## LibcSearcher
LibcSearcher可以通过泄露函数地址来确定libc版本
```bash
git clone https://github.com/lieanu/LibcSearcher.git
cd LibcSearcher
python setup.py develop
```
在线查询libc函数偏移网站 https://libc.blukat.me/


## main_arena_offset
计算main_arena的偏移
```bash
git clone https://github.com/bash-c/main_arena_offset
```

## 32位库
```bash
sudo apt install libc6-dev-i386
sudo apt-get install lib32z1
```

<br/>

# Linux保护机制
在Linux中有很多安全措施用来防护或降低程序遭受缓冲区攻击的风险，而要编写利用脚本就需要绕过这些防御机制，所以需要了解这些安全措施

## NX
No-eXecute，栈不可执行，基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令
```c
gcc -o test test.c // 默认情况下，开启NX保护
gcc -z execstack -o test test.c // 禁用NX保护
gcc -z noexecstack -o test test.c // 开启NX保护
```
在Windows下，类似的保护措施是DEP(Data Execution Prevention)数据执行保护

## CANARY
启用canary后，函数开始执行的时候会先往栈里插入canary信息，当函数返回时验证插入的canary是否被修改，如果是，则说明发生了栈溢出，程序停止运行，在Windows下，这一机制被称为gs机制

gcc在4.2版本中添加了-fstack-protecktor和-fstack-protector-all编译参数以支持栈保护功能，4.9新增了fstack-protector-strong编译参数让保护的范围更广
```c
gcc -o test test.c  // 默认情况下，不开启Canary保护
gcc -fno-stack-protector -o test test.c //禁用栈保护
gcc -fstack-protector -o test test.c //启用堆栈保护，不过只为局部变量中含有char数组的函数插入保护代码
gcc -fstack-protector-all -o test test.c //启用堆栈保护，为所有函数插入保护代码
```

## FORTIFY
fority其实非常轻微的检查，用于检查是否存在缓冲区溢出的错误。适用情形是程序采用大量的字符串或者内存操作函数，如memcpy，memset，stpcpy，strcpy，strncpy，strcat，strncat，sprintf，snprintf，vsprintf，vsnprintf，gets以及宽字符的变体
```c
gcc -o test test.c // 默认情况下，不会开这个检查
gcc -D_FORTIFY_SOURCE=1 -o test test.c // 较弱的检查，仅仅只会在编译时进行检查 (特别像某些头文件 #include <string.h>)
gcc -D_FORTIFY_SOURCE=2 -o test test.c // 较强的检查，程序执行时也会有检查 (如果检查到缓冲区溢出，就终止程序)，可能会导致程序的崩溃
```

## RELRO
read only relocation，设置符号重定向表为只读或在程序启动时就解析并绑定所有动态符号，从而减少对 GOT（Global Offset Table）的攻击。RELRO为” Partial RELRO”，说明我们对GOT表具有写权限

RELRO可分为：
- Partial RELRO(部分RELRO) //开启Partial RELRO后GOT表是可写的
- Full RELRO(完整RELRO)   //开启FULL RELRO后GOT表是只读的，不可写

```c
gcc -o test test.c // 默认情况下，是Partial RELRO
gcc -z norelro -o test test.c // 关闭，即No RELRO
gcc -z lazy -o test test.c // 部分开启，即Partial RELRO
gcc -z now -o test test.c // 全部开启
```

## PIE
PIE(Position Independent Executables，位置无关可执行文件)，配合内存地址随机化机制（address space layout randomization)使用，其中ASLR由操作系统完成，而PIE则有编译器完成，并且ASLR有以下三种情况：

- 0 - 表示关闭进程地址空间随机化
- 1 - 表示将mmap的基址，stack和vdso页面随机化
- 2 - 表示在1的基础上增加栈（heap）的随机化。

liunx下关闭随机化的命令如下：
```c
sudo -s echo 0 > /proc/sys/kernel/randomize_va_space
```
```c
gcc -o test test.c				// 默认情况下，不开启PIE
gcc -fpie -pie -o test test.c	// 开启PIE，此时强度为1
gcc -fPIE -pie -o test test.c	// 开启PIE，此时为最高强度2
gcc -fpic -o test test.c		// 开启PIC，此时强度为1，不会开启PIE
gcc -fPIC -o test test.c		// 开启PIC，此时为最高强度2，不会开启PIE
```

<br/>

# 汇编基础
## 字节序
大端模式和小端模式：

- 大端模式：高位字节数据存放在低地址处，低位数据存放在高地址处
- 小端模式：高位字节数据存放在高地址处，低位数据存放在低地址处

以0x12345678为例
小端 \x78\x56\x34\x12
大端 \x12\x34\x56\x78

## 寄存器
寄存器是有限存贮容量的高速存贮部件，它们可用来暂存指令、数据和地址。以8086CPU为例，共有14个寄存器


**数据寄存器**
- AX (Accumulator)  累加寄存器
- BX (Base) 基地址寄存器
- CX (Count)    计数器寄存器
- DX (Data) 数据寄存器

**指针寄存器**
- SP (Stack Pointer)    堆栈指针寄存器
- BP (Base Pointer) 基指针寄存器

**变址寄存器**
- SI (Source Index) 源变址寄存器
- DI (Destination Index)    目的变址寄存器

**控制寄存器**
- IP (Instruction Pointer)  指令指针寄存器
- FLAG  标志寄存器

**段寄存器**
- CS (Code Segment) 代码段寄存器
- DS (Data Segment) 数据段寄存器
- SS (Stack Segment)    堆栈段寄存器
- ES (Extra Segment)    附加段寄存器


## 指令
常见汇编指令

| 指令 | 中文 | 格式 | 功能 | 
| -----|------|-----|------|
| mov  | 传输指令 | MOV DST, SRC | 将 SRC 传至 DST |
| XCHG | 交换指令 | XCHG OPER1,OPER2 | 把oper1的内容与oper2的内容交换 |
| ADD | 加法指令 |  ADD DEST,SRC| 两数相加|
| SUB | 减法指令 | SUB DEST,SRC | 两数相减|
| AND | 与运算指令 | AND DEST，SRC | 同1得1，否则得0|
| OR | 或运算指令 | OR DEST，SRC |  同0得0，否则得1|
| XOR | 异或运算 | XOR DEST，SRC | 相同得0不同得1 |
| LEA | 取地址指令 | LEA REC,OPRD | 把oprd的地址传送到rec |
| PUSH | 压入堆栈指令 | PUSH SRC |将 SRC 压入栈|
| POP | 弹出堆栈指令 | POP DST| 将栈顶的数据弹出并存至 DST|
| CALL | 调用指令 | CALL PTR | 将程序当前执行位置IP压栈并转移到调用的子程序，相当于 push ip ， jmp near ptr|
| RET | 返回指令 | RET | 将栈顶数据弹出至 ip，相当于pop ip |

<br/>

# Pwntools使用
官方文档 http://docs.pwntools.com/en/latest/

## 连接
```python
from pwn import * #导入pwn模块

p=remote("域名或ip", port) #连接指定的地址和端口，用于远程连接
p=process('./filename')    #连接本地环境，用于本地调试

gdb.attach(p) #用于gdb调试
```

## context
```python
context(os='linux', arch='amd64', log_level='debug')

context.log_level = 'debug' #设置日志级别
context.arch = 'amd64'      #设置架构
```

## IO
```python
p.send(data) #发送data
p.sendline(data) #发送data，并换行（相当于末尾\n）
p.sendafter(string, data) #接收到string后, 再发送data

p.recvn(N)   #接收 N(数字) 字符
p.recvline() #接收一行输出
p.recvuntil(string) #接收到string为止

p.interactive() #与shell交互
```

## 打/解包
将data打/解包成32/64位的小端序的值
```python
p32/p64(data)
u32/u64(data) 
```

## ELF
```python
elf=ELF("./filename")     #加载ELF文件信息
elf.symbols['a_function'] #找到 a_function的函数地址
elf.got['a_function']     #找到 a_function的got表地址
elf.plt['a_function']     #找到 a_function 的 plt表的地址
```

## shellcraft
shellcraft模块生成shellcode
```python
shellcraft.sh()
shellcraft.i386.linux.sh()
shellcraft.amd64.linux.sh()
```

<br/>

# 参考
[PWN虚拟机配置](https://www.yuque.com/hxfqg9/bin/hg3qeh)
[CTF ALL IN ONE](https://firmianay.gitbooks.io/ctf-all-in-one/doc/4.4_gcc_sec.html)
[汇编语言之寄存器总结](https://blog.csdn.net/qq_41115702/article/details/82763383)
[汇编常用指令](https://blog.csdn.net/qq_36982160/article/details/82950848)

