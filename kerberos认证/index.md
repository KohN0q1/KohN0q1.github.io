# Kerberos认证


</br>

## Kerberos认证

Kerberos是一种计算机网络授权协议，由麻省理工研发，一词来源于古希腊神话中的地狱三头犬。Kerberos 由以下三部分组成：客户机、服务器以及可信的第三方（称为 Kerberos 密钥分发中心，KDC）。KDC 提供认证和凭单授予服务。

</br>

### 名词解释

**DC（Domain Controller）**：域控制器

**KDC（Key Distribution Center）**： 密钥分发中心，其中包含AS和TGS，由DC担任

**AS（Authentication Server）**：身份认证服务器

**TGS（Ticket Granting Server）**： 票证授予服务器 

**AD（Account Database）**：活动目录，安装AD的服务器为DC（域控）


</br>


**TGT（Ticket Granting Ticket）**： 票据授权票据

**SS（Service Server）**： 特定服务提供端

**Session key**：短期会话密钥（临时秘钥），内容是随机生成的

**krbtgt用户**：用于Kerberos身份验证的帐户

**Ticket**：票据

**Client**：客户端

**Server**：服务端


</br  >

### 整体流程

Kerberos认证可以分为三部分（六小步）

1. client向KDC（Kerberos服务）请求访问server

2. KDC会判断该client是否信任（AS），通过则返回TGT到client

3. client拿到TGT之后，继续向KDC发起请求
4. KDC的TGS服务会认证client的TGT，通过则返回Ticket票据到client

5. client拿到Ticket之后，向server发起请求

6. server收到Ticket，完成校验，client才可以访问server（只允许访问认证服务器，无法访问其他服务器）

   ![image-20220122215417625](/Kerberos认证.assets/image-20220122215417625.png)	

这是我理解的Kerberos认证的整体流程。


</br>

### 具体流程


#### Client与AS

目的：AS对client进行认证，返回TGT给client。

![image-20220123210556311](/Kerberos认证.assets/image-20220123210556311.png)

1. 当client想要访问某一个server的时候，需要向KDC发送一个**AS_REQ**，里面包含了client的NTML hash加密的时间戳，client info，server info信息。

2. KDC收到**AS_REQ**由AS进行处理，首先验证用户是否存在（AS向AD请求，查看AD里面是否存在该用户），如果有则用该client的NTML hash进行解密，解密出来的时间戳如果和当前的时间戳相差在五分钟之内，则认证成功（Kerberos设计之初就是模拟在一个不安全的环境下，限制时间是为了防止**AS_REQ**被截获可能出现中间人攻击，破解需要一定时间，超出时间则重新认证）。

3. 认证成功之后，AS会发送一个**AS_REP**返回给client，里面包含一个经过client的NTML hash加密过的session key（AS生成，用于跟TGS通信）和krbtgt用户的NTML hash加密的TGT（session key、client info、end time），其中end time是TGT到期时间，一般为八小时，到期则重新申请。

4. client收到AS返回来的**AS_REP**，用自己（client）的NTML hash将session key（AS）解密出来，而TGT则无法解密，因为client没有krbtgt的NTML hash。

</br>

#### Client与TGS

目的：TGS对client进行认证，返回Ticket给client。

![image-20220123231515825](/Kerberos认证.assets/image-20220123231515825.png)

1. client会发送一个**TGS_REQ**给TGS，里面包含前面AS发送的TGT和解密出来的session key（AS）加密的时间戳以及client info和server info 等信息

2. TGS收到**TGS_REQ**会用krbtgt用户NTLM-Hash解密TGT得到session key和client info，再使用session key来解密被session key（AS）加密的信息，将两个数据进行对比（TGS里面的client info和被session key（AS）加密的client info比较），同时对比解密出来的时间戳与当前时间，相差过大则需要重新验证。

3. 如果没问题，TGS会返回一个**TGS_REP**给client，里面包含一个session key（TGS生成，用于与server进行通信，称为server session key，与上面AS生成的session key不一样），然后再用之前的session key（AS）加密这个 server session，还有一个Ticket（经过server的NTML hash加密过的server session key、client info，end time ），其中end time是Ticket到期时间。
4. client收到TGS返回来的**TGS_REP**，用session key（AS）来解密得到server session key，同样无法解密Ticket，因为client没有server NTML hash。

</br>

#### Client与Server

目的：Server对client进行认证，获取访问Server的权限

![image-20220123235916295](/Kerberos认证.assets/image-20220123235916295.png)	

1. （基本算是故技重施了）client要想访问server，则会发送一个**AP_REQ**，里面包含前面发送的Ticket和用server session key（也就是TGS生成的session key）加密的时间戳、client info和server info等信息。
2. server收到**AP_REQ**后解密Ticket，得到server session key再去解密被server session key加密的信息，再次进行对比（Ticket里面的client info和被server session key加密的client info比较），对比当前时间和解密出来的时间戳。
3. 通过验证之后会返回一个**AP_REP**，内容是server session key加密的时间戳给client。
4. client收到**AP_REP**，通过缓存的server session key解密得到时间戳，成功通过验证则与服务器信息通信，同时票据也会存在client的内存当中。

</br>

### 参考资料

https://www.freebuf.com/articles/web/290907.html

https://www.freebuf.com/articles/network/273725.html

https://www.bilibili.com/video/BV1S4411q7Cw

https://docs.microsoft.com/zh-cn/archive/blogs/apgceps/packerberos-2

[域认证所参与的角色 \(三只狗头\)](https://payloads.online/archivers/2018-11-30/1/#%E5%9F%9F%E8%AE%A4%E8%AF%81%E6%89%80%E5%8F%82%E4%B8%8E%E7%9A%84%E8%A7%92%E8%89%B2-%E4%B8%89%E5%8F%AA%E7%8B%97%E5%A4%B4)

[Windows域认证体系—Kerberos认证](https://evilh2o2.github.io/2019/08/25/Windows%E5%9F%9F%E8%AE%A4%E8%AF%81%E4%BD%93%E7%B3%BB%E2%80%94Kerberos%E8%AE%A4%E8%AF%81/)



