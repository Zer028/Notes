# Page 1

Nmap扫描目标C段及端口开放信息

```
┌──(root㉿kali)-[~/Desktop/test/Dante]
└─# nmap -sT -sV -sC 10.10.110.0/24
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-04 07:31 EST
Nmap scan report for 10.10.110.2
Host is up (0.34s latency).
All 1000 scanned ports on 10.10.110.2 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Nmap scan report for 10.10.110.100
Host is up (0.33s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.16.1.100 is not the same as 10.10.110.100
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 8f:a2:ff:cf:4e:3e:aa:2b:c2:6f:f4:5a:2a:d9:e9:da (RSA)
|   256 07:83:8e:b6:f7:e6:72:e9:65:db:42:fd:ed:d6:93:ee (ECDSA)
|_  256 13:45:c5:ca:db:a6:b4:ae:9c:09:7d:21:cd:9d:74:f4 (ED25519)
65000/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 2 disallowed entries 
|_/wordpress DANTE{Y0u_Cant_G3t_at_m3_br0!}
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (2 hosts up) scanned in 169.43 seconds
```

可以看到10.10.110.100这个主机的21端口可以匿名登录，同时还有一个172.16.1.100的IP地址

```
┌──(root㉿kali)-[~/Desktop/test/Dante]
└─# ftp 10.10.110.100 21
Connected to 10.10.110.100.
220 (vsFTPd 3.0.3)
Name (10.10.110.100:root): Anonymous 
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> help
Commands may be abbreviated.  Commands are:

!               close           fget            lpage           modtime         pdir            rcvbuf          sendport        type
$               cr              form            lpwd            more            pls             recv            set             umask
account         debug           ftp             ls              mput            pmlsd           reget           site            unset
append          delete          gate            macdef          mreget          preserve        remopts         size            usage
ascii           dir             get             mdelete         msend           progress        rename          sndbuf          user
bell            disconnect      glob            mdir            newer           prompt          reset           status          verbose
binary          edit            hash            mget            nlist           proxy           restart         struct          xferbuf
bye             epsv            help            mkdir           nmap            put             rhelp           sunique         ?
case            epsv4           idle            mls             ntrans          pwd             rmdir           system
cd              epsv6           image           mlsd            open            quit            rstatus         tenex
cdup            exit            lcd             mlst            page            quote           runique         throttle
chmod           features        less            mode            passive         rate            send            trace
ftp> ls
229 Entering Extended Passive Mode (|||36056|)
ftp: Can't connect to `10.10.110.100:36056': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    4 0        0            4096 Apr 14  2021 Transfer
226 Directory send OK.
ftp>
```

我们看下Transfer这个目录下有没有有用的信息

```
ftp> cd Transfer
ls
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Apr 14  2021 Incoming
drwxr-xr-x    2 0        0            4096 Aug 04  2020 Outgoing
226 Directory send OK.

ftp> cd Incoming
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             310 Aug 04  2020 todo.txt
226 Directory send OK.
ftp> get todo.txt
local: todo.txt remote: todo.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for todo.txt (310 bytes).
100% |***************************************************************************************************************|   310       11.82 MiB/s    00:00 ETA
226 Transfer complete.
310 bytes received in 00:00 (0.34 KiB/s)
```

Incoming这个目录下有个文件将它下载下来查看 ，Outgoing这个目录下没东西，我们看看todo文件有没有什么有用的信息

```
┌──(root㉿kali)-[~/Desktop/test/Dante]
└─# cat todo.txt                                
- Finalize Wordpress permission changes - PENDING
- Update links to to utilize DNS Name prior to changing to port 80 - PENDING
- Remove LFI vuln from the other site - PENDING
- Reset James' password to something more secure - PENDING
- Harden the system prior to the Junior Pen Tester assessment - IN PROGRESS

```

这里记录了几条信息，

1. 这个网站是一个Wordpress 的网站
2. 从其它站点中删除了一个LFI漏洞
3. 将 James 的密码重置为更安全的密码

除了这以外似乎没有立足点，我们尝试访问一下它的65000端口

<figure><img src="../../../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

是一个apache的默认页面，我们nikto扫描一下看看

```
┌──(root㉿kali)-[~/Desktop/test/Dante]
└─# nikto -host http://10.10.110.100:65000/
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.110.100
+ Target Hostname:    10.10.110.100
+ Target Port:        65000
+ Start Time:         2024-01-04 08:19:01 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /wordpress/: Uncommon header 'x-redirect-by' found, with contents: WordPress.
+ /robots.txt: contains 2 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ /: Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 5a53d3c65fdfa, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .

```

可以看到有/robots.txt这个文件还有wordpress的一个目录，我们先访问robots.txt这个文件

<figure><img src="../../../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

除了/wordpress这个目录还有第一个flag，我们访问wordpress这个目录
