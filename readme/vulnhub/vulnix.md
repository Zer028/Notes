# Vulnix

### 信息收集

使用nmap扫描

```
┌──(root㉿kali)-[~]
└─# nmap -sS -sV 192.168.23.141           
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-03 04:06 EDT
Nmap scan report for 192.168.23.141
Host is up (0.00016s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp       Postfix smtpd
79/tcp   open  finger     Linux fingerd
110/tcp  open  pop3?
111/tcp  open  rpcbind    2-4 (RPC #100000)
143/tcp  open  imap       Dovecot imapd
512/tcp  open  exec       netkit-rsh rexecd
513/tcp  open  login      OpenBSD or Solaris rlogind
514/tcp  open  tcpwrapped
993/tcp  open  ssl/imap   Dovecot imapd
995/tcp  open  ssl/pop3s?
2049/tcp open  nfs        2-4 (RPC #100003)
MAC Address: 00:0C:29:70:BD:7E (VMware)
Service Info: Host:  vulnix; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 178.25 seconds
```

开放了很多端口，可以看到很多RPC服务，看看111端口运行了扫描服务

```
┌──(root㉿kali)-[~]
└─# rpcinfo -p 192.168.23.141
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100024    1   udp  35863  status
    100024    1   tcp  34569  status
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    2   tcp   2049  nfs_acl
    100227    3   tcp   2049  nfs_acl
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100227    2   udp   2049  nfs_acl
    100227    3   udp   2049  nfs_acl
    100021    1   udp  40723  nlockmgr
    100021    3   udp  40723  nlockmgr
    100021    4   udp  40723  nlockmgr
    100021    1   tcp  46719  nlockmgr
    100021    3   tcp  46719  nlockmgr
    100021    4   tcp  46719  nlockmgr
    100005    1   udp  36062  mountd
    100005    1   tcp  60780  mountd
    100005    2   udp  57754  mountd
    100005    2   tcp  46383  mountd
    100005    3   udp  33475  mountd
    100005    3   tcp  38784  mountd
```

可以看到nfs文件共享服务，让我们看看我们是否有任何共享：

```
┌──(root㉿kali)-[~]
└─# showmount -e 192.168.23.141
Export list for 192.168.23.141:
/home/vulnix *
```

所以看起来我们有一个用户vulnix并且他的主目录是共享的。让我们安装它并检查一下

```
```
