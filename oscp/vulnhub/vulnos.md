# Vulnos

### 主机发现

在我们开始侦察之前，我们需要知道目标住在哪里。我们将使用_Arp-scan_。

```
┌──(root㉿kali)-[~]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.23.129
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.23.1    00:50:56:c0:00:08       VMware, Inc.
192.168.23.2    00:50:56:ec:db:1b       VMware, Inc.
192.168.23.132  00:0c:29:b5:92:da       VMware, Inc.
192.168.23.137  00:0c:29:33:c8:07       VMware, Inc.
192.168.23.141  00:0c:29:70:bd:7e       VMware, Inc.
192.168.23.254  00:50:56:f1:1f:4e       VMware, Inc.

6 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.931 seconds (132.57 hosts/sec). 6 responded
```

### 扫描目标

我们将运行端口扫描来查看_VulnOS_计算机正在侦听哪些端口，使用nmap查看目标开放了哪些端口。

```
┌──(root㉿kali)-[~]
└─# nmap -sS -sV -p- 192.168.23.141
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-02 03:58 EDT
Nmap scan report for 192.168.23.141
Host is up (0.0038s latency).
Not shown: 65518 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
25/tcp    open  smtp       Postfix smtpd
79/tcp    open  finger     Linux fingerd
110/tcp   open  pop3       Dovecot pop3d
111/tcp   open  rpcbind    2-4 (RPC #100000)
143/tcp   open  imap       Dovecot imapd
512/tcp   open  exec       netkit-rsh rexecd
513/tcp   open  login
514/tcp   open  tcpwrapped
993/tcp   open  ssl/imap   Dovecot imapd
995/tcp   open  ssl/pop3   Dovecot pop3d
2049/tcp  open  nfs        2-4 (RPC #100003)
37161/tcp open  mountd     1-3 (RPC #100005)
40397/tcp open  status     1 (RPC #100024)
42784/tcp open  mountd     1-3 (RPC #100005)
51732/tcp open  mountd     1-3 (RPC #100005)
51967/tcp open  nlockmgr   1-4 (RPC #100021)
MAC Address: 00:0C:29:70:BD:7E (VMware)
Service Info: Host:  vulnix; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.55 seconds
```

看起来我们有标准的 SSH 和 HTTP 服务器以及在机器上运行的 IRC 守护进程。我们将从枚举 HTTP 开始。

