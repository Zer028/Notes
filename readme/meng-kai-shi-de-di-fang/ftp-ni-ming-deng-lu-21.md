# FTP匿名登录21

nmap扫描目标开放端口

```
┌──(root㉿kali)-[~]
└─# nmap -sS -sV -sC 10.129.1.14   
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-02 04:44 EDT
Nmap scan report for 10.129.1.14
Host is up (2.1s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.16.28
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.71 seconds
```

可以看到输出的内容中FTP支持匿名登录，下面尝试一下匿名登录

```
┌──(root㉿kali)-[~]
└─# ftp 10.129.1.14 21           
Connected to 10.129.1.14.
220 (vsFTPd 3.0.3)
Name (10.129.1.14:root): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||37403|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
226 Directory send OK.
ftp> cat flag.txt
?Invalid command.
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||7874|)
150 Opening BINARY mode data connection for flag.txt (32 bytes).
100% |***********************************************************************|    32        0.12 KiB/s    00:00 ETA
226 Transfer complete.
32 bytes received in 00:01 (0.02 KiB/s)
ftp> 
```
