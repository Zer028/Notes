# Format

目标探测

Nmap扫描目标全端口的开放端口

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/Format]
└─# nmap -n -v -sS -p- 10.10.11.213 --max-retries=0 -oN allport.txt -Pn
# Nmap 7.94 scan initiated Thu Aug 31 04:33:31 2023 as: nmap -n -v -sS -p- --max-retries=0 -oN allport.txt -Pn 10.10.11.213
Warning: 10.10.11.213 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.11.213
Host is up (0.45s latency).
Not shown: 37673 closed tcp ports (reset), 27859 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Aug 31 04:43:48 2023 -- 1 IP address (1 host up) scanned in 617.53 seconds
```

对这三个端口进行详细扫描

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/Format]
└─# nmap -n -v -sC -sV -p $(cat allport.txt | grep ^[0-9]|cut -d / -f1|tr '\n' ','|sed s/,$//) 10.10.11.213 -oN nmap.txt -Pn
# Nmap 7.94 scan initiated Thu Aug 31 04:49:25 2023 as: nmap -n -v -sC -sV -p 22,80,3000 -oN nmap.txt -Pn 10.10.11.213
Nmap scan report for 10.10.11.213
Host is up (0.52s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c3:97:ce:83:7d:25:5d:5d:ed:b5:45:cd:f2:0b:05:4f (RSA)
|   256 b3:aa:30:35:2b:99:7d:20:fe:b6:75:88:40:a5:17:c1 (ECDSA)
|_  256 fa:b3:7d:6e:1a:bc:d1:4b:68:ed:d6:e8:97:67:27:d7 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
3000/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 31 04:50:21 2023 -- 1 IP address (1 host up) scanned in 56.17 seconds
```

在端口 3000 上，它将我们重定向到microblog.htb域，因此我们将其添加到 /etc/hosts, 如果我们尝试通过端口 80 访问该网站，它会将我们重定向到app.microblog.htb子域，因此我们也添加它,我们访问主网站，在本例中是子域。

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

我们在网站上注册，创建一个子域并将其添加到/etc/hosts。

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/Format]
└─# cat /etc/hosts                                                            
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.213    app.microblog.htb
10.10.11.213    microblog.htb
10.10.11.213    myawesomeblog.microblog.htb
```

<figure><img src="../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

添加后，我们可以编辑子域，因此我们尝试创建 XSS。

