# Debian安装nessus破解版

系统：Debian 12&#x20;

下载安装包：下载[Debian-amd64](https://www.tenable.com/downloads/nessus?loginAttempted=true)位版本，自己的CPU适配

安装下载好的安装包

```
➜ sudo dpkg -i Nessus-10.6.4-debian10_amd64.deb 
Unpacking Nessus Scanner Core Components...

 - You can start Nessus Scanner by typing /bin/systemctl start nessusd.service
 - Then go to https://debian:8834/ to configure your scanner
```

根据提示启动nessus服务

```
➜   systemctl start nessusd.service
➜  s systemctl status nessusd.service
● nessusd.service - The Nessus Vulnerability Scanner
     Loaded: loaded (/lib/systemd/system/nessusd.service; enabled; preset: enab>
     Active: active (running) since Thu 2023-12-21 20:43:45 EST; 11s ago
   Main PID: 24728 (nessus-service)
      Tasks: 14 (limit: 4582)
     Memory: 78.9M
        CPU: 11.243s
     CGroup: /system.slice/nessusd.service
             ├─24728 /opt/nessus/sbin/nessus-service -q
             └─24729 nessusd -q

Dec 21 20:43:45 debian systemd[1]: Started nessusd.service - The Nessus Vulnera>
Dec 21 20:43:48 debian nessus-service[24729]: Cached 0 plugin libs in 0msec
Dec 21 20:43:48 debian nessus-service[24729]: Cached 0 plugin libs in 0msec
```

然后访问本地8834端口，选择continue

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

根据提示步骤，选择 `Managed Scanner`

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

选择.sc的这个&#x20;

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

输入账号密码创建账号

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

注册个账号获取一下挑战码

<figure><img src="../.gitbook/assets/image (103).png" alt=""><figcaption></figcaption></figure>

邮件里面会有一个key

```
Welcome To Nessus Essentials
Welcome to Nessus Essentials and congratulations on taking action to secure your network! We offer the latest plugins for vulnerability scanning today, helping you identify more vulnerabilities and keep your network protected.

If you’re looking for more advanced capabilities, such as live results and configuration checks – as well as the ability to scan unlimited IPs, check out Nessus Professional. To learn more view the Nessus Professional datasheet.

Activating Your Nessus Essentials License
Your activation code for Nessus Essentials is:
6TJA-S42W-C237-Q4CB-JPSW
```

<figure><img src="../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

再打开 Nessus 本地安装目录，执行CDM命令获取 `Challenge Code` 值

```
➜  ~ cd /opt/nessus/sbin/
➜  sbin ls
nessuscli  nessusd  nessus-service
➜  sbin ./nessuscli fetch --challenge

Challenge code: d5ce3f1f92334c91c717c956dbdedfca9657c3f1

You can copy the challenge code above and paste it alongside your
Activation Code at:
https://plugins.nessus.org/v2/offline.php
```

访问更新包链地址，填写 `Challenge Code` 和 `Activation Code` 获取 `all-2.0.tar.gz` 文件。

更新包地址：[https://plugins.nessus.org/v2/offline.php](https://cloud.tencent.com/developer/tools/blog-entry?target=https%3A%2F%2Fplugins.nessus.org%2Fv2%2Foffline.php\&source=article\&objectId=2148812)



<figure><img src="../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

下载一下注册码，将它放到/opt/nessus/sbin目录下

<figure><img src="../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

```
➜  sbin ./nessuscli fetch --register-offline nessus.license
Your Activation Code has been registered properly - thank you
```

然后会得到一个链接  下载all-2.0.tar.gz 就好了，将它放到/opt/nessus/sbin目录下

```
➜  sbin ./nessuscli update all-2.0.tar.gz 

[info] Copying templates version 202312191821 to /opt/nessus/var/nessus/templates/tmp
[info] Finished copying templates.
[info] Moved new templates with version 202312191821 from plugins dir.
[info] Moved new pendo client with version 2.169.1
 from plugins dir.
 * Update successful.  The changes will be automatically processed by Nessus.
```

注意：更新完漏洞库后，记住version版本号，如上述中的version版本号为 202312191821 ，之后破解时会用到这个。

重启一下Nessus

```
➜  sbin ./nessusd
nessusd (Nessus) 10.6.4 [build 20005] for Linux
Copyright (C) 1998 - 2023 Tenable, Inc.
```

<figure><img src="../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

这样就成功了，如果后续出现问题可以重复一下以下步骤

```
./nessuscli update all-2.0.tar.gz 
```
