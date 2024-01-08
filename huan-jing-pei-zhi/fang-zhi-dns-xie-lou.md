# 防止DNS泄露

DNS（Domain Name System）泄漏是指通过 DNS 查询或响应中泄露敏感信息的情况。DNS 是互联网中负责将域名映射到 IP 地址的系统，使用户能够通过易记的域名访问网站，而无需记住复杂的数字 IP 地址。

DNS 泄漏的原理可以分为两种情况：

1. **DNS查询时的泄露：** 当用户在浏览器中输入一个域名并按下回车时，计算机会向DNS服务器发送一个查询，以获取该域名对应的IP地址。这个查询通常包含用户的公共IP地址。如果在这个过程中，用户的IP地址被记录或截获，就可能发生DNS查询时的泄露。攻击者或第三方可以监视网络流量，捕获这些DNS查询请求，从而得知用户正在访问的域名，以及用户的IP地址。
2. **DNS响应时的泄露：** 在访问一个网站时，DNS服务器会返回一个包含目标网站IP地址的响应。这个响应也可能包含其他一些信息，如TTL（生存时间）和其他域名解析相关的信息。如果这个响应被恶意截获，攻击者可以获取到用户的IP地址和其他敏感信息。

DNS泄露可能对用户隐私构成风险，因为攻击者可以利用这些泄露的信息来跟踪用户的在线活动。为了减轻DNS泄露的风险，一些安全措施包括使用加密的DNS协议（如DNS over HTTPS或DNS over TLS）以及使用VPN等工具来隐藏用户的真实IP地址。

### 环境准备

由于我的Kali是安装在Vmware上的，所以我这里先配置我物理机的环境

工具：[Qv2ray](https://github.com/Qv2ray/Qv2ray)、[v2ray](https://github.com/v2ray/v2ray-core)、[proxifier](https://www.proxifier.com/)

#### V2ray配置

Qv2ray和v2ray下载编译好的不要下载源码，将v2ray放到Qv2ray的安装目录下，先安装Qv2ray，然后在首选项中配置核心路径，也可以用Clsh for windows 代替v2ray效果是一样的

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

再进入到分组选项的订阅设置，订阅地址需要自行购买，订阅类型选择这个Base64的，然后更新订阅OK保存就可以了

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

首选项连接设置

<figure><img src="../.gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

首选项入站设置

<figure><img src="../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

首选项常规设置

<figure><img src="../.gitbook/assets/image (98).png" alt=""><figcaption></figcaption></figure>

#### Proxifier配置

选择Proxy Servers，add一个代理，1089是v2ray的socks代理端口，可自行修改保存和v2ray一致就行

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

选择Proxification  Rules配置代理规则，按照如下配置

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

将Vmware所有流量都走代理，防止流量偷跑

```
vmware.exe; vmnetcfg.exe; vmnat.exe; vmrun.exe; vmware-vmx.exe; mkssandbox.exe; vmware-hostd.exe; vmnat.exe; vmnetdhcp.exe
```

<figure><img src="../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

由于我物理机默认是走代理的，所以我这里还需要配置一下v2ray走直连

```
v2ray.exe; v2ctl.exe; wv2ray.exe; qv2ray.exe
```

<figure><img src="../.gitbook/assets/image (6) (1) (1).png" alt=""><figcaption></figcaption></figure>

这样就配置好了虚拟机的代理，接下来我们来配置防止DNS泄露的配置



### 环境准备

在Linux中防止DNS泄露可以使用DNS over HTTPS（DoH）或DNS over TLS（DoT）来加密DNS流量，我这里先介绍DNS over TLS（DoT）来加DNS流量

DNS over HTTPS（DoH）和DNS over TLS（DoT）的主要区别：

1. **传输协议：**
   * **DoH：** 使用HTTP协议。
   * **DoT：** 使用TLS协议。
2. **端口：**
   * **DoH：** 默认端口是443（HTTPS）。
   * **DoT：** 默认端口是853。
3. **集成方式：**
   * **DoH：** 更容易与Web浏览器集成，通过浏览器或操作系统设置启用。
   * **DoT：** 需要在DNS客户端和服务器之间建立专用的TLS连接，通常需要在操作系统或应用程序层面进行配置。
4. **可用性：**
   * **DoH：** 更容易穿越防火墙，有更广泛的支持。
   * **DoT：** 可能在某些网络环境中受到阻碍，但提供更直接的DNS安全，因为使用专用端口和TLS协议。

选择使用DoH或DoT取决于网络环境和个人偏好。 DoH更易于部署，而DoT提供更直接的DNS安全。

1. **安装 `stubby`：**

```
apt install stubby
```

2. **编辑 `stubby` 配置文件：**

```
vim /etc/stubby/stubby.yml
```

#### 3. 将**`stubby`**设置为开机自启动

```
systemctl enable stubby
systemctl start stubby #启动服务
```

4. **修改网络配置文件：**

```
vim /etc/NetworkManager/NetworkManager.conf
```

在\[main]的下方加入

```
dns=none
```

保持文件后，重启网络管理器

```
systemctl restart NetworkManager
```

5. 查看/etc/stubby/stubby.yml这个配置文件并编辑/etc/resolv.conf这个DNS 配置文件

```
cat /etc/stubby/stubby.yml
vim /etc/resolv.conf
```

<figure><img src="../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

这里是将stubby的ipv4和ipv6加入到了系统的DNS配置文件当中，由于kali系统启用ipv6，所以同样也需要加入到配置文件，除非不用它

resolv.conf这个文件包含了用于域名解析的DNS服务器信息，注意：每次vim resolv.conf这个文件的时候退出都必须wq 保存退出，q退出会导致这个文件回复默认配置

修改完成后建议查看一下配置文件有没有修改成功

```
┌──(root㉿kali)-[~]
└─# cat /etc/resolv.conf
#domain localdomain
#search localdomain
#nameserver 145.100.185.15
nameserver 145.100.185.16
#nameserver 199.58.81.218
nameserver 89.234.186.112
nameserver 1.1.1.1
nameserver 2001:610:1:40ba:145:100:185:16
nameserver 2001:610:1:40ba:145:100:185:15
#nameserver 192.168.5.2

┌──(root㉿kali)-[~]
└─# chattr +i /etc/resolv.conf  #将文件设置为不可修改
    chattr -i /etc/resolv.conf  #要解锁文件
```

我们去DNS泄露网站查询一下我们配置完成之后的DNS 有没有泄露

<figure><img src="../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>
