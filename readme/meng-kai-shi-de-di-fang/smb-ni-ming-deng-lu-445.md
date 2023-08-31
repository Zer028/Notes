# SMB匿名登录445

运行以下命令将使 nmap 扫描所有端口并显示每个端口的服务版本

```
┌──(root㉿kali)-[~]
└─# nmap -sS -sV 10.129.105.148  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-02 21:10 EDT
Nmap scan report for 10.129.105.148
Host is up (1.2s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 158.63 seconds
```

如前所述，我们观察到 SMB 的端口 445 TCP 已启动并正在运行，这意味着我们有一个可以探索的活跃共享。 将此共享视为可以通过 Internet 访问的文件夹。

Smbclient 将尝试连接到远程主机并检查是否需要任何⾝份验证。如果有，它会要求您输⼊本地⽤⼾名的密码。我们 应该注意到这⼀点。如果我们在尝试连接到远程主机时没有为 smbclient 指定特定的⽤⼾名，它将仅使⽤本地计算 机的⽤⼾名。这是您当前登录虚拟机所⽤的虚拟机。这是因为 SMB ⾝份验证始终需要⽤⼾名，因此如果不明确为其提供 ⽤⼾名来尝试登录，则只需传递您当前的本地⽤⼾名即可避免引发协议错误。

该密码与您之前输⼊的⽤⼾名相关。假设，如果我们是尝试登录其资源的合法远程⽤⼾，我们将知道我们的⽤⼾名和密码并正常登录以访问我们的共 享。在这种情况下，我们没有此类凭据，因此我们将尝试执⾏以下任⼀操作：

```
┌──(root㉿kali)-[~]
└─# smbclient -L 10.129.105.148
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        WorkShares      Disk      
Reconnecting with SMB1 for workgroup listing.
```

运⾏上⾯的命令，我们看到显⽰了四个单独的共享。让我们逐⼀浏览并了解它们的含义。

* ADMIN$ - 管理共享是由 Windows NT 系列操作系统创建的隐藏⽹络共享，允许系统管理员远程访问⽹络连接系统上的每个磁盘卷。 这些共享可能不会被永久删除，但可能会被禁⽤。
* C$ - C:\ 磁盘卷的管理共享。 这是操作系统的托管位置。
* IPC$ - 进程间通信共享。⽤于通过命名管道进⾏进程间通信，不属于⽂件系统的⼀部分。
* WorkShares - ⾃定义共享。

我们将尝试连接除 IPC$ 之外的每个共享，这对我们来说没有价值，因为它是 无法像任何常规目录一样可浏览，并且不包含我们可以在此使用的任何文件 我们的学习经历的阶段。 我们将使用与之前相同的策略，尝试在没有 正确的凭据来查找任何这些共享上配置不当的权限。 我们只给一个空白 每个用户名的密码，看看它是否有效。 首先，让我们尝试一下 ADMIN$ 。

```
┌──(root㉿kali)-[~]
└─# smbclient \\\\10.129.105.148\\ADMIN$
Password for [WORKGROUP\root]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```

输出 NT\_STATUS\_ACCESS\_DENIED，让我们知道我们没有正确的凭据 连接到此共享。 我们将跟进加元行政份额。

```
┌──(root㉿kali)-[~]
└─# smbclient \\\\10.129.105.148\\C$    
Password for [WORKGROUP\root]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```

这里有同样的想法。 最后的机会。 我们继续尝试登录自定义 WorkShares SMB 共享。 这似乎是人为的，因此容易出现配置错误。

```
┌──(root㉿kali)-[~]
└─# smbclient \\\\10.129.105.148\\WorkShares
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> 
```

成功！ WorkShares SMB 共享配置不当，导致我们无法在没有适当权限的情况下登录 证书。 我们可以看到终端提示符更改为 smb: > ，让我们知道我们的 shell 现在是 与服务交互。 我们可以使用 help 命令来查看在此 shell 中可以执行哪些操作。

```
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         .. 
```

从输出中，我们可以注意到我们在 Linux 中习惯的大部分命令都存在。 我们将 使用以下命令导航共享：

```
ls ：列出共享中目录的内容
cd ：更改共享中的当前目录
get ：下载共享中目录的内容
exit : 退出 smb shell
```

输入 ls 命令将显示两个目录，一个用于 Amy.J ，另一个用于 James.P 。 我们参观了 第一个是一个名为 worknotes.txt 的文件，我们可以使用 get 命令下载该文件。

```
smb: \> ls
  .                                   D        0  Mon Mar 29 04:22:01 2021
  ..                                  D        0  Mon Mar 29 04:22:01 2021
  Amy.J                               D        0  Mon Mar 29 05:08:24 2021
  James.P                             D        0  Thu Jun  3 04:38:03 2021

                5114111 blocks of size 4096. 1753207 blocks available
```

该文件现在保存在我们运行 smbclient 命令的位置中。 让我们继续 在 James.P 的目录中寻找其他有价值的文件。 导航到它，我们可以找到所寻找的flag.txt 文件也是如此。 检索到该文件后，我们可以使用 exit 命令退出 shell 并检查我们的文件 刚刚取回。

```
smb: \> ls
  .                                   D        0  Mon Mar 29 04:22:01 2021
  ..                                  D        0  Mon Mar 29 04:22:01 2021
  Amy.J                               D        0  Mon Mar 29 05:08:24 2021
  James.P                             D        0  Thu Jun  3 04:38:03 2021

                5114111 blocks of size 4096. 1753207 blocks available
smb: \> cd James.P
smb: \James.P\> ls
  .                                   D        0  Thu Jun  3 04:38:03 2021
  ..                                  D        0  Thu Jun  3 04:38:03 2021
  flag.txt                            A       32  Mon Mar 29 05:26:57 2021
c
                5114111 blocks of size 4096. 1753175 blocks available
smb: \James.P\> get flag.txt
getting file \James.P\flag.txt of size 32 as flag.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```
