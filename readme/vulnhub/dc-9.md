# DC-9

nmap扫描4步

```
┌──(root㉿kali)-[~/Desktop/test/DC-9]
└─# nmap -sT --min-rate 10000 -p- 192.168.5.145 -oA nmapscan/tcpscanport && nmap -sT -sV -sC -O -p $(awk -F/ '/^[0-9]+\// { printf $1" " } END { printf "\n" }' nmapscan/tcpscanport.nmap) 192.168.5.145 -oA nmapscan/detailed && nmap -sU --top-ports 20 192.168.5.145 -oA nmapscan/udpport && nmap --script=vuln -p $(awk -F/ '/^[0-9]+\// { printf $1" " } END { printf "\n" }' nmapscan/tcpscanport.nmap) 192.168.5.145 -oA nmapscan/vuln
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 21:07 EST
Nmap scan report for 192.168.5.145
Host is up (0.0090s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:1A:2A:4A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 2.25 seconds
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 21:07 EST
Nmap scan report for 192.168.5.145
Host is up (0.0014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:b3:38:74:32:74:0b:c5:16:dc:13:de:cb:9b:8a:c3 (RSA)
|   256 06:5c:93:87:15:54:68:6b:88:91:55:cf:f8:9a:ce:40 (ECDSA)
|_  256 e4:2c:88:da:88:63:26:8c:93:d5:f7:63:2b:a3:eb:ab (ED25519)
MAC Address: 00:0C:29:1A:2A:4A (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (1 host up) scanned in 4.95 seconds
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 21:08 EST
Nmap scan report for 192.168.5.145
Host is up (0.00075s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    closed        tftp
123/udp   closed        ntp
135/udp   closed        msrpc
137/udp   closed        netbios-ns
138/udp   closed        netbios-dgm
139/udp   closed        netbios-ssn
161/udp   closed        snmp
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   closed        isakmp
514/udp   closed        syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  closed        nat-t-ike
49152/udp closed        unknown
MAC Address: 00:0C:29:1A:2A:4A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 16.36 seconds
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 21:08 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.5.145
Host is up (0.00096s latency).

PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 00:0C:29:1A:2A:4A (VMware)

Nmap done: 2 IP addresses (1 host up) scanned in 37.83 seconds
```
