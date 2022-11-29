# HTTP-HOST HEADER ATTACKS

WHAT IS THE HOST HEADER?

&#x20;In layman’s terms, the HTTP host header is compulsory in the request it contains the domain name of the website that a user wants to access.

For example, if a user wants to access youtube.com . When he sends the request the host header of that request will contain the address of youtube.com.

<figure><img src="https://miro.medium.com/max/640/1*kfEeqmrwMsnYoWfHCxovlw.png" alt=""><figcaption></figcaption></figure>

Example&#x20;



**What is an HTTP Host header attack?**

If a web application does not validate the value in the host header then an attacker could manipulate the value and use this to inject harmful payloads into the web application this vulnerability could lead to many other vulnerabilities like

Web cache poisoning SSRF And in some cases SQL injections as well.

**How do they arise?**&#x20;

HTTP host header vulnerabilities arise due to the developer’s false assumption that host header values are not controllable by the user.

And web applications inherently trust all the values in the host header and don't validate them. Even if the validation is applied in some cases it is very weak and simple injections can bypass the validation.

**Testing for Host Header Injection?**&#x20;

Initial testing of host header injection is simple you just have to supply an arbitrary value in the Host header and see if you can still get a valid response.

****

For example:

```
GET / HTTP/1.1Host: www.attacker.com[...]
```

Response:

```
HTTP/1.1 302 Found[...]Location: http://www.attacker.com/login.php
```



&#x20;If you got a valid response that means the target is vulnerable to Host Header injection.

If there is some kind of validation is applied you can still try to bypass it using various techniques that we will see in a minute.

**What attacks can be performed?**&#x20;

The attacker can perform multiple exploits using this vulnerability.

**Password Reset Poisoning:**

An attacker can obtain the username or email to submit a password request on their behalf after that he needs to intercept this request and manipulate the host header and change the value to point to the domain that the attacker control. If the host header injection exists the attacker will receive the reset token and rest the password to his liking.

<figure><img src="https://miro.medium.com/max/720/1*T1vUxK-h__H7PJnsJP3Ing.png" alt=""><figcaption></figcaption></figure>

Submitting a request on the victim's behalf Intercept the request:

<figure><img src="https://miro.medium.com/max/720/1*85LgL2N3BMCa-mOjkJhCyw.png" alt=""><figcaption></figcaption></figure>

Now manipulate the host header to point to your domain.

<figure><img src="https://miro.medium.com/max/720/1*v-AkYRCoKkQXl41nXnYIvw.png" alt=""><figcaption></figcaption></figure>

We can see in the access logs we have a reset token

<figure><img src="https://miro.medium.com/max/720/1*zPQwYkYfpcLQWRE7rO2ovg.png" alt=""><figcaption></figcaption></figure>

Now just use this token to set a new password for Carlos.

<figure><img src="https://miro.medium.com/max/720/1*jwNJnT0XCl5XDBaLdRl66w.png" alt=""><figcaption></figcaption></figure>

Log In

<figure><img src="https://miro.medium.com/max/720/1*1QiZlAaLb1iSVBZUBVVcew.png" alt=""><figcaption></figcaption></figure>

Solved We can see how a host header injection vulnerability caused a full account takeover of another user.

**Authentication Bypass Using Host Header Injection** :thumbsup:****

Websites hide some functionalities for internal users only like admins and webmasters. But if the host injection vulnerability exists this can be bypassed because the developer made the flawed assumption that the host header is not user controllable.

<figure><img src="https://miro.medium.com/max/720/1*b0tSP--fK3TGkZv19ptxmQ.png" alt=""><figcaption></figcaption></figure>

Admin We don't have any credentials nor we can register an account so how can we tackle this….

Let's intercept the request to access the admin panel and try different injections.

<figure><img src="https://miro.medium.com/max/720/1*HlEpZYZcXXHiabiB5QFoWg.png" alt=""><figcaption></figcaption></figure>

We can see we got a 200 response code but how !!!

The localhost resolves to 127.0.0.1 where the admin panel is also live so by changing the host header we were able to access the admin panel thus bypassing the authentication mechanism.

<figure><img src="https://miro.medium.com/max/720/1*DZzz4jcMYmGDt8eAhuYtiw.png" alt=""><figcaption></figcaption></figure>

In the upcoming blog, we will see how to chain this vulnerability to perform SSRF and Web cache poisoning and many other advanced techniques.

<figure><img src="https://miro.medium.com/max/720/1*HUjaRARMPOv-DEdsMHb2ug.png" alt=""><figcaption></figcaption></figure>

Now it's finally time to discuss how to bypass the validation in the HOST header This will help in performing future labs.&#x20;

**BYPASSING VALIDATIONS FOR HOST HEADER INJECTIONS:**&#x20;

Sometimes web applications do validate what’s inside the host header but this validation can sometimes also be bypassed using various techniques.

We will discuss some of them here.

**Duplicate Host Headers:**

We will insert 2 Host headers one of them will contain a malicious payload and another one will be original But you may have a question that how that will help us to bypass the validation.

The answer is one of those host headers will overwrite the value of the other one we can not determine which one will work and be accepted but different technologies and systems handle this process differently.



```
GET /example HTTP/1.1 
Host: vulnerable-website.com 
Host: evil.com
```

**Or**

```
GET /example HTTP/1.1 
Host: bad-stuff-here
Host: vulnerable-website.com
```

**ADD A LINE WRAPPING:**

It is the same as injecting duplicate host headers but with an indent, in the host header, the server will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header’s value. Different servers will respond to this technique differently.

```
GET /example HTTP/1.1 
Host: bad-stuff-here 
Host: vulnerable-website.com
```

INJECT HOST OVERRIDE HEADERS:

If the host header is validated you can try to inject some HTTP methods that could override the value in the host header Some of these headers are given below.

```
GET /example HTTP/1.1 
Host: vulnerable-website.com
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
Forwarded: evil.com
```

SUPPLY ABSOLUTE URL:

We can try to inject the absolute path or URL in the GET request and change the HOST to evil and see if the server responds to us with a 200 response code.

For Example:

```
GET https://vulnerable-website.com/ HTTP/1.1 
Host: evil.com
```
