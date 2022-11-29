# 🐶 THE ANATOMY OF KERBEROS AUTHENTICATION

### What is Kerberos? <a href="#e92f" id="e92f"></a>

Kerberos is an authentication protocol that Microsoft widely implements in their Active Directory Services. It allows users to access services or data over an untrusted network by proving their identity with the help of tickets. All major operating systems like macOS, Linux, etc also support Kerberos.

### Why understand Kerberos? <a href="#367f" id="367f"></a>

“ If you know yourself but not the enemy, for every victory gained you will also suffer a defeat” (Sun Tzu)

From a penetration tester point of view, almost 90 percent of big companies use Active Directory Environment. And Kerberos is the main authentication system used in AD services. So it is detrimental for every wannabe pentester or red teamer to understand how Kerberos authentication works.

### ANATOMY OF KERBEROS AUTHENTICATION. <a href="#1a98" id="1a98"></a>

Now we will see how this authentication system works and what are the components or entities involved in this process.

<figure><img src="https://miro.medium.com/max/720/1*iXp8f8wFqCKqWIrHqkQnEQ.webp" alt=""><figcaption><p>TOPOLOGY</p></figcaption></figure>

### STEP 1: Authentication Server Request (AS-REQ) <a href="#ad56" id="ad56"></a>

Let’s say a client wants to access some resource at the resource server to do that first it needs to send a request to the Key Distribution Center (KDC). This request will contain the _**NTLM hash of the client’s password**_ and a _**timestamp encrypted with that NTLM hash**_. This is to certain that the request is actually coming from a user that it claims to be.

At the end of step one. The KDC receives the request made by the user and decrypts it.ima



<figure><img src="https://miro.medium.com/max/720/1*k5j6PipLTItWoGVa7CrjYA.webp" alt=""><figcaption></figcaption></figure>

### STEP 2: Authentication Server Response (AS-REP) <a href="#79f4" id="79f4"></a>

A key distribution center is composed of essentially 2 components.

* Authentication Server
* Ticket Granting Server

The KDC receives the request made by the user and decrypts it. If the request is validated the KDC responds with the TGT (Ticket Granting Ticket). The TGT is encrypted and signed with the hash of a special account of the domain controller name “KRBTGT”. Only the KRBTGT account can open and read the tickets.

<figure><img src="https://miro.medium.com/max/720/1*ZNjFV6KIhi0oxj40V1AXGw.webp" alt=""><figcaption></figcaption></figure>

**STEP 3: Ticket Granting Service Request (TGS-REQ)**

Now the client has a TGT but he cannot decrypt it because it was encrypted using a hash of the krbtgt account. So the client sends back the TGT to KDC and requests a TGS ticket a TGS ticket is a ticket that grants access to a specific service on an AD domain environment. At the end of step 3, the KDC receives the request and Decrypts the TGT. This is the only validation at this step if the TGT is validated the KDC assumes that whatever is returned inside the TGT is valid.

<figure><img src="https://miro.medium.com/max/720/1*3Np9byRP4g4mMo9ru9xEBA.webp" alt=""><figcaption></figcaption></figure>

### STEP 4: Ticket Granting Server Response (TGS-REP) <a href="#db63" id="db63"></a>

Once the TGT is validated the KDC response with TGS. TGS is encrypted using the target server or resource server’s NTLM hash. So that client could not decrypt it only the Resource server could decrypt it.

<figure><img src="https://miro.medium.com/max/720/1*Z8IeR9m2s-zhGoUEdUsTig.webp" alt=""><figcaption></figcaption></figure>

### STEP 5: Connect to Resource Server (AP-REQ) <a href="#10d9" id="10d9"></a>

> RESOURCE SERVER CAN ALSO BE CALLED AS APPLICATION SERVER

Now the client has a TGS the client or user can connect to the resource server and presents their TGS to the resource server.

**STEP 6: Response from the Resource Server (AP-REP)**

Now because the TGS is encrypted using the application server or resource server’s NTLM hash. It decrypts it and decides on the privileges of the user whether it can access the service or not.

<figure><img src="https://miro.medium.com/max/640/1*o_PCThIYloy80uFh6twAzQ.webp" alt=""><figcaption></figcaption></figure>

That is all that happens in the Kerberos Authentication protocol.
