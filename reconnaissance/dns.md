# DNS&#x20;

## **DNS**

The Domain Name System (DNS) Server is a server that is specifically used for **matching website hostnames (like example.com)to their corresponding Internet Protocol or IP addresses**. The DNS server contains a database of public IP addresses and their corresponding domain names.

> _PORT_

* 53

***

**ENUMERATION**

> _HOST_

Find IP address of a domain

`host megacorp.com`

By default, host command looks for A records, but we can also enumarate mailserver records and TXT records.

`$ host -t mx megacorpone.com` `$ host -t txt megacorpone.com`

Automating the hostname enumeration:

`for ip in $(cat wordlistlist.txt); do host $ip.domain.com; done`

This will try every hostname and see if it resolves.

> _DIG_

DIG REVERSE LOOKUP

\`dig @10.13.37.10 -x 10.13.37.10

`dig axfr @10.10.11.158`

`dig ANY @<DNS\_IP> <DOMAIN>`

> _Zone transfer_

A zone transfer is basically a database replication between related DNS servers in which the zone file is copied from a master DNS server to a slave server. The zone file contains a list of all the DNS names configured for that zone. Zone transfers should only be allowed to authorized slave DNS servers but many administrators misconfigure their DNS servers, and in these cases, anyone asking for a copy of the DNS server zone will usually receive one. This is equivalent to handing a hacker the corporate network layout on a silver platter. All the names, addresses, and functionality of the servers can be exposed to prying eyes.

The host command syntax for performing a zone transfer is as follows:

`host -l <domain name> <dns server address>`

i.e:

`host -l megacorpone.com ns1.megacorpone.com`

> _DNS RECON_

DNSRecon193 is an advanced, modern DNS enumeration script written in Python. Running dnsrecon against megacorpone.com using the -d option to specify a domain name, and -t to specify the type of enumeration to perform (in this case a zone transfer), produces the following output:

`dnsrecon -d megacorpone.com -t axfr` :: axfr is domain transfer

To use dns recon in bruteforce mode

`dnsrecon -d megacorpone.com -D ~/list.txt -t brt` :: brt means bruteforce

> _DNS ENUM_

DNSEnum is another popular DNS enumeration tool. To show a different output, let’s run dnsenum against the zonetransfer.me domain (which is owned by DigiNinja194 and specifically allows zone transfers):

`dnsenum zonetransfer.me`
