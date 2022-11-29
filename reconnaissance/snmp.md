# SNMP

Simple Network Management Protocol (SNMP) is a networking protocol used for the **management and monitoring of network-connected devices in Internet Protocol networks**. SNMP is based on UDP, a simple, stateless protocol, and is therefore susceptible to IP spoofing and replay attacks. In addition, the commonly used SNMP protocols 1, 2, and 2c offer no traffic encryption, meaning that SNMP information and credentials can be easily intercepted over a local network.

> Onesixtyone
>
> &#x20;SNMP Check&#x20;
>
> Snmp-walk

***

**ENUMERATION**

_**ONESIXTYONE:**_

First thing’s first, we need to discover the “Community String” that SNMP is using for verification. To do this we use a tool called onesixtyone.

`onesixtyone -c common-snmp-community-strings-onesixtyone.txt <TARGET>`

If we have a list of targets wecan use -i option to pass a list of ips.

_**SNMP Check:**_ Syntax:

`snmp-check <ip>`

_**SNMP-WALK:**_

We can probe and query SNMP values using a tool such as snmpwalk provided we at least know the SNMP read-only community string, which in most cases is “public”

* \-c is a comunnity string
* \-v1 specifies version number, change it accordingly
* \-t specifies target.

> Enumerating entire mib tree:

`snmpwalk -c public -v1 -t 10 10.11.1.14`

> Enumerating Windows Users

`snmpwalk -c public -v1 <ip> 1.3.6.1.4.1.77.1.2.25`

> Enumerating Running Windows Processes

`snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.4.2.1.2`

> Enumerating Open TCP Ports

`snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3`

> Enumerating Installed Software

`snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2`

\
