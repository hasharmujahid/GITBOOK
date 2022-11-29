# SMB

The Server Message Block (SMB) protocol is a network file sharing protocol that **allows applications on a computer to read and write to files and to request services from server programs in a computer network**.

> _PORTS_

* 139
* 445

***

**ENUMERATION**

> LOOK FOR OPEN PORTS WITH NMAP SCAN

`nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254`

OR

&#x20;`sudo nbtscan -r 10.11.1.0/24`

> NMAP SMB NSE SCRIPTS

Nmap contains many useful NSE scripts that can be used to discover and enumerate SMB services. These scripts can be found in the /usr/share/nmap/scripts directory.

`ls -1 /usr/share/nmap/scripts/smb*`

There will be alot of smb scripts that can use to enumerate this service more and more.

To use a script : specify the command in this manner: `nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227`

> SMB MAP

`Smbmap -u anonymous -H $t # List Shares` $t is target's IP adress

> SMB CLIENT

`smbclient -L 192.168.1.40 # List Shares`

`smbclient [\\\\192.168.1.40\\guest](\\\\192.168.1.40\\guest) # to connect to a share`

> CRACKMAPEXEC

`crackmapexec smb <target-ip>`

> PSEXEC.PY

Psexec.py `psexec.py Domainname/username:Password@<ip>`

> METASPLOIT MODULE

You can also use metasploit for psexec

`windows/smb/psexec`

**SMB FILES DOWNLOAD**

> SMBGET

[SMBGET](https://www.samba.org/samba/docs/current/man-html/smbget.1.html)

`smbget -U sbradley smb://raz0rblack.thm/trash/experiment_gone_wrong.zip`

\
