# SMTP

Port 25

> We can also gather information about a host or network from vulnerable mail servers. The Simple Mail Transport Protocol (SMTP)216 supports several interesting commands, such as VRFY and EXPN. A VRFY request asks the server to verify an email address, while EXPN asks the server for the membership of a mailing list. These can often be abused to verify existing users on a mail server, which is useful information during a penetration test. Consider this example.

Connect using netcat: `nc -nv <IP> <PORT>`

VRFY: After connection run : `VRFY root or any syspected username`

> Using metasploit

`auxiliary/scanner/smtp/smtp_enum`

> NMAP SCRIPTS

```bash
ls /usr/share/nmap/scripts/smtp*/usr/share/nmap/scripts/smtp-brute.nse       /usr/share/nmap/scripts/smtp-strangeport.nse/usr/share/nmap/scripts/smtp-commands.nse    /usr/share/nmap/scripts/smtp-vuln-cve2010-4344.nse/usr/share/nmap/scripts/smtp-enum-users.nse  /usr/share/nmap/scripts/smtp-vuln-cve2011-1720.nse/usr/share/nmap/scripts/smtp-ntlm-info.nse   /usr/share/nmap/scripts/smtp-vuln-cve2011-1764.nse/usr/share/nmap/scripts/smtp-open-relay.nse
```

> GET NTML AUTH IF SERVER SUPPORTS IT

[NTLM AUTH](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp#ntlm-auth-information-disclosure)

[RESOURCES](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)
