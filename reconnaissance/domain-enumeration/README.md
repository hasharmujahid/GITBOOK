---
description: ACTIVE DIRECTORY DOMAIN ENUMERATION
---

# DOMAIN ENUMERATION



## ENUMERATION BY USING NATIVE EXECUTABLES AND .NET CLASSES

When we get a foothold in a domain, we should start enumerating and map variou entities, trusts, relationships, and privileges for the target domain.

> GET INFORMATION ABOUT THE CURRENT DOMAIN

```powershell
$ADClass=[System.DirectoryServices.ActiveDirectory.Domain]$ADClass::GetCurrentDomain()
```

Defined a variable in powershell named ADClass and then used it to call a function of GetCurrentDomain.

```powershell
PS C:\Users\Administrator> $ADClass=[System.DirectoryServices.ActiveDirectory.Domain]PS C:\Users\Administrator> $ADClass::GetCurrentDomain()Forest                  : CONTROLLER.localDomainControllers       : {Domain-Controller.CONTROLLER.local}Children                : {}DomainMode              : UnknownDomainModeLevel         : 7Parent                  :PdcRoleOwner            : Domain-Controller.CONTROLLER.localRidRoleOwner            : Domain-Controller.CONTROLLER.localInfrastructureRoleOwner : Domain-Controller.CONTROLLER.localName                    : CONTROLLER.local
```

To speed things up, we can use [powerview](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) or Active Directory Powershell module made by Microsoft pre-install with RSAT. If RSAT isnot installed, we can load the module by following these instructions from this [github](https://github.com/samratashok/ADModule) repository.

## DOMAIN ENUMERATION WITH POWERVIEW AND ADMODULE

> LOAD POWERVIEW

To load powerview in our shell we need to run this command.

`PS C:\Users\Administrator> . .\Powerview.ps1`

> GET CURRENT DOMAIN

* PowerView

```powershell
Get-NetDomain
```

* AD Module

```powershell
Get-ADDomain
```

> GET OBJECT OF ANOTHER DOMAIN

* PowerView

```powershell
Get-NetDomain -Domain <DOMAINNAME>
```

* AD Module

```powershell
Get-ADDomain -Identity <DOMAINAME>
```

> GET SID FOR CURRENT DOMAIN

* PowerView

```powershell
Get-DomainSID
```

* AD Module

```powershell
(Get-ADDomain).DomainSID
```

SID looks like `S-1-5-21-849420856-2351964222-986696166` this .

> GET DOMAIN POLICY

* PowerView

```powershell
Get-DomainPolicy(Get-DomainPolicy)."system access" {will bring default system policy}(Get-DomainPolicy)."kerberos policy"
```

> GET DOMAIN POLICY FOR ANOTHER DOMAIN

* PowerView

```powershell
(Get-DomainPolicy -domain <domain name>)."system access"
```

> GET DOMAIN CONTROLLERS FOR THE CURRENT DOMAIN

* PowerView

```powershell
Get-NetDomainController
```

* AD Module

```powershell
Get-ADDomainController
```

> GET DOMAIN CONTROLLER INFORMATION FOR THE ANOTHER DOMAIN

* PowerView

```powershell
Get-NetDomainController -Domain <DOMAINNAME>
```

* AD Module

```powershell
Get-ADDomainController -DomainName <DOMAIN> -Discover
```

> GETLIST OF USERS OF THE CURRENT DOMAIN

* PowerView

```powershell
Get-NetUserGet-NetUser -Username <Username>
```

* AD Module

```powershell
Get-ADUser -Filter *  -Properties *Get-ADUser -Identify <username>  -Properties *
```

> GET THE LIST OF ALL PROPERTIES FOR USERS IN THE CURRENT DOMAIN

* PowerView

```powershell
Get-UserPropertyGet-UserProperty -Properties <propertyname>
```

* AD Module

```powershell
Get-ADUser -Filter *  -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
```

> SEAERCH FOR A PARTICULAR STRING IN USERS ATTRIBUTES

Some users tend to store their passwords in the description of their accounts.

* PowerView

```powershell
Find-UserField -SearchField Description -SearchTerm "built" {add any string here}PS C:\Users\Administrator\Downloads> Find-UserField -SearchField Description -SearchTerm "password"samaccountname description-------------- -----------SQLService     My password is MYpassword123#
```

* AD Module

```powershell
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```
