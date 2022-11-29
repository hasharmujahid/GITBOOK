# DOMAIN ENUMERATION - USER HUNTING

## USER HUNTING

In this section, we will see how we can hunt for users with specific privilleges.

> FIND ALL MACHINES ON THE CURRENT DOMAIN WHERE THE CURRENT USER HAS LOCAL ADMIN ACCESS.

* Powerview

```powershell
Find-LocalAdminAccess -Verbose
```

This powerview command will find all the machines in the domain where your compromised users has admin access.

This function queries the Domain Controller of the current or provided domain for a list of computer using `Get-NetComputer` and then uses multithreaded `Invoke-CheckLocalAdminAccess` on each machine.

> FIND LOCAL ADMIN ON ALL MACHINES OF THE DOMAIN (Needs administrator Privs on non-dc machines)

* PowerView

```powershell
Invoke-EnumerateLocalAdmin -verbose
```

This function queries the Domain Controller of the current or provided domain for a list of computer using `Get-NetComputer` and then run `Get-NetLocalGroup` On each machine.

> FIND COMPUTERS WHERE A DOMAIN ADMIN (Or specified user/group hash sessions):

* PowerView

```powershell
Invoke-UserHunter

Invoke-UserHunter -GroupName "RDPUsers"

To confrom the access 

Invoke-UserHunter -CheckAccess

Find Computers where Domain admin is logged in.

Invoke-UserHunter -Stealth
```

One of the easiest ways to escalate our privilleges to a Domain Admin is to look for a machine where the domain admin session or token is available and to see if we have a local admin access on that machine . With the local admin access, we can extract domain admin's session creds , NTLM hashes or TGT etc.

We can also target any other user with this .

This function request 2 pieces of information from Domain Controller. 1: List of computer with `Get-NetComputer` 2: Get the membership of domain admin group using `Get-NetGroupMember`

After that it checks of the logon session of target user on each machine.
