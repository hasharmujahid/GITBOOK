# NFS

The Network File System (NFS) is a mechanism for **storing files on a network**. It is a distributed file system that allows users to access files and directories located on remote computers and treat those files and directories as if they were local.

**PORTS**

* 111
* 2049

***

**ENUMERATION**

> USING NMAP

Locate scripts:

`ls -1 /usr/share/nmap/scripts/nfs*`

We can run all three of these scripts using the wildcard character `*` in the script name:

`nmap -p 111 --script nfs* 10.11.1.72`

> SHOWMOUNT

To know which folder has the server available to mount, you an ask it using:

`showmount -e <IP>`

Then mount it using:

`sudo mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock`

You should specify to **use version 2** because it doesn't have any authentication or authorization.

_Example:_

`mkdir /mnt/new_back`

`mount -t nfs [-o vers=2] 10.12.0.150:/backup /mnt/new_back -o nolock`

\
