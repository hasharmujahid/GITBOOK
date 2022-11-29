# DOMAIN ENUMERATION - BLOOD HOUND

## BLOOD HOUND

Bloodhound is a graphical interface that allows you to visually map out the network. This tool along with SharpHound which similar to PowerView takes the user, groups, trusts etc. of the network and collects them into .json files to be used inside of Bloodhound.

Well be focusing on how to collect the .json files and how to import them into Bloodhound.

> BloodHound Installation

* `apt-get install bloodhound`
* `neo4j console - default credentials -> neo4j:neo4j`

First, you need to bypass the execution policy of powershell, so you can run the scripts easily.

`powershell -ep bypass`

After that run the sharphound.ps1

`. .\sharphound.ps1`

After that, you need to invoke the bloodhound.

`Invoke-Bloodhound -CollectionMethod All -Domain <DOMAIN NAME.LOCAL> -ZipFileName loot.zip`

> TRANSFER LOOT TO YOUR ATTACKER MACHINE

COPY FILE THROUGH SSH

`Pscp  target@<ip>:<path to file > <path to local >`

If you are getting the incompatible collector error in bloodhound, make sure to install the latest version of Sharphound.ps1 and run it.
