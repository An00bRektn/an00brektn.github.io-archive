---
layout: post
title: "Cyberforce 2023: Writeups"
image: '"/img/cyberforce23/newcfclogo.jpg"'
date: 2023-11-12 00:00:00
tags: 
- reverse-engineering
- cutter
- pyinstaller
- cyberforce
- wireshark
- forensics
- virtual-machine
- nim
description: "mfw reversing a vm that runs emoji bytecode while also dealing with three different assume breach exercises at once"
categories: 
published: true
comments: false
---

<img src="https://an00brektn.github.io/img/cyberforce23/newcfclogo.jpg" style="width:60%;height:60%">

## Intro
Part of the Cyberforce competition I covered last week was the anomaly section, with ~60 CTF-style challenges to be solved. Admittedly, some of them were a lot more work than they were worth, but this year, many of them were weighted towards reverse engineering and some forensics. I didn't get a lot of time to really work on these during the event as I was bogged down in incident response, but here are some writeups, mostly for me, if we're being honest. 

* buh
{:toc}

## What's Up Bro? (formerly brah)
> Anomaly 13

### Description
`We have noticed some suspicious activity leaving a particular machine in the network. We have isolated the machine and recorded its behavior over the course of 20 minutes or so. Either way it is not a full day so hopefully it was enough to get what we need for analysis.

`We are worried it is exfiltrating some data over a C2 channel but we have not been able to pinpoint the channel. Our only indicator is some shady website online that keeps showing data that has been leaked from our network and specifically data on that machine!`

Author: @pascal_0x90 (LLNL - Nate)
### Challenge
We're only given the README.md with the description and the packet capture, so we can pop the packet capture right into Wireshark. Since the packet capture is ~14 MB, we can use the statistics tab to get a gist of what's at play here, and we find *a lot* of TLS traffic.

![Pasted image 20231108222526.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231108222526.png)

In order to decrypt TLS, we would somehow need to get access to the session keys, which, unless they were transmitted in cleartext at some point over HTTP, we're not getting them. The next most frequent protocol is DNS, which is actually quite interesting given the description.

### Solution
[Unit 42](https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/) has a very solid blog explaining exactly how this technique works, and you can see examples of it documented with [Sliver](https://github.com/BishopFox/sliver/wiki/DNS-C2) or [Cobalt Strike](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_beacon-dns.htm). The core idea is that if I have a DNS server and keep track of the DNS queries made to the server, in this case for A records, I can parse data transmitted in the subdomain as basic information, as opposed to actual DNS information. This is not the only way DNS can be leveraged for covert operations. For instance, a TXT record could be used to store payloads that could then be used in PowerShell payloads (source: [Alh4zr3d](https://twitter.com/Alh4zr3d/status/1566489367232651264), [John Hammond](https://www.youtube.com/watch?v=Y3fi9pc81NY)).

If we filter the packet capture for DNS, we see this in action.

![Pasted image 20231108232104.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231108232104.png)

The goal now is to recover the data sent through here. Rather than copy this out by hand, we can use `pyshark` like we did with [corCTF 2022: whack-a-frog](https://notateamserver.xyz/corctf22/#whack-a-frog) to automate this process.

```python
import pyshark

def get_domains():
    pcap_path = "./out.pcap"
    domains = []
    packets = pyshark.FileCapture(pcap_path, display_filter="dns")

    print("[*] Parsing packets...")
    for pkt in packets:
        if pkt.dns.qry_name and "cybrforce.io" in pkt.dns.qry_name and pkt.dns.qry_name not in domains:
            domains.append(pkt.dns.qry_name)
    packets.close()
    print("[+] Parsing complete.")
    return domains

domains = get_domains()
payload = ""
for d in domains:
    payload += d.split(".")[0]

print(bytes.fromhex(payload))
```

One thing to note is the `pkt.dns.qry_name not in domains` in the if statement; DNS uses UDP, which doesn't exactly prioritize the continuity of packets, and instead focuses on speed. As a result, UDP packets can get transmitted multiple times. This is not a perfect solution, as the same domain may have been used in two different places with how the plaintext might have been split up, but it ends up working fine here.

If we run the script, we see some base64:
```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 13 - What’s up Bro (formerly brah)/challenge_dist$ python3 parse.py
[*] Parsing packets...
[+] Parsing complete.
b'SW4gYSB3b3JsZCB3aGVyZSBieXRlcyBhbmQgcGFja2V0cyBwbGF5LApUaHJvdWdoIHRoZSBkaWdpdGFsIG1pc3QsIHRoZXkgZmluZCB0aGVpciB3YXkuCkFtb25nIHRoZSBzdHJlYW1zIG9mIGRhdGEsIHZhc3QgYW5kIGRlZXAsCkxpZXMgYSBzZWNyZXQgdGhhdCB0aGUgc2hhZG93cyBrZWVwLgoKVGhyb3VnaCBzdWJkb21haW5zLCBhIGpvdXJuZXkgc3B1biwKQSB0YWxlIG9mIGV4ZmlsdHJhdGlvbiwgc3VidGx5IGRvbmUuCkVhY2ggRE5TIHF1ZXJ5LCBhIHNpbGVudCB3aGlzcGVyLApSZXZlYWxzIGEgc3RvcnksIGJvdGggY2xlYXIgYW5kIGNyaXNwZXIuCgpHYXplIHVwb24gdGhlIGZyYWdtZW50cywgc2NhdHRlcmVkIHdpZGUsCldoZXJlIHNlY3JldHMgaW4gdGhlIG9wZW4sIGNob29zZSB0byBoaWRlLgpEYXRhIHRyYXZlbHMgaW4gZGlzZ3Vpc2UsIHNvIHNsZWVrLApNYXNraW5nIHRydXRocyB0aGF0IHRoZSBjdXJpb3VzIHNlZWsuCgpUd2lzdHMgYW5kIHR1cm5zIGluIGV2ZXJ5IGJ5dGUsCkNoYWxsZW5nZSB0aGUgbWluZCwgYm90aCBkYXkgYW5kIG5pZ2h0LgpTZWVrZXJzIHNpZnQgdGhyb3VnaCByZWNvcmRzLCB2YXN0IGFuZCB0YWxsLApEZWNvZGluZyBtZXNzYWdlcyB0aGF0IHNpbGVudGx5IGNhbGwuCgpJbiBhIHN5bXBob255IG9mIGRpZ2l0YWwgZmxvd3MsCkxpZXMgYSBwYXR0ZXJuIG9ubHkgdGhlIHZpZ2lsYW50IGtub3dzLgpTdWJ0bGUgY2x1ZXMgaW4gdGhlIHZhc3QgZGF0YSBmb2csCkxlYWQgdG8gdGhlIHJldmVsYXRpb24sIG5vdCBqdXN0IGFueSBsb2cuCgpCdXQgaW4gdGhpcyBjeWJlciBxdWVzdCBzbyBncmFuZCwKQmUgd2FyeSBvZiB3aGF0IHRoZSBudW1iZXJzIGRlbWFuZC4KTm8gcGVyc29uYWwgc2VjcmV0cywgbm8gbnVtYmVycyB0byB0cmFjaywKSnVzdCBhIHB1enpsZSB0byBzb2x2ZSwgbm8gZXRoaWNhbCBjcmFjay4KCkFuZCBzbyB0aGUgam91cm5leSBjb21lcyB0byBhbiBlbmQsCkEgdGFsZSBvZiBpbnRyaWd1ZSwgYXJvdW5kIGV2ZXJ5IGJlbmQuCkJ1dCBhbGFzLCB0aGVyZSB3YXMganVzdCBhIGZsYWcsCkhpZGRlbiBub3QgaW4gcmljaGVzLCBub3IgaW4gYSByYWc6CgoiZmxhZ3t3aDR0NV91cF9icjBfdzNyM195MHVfY2gwcHAxbl9sMGc1P30iCgpJbiB0aGVzZSBjaGFyYWN0ZXJzLCB2aWN0b3J5IGlzIGNsZWFyLApGb3IgdGhvc2Ugd2hvIHNvdWdodCwgd2l0aCBtaW5kcyBzbyBzaGVlci4KVGhlIGNoYWxsZW5nZSBjb21wbGV0ZSwgdGhlIGpvdXJuZXksIGEgc29uZywKSW4gdGhlIHdvcmxkIG9mIGN5YmVyc3BhY2UsIHdoZXJlIG1pbmRzIGJlbG9uZy4='
```

We can add an extra line to then decode the base64, and find the flag:
```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 13 - What’s up Bro (formerly brah)/challenge_dist$ python3 parse.py
[*] Parsing packets...
[+] Parsing complete.
b'In a world where bytes and packets play,\nThrough the digital mist, they find their way.\nAmong the streams of data, vast and deep,\nLies a secret that the shadows keep.\n\nThrough subdomains, a journey spun,\nA tale of exfiltration, subtly done.\nEach DNS query, a silent whisper,\nReveals a story, both clear and crisper.\n\nGaze upon the fragments, scattered wide,\nWhere secrets in the open, choose to hide.\nData travels in disguise, so sleek,\nMasking truths that the curious seek.\n\nTwists and turns in every byte,\nChallenge the mind, both day and night.\nSeekers sift through records, vast and tall,\nDecoding messages that silently call.\n\nIn a symphony of digital flows,\nLies a pattern only the vigilant knows.\nSubtle clues in the vast data fog,\nLead to the revelation, not just any log.\n\nBut in this cyber quest so grand,\nBe wary of what the numbers demand.\nNo personal secrets, no numbers to track,\nJust a puzzle to solve, no ethical crack.\n\nAnd so the journey comes to an end,\nA tale of intrigue, around every bend.\nBut alas, there was just a flag,\nHidden not in riches, nor in a rag:\n\n"flag{wh4t5_up_br0_w3r3_y0u_ch0pp1n_l0g5?}"\n\nIn these characters, victory is clear,\nFor those who sought, with minds so sheer.\nThe challenge complete, the journey, a song,\nIn the world of cyberspace, where minds belong.'
```

**flag**: `flag{wh4t5_up_br0_w3r3_y0u_ch0pp1n_l0g5?}`
## EmojiWare
> Anomaly 14

### Description

`This is an entire program written in emojis... Yes. You heard right. Emojis! The program that is in this challenge is an emulator that can interpret the emojis and provide emulation support. The code created acts like all the files on the computer have been encrypted. The goal of this challenge? Get the program to print out the encrypted flag.`

Author: @pascal_0x90 (LLNL - Nate)
### Challenge

We're given a few files to work with here.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 14 - EmojiWare/dist$ ls -la
total 6500
drwxr-xr-x 2 kali kali    4096 Nov  2 15:22 .
drwx------ 4 kali kali    4096 Nov  9 11:21 ..
-rw-r--r-- 1 kali kali     161 Oct 29 07:52 Dockerfile
-rw-r--r-- 1 kali kali  658415 Oct 29 07:52 emojis.out
-rw-r--r-- 1 kali kali 5979208 Oct 29 07:52 emulator
-rw-r--r-- 1 kali kali     378 Nov  2 15:23 README.txt
```

The `README.txt` contained the description, so that's unimportant. The `emojis.out` is exactly what it sounds like, it's a lot of emojis.
```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 14 - EmojiWare/dist$ head emojis.out
👻😡🤖👻😓🤖👻😷🤖😖😡🙈😖😡🙈😖😡🙈😖😡👾😖😷🤖😭😡😷👻😡🤖👻😓🤖👻😷🤖😖😡🙈😖😡🙈😖😡🙈😖😡👾😖😷😍😭😡😷👻😡🤖👻😓🤖👻😷🤖😖😡[trim...]
```

The `emulator` is an ELF executable that seems like the point of interest here, but we'll come back to that shortly. 

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 14 - EmojiWare/dist$ file emulator
emulator: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b3a59e7c076b3b5dce5196ca64d323f0e0d84424, for GNU/Linux 2.6.32, stripped
```

The `Dockerfile` is an interesting addition, since `emulator` isn't built on some esoteric architecture. Reading it, we get an interesting clue.

```python
FROM ubuntu:18.04

RUN apt update && apt install -y gcc python3.8-dev

ADD ./emulator /emulator
ADD ./emojis.out /emojis.out
WORKDIR /

ENTRYPOINT ["/emulator"]
```

It doesn't make sense to explicitly include `python3.8-dev` without actual python unless (a) this is a distraction or (b) there's some Python-magic going on here. If we start running through our basic reversing checks, something immediately jumps out at us:

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 14 - EmojiWare/dist$ strings -n 8 emulator
[trim...]
blib-dynload/resource.cpython-38-x86_64-linux-gnu.so
blib-dynload/termios.cpython-38-x86_64-linux-gnu.so
blibbz2.so.1.0
blibcrypto.so.1.1
blibexpat.so.1
blibffi.so.6
bliblzma.so.5
blibmpdec.so.2
blibpython3.8.so.1.0
blibssl.so.1.1
blibz.so.1
opyi-contents-directory _internal
xbase_library.zip
zPYZ-00.pyz
4libpython3.8.so.1.0
.shstrtab
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.comment
```

### Solution
Notice the references to Python? Unless the author was trying to make it seem as if this was written with Python, there is very real likelihood that this binary was produced by using some library to compile Python to executable code. We can test this by pointing [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) at it.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 14 - EmojiWare/dist$ python3 pyinstxtractor.py emulator
[+] Processing emulator
[+] Pyinstaller version: 2.1+
[+] Python version: 3.8
[+] Length of package: 5923152 bytes
[+] Found 42 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: emulator.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.8 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: emulator

You can now use a python decompiler on the pyc files within the extracted directory
```

Our hypothesis was right, and we can now dig into the `emulator_extracted/` directory to find `emulator.pyc` which has the Python byte code in it (i.e. a compiled Python file, which is what the interpreter actually parses).

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 14 - EmojiWare/dist$ ls -la emulator_extracted/
total 11480
drwxr-xr-x 4 kali kali    4096 Nov  9 11:46 .
drwxr-xr-x 3 kali kali    4096 Nov  9 11:46 ..
-rw-r--r-- 1 kali kali  841682 Nov  9 11:46 base_library.zip
-rw-r--r-- 1 kali kali   11358 Nov  9 11:46 emulator.pyc
-rw-r--r-- 1 kali kali   66728 Nov  9 11:46 libbz2.so.1.0
-rw-r--r-- 1 kali kali 2917216 Nov  9 11:46 libcrypto.so.1.1
drwxr-xr-x 2 kali kali    4096 Nov  9 11:46 lib-dynload
-rw-r--r-- 1 kali kali  202880 Nov  9 11:46 libexpat.so.1
-rw-r--r-- 1 kali kali   31032 Nov  9 11:46 libffi.so.6
-rw-r--r-- 1 kali kali  153912 Nov  9 11:46 liblzma.so.5
-rw-r--r-- 1 kali kali  227944 Nov  9 11:46 libmpdec.so.2
-rw-r--r-- 1 kali kali 5477560 Nov  9 11:46 libpython3.8.so.1.0
-rw-r--r-- 1 kali kali  577312 Nov  9 11:46 libssl.so.1.1
-rw-r--r-- 1 kali kali  116960 Nov  9 11:46 libz.so.1
-rw-r--r-- 1 kali kali     875 Nov  9 11:46 pyiboot01_bootstrap.pyc
-rw-r--r-- 1 kali kali    3678 Nov  9 11:46 pyimod01_archive.pyc
-rw-r--r-- 1 kali kali   16926 Nov  9 11:46 pyimod02_importers.pyc
-rw-r--r-- 1 kali kali    4019 Nov  9 11:46 pyimod03_ctypes.pyc
-rw-r--r-- 1 kali kali     851 Nov  9 11:46 pyi_rth_inspect.pyc
-rw-r--r-- 1 kali kali    2425 Nov  9 11:46 pyi_rth_multiprocessing.pyc
-rw-r--r-- 1 kali kali    1158 Nov  9 11:46 pyi_rth_pkgutil.pyc
-rw-r--r-- 1 kali kali 1043281 Nov  9 11:46 PYZ-00.pyz
drwxr-xr-x 2 kali kali    4096 Nov  9 11:46 PYZ-00.pyz_extracted
-rw-r--r-- 1 kali kali     311 Nov  9 11:46 struct.pyc
```

I'm in the process of writing something on reversing Python malware, so I'll save an in-depth discussion of the topic for then, but `pycdc` is nice in that we can clone the repo, build the project, and just point the decompiler at the `.pyc` file. The build instructions aren't entirely clear from the repo, but you can just set up the Makefile using `cmake` and go from there.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies$ cd pycdc/
kali@transistor:~/Documents/cyberforce-23/anomalies/pycdc$ cmake -S .
-- The C compiler identification is GNU 13.1.0
-- The CXX compiler identification is GNU 13.1.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Found PythonInterp: /usr/bin/python (found version "3.11.4")
-- Configuring done (0.4s)
-- Generating done (0.0s)
-- Build files have been written to: /home/kali/Documents/cyberforce-23/anomalies/pycdc
kali@transistor:~/Documents/cyberforce-23/anomalies/pycdc$ make
[trim...]
```

I'll move the `emulator.pyc` out to a different directory, and then point `pycdc` at it to obtain the original source code.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/Z-2023 CFC Dependency Files/Anomaly 14 - EmojiWare/dist$ ../../../pycdc/pycdc emulator.pyc
# Source Generated with Decompyle++
# File: emulator.pyc (Python 3.8)

Unsupported opcode: BEGIN_FINALLY
from io import TextIOWrapper
from sys import stdout, stdin, exit
from math import ceil
from time import sleep
from copy import deepcopy
from enum import Enum, auto
from dataclasses import dataclass
from multiprocessing.dummy import Process
from typing import Dict, Tuple

class ISA(Enum):
    IMM = auto()
    ADD = auto()
[trim...]
```

We get a couple of warnings, but it seems like we get most of the source code, which we can put in a separate `.py` file for easier viewing. The file itself comes out to be ~400 lines, so I might put it in a gist or on GitHub later, so we'll only be looking at the most relevant segments.

We've solved a challenge similar in concept to this before here, HTB's [Alien Saboteur](https://notateamserver.xyz/ca23-alien-saboteur/) challenge was a nice introduction to VM reversing challenges, and I highly recommend you check that out if you're unfamiliar with the idea. Luckily for us here, the emulator is written in Python, so more of the work is on parsing the `emojis.out` than actually reversing the VM. Lines 36 - 72 give us what each of the emojis mean.

```python
VMCODE = {
    '🈳': ISA.NOP,
    '➕': ISA.ADD,
    '😖': ISA.ADDI,
    '➖': ISA.SUB,
    '✨': ISA.SUBI,
    '❌': ISA.MULT,
    '⏬': ISA.PUSH,
    '🔝': ISA.POP,
    '😄': ISA.LDM,
    '😭': ISA.STM,
    '💯': ISA.CMP,
    '🚀': ISA.JMP,
    '🌮': ISA.JMPN,
    '💀': ISA.SYS,
    '👻': ISA.IMM,
    '🥑': ISA.XOR }
VMDATA = {
    '🤖': 0,
    '😍': 1,
    '💢': 2,
    '🤙': 3,
    '😩': 4,
    '👾': 5,
    '🤢': 6,
    '😿': 7,
    '💙': 8,
    '🙉': 9,
    '🙈': 10 }
REGS = {
    '🤡': 'SP',
    '🦷': 'IP',
    '😡': 'A',
    '😓': 'B',
    '😷': 'C',
    '🤥': 'D',
    '😿': 'F' }
```

The emulator, as expected, tells us exactly how to interpret these opcodes in the `interp_instr()` function.

```python
def parse_instr(self = None, instr = None):
	opcode = instr[self.order[0]]
	arg1 = instr[self.order[1]]
	arg2 = instr[self.order[2]]
	return (opcode, arg1, arg2)
# ...trim...
def interp_instr(self, instr):
	(opcode, arg1, arg2) = self.parse_instr(instr)
	op = VMCODE[opcode]
	if op == ISA.NOP:
		temp = 3
		temp2 = 2 + temp
		temp3 = temp + temp2
		del temp3
		del temp2
		return None
	if None == ISA.ADD:
		(r1name, reg1val) = self.get_register_value(arg1)
		(_, reg2val) = self.get_register_value(arg2)
		val = reg1val + reg2val
		calculated = val
		self.set_register_value(r1name, calculated)
		return None
	if None == ISA.ADDI:
		(r1name, reg1val) = self.get_register_value(arg1)
		imm = VMDATA[arg2]
		val = reg1val + imm
		calculated = val
		self.set_register_value(r1name, calculated)
		return None
	# trim...
```

An interesting thing to note is the `Processor()` class that this is all coming from seems to have code to debug the registers.

```python
def print_regs(self):
	regs = f'''\n======\nSP: {self._REGISTERS.SP}\nIP: {(self._REGISTERS.IP - 2048) / 3}\n======\nA: {self._REGISTERS.A}\nB: {self._REGISTERS.B}\nC: {self._REGISTERS.C}\nD: {self._REGISTERS.D}\n======\nF: {self._REGISTERS.F}\n======\nSTACK (first 10 values from SP):\n{self._MEM[max(0, (self._REGISTERS.SP - 10) + 1):self._REGISTERS.SP + 1]}\n======\n        '''
	print(regs)


def load_code(self, exec_code):
	'''
	MEM:
	code
	stack
	data_stored
	'''
	code = deepcopy(exec_code)
	MAX_SIZE = roundup(len(code) + 2048)
	self._MEM = [
		''] * MAX_SIZE
	for i in range(len(code)):
		self._MEM[i + 2048] = code[i]
	stats = f'''\n        CODE LENGTH: {len(code)}\n        MEM  LENGTH: {len(self._MEM)}\n        '''
	print(stats)


def init_registers(self = None):
	if self._REGISTERS is not None:
		print('Overriding a current state!')
		s = input('Continue? [yY/nN]')
		if 'n' in s.lower():
			return -1
		self._REGISTERS = None(0, 2048, 0, 0, 0, 0, 0)
		return 0
```

However, it seems like these functions don't get used in the actual execution of the program when we try to run the emulator (which I totally forgot to check until now).

```shell
$ ./emulator

        CODE LENGTH: 164622
        MEM  LENGTH: 166912

################################################
# YOUR COMPUTER HAS BEEN FULLY ENCRYPTED!!!!   #
#    IN ORDER TO GET YOUR FILES BACK           #
#    YOU MUST ENTER IN THE SECRET KEY          #
#    THAT WE SEND YOU IN EXCHANGE FOR          #
#    DOGECOIN.                                 #
################################################

ENTER IN THE SECRET KEY:PASSWORD
YOU HAVE ENTERED AN INCORRECT KEY! KILLING DECRYPTOR!
```

From here, there's a couple of different ways to go about this:
1. Write a disassembler like we did for Alien Saboteur
2. Clean up the `emulator.py` we got from `pycdc` and use that to debug the registers
3. Debug `emulator` with GDB and find the right things to breakpoint on

The third is definitely the worst way to go about this, since it's still using Python bytecode in the ELF, so we're not only debugging the emoji VM, but also the underlying Python VM used to make the emulator. As for the other two options, I actually originally tried to do option 1, but when I did, I got 54873 instructions. For reference, the other VM challenge I did only had < 1000. For sanity's sake (although the brain worms want me to look at the assembly), we're reconstructing the emulator.

As good as `pycdc` is, it did not give us a perfect decompile. For one, there's various `continue` statements strewn across the program in weird spots, and I also have ambiguous things happening:

```python
REGISTERS = dataclass(<NODE:12>)
FILE = dataclass(<NODE:12>)
```

Part of the reason Python bytecode reversing is so funky is that with every new release of Python, the way control flow works is *slightly* different. `pycdc`'s merits come from the fact it's written in C++ and generally does not care for the version up until the more recent ones. However, it seems as though we might need to use a Python tool instead, and I used [decompyle3](https://github.com/rocky/python-decompile3), because `pycdc` told us the version was 3.8, and that's what `decompyle3` was made for.

In order to use `decompyle3`, you'll need an install of Python 3.8. The easiest solution would probably be using [pyenv](https://github.com/pyenv/pyenv) to manage the versions you have installed, but I used Docker. I pulled down the Python 3.8.5 Docker container, mounted my current directory using a volume, and then entered the container. 

> Note, when using volumes, make sure your path has no weird characters in it or spaces, you'll get an error like [this](https://stackoverflow.com/questions/48522615/docker-error-invalid-reference-format-repository-name-must-be-lowercase) and be confused until you remember why!

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist/better$ docker run --rm -it -v $(pwd):/data -d python:3.8.5
Unable to find image 'python:3.8.5' locally
3.8.5: Pulling from library/python
57df1a1f1ad8: Pull complete
71e126169501: Pull complete
1af28a55c3f3: Pull complete
03f1c9932170: Pull complete
65b3db15f518: Pull complete
3e3b8947ed83: Pull complete
a4850b8bdbb7: Pull complete
416533994968: Pull complete
1b580f9ce4ce: Pull complete
Digest: sha256:e9b7e3b4e9569808066c5901b8a9ad315a9f14ae8d3949ece22ae339fff2cad0
Status: Downloaded newer image for python:3.8.5
eecf03d12646e7f2835d8fc05277ca368767deeddcebfe2b1446576881ef350f
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist/better$ docker ps
CONTAINER ID   IMAGE          COMMAND     CREATED              STATUS              PORTS     NAMES
eecf03d12646   python:3.8.5   "python3"   About a minute ago   Up About a minute             fervent_kirch
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist/better$ docker exec -it eecf03d12646 /bin/bash
root@eecf03d12646:/# cd /data
root@eecf03d12646:/data# ls -la
total 20
drwxr-xr-x 2 1000 1000  4096 Nov 12 03:18 .
drwxr-xr-x 1 root root  4096 Nov 12 03:21 ..
-rw-r--r-- 1 1000 1000 11358 Nov 12 00:36 emulator.pyc
root@eecf03d12646:/data# pip install decompyle3
root@eecf03d12646:/data# decompyle3 emulator.pyc > emulator.py
root@eecf03d12646:/data# exit
exit
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist/better$ docker stop eecf03d12646
eecf03d12646
```

This `emulator.py` is already *way* better if you look at the source code. Let's try running it and see what happens to make sure it works.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ python3 emulator.py

        CODE LENGTH: 164622
        MEM  LENGTH: 166912

Traceback (most recent call last):
  File "/home/kali/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist/emulator.py", line 496, in <module>
    p.execvm()
  File "/home/kali/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist/emulator.py", line 140, in execvm
    self.interp_instr(instr=instr)
  File "/home/kali/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist/emulator.py", line 224, in interp_instr
    r1name, reg1val = self.get_register_value(arg1)
    ^^^^^^^^^^^^^^^
TypeError: cannot unpack non-iterable NoneType object
```

Ah. Very cool! This part took a minute to figure out, but the problem function is here:
```python
REGS_INV = {k: v for k, v in REGS.items()}
# ...trim...
def get_register_value(self, reg) -> Tuple[(str, int)]:
	try:
		emoji = REGS_INV[reg]
	except:
		emoji = reg
	else:
		if emoji == '🤡':
			return ('SP', self._REGISTERS.SP)
		if emoji == '🦷':
			return ('IP', self._REGISTERS.IP)
		if emoji == '😡':
			return ('A', self._REGISTERS.A)
		if emoji == '😓':
			return ('B', self._REGISTERS.B)
		if emoji == '😷':
			return ('C', self._REGISTERS.C)
		if emoji == '🤥':
			return ('D', self._REGISTERS.D)
		if emoji == '😿':
			return ('F', self._REGISTERS.F)
```

The problem is that the `REGS_INV` dictionary doesn't actually invert the keys and values, and the `else` statement here isn't really necessary. We can fix that pretty quickly though:
```python
REGS_INV = {v: k for k, v in REGS.items()}
# ...trim...
def get_register_value(self, reg) -> Tuple[(str, int)]:
	try:
		emoji = REGS_INV[reg]
	except:
		emoji = reg

	if emoji == '🤡':
		return ('SP', self._REGISTERS.SP)
	if emoji == '🦷':
		return ('IP', self._REGISTERS.IP)
	if emoji == '😡':
		return ('A', self._REGISTERS.A)
	if emoji == '😓':
		return ('B', self._REGISTERS.B)
	if emoji == '😷':
		return ('C', self._REGISTERS.C)
	if emoji == '🤥':
		return ('D', self._REGISTERS.D)
	if emoji == '😿':
		return ('F', self._REGISTERS.F)
```

If we try it again, we can safely say we've restored the emulator!

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ python3 emulator.py

        CODE LENGTH: 164622
        MEM  LENGTH: 166912

################################################
# YOUR COMPUTER HAS BEEN FULLY ENCRYPTED!!!!   #
#    IN ORDER TO GET YOUR FILES BACK           #
#    YOU MUST ENTER IN THE SECRET KEY          #
#    THAT WE SEND YOU IN EXCHANGE FOR          #
#    DOGECOIN.                                 #
################################################

ENTER IN THE SECRET KEY:password
YOU HAVE ENTERED AN INCORRECT KEY! KILLING DECRYPTOR!
```

So what's changed? Now that we have the Python source code, we can change things how ever we want! In particular, we can change the code that interprets instructions to print out exactly what's happening. Since this is a crackme, we can start by checking any uses of the `CMP` instruction.

```python
# ...trim
	if op == ISA.CMP:
		_, reg1val = self.get_register_value(arg1)
		_, reg2val = self.get_register_value(arg2)
		# NEW
		print(f"[DEBUG] {reg1val} == {reg2val}")
		self._REGISTERS.F = 0
		if reg1val == reg2val:
			self._REGISTERS.F |= 1
		if reg1val > reg2val:
			self._REGISTERS.F |= 2
		if reg1val < reg2val:
			self._REGISTERS.F |= 4
		if reg1val != reg2val:
			self._REGISTERS.F |= 8
		return
# trim...
```

If we try running the program now, we get a debug statement.
```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ python3 emulator.py

        CODE LENGTH: 164622
        MEM  LENGTH: 166912

################################################
# YOUR COMPUTER HAS BEEN FULLY ENCRYPTED!!!!   #
#    IN ORDER TO GET YOUR FILES BACK           #
#    YOU MUST ENTER IN THE SECRET KEY          #
#    THAT WE SEND YOU IN EXCHANGE FOR          #
#    DOGECOIN.                                 #
################################################

ENTER IN THE SECRET KEY:password
[DEBUG] 69 == 119
YOU HAVE ENTERED AN INCORRECT KEY! KILLING DECRYPTOR!
```

There are two things to be gleaned from this:
1. Despite submitting an 8 character entry, we only had one comparison. This could either be because of a length check, or it is checking one byte at a time and exiting if it's wrong.
2. 69 (nice) and 119 are both decimal values, neither of which correspond to the first character. 119 could be the "w" in the middle of the password but that's just weird.

If we make a hypothesis and assume that there's some encryption going on, we could try to hook the XOR opcode as well and see what happens.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ python3 emulator.py

        CODE LENGTH: 164622
        MEM  LENGTH: 166912

################################################
# YOUR COMPUTER HAS BEEN FULLY ENCRYPTED!!!!   #
#    IN ORDER TO GET YOUR FILES BACK           #
#    YOU MUST ENTER IN THE SECRET KEY          #
#    THAT WE SEND YOU IN EXCHANGE FOR          #
#    DOGECOIN.                                 #
################################################

ENTER IN THE SECRET KEY:password
[DEBUG]: A <-- 69 = 0 ^ 69
[DEBUG]: A <-- 12 = 0 ^ 12
[DEBUG]: A <-- 69 = 0 ^ 69
[DEBUG]: A <-- 12 = 0 ^ 12
[DEBUG]: A <-- 69 = 0 ^ 69
[DEBUG]: A <-- 12 = 0 ^ 12
[trim...]
```

Turns out there's a lot of XORs, ~100 to be exact. We also see that there's an alternating pattern of XORs with 69 then 12, which we can only assume to be the key (remember that this is decimal!). I'll use the `cyclic` tool from pwntools to generate a string of 100 characters to see if I can pass the length check.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ python3 emulator.py

        CODE LENGTH: 164622
        MEM  LENGTH: 166912

################################################
# YOUR COMPUTER HAS BEEN FULLY ENCRYPTED!!!!   #
#    IN ORDER TO GET YOUR FILES BACK           #
#    YOU MUST ENTER IN THE SECRET KEY          #
#    THAT WE SEND YOU IN EXCHANGE FOR          #
#    DOGECOIN.                                 #
################################################

ENTER IN THE SECRET KEY:aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
[DEBUG]: A <-- 36 = 97 ^ 69
[DEBUG]: A <-- 109 = 97 ^ 12
[DEBUG]: A <-- 36 = 97 ^ 69
[DEBUG]: A <-- 109 = 97 ^ 12
[DEBUG]: A <-- 39 = 98 ^ 69
[DEBUG]: A <-- 109 = 97 ^ 12
[DEBUG]: A <-- 36 = 97 ^ 69
[DEBUG]: A <-- 109 = 97 ^ 12
[DEBUG]: A <-- 38 = 99 ^ 69
[DEBUG]: A <-- 109 = 97 ^ 12
[trim...]
[DEBUG] 36 == 119
YOU HAVE ENTERED AN INCORRECT KEY! KILLING DECRYPTOR!
```

It still didn't give us additional CMP checks, but at least we can confirm that the XORs are being applied to the password. At this point, you could write a pwntools script to bruteforce the password, or we could try to "dump the memory" at the password check. I can modify the `execvm()` function as follows:

```python
def execvm(self):
	self.init_registers()
	self._REGISTERS.IP = 2048
	while self._REGISTERS.IP >= 2048:
		while self._REGISTERS.IP <= len(self._MEM):
			try:
				instr = self._MEM[self._REGISTERS.IP:self._REGISTERS.IP + 3]
				self.interp_instr(instr=instr)
			except KeyboardInterrupt:
				#self.print_regs()
				print(self._MEM[:2048])
				input()

			self._REGISTERS.IP += 3
```

Now, when I hit CTRL+C at the password prompt, I see this.
```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ python3 emulator.py

        CODE LENGTH: 164622
        MEM  LENGTH: 166912

################################################
# YOUR COMPUTER HAS BEEN FULLY ENCRYPTED!!!!   #
#    IN ORDER TO GET YOUR FILES BACK           #
#    YOU MUST ENTER IN THE SECRET KEY          #
#    THAT WE SEND YOU IN EXCHANGE FOR          #
#    DOGECOIN.                                 #
################################################

ENTER IN THE SECRET KEY:^C['', 0, '', [...trim...] '', '', '', '', '', 119, 60, 33, 60, 113, 58, 38, 57, 125, 105, 114, 61, 119, 61, 115, 56, 32, 106, 116, 109, 32, 62, 35, 53, 36, 52, 118, 56, 113, 109, 118, 105, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
```

Interestingly, this is only ~32 bytes. Still, we can pull these numbers out, apply the XOR key, and see what the plaintext is.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ python3
Python 3.11.4 (main, Jun  7 2023, 10:13:09) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> ct = bytearray([119, 60, 33, 60, 113, 58, 38, 57, 125, 105, 114, 61, 119, 61, 115, 56, 32, 106, 116, 109, 32, 62, 35, 53, 36, 52, 118, 56, 113, 109, 118, 105])
KeyboardInterrupt
>>> from pwn import xor # this is just easy
>>> ct = bytearray([119, 60, 33, 60, 113, 58, 38, 57, 125, 105, 114, 61, 119, 61, 115, 56, 32, 106, 116, 109, 32, 62, 35, 53, 36, 52, 118, 56, 113, 109, 118, 105])
>>> key = bytes.fromhex('450c')
>>> xor(ct, key)
b'20d046c58e712164ef1ae2f9a8344a3e'
```

If I copy this result three times into the password prompt 4 times (to reach the 100 characters), we get the flag.

```shell
kali@transistor:~/Documents/cyberforce-23/anomalies/2023-CFC-Dependencies/A14-Emojiware/dist$ python3 emulator.py

        CODE LENGTH: 164622
        MEM  LENGTH: 166912

################################################
# YOUR COMPUTER HAS BEEN FULLY ENCRYPTED!!!!   #
#    IN ORDER TO GET YOUR FILES BACK           #
#    YOU MUST ENTER IN THE SECRET KEY          #
#    THAT WE SEND YOU IN EXCHANGE FOR          #
#    DOGECOIN.                                 #
################################################

ENTER IN THE SECRET KEY:20d046c58e712164ef1ae2f9a8344a3e20d046c58e712164ef1ae2f9a8344a3e20d046c58e712164ef1ae2f9a8344a3e20d046c58e712164ef1ae2f9a8344a3e
Congrats! Here is the flag:
flag{3m0j1s_L1ght_Up_My_D4y}
```

**flag**: `flag{3m0j1s_L1ght_Up_My_D4y}`
## WATT's The Story Morning Glory?
> Anomaly 44 - 47
### Description
`You are a seasoned QA Engineer at DER8.9 testing a new system named the 'SmartMeter Workstation for Administration of Telemetric Technologies (WATT) Control and Maintenance Interface' prior to deployment for business customers and residential field technicians. Before this software goes live, it's crucial to ensure that it is not only free from defects but also securely designed and implemented. Thoroughly test the application and identify all functional and security issues, spotting any vulnerabilities and insecure code practices. Retrieve a set of 4 associated flags for each insecure coding practice / vulnerability as a proof of discovery.`

Author: @ANL - Jocelyn

> To any Cyberforce competitor, I sincerely apologize for the existence of this challenge. I am friends with the challenge author outside of this event and I am the one who mentioned Nim when that was hot (before I realized writing C, or even better, PIC shellcode, was God's way).
### Solution 1: Hardcoded Key
We're given a file called `smartmeter_management_interface.exe`, some additional information in `Question.md` that just adds some context that isn't necessarily worth mentioning here. If I run the binary, we're immediately hit with roadblock #1.

![Pasted image 20231109001048.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231109001048.png)

Ah, a crackme. Of course.

Before jumping to disassembling the binary, let's briefly take a look at what PEStudio tells us. There are no immediately weird looking imports (e.g. `CreateRemoteThread`, `Nt*`), but as soon as we look at strings, we know what were up against.

![Pasted image 20231109001529.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231109001529.png)

If it isn't my old enemy Nim. For the uninitiated, [Nim](https://nim-lang.org/) is a language that was very hyped up last year in the red teaming space as something extremely evasive and hard to reverse engineer, while also embracing Python-like simplicity in syntax, yet supporting memory management and macros like languages like Rust or C++ do. An in-depth discussion of the merits of using Nim and other esolangs for malware development is beyond the scope of this blog, but the key factor we'll be dealing with is the reverse engineering bit. 

Nim compiles to C, and then uses a compiler for C to finish it off, meaning symbols and functions get seriously garbled. It's still very possible to work through it, it's just a pain. For languages like Nim, I prefer using [Cutter](https://github.com/rizinorg/cutter) over Ghidra. Once the binary is loaded into Cutter, we can start by looking for the main function. If we use the side bar to search for `main`, we're greeted with 6 different "mains".

![Pasted image 20231109002523.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231109002523.png)

For the purposes of reverse engineering, we can usually jump right to `NimMainModule`. Keeping the window open in graph view, we have a little bit of noise from what Nim does at an assembly level, but we can stay focused if we just look for calls to other symbols that look like functions. Eventually, we should find `main__smartmeter95management95interface_528`, which is where we can actually see assembly that corresponds to what we saw with the execution. Let's zoom into the first block of assembly here:

```c
0x140038213      push    rbp
0x140038214      mov     rbp, rsp
0x140038217      sub     rsp, 0x190
0x14003821e      lea     rax, str.main ; 0x14004ae07
0x140038225      mov     qword [var_50h], rax
0x140038229      lea     rax, str.C:_Cyberforce_November_2023_smartmeter_management_interface.nim ; 0x14004ab90
0x140038230      mov     qword [var_40h], rax
0x140038234      mov     qword [var_48h], 0
0x14003823c      mov     word [var_38h], 0
0x140038242      lea     rax, [var_58h]
0x140038246      mov     rcx, rax  ; int64_t arg1
0x140038249      call    nimFrame  ; sym.nimFrame_0x14003346b
0x14003824e      call    getFrame  ; sym.getFrame_0x140036e8e
0x140038253      mov     qword [var_10h], rax
0x140038257      mov     qword [var_48h], 0x125 ; 293
0x14003825f      lea     rax, str.C:_Cyberforce_November_2023_smartmeter_management_interface.nim ; 0x14004ab90
0x140038266      mov     qword [var_40h], rax
0x14003826a      call    mainBanner__smartmeter95management95interface_126 ; sym.mainBanner__smartmeter95management95interface_126
0x14003826f      mov     qword [var_48h], 0x126 ; 294
0x140038277      lea     rax, str.C:_Cyberforce_November_2023_smartmeter_management_interface.nim ; 0x14004ab90
0x14003827e      mov     qword [var_40h], rax
0x140038282      mov     edx, 1    ; int64_t arg2
0x140038287      lea     rax, data.140048e38 ; 0x140048e38
0x14003828e      mov     rcx, rax  ; int64_t arg1
0x140038291      call    echoBinSafe ; sym.echoBinSafe
0x140038296      mov     qword [var_48h], 0x129 ; 297
0x14003829e      lea     rax, str.C:_Cyberforce_November_2023_smartmeter_management_interface.nim ; 0x14004ab90
0x1400382a5      mov     qword [var_40h], rax
0x1400382a9      mov     byte [var_19h], 0
0x1400382ad      call    accessMaintenanceInterface__smartmeter95management95interface_245 ; sym.accessMaintenanceInterface__smartmeter95management95interface_245
0x1400382b2      mov     byte [var_19h], al
0x1400382b5      cmp     byte [var_19h], 0
0x1400382b9      jne     0x140038317
```

If you've been following along, or you see this mess, you begin to understand why looking at Nim can be challenging- there's just a lot of stuff that you don't need to be looking at 90% of the time. However, at `0x14003826a`, we see a call to what looks like the function that prints the main banner. At `0x1400382ad`, we have another call, this time to the `accessMaintenanceInterface()` function. Looking at that function, this bit of assembly jumps out at me.

```c
0x14003444a      mov     qword [var_70h], rax
0x14003444e      mov     qword [var_20h], 0
0x140034456      mov     qword [var_28h], 0
0x14003445e      lea     rax, data.140048f80 ; 0x140048f80
0x140034465      mov     rcx, rax  ; int64_t arg1
0x140034468      call    decodeBase64__smartmeter95management95interface_89 ; sym.decodeBase64__smartmeter95management95interface_89
0x14003446d      mov     qword [var_28h], rax
0x140034471      mov     qword [var_30h], 0
0x140034479      lea     rax, data.140048fc0 ; 0x140048fc0
0x140034480      mov     rcx, rax  ; int64_t arg1
0x140034483      call    decodeBase64__smartmeter95management95interface_89 ; sym.decodeBase64__smartmeter95management95interface_89
0x140034488      mov     qword [var_30h], rax
0x14003448c      cmp     qword [var_28h], 0
0x140034491      je      0x14003449c
```

I don't know the exact calling convention at play here, but if I had to guess, those `data.1400...` addresses are being passed into the `decodeBase64()` function. Following those, we get two base64 strings: `Y2VhZTA5YzM5YTRiMjczOQ==` and `ZDVlMDMwODBmNDI2YzkyMA==`. We can decode them to get the values `ceae09c39a4b2739` and `d5e03080f426c920`, respectively. Concatenating these and decoding as hex gives random bytes, so we're still not entirely sure how this gets used. Later on in this function, however, we see the following:

```c
0x14003457c      call    readLine__systemZio_364 ; sym.readLine__systemZio_364
0x140034581      mov     qword [var_48h], rax
0x140034585      mov     qword [var_78h], 0x86 ; 134
0x14003458d      lea     rax, str.C:_Cyberforce_November_2023_smartmeter_management_interface.nim ; 0x14004ab90
0x140034594      mov     qword [var_70h], rax
0x140034598      mov     rax, qword [var_48h]
0x14003459c      mov     rcx, rax  ; int64_t arg1
0x14003459f      call    getMD5__OOZ85sersZmurraZOnimbleZpkgs50Zchecksums4548O49O48455352525551dcb50db5649cc5154fc54ac5154ab5453df48e4957525251534948Zch ; sym.getMD5__OOZ85sersZmurraZOnimbleZpkgs50Zchecksums4548O49O48455352525551dcb50db5649cc5154fc54ac5154ab5453df48e4957525251534948Zch
0x1400345a4      mov     qword [var_50h], rax
0x1400345a8      mov     qword [var_78h], 0x87 ; 135
0x1400345b0      lea     rax, str.C:_Cyberforce_November_2023_smartmeter_management_interface.nim ; 0x14004ab90
0x1400345b7      mov     qword [var_70h], rax
0x1400345bb      mov     rdx, qword [var_38h] ; int64_t arg2
0x1400345bf      mov     rax, qword [var_50h]
0x1400345c3      mov     rcx, rax  ; int64_t arg1
0x1400345c6      call    eqStrings ; sym.eqStrings_0x14003428e
```

That `getMD5` suggests that the user's input is actually being compared via hashing, so one might guess that the base64 strings encode the hash. We can try both ways, and using Crackstation, we eventually find that `ceae09c39a4b2739d5e03080f426c920` corresponds to `neverhere`.

We can try this in the terminal and see that it works.
```shell
PS C:\Users\sreisz\Desktop\wattsup> .\smartmeter.exe

------------------------------------------------------------
DER8.9 SmartMeter Workstation for Administration of Telemetric Technologies (WATT)
------------------------------------------------------------


------------------------------------------------------------
             Control and Maintenance Interface
------------------------------------------------------------

                       @    @
                      @    @
                     @    @/ .@
                    #       @
                    @@* @ @
                       @ @
                      @@
                     @&
                    @


Welcome to DER8.9s SmartMeter WATT Maintenance Interface.
Please enter the maintenance token and select an option from the menu.

Enter maintenance token:
neverhere

Accepted Maintenance Token... Access Granted!


DER8.9 SmartMeter WATT Control and Maintenance Interface

------------------------------------------------------------
                        MENU OPTIONS
------------------------------------------------------------

1. Display current reading
2. Display historical readings
3. Add Configuration
4. Delete Configuration
5. Update Configuration
6. Display Configuration
7. Process Configuration
8. Access meter logs
9. Display meter firmware version
10. Export Configurations as JSON
11. Import Configurations from JSON
12. Restore Configurations
13. Exit

Enter your choice:
```

**flag**: `neverhere`
### Solution 2: Data Deletion
Finding the other flags is a little bit of a challenge, as we don't really have direction for what to do other than look for vulnerabilities. However, we can do a little bit of metagaming and look for interesting strings, and we find the following.

![Pasted image 20231111225615.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231111225615.png)

Since I am privy to the order of the flags, we'll start with the "insecure data deletion". First, let's try to look at this in the program. We have a few options related to configuration management:
- (3) Add Configuration
- (4) Delete Configuration
- (5) Update Configuration
- (6) Display Configuration
- (7) Process Configuration
- (12) Restore Configurations

If we display configurations, we see what's already loaded.
```shell
------------------------------------------------------------
                   CONFIGURATION DISPLAY
------------------------------------------------------------

ID: 999 Data: 5,7,0,2,24,7,14,16,5,14,16,19,2,23,6,8,19


DER8.9 SmartMeter WATT Control and Maintenance Interface
```

Let's try to delete it and see what happens.
```shell
Enter your choice:
4

------------------------------------------------------------
                    DELETE CONFIGURATION
------------------------------------------------------------

Enter maintenance token:
neverhere

Enter configuration ID to delete:
999

DER8.9 SmartMeter WATT Control and Maintenance Interface

------------------------------------------------------------
                        MENU OPTIONS
------------------------------------------------------------

[...trim...]

Enter your choice:
6

------------------------------------------------------------
                   CONFIGURATION DISPLAY
------------------------------------------------------------

ID: 999 Data: DELETED

DER8.9 SmartMeter WATT Control and Maintenance Interface
```

Well that was easy. Based on the string we found, let's try to restore it.

```shell
Enter your choice:
12

------------------------------------------------------------
                   RESTORE CONFIGURATION
------------------------------------------------------------


Enter maintenance token:
neverhere
Configurations restored!


DER8.9 SmartMeter WATT Control and Maintenance Interface

------------------------------------------------------------
                        MENU OPTIONS
------------------------------------------------------------

[...trim...]

Enter your choice:
6

------------------------------------------------------------
                   CONFIGURATION DISPLAY
------------------------------------------------------------

ID: 999 Data: RESTORED DELETED DATA || INSECURE DATA DELETION FLAG #2: DONT-LOOK-BACK-AT-DELETED-DATA-I-HEARD-YOU-SAY


DER8.9 SmartMeter WATT Control and Maintenance Interface
```

Well that was even easier. Moral of the story, when data gets deleted, make sure it actually gets deleted and wiped from memory. We could dig into why this is happening by looking at the assembly, but this post is long enough as is and we have two more to get through. I might make a follow up post later to dive even deeper, but I'll be honest, I'm too tired to dig into this right now. 

**flag**: `DONT-LOOK-BACK-AT-DELETED-DATA-I-HEARD-YOU-SAY`
### Solution 3: JSON Deserialization
Another one of the strings had to do with deserialization, and we have two options that would be related to this.

- (10) Export Configurations as JSON
- (11) Import Configurations as JSON

If we try to call (10), we get this:
```shell
Enter your choice:
10

------------------------------------------------------------
                    EXPORT CONFIGURATION
------------------------------------------------------------

[{"id":999,"data":"5,7,0,2,24,7,14,16,5,14,16,19,2,23,6,8,19"}]

DER8.9 SmartMeter WATT Control and Maintenance Interface
```

It seems like we also have the option to submit our own data. I can submit a made up configuration and it seems like it goes through no problem.

```shell
Enter your choice:
11

Provide JSON data for configurations:
[{"id":123,"data":"1,1,1,1,1"}]

[...trim...]

Enter your choice:
10

------------------------------------------------------------
                    EXPORT CONFIGURATION
------------------------------------------------------------

[{"id":999,"data":"5,7,0,2,24,7,14,16,5,14,16,19,2,23,6,8,19"},{"id":123,"data":"1,1,1,1,1"}]
```

Looks like we can't submit arbitrary keys and values though:

```shell
Enter your choice:
11

Provide JSON data for configurations:
[{"fakeKey":"fakeValue"}]

------------------------------------------------------------
                    IMPORT CONFIGURATION
------------------------------------------------------------

C:\Cyberforce-November-2023\smartmeter_management_interface.nim(341) smartmeter_management_interface
C:\Cyberforce-November-2023\smartmeter_management_interface.nim(331) main
C:\Cyberforce-November-2023\smartmeter_management_interface.nim(261) importConfigurations
C:\msys64\mingw64\lib\nim\pure\json.nim(517) []
C:\msys64\mingw64\lib\nim\pure\collections\tables.nim(246) []
C:\msys64\mingw64\lib\nim\pure\collections\tables.nim(234) raiseKeyError
Error: unhandled exception: key not found: id [KeyError]
```

If that's the case, it seems like we need to find what the possible keys are. We have a couple of functions to look at as far as the Nim code goes: `exportConfigurations()`, `importConfigurations()`, `processConfiguration()`, `updateConfiguration()`. After a long winded journey of exploring the various functions, first `updateConfiguration()` then `importConfigurations()`, we find the following assembly.

```c
0x140037332      lea     rdx, data.14004a2a0 ; 0x14004a2a0 ; int64_t arg2
0x140037339      mov     rcx, rax  ; int64_t arg1
0x14003733c      call    hasKey__pureZjson_3212 ; sym.hasKey__pureZjson_3212
0x140037341      mov     byte [var_29h], al
0x140037344      movzx   eax, byte [var_29h]
0x140037348      xor     eax, 1
0x14003734b      test    al, al
0x14003734d      jne     0x140037384
0x14003734f      mov     qword [var_78h], 0
0x140037357      mov     rax, qword [var_48h]
0x14003735b      lea     rdx, data.14004a2a0 ; 0x14004a2a0 ; int64_t arg2
0x140037362      mov     rcx, rax  ; int64_t arg1
0x140037365      call    X5BX5D___pureZjson_3095 ; sym.X5BX5D___pureZjson_3095
0x14003736a      mov     qword [var_78h], rax
0x14003736e      mov     rax, qword [var_78h]
0x140037372      mov     edx, 0    ; int64_t arg2
0x140037377      mov     rcx, rax  ; int64_t arg1
0x14003737a      call    getBool__pureZjson_189 ; sym.getBool__pureZjson_189
0x14003737f      mov     byte [var_29h], al
0x140037382      jmp     0x140037385
0x140037384      nop
0x140037385      movzx   eax, byte [var_29h]
```

That `hasKey__pureZjson_3212` is particularly interesting, considering there's something going on with `data.14004a2a0` before it. If I follow that variable, the nearest string in Cutter is `isAdmin`, which absolutely looks like a key. We can also see a later call to `getBool`, which may imply the data type to go with the `isAdmin` key is a boolean. All together, we can try injecting some JSON.

```
Enter your choice:
11

Provide JSON data for configurations:
[{"isAdmin":true}]

------------------------------------------------------------
                    IMPORT CONFIGURATION
------------------------------------------------------------

ADMIN ACCESS GRANTED || INSECURE DESERIALIZATION FLAG #4: WOO-HOO-AND-IM-INSECURE-WITH-DESERIALIZATION


DER8.9 SmartMeter WATT Control and Maintenance Interface
```

Despite the fact that we're not using something like [ysoserial](https://github.com/frohoff/ysoserial) to get RCE, this is still deserialization! The JSON gets loaded into the program as some kind of dictionary structure, which is how it's checking for keys. Since there's no checks on what we can submit, that malicious config gets evaluated and injects the admin condition.

**flag**: `WOO-HOO-AND-IM-INSECURE-WITH-DESERIALIZATION`
### Solution 4: IDOR
Out last challenge has to do with an insecure direct object reference. We can use the success string to find exactly the code block we want to get to. One thing I learned while solving this is that you can't directly check for X-Refs from the string, you want to scroll up (at least in Cutter) for the `data.XXXXXXX` reference and use that.

![Pasted image 20231112100625.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231112100625.png)

We're inside the `processConfiguration()` function, and the control flow graph is a little bit more complicated than we might want to look at statically. Let's take a look at what "processing" a configuration does.

```shell
Enter your choice:
7

------------------------------------------------------------
                   PROCESS CONFIGURATIONS
------------------------------------------------------------


Processed Configuration (Not a flag... sadly): USZXBSLJULJGXCTRG

(Hint: do you think the developers took out any backdoors for debug access?)


DER8.9 SmartMeter WATT Control and Maintenance Interface
```

While attempting to solve this one, I actually ended up reverse engineering the entire algorithm to go from configuration to processed string. It didn't help at all, but you can see from when we looked at the default configuration, the indices are all less than 26, and the resulting string is entirely alphabetic. If you look at the strings, you find the string `ZYXWVUTSRQPONMLKJIHGFEDCBA-123456#`, which looks like a lookup array. For instance, the first number in the default config is 5, and U has index 5 (we're starting from Z = 0, sorry Lua devs).

Although figuring this out was fun, the solution is actually way simpler than that. Knowing what our end goal is, we can trace stuff back through the CFG to find what conditions are necessary to get to our end goal. At one point, we find this block:

```c
0x140035ee1      mov     rax, qword [var_50h]
0x140035ee8      mov     rax, qword [rax + 8]
0x140035eec      lea     rdx, data.140048a80 ; 0x140048a80 ; int64_t arg2
0x140035ef3      mov     rcx, rax  ; int64_t arg1
0x140035ef6      call    eqStrings ; sym.eqStrings_0x14003428e
0x140035efb      mov     byte [var_11h], al
0x140035f01      jmp     0x140035f04
```

The data in `data.140048a80` is `@5,7,0,2,24,7,14,16,5,14,16,19,2,23,6,8,19`, which is what the default config was. Following this is a call to `eqStrings` which probably does what it says it does, checks if two strings are equal. If we try submitting a new config like this, it doesn't look like anything changes.

```shell
Enter your choice:
3

------------------------------------------------------------
                     ADD CONFIGURATION
------------------------------------------------------------


Enter maintenance token:
neverhere

Enter configuration ID:
1337

Enter configuration data:
5,7,0,2,24,7,14,16,5,14,16,19,2,23,6,8,19


DER8.9 SmartMeter WATT Control and Maintenance Interface

------------------------------------------------------------
                        MENU OPTIONS
------------------------------------------------------------

[...trim...]

Enter your choice:
7

------------------------------------------------------------
                   PROCESS CONFIGURATIONS
------------------------------------------------------------


Processed Configuration (Not a flag... sadly): USZXBSLJULJGXCTRG

(Hint: do you think the developers took out any backdoors for debug access?)

Processed Configuration (Not a flag... sadly): USZXBSLJULJGXCTRG

(Hint: do you think the developers took out any backdoors for debug access?)


DER8.9 SmartMeter WATT Control and Maintenance Interface
```

There might be an additional check going on. In the block immediately before the `eqStrings`, we see another interesting comparison.

```c
0x140035eaf      mov     qword [var_130h], rax
0x140035eb3      mov     byte [var_11h], 0
0x140035eba      mov     rax, qword [var_50h]
0x140035ec1      mov     rax, qword [rax]
0x140035ec4      cmp     rax, 0x7c9 ; 1993
0x140035eca      sete    al
0x140035ecd      mov     byte [var_11h], al
0x140035ed3      movzx   eax, byte [var_11h]
0x140035eda      xor     eax, 1
0x140035edd      test    al, al
0x140035edf      jne     0x140035f03
```

Although this is Nim and there's a bunch of random noise that is happening, the comparison at `0x140035ec4` is such an oddly specific number. We could probably go backwards to confirm that this is a desired configuration ID, but there's no harm in trying. I'll restart the program and try again.

```shell
Enter your choice:
3

------------------------------------------------------------
                     ADD CONFIGURATION
------------------------------------------------------------


Enter maintenance token:
neverhere

Enter configuration ID:
1993

Enter configuration data:
5,7,0,2,24,7,14,16,5,14,16,19,2,23,6,8,19


DER8.9 SmartMeter WATT Control and Maintenance Interface

------------------------------------------------------------
                        MENU OPTIONS
------------------------------------------------------------

[...trim...]

Enter your choice:
7

------------------------------------------------------------
                   PROCESS CONFIGURATIONS
------------------------------------------------------------


Processed Configuration (Not a flag... sadly): USZXBSLJULJGXCTRG

(Hint: do you think the developers took out any backdoors for debug access?)

DEVELOPER DEBUG MODE ACTIVATED || Processed Configuration! INSECURE DIRECT OBJECT REFERENCE FLAG #3: INSECURE-REFS-LIKE-INSECURE-PROGRAMS-DO


DER8.9 SmartMeter WATT Control and Maintenance Interface
```

And that's the flag! In most examples of IDOR, it's usually about accessing information you shouldn't have access to by changing a parameter, usually an index. While this might not be that, I would still call it an IDOR in the sense that no normal user should just be able to call the debug mode by calling a specific ID (after all, we did find an admin attribute). It's mostly a problem of hard coded keys, but I don't think calling this IDOR is extremely wrong.

**flag**: `INSECURE-REFS-LIKE-INSECURE-PROGRAMS-DO`

## Conclusion
This year's Cyberforce main event had way more difficult challenges than previous years, and while some of them were extremely stupid (looking at you Ste-what-graphy), the progress the anomaly team has made over the years has been great. I still remember back in 2020 and 2021 where you could cheese half of the reversing and steg challenges by doing `strings binary | grep flag`. I wish I was able to solve these during the event, but got extremely bogged down in incident response, but I appreciate the work nonetheless.

If you're interested in doing some of these challenges yourself (and are a US collegiate student), [Cyberforce](https://cyberforce.energy.gov/) has some more events coming up that might be worth checking out. I'm not allowed back after [(allegedly) stealing the agenda](https://notateamserver.xyz/doe-cyberforce-23/) but that's besides the point :p

Until next time! :D