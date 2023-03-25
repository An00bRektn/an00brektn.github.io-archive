---
layout: post
title: "Cyber Apocalypse 2023: Alien Saboteur"
image: '/img/htb-cyber-apocalypse-23/ca-logo-2023.webp'
date:   2023-03-25 00:00:00
tags:
- rev
- reverse-engineering
- linux
- ghidra
- gdb
- ptrace
- htb-cyber-apocalypse
- virtual-machine
description: 'You spin me right round baby right round baby right round baby right round baby right round baby right round baby right round baby right round baby ...'
categories:
published: true
comments: false
---

![logo](https://an00brektn.github.io/img/cyber-apocalypse-23/ca-logo-2023.webp)

## Intro
After sacrificing my soul, sanity, and sleep to play this year's Cyber Apocalypse CTF, InactiveDirectory got 92nd! To be totally honest, not the best, but given that some of our better players were busy this week, I'll take a top 100 finish. As per usual, I'll be doing writeups on some of my favorite challenges throughout the event.

One of my favorite challenges from the event was in the Reversing category: Alien Saboteur. In addition to the `vm` binary we get, we also get a file of an unknown format that needs to be processed by the binary. Some initial analysis makes it clear `vm` is a virtual machine to run a novel file format, so the real challenge is taking apart the mystery file, as opposed to the `vm` binary. I'll write a scuffed disassembler by parsing the binary file, and slowly reverse this new layer of assembly to figure out where a password and the flag are coming from.

* buh
{:toc}

### Description
`You finally manage to make it into the main computer of the vessel, it's time to get this over with. You try to shutdown the vessel, however a couple of access codes unknown to you are needed. You try to figure them out, but the computer start speaking some weird language, it seems like gibberish...`

## Initial Analysis
### Poking Around
When we unzip the download file, we're presented with more than one file, but unfortunately, we have no idea what that second file is.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev$ unzip rev_alien_saboteur.zip
Archive:  rev_alien_saboteur.zip
   creating: rev_alien_saboteur/
  inflating: rev_alien_saboteur/vm
  inflating: rev_alien_saboteur/bin
kali@transistor:~/ctf/cyber-apocalypse-2023/rev$ file rev_alien_saboteur/vm
rev_alien_saboteur/vm: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=10fb238b19d3a82b46536b51e47396525086a09c, for GNU/Linux 3.2.0, not stripped
kali@transistor:~/ctf/cyber-apocalypse-2023/rev$ file rev_alien_saboteur/bin
rev_alien_saboteur/bin: data
```

The executable is not stripped, so that definiely saves us time. However, I still wanted to figure out if `bin` was any format I already knew about. Looking at the first few bytes in a hexdump, however, it appears to be something custom.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ xxd bin | head
00000000: 5577 5510 5b00 0000 0010 4d00 0000 0010  UwU.[.....M.....
00000010: 6100 0000 0010 6900 0000 0010 6e00 0000  a.....i.....n...
00000020: 0010 2000 0000 0010 5600 0000 0010 6500  .. .....V.....e.
00000030: 0000 0010 7300 0000 0010 7300 0000 0010  ....s.....s.....
00000040: 6500 0000 0010 6c00 0000 0010 2000 0000  e.....l..... ...
00000050: 0010 5400 0000 0010 6500 0000 0010 7200  ..T.....e.....r.
00000060: 0000 0010 6d00 0000 0010 6900 0000 0010  ....m.....i.....
00000070: 6e00 0000 0010 6100 0000 0010 6c00 0000  n.....a.....l...
00000080: 0010 5d00 0000 0010 0a00 0000 0010 3c00  ..]...........<.
00000090: 0000 0010 2000 0000 0010 4500 0000 0010  .... .....E.....
```

It's definitely not just encrypted data. The first three bytes are "UwU", which seems like made up magic bytes. A keen observer will also see that those other printable characters seem to print out "`[Main Vessel Terminal]`", but I'm not sure what purpose the other bytes serve. Running strings also doesn't reveal all too much other than the symbols that are already present in the file.

### Running It
I'll get a quick overview of the behavior of the binary by running it, but it looks like we need to feed `vm` the mystery `bin` file to do anything.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ ./vm
Usage: ./chall file
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ ./vm bin
[Main Vessel Terminal]
< Enter keycode
>
```

It seems just like a standard "crackme" format, just asking for a password.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ ./vm bin
[Main Vessel Terminal]
< Enter keycode
> HTB{f4k3_fl4g_f0r_t3st1ng!}
Unknown keycode!
```

If I run the binary against any other file on my system, we get an error.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ ./vm /etc/passwd
dead
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ ./vm $(which true)
dead
```

That seems like all of the information we're going to get without disassembling.

## Reversing `vm`
My preferred tool for disassembly/decompiling is [Ghidra](https://ghidra-sre.org/), although I mix in [Cutter](https://github.com/rizinorg/cutter) since Ghidra is garbage at finding `main()` and lacks a nice graph view. Since the binary isn't stripped, reversing isn't all too challenging, since the function names are all there, so it's mostly about how it's all organized and used.  I'll be be presenting functions as far as I reversed them, so it will not be perfect, but hopefully good enough to understand.

```c
int main(int argc,long argv) {
  FILE *__stream;
  size_t __size;
  void *__ptr;
  undefined8 binary_data;
  
  if (argc < 2) {
    printf("Usage: ./chall file");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  __stream = fopen(*(char **)(argv + 8),"rb");
  fseek(__stream,0,2);
  __size = ftell(__stream);
  rewind(__stream);
  __ptr = malloc(__size);
  fread(__ptr,__size,1,__stream);
  fclose(__stream);
  binary_data = vm_create(__ptr,__size);
  vm_run(binary_data);
  return 0;
}
```

The `main` function is fairly simple. We open the file passed via command line arguments, and then we allocate some space on the heap equal to the size of the binary file. We then pass the pointer to this data and the size of the data to the `vm_create` function, whose return value is then given to `vm_run`.

`vm_create` looks like a whole bunch of `malloc` shenanigans, but ultimately, it's reading the file from the first three bytes onward, which makes sense since the first three bytes were "UwU", so we can skip that function for now. `vm_run` is a little bit more interesting.

```c
void vm_run(long bin_dat_ptr){
  while (*(char *)(bin_dat_ptr + 4) == '\0') {
    vm_step(bin_dat_ptr);
  }
  return;
}
```

We are looping everytime the 4th byte after whereever our pointer is pointing is a null byte, and then calling `vm_step`. Interestingly, nothing here actually increments or decrements that value, so you'd think it would just run infinitely. Looking at `vm_step`, we see some fancy C going on.

```c
void vm_step(uint *bin_dat_pointer)

{
  if (0x19 < *(byte *)((ulong)*bin_dat_pointer + *(long *)(bin_dat_pointer + 0x24))) {
    puts("dead");
    exit(0);
  }
  (**(code **)(original_ops +
              (long)(int)(uint)*(byte *)((ulong)*bin_dat_pointer + *(long *)(bin_dat_pointer + 0x24)
                                        ) * 8))(bin_dat_pointer);
  return;
}
```

The first part of this seems fairly clear. Not entirely sure what the `0x24` stuff is, but it generally seems like if the byte pointed to by our pointer is greater than `0x19` (25), then print "`dead`", and exit. This lines up with what we were seeing with our attempts to use this against any other file, as the metadata/ASCII in those files is already much greater than that hex file. 

For the second part, I think it's more helpful to look at the assembly.

```c
                             LAB_001023f2                                    XREF[1]:     001023d7(j)  
        001023f2 0f b6 45 ff     MOVZX      EAX,byte ptr [RBP + local_9]
        001023f6 48 98           CDQE
        001023f8 48 8d 14        LEA        RDX,[RAX*0x8]
                 c5 00 00 
                 00 00
        00102400 48 8d 05        LEA        RAX,[original_ops]
                 19 2c 00 00
        00102407 48 8b 14 02     MOV        RDX,qword ptr [RDX + RAX*0x1]=>original_ops
        0010240b 48 8b 45 e8     MOV        RAX,qword ptr [RBP + local_20]
        0010240f 48 89 c7        MOV        bin_dat_pointer,RAX
        00102412 ff d2           CALL       RDX
        00102414 90              NOP
        00102415 c9              LEAVE
        00102416 c3              RET
```

Here, all we're really doing is taking whatever is located at `original_ops`, some kind of global variable, sticking it in the RAX register, and taking some offset from that, and putting it into the RDX register. The value of the pointer to our data is then restored, and we call RDX directly, which is interesting. Anytime we call a function like `puts`, we do some lazy loading from libc and do a whole song and dance with the Global Offset Table that you read a quick summary about [here](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got).

I really want to understand what's being put into that register, so I'm going to open my binary in `gdb`, and then set a breakpoint at that instruction.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ gdb vm
For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 201 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from vm...
(No debugging symbols found in vm)
------- tip of the day (disable with set show-tips off) -------
Pwndbg context displays where the program branches to thanks to emulating few instructions into the future. You can disable this with set emulate off which may also speed up debugging
pwndbg> disass vm_step
Dump of assembler code for function vm_step:
   0x00000000000023a7 <+0>:     endbr64
   0x00000000000023ab <+4>:     push   rbp
   0x00000000000023ac <+5>:     mov    rbp,rsp
   0x00000000000023af <+8>:     sub    rsp,0x20
   0x00000000000023b3 <+12>:    mov    QWORD PTR [rbp-0x18],rdi
   0x00000000000023b7 <+16>:    mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000023bb <+20>:    mov    rdx,QWORD PTR [rax+0x90]
   0x00000000000023c2 <+27>:    mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000023c6 <+31>:    mov    eax,DWORD PTR [rax]
   0x00000000000023c8 <+33>:    mov    eax,eax
   0x00000000000023ca <+35>:    add    rax,rdx
   0x00000000000023cd <+38>:    movzx  eax,BYTE PTR [rax]
   0x00000000000023d0 <+41>:    mov    BYTE PTR [rbp-0x1],al
   0x00000000000023d3 <+44>:    cmp    BYTE PTR [rbp-0x1],0x19
   0x00000000000023d7 <+48>:    jbe    0x23f2 <vm_step+75>
   0x00000000000023d9 <+50>:    lea    rax,[rip+0xc47]        # 0x3027
   0x00000000000023e0 <+57>:    mov    rdi,rax
   0x00000000000023e3 <+60>:    call   0x1150 <puts@plt>
   0x00000000000023e8 <+65>:    mov    edi,0x0
   0x00000000000023ed <+70>:    call   0x1230 <exit@plt>
   0x00000000000023f2 <+75>:    movzx  eax,BYTE PTR [rbp-0x1]
   0x00000000000023f6 <+79>:    cdqe
   0x00000000000023f8 <+81>:    lea    rdx,[rax*8+0x0]
   0x0000000000002400 <+89>:    lea    rax,[rip+0x2c19]        # 0x5020 <original_ops>
   0x0000000000002407 <+96>:    mov    rdx,QWORD PTR [rdx+rax*1]
   0x000000000000240b <+100>:   mov    rax,QWORD PTR [rbp-0x18]
   0x000000000000240f <+104>:   mov    rdi,rax
   0x0000000000002412 <+107>:   call   rdx
   0x0000000000002414 <+109>:   nop
   0x0000000000002415 <+110>:   leave
   0x0000000000002416 <+111>:   ret
End of assembler dump.
pwndbg> b *vm_step+107
Breakpoint 1 at 0x2412
```

I can then run the binary, passing in the file via `r bin`, and we see something interesting at the breakpoint.

```shell
pwndbg> r bin
Starting program: /home/kali/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur/vm bin
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555556412 in vm_step ()
[REGISTERS]
 RAX  0x55555555a480 ◂— 0x7f0000000000
 RBX  0x7fffffffdbb8 —▸ 0x7fffffffdf70 ◂— '/home/kali/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur/vm'
 RCX  0x55555555a520 ◂— 0x0
 RDX  0x5555555559ae (vm_putc) ◂— endbr64
 RDI  0x55555555a480 ◂— 0x7f0000000000
 RSI  0x0
 R8   0x0
 R9   0x7ffff7f9a2d0 (main_arena+1648) —▸ 0x7ffff7f9a2c0 (main_arena+1632) —▸ 0x7ffff7f9a2b0 (main_arena+1616) —▸ 0x7ffff7f9a2a0 (main_arena+1600) —▸ 0x7ffff7f9a290 (main_arena+1584) ◂— ...
 R10  0x0
 R11  0x0
 R12  0x0
 R13  0x7fffffffdbd0 —▸ 0x7fffffffdfb3 ◂— 'SHELL=/bin/bash'
 R14  0x555555558d48 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555552e0 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffda40 —▸ 0x7fffffffda60 —▸ 0x7fffffffdaa0 ◂— 0x2
 RSP  0x7fffffffda20 —▸ 0x7fffffffda60 —▸ 0x7fffffffdaa0 ◂— 0x2
 RIP  0x555555556412 (vm_step+107) ◂— call   rdx
```

The RDX register contains the address of the `vm_putc` function, which we never saw in control flow from Ghidra. In fact, if we look at what functions are in the binary, we have stuff like `vm_add`, `vm_mov`, `vm_input`, etc. which all have striking similarities to assembly instructions in x86. If I continue far enough with the same breakpoint, I see this `vm_putc` function being called, while printing out that "Main Terminal" message from earlier, and eventually hit `vm_mov`.

At this point, I think it's abundantly clear we're working with a virtual machine. For the unfamiliar, a virtual machine can be more than just what you see in VirtualBox/VMWare. Virtual Machines are simply defined as the emulation of a computer system. It doesn't need to be a full operating system, it can be like the Java Virtual Machine (JVM) or the .NET Common Language Runtime (CLR), which take these custom formats that their languages produce, and translate them to machine instructions that the operating system knows how to use.

Our job, then, is to understand how this translation is happening, and what the instructions are doing. For that, we'll need to take apart the `bin` file ourselves, because I'm not good enough with GDB to debug any individual instruction.

## Building a Disassembler
I'm not trying to make the IDA of what I'm going to call "UwU files"- all I want to do is dump out all of the virtual instructions that are being called, see what those functions are doing, and see what happens from there. Our first order of business is figuring out what opcode corresponds to what function.

If we go to `original_ops`, we can get a sense for how the functions are indexed.
```
                             original_ops                                    XREF[3]:     Entry Point(*), 
                                                                                          vm_step:00102400(*), 
                                                                                          vm_step:00102407(R)  
        00105020 64 1a 10        undefine
                 00 00 00 
                 00 00 24 
           00105020 64              undefined164h                     [0]           ?  ->  00101a64     XREF[3]:     Entry Point(*), 
                                                                                                                     vm_step:00102400(*), 
                                                                                                                     vm_step:00102407(R)  
           00105021 1a              undefined11Ah                     [1]
           00105022 10              undefined110h                     [2]
           00105023 00              undefined100h                     [3]
           00105024 00              undefined100h                     [4]
           00105025 00              undefined100h                     [5]
           00105026 00              undefined100h                     [6]
           00105027 00              undefined100h                     [7]
           00105028 24              undefined124h                     [8]           ?  ->  00101b24
           00105029 1b              undefined11Bh                     [9]
           0010502a 10              undefined110h                     [10]
           0010502b 00              undefined100h                     [11]
           0010502c 00              undefined100h                     [12]
           0010502d 00              undefined100h                     [13]
           0010502e 00              undefined100h                     [14]
           0010502f 00              undefined100h                     [15]
...trim...
```

Ghidra didn't exactly catch it, but based on what we know so far, it looks like it reads the byte at the current pointer, and then checks where that lands us in the `original_ops` "array". I copied these bytes out (and fixed the endianness), and put them in an array in my disassembler script I'm writing in Python. One problem: I don't know what value corresponds to what function. If I do `info functions` in pwndbg (before running the binary), I get some interesting output.

```python
0x0000000000001415  vm_nop
0x0000000000001433  vm_input
0x0000000000001493  vm_store
0x0000000000001531  vm_load
0x00000000000015d2  vm_xor
0x0000000000001692  vm_je
0x0000000000001759  vm_jne
0x0000000000001820  vm_jle
0x00000000000018e7  vm_jge
0x00000000000019ae  vm_putc
0x00000000000019fc  vm_print
0x0000000000001a64  vm_add
0x0000000000001b24  vm_addi
0x0000000000001bd9  vm_sub
0x0000000000001c99  vm_subi
0x0000000000001d4e  vm_mul
0x0000000000001e0f  vm_muli
0x0000000000001ec5  vm_cmp
0x0000000000001f60  vm_div
0x0000000000002025  vm_inv
0x000000000000217c  vm_jmp
0x00000000000021e2  vm_exit
0x000000000000220c  vm_push
0x0000000000002295  vm_pop
0x0000000000002327  vm_mov
```

These offsets are very similar to the values stored in `original_ops`, with the exception of an additional `0x100000`. Common sense tells us how these map, so we can just use Python to figure all of this out for us. Excuse the CTF-quality code.

```python
order = ['0000000000101a64', '0000000000101b24', '0000000000101bd9', '0000000000101c99', '0000000000101d4e', '0000000000101e0f', '0000000000101f60', '0000000000101ec5', '000000000010217c', '0000000000102025', '000000000010220c', '0000000000102295', '0000000000102327', '0000000000101415', '00000000001021e2', '00000000001019fc', '00000000001019ae', '0000000000101692', '0000000000101759', '0000000000101820', '00000000001018e7', '00000000001015d2', '0000000000101493', '0000000000101531', '0000000000101433']

pwn_funcs = { 
0x0000000000101415:  "vm_nop",
0x0000000000101433:  "vm_input",
0x0000000000101493:  "vm_store",
0x0000000000101531:  "vm_load",
0x00000000001015d2:  "vm_xor",
0x0000000000101692:  "vm_je",
0x0000000000101759:  "vm_jne",
0x0000000000101820:  "vm_jle",
0x00000000001018e7:  "vm_jge",
0x00000000001019ae:  "vm_putc",
0x00000000001019fc:  "vm_print",
0x0000000000101a64:  "vm_add",
0x0000000000101b24:  "vm_addi",
0x0000000000101bd9:  "vm_sub",
0x0000000000101c99:  "vm_subi",
0x0000000000101d4e:  "vm_mul",
0x0000000000101e0f:  "vm_muli",
0x0000000000101ec5:  "vm_cmp",
0x0000000000101f60:  "vm_div",
0x0000000000102025:  "vm_inv",
0x000000000010217c:  "vm_jmp",
0x00000000001021e2:  "vm_exit",
0x000000000010220c:  "vm_push",
0x0000000000102295:  "vm_pop",
0x0000000000102327:  "vm_mov",
}

original_ops = {}
for addr in order:
    a = int(addr, 16)
    original_ops[a] = pwn_funcs[a]

original_ops = list(original_ops.values())
```

Now, the indices of that `original_ops` list in Python correspond with what's in the virtual machine. Our next order of business is to recreate the `vm_step` function. If this was an ideal world where I had infinite time to work on this, I would have loved to build out a proper debugger and disassembler that executed instructions and whatnot, but for the time being, we'll have to settle with printing out the instruction, followed by the bytes after the instruction.

```python
def vm_step(i: int):
    opcode = uwu[i]
    print(f"{hex(i)}: ", end="")
    
    if 0x19 < opcode:
        print("dead")
        print(f"[ DEBUG ]: {hex(i)} {hex(i+9)}")
        #exit(0)
        raise Exception

    readable = original_ops[opcode]
    args = [hex(uwu[i+x]) for x in range(1,6)]
    print_args = ""
    for a in args:
        print_args += f"{a} "

    print(f"{readable}\t{print_args}")
    next_i = i+6
    return next_i, readable, [uwu[x] for x in range(i,6)]

def vm_run(i: int):
    if uwu[i+4] == 0:
        next_i, opcode, args = vm_step(i)
    else:
        return

    vm_run(next_i)

vm_run(0)
```

So, we start our `vm_run` from the first byte, validate it, check the opcode, and print everything out accordingly. Looking at some of the `vm_[instruction]` functions, it seems like every time they execute, they increment what is essentially the instruction pointer by 6, so I put that in as well. If we run it, we get a good chunk of assembly.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ python3 disasm.py bin
0x0: vm_putc    0x5b 0x0 0x0 0x0 0x0
0x6: vm_putc    0x4d 0x0 0x0 0x0 0x0
0xc: vm_putc    0x61 0x0 0x0 0x0 0x0
0x12: vm_putc    0x69 0x0 0x0 0x0 0x0
0x18: vm_putc    0x6e 0x0 0x0 0x0 0x0
0x1e: vm_putc    0x20 0x0 0x0 0x0 0x0
0x24: vm_putc    0x56 0x0 0x0 0x0 0x0
0x2a: vm_putc    0x65 0x0 0x0 0x0 0x0
0x30: vm_putc    0x73 0x0 0x0 0x0 0x0
```

Well would you look at that! The first ~40-ish instructions are all `vm_putc`, which looks like it's just printing the character after the opcode. As I begin to understand what each instruction is doing, I'll add it to a larger `if` statement to translate the arguments to a nicer format.

## Analyzing the Assembly in the Assembly
### Stage 1
#### Finding the Password
After the initial banner printing, we come to this block of instructions.

```python
0xfc: vm_mov	0x1e 0xa0 0xf 0x0 0x0 
0x102: vm_mov	0x1c 0x0 0x0 0x0 0x0 
0x108: vm_mov	0x1d 0x11 0x0 0x0 0x0 
0x10e: vm_input	0x19 0x0 0x0 0x0 0x0 
0x114: vm_store	0x1e 0x19 0x0 0x0 0x0 
0x11a: vm_addi	0x1e 0x1e 0x1 0x0 0x0 
0x120: vm_addi	0x1c 0x1c 0x1 0x0 0x0 
0x126: vm_jle	0x1c 0x1d 0x2d 0x0 0x0 
0x12c: vm_mov	0x1e 0x4 0x10 0x0 0x0 
0x132: vm_mov	0x1f 0xa0 0xf 0x0 0x0 
0x138: vm_mov	0x1c 0x0 0x0 0x0 0x0 
0x13e: vm_mov	0x1d 0xa 0x0 0x0 0x0 
0x144: vm_mov	0x1b 0xa9 0x0 0x0 0x0 
0x14a: vm_mov	0x17 0x0 0x0 0x0 0x0 
0x150: vm_load	0x19 0x1e 0x0 0x0 0x0 
0x156: vm_load	0x18 0x1f 0x0 0x0 0x0 
0x15c: vm_xor	0x19 0x19 0x1b 0x0 0x0 
0x162: vm_je	0x19 0x18 0x4e 0x0 0x0 
```

We could try to break down each individual function from the virtual machine, but that's a little excessive, and common sense can help us figure out the big picture. Notice the constant reuse of hex values such as `0x1e`, `0x1c`, `0x19`, etc. Intuitively, these must be register values. Assuming the functions were named as they should be, the structure lines up with normal ASM languages. The next order of business to really understand for each instruction is what the bytes after the first argument really mean. Looking at `vm_mov`, for instance:

```c
void vm_mov(uint *instruction_pointer){
  long lVar1;
  byte register;
  uint value;
  
  lVar1 = *(long *)(instruction_pointer + 0x24);
  value = *instruction_pointer;
  register = u8((ulong)*instruction_pointer + 1 + *(long *)(instruction_pointer + 0x24));
  value = u32(lVar1 + (ulong)value + 2);
  instruction_pointer[(long)(int)(uint)register + 2] = value;
  *instruction_pointer = *instruction_pointer + 6;
  return;
}
```

We're taking the first byte after the opcode as a register, and then the values after that are being interpreted as some 32-bit value (`u8`, `u16`, and `u32` are all "casting" functions for our VM), and the register is set to that value.

I repeated this process for every new instruction as it came up, and added specific parsing to my disassembler to get nicer output. You can find the full, CTF-quality script on [GitHub](https://github.com/An00bRektn/CTF/blob/main/live_events/htb_cyber_apocalypse_23/rev/rev_alien_saboteur/solve.py), but our new output now looks like this:

```python
0xfc: vm_mov	0x1e 0x00000fa0
0x102: vm_mov	0x1c 0x00000000
0x108: vm_mov	0x1d 0x00000011
0x10e: vm_input	0x19 
0x114: vm_store	0x1e 0x19
0x11a: vm_addi	0x1e 0x1e 0x1
0x120: vm_addi	0x1c 0x1c 0x1
0x126: vm_jle	0x1c 0x1d 0x2d 
0x12c: vm_mov	0x1e 0x00001004
0x132: vm_mov	0x1f 0x00000fa0
0x138: vm_mov	0x1c 0x00000000
0x13e: vm_mov	0x1d 0x0000000a
0x144: vm_mov	0x1b 0x000000a9
0x14a: vm_mov	0x17 0x00000000
0x150: vm_load	0x19 0x1e
0x156: vm_load	0x18 0x1f
0x15c: vm_xor	0x19 0x19 0x1b 
0x162: vm_je	0x19 0x18 0x4e
```

This is now much easier to read, and much easier to break down.
- **Instructions `0xfc` - `0x108`**: Initialize the `0x1e`, `0x1c`, and `0x1d` registers with the values `0xfa0`, `0x0`, and `0x11`, respectively.
- **Instructions `0x10e` - `0x114`**: Take the user's input, and store it in address `0x1e` tells us.
- **Instructions `0x11a` - `0x126`**: Add 1 to the `0x1e` and `0x1c` registers, and jump backward `0x2d` bytes if the value of `0x1c` is less than `0x1d`.
- **Instructions `0x12c` - `0x162`**: XOR the values stored at the address pointed to by `0x19` with `0xa9` (stored in `0x1b`). Compare this XORed value with the value stored at `0x18`.

TL;DR: Take the user's input, store it at an address, check if it's 17 bytes long. If it is, XOR the value at `0x1004` with `0xa9`, and check if they're equal.

So where are any of these values? If we take a hexdump of the `bin` file (removing the UWU bytes because the code does too), we get an idea of what's going on.

```c
00000fa0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000fb0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000fc0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000fd0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000fe0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000ff0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001000: 0000 0000 ca99 cd9a f6db 9acd f69c c1dc  ................
00001010: ddcd 99de c700 0000 0000 0000 0000 0000  ................
```

The user-supplied value will be stored at the `0xfa0` offset, and that long hexstring is the value that's being XORed. If we extract that hex string, and XOR correctly, we find the first passcode.

```python
Type "help", "copyright", "credits" or "license" for more information.
>>> enc = bytes.fromhex("ca99cd9af6db9acdf69cc1dcddcd99dec7")
>>> key = 0xa9
>>> bytes([a^key for a in enc])
b'c0d3_r3d_5hutd0wn'
```

If we supply this password to the binary, we move to the next stage. However, using it as the password for stage 2 fails. Weirdly, I'm able to copy and paste this multiple times before the binary finally kicks me out. it doesn't look like it's giving me more attempts, so it's probably waiting for me to input the exact number of bytes it's looking for before moving on.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ ./vm bin
[Main Vessel Terminal]
< Enter keycode
> c0d3_r3d_5hutd0wn
< Enter secret phrase
> c0d3_r3d_5hutd0wn
c0d3_r3d_5hutd0wn
c0d3_r3d_5hutd0wn
Wrong!
```

#### Dealing with `ptrace`
Looking back at the dumped assembly, we can see what gets executed after the initial password check.

```c
0x1d4: vm_addi	0x1e 0x1e 0x1
0x1da: vm_addi	0x1f 0x1f 0x1
0x1e0: vm_addi	0x1c 0x1c 0x1
0x1e6: vm_jle	0x1c 0x1d 0x38 
0x1ec: vm_mov	0xf 0x00000000
0x1f2: vm_push	0xf
0x1f8: vm_push	0xf
0x1fe: vm_push	0xf
0x204: vm_inv	0x65 0x3 
0x20a: vm_mov	0x10 0x00000000
0x210: vm_je	0x1f 0x10 0x6c 
```

I'll be honest, not entirely sure what purpose instructions `0x1d4` to `0x1e6` really serve, but the next instructions are interesting. `vm_push` pushes the value stored in `0xf` (which is 0), onto the virtual stack three times, before finally calling `vm_inv`. Looking at the source code, we see one of our longer functions.

```c
void vm_inv(uint *instruction_ptr)

{
  byte syscall_no;
  byte argc;
  uint arg1;
  uint arg2;
  uint arg3;
  long ret_val;
  
  syscall_no = u8((ulong)*instruction_ptr + 1 + *(long *)(instruction_ptr + 0x24));
  argc = u8((ulong)*instruction_ptr + 2 + *(long *)(instruction_ptr + 0x24));
  if (argc == 0) {
    arg1 = 0;
  }
  else {
    arg1 = instruction_ptr[0x28];
    instruction_ptr[0x28] = arg1 - 1;
    arg1 = *(uint *)((ulong)(arg1 - 1) * 4 + *(long *)(instruction_ptr + 0x26));
  }
  if (argc < 2) {
    arg2 = 0;
  }
  else {
    arg2 = instruction_ptr[0x28];
    instruction_ptr[0x28] = arg2 - 1;
    arg2 = *(uint *)((ulong)(arg2 - 1) * 4 + *(long *)(instruction_ptr + 0x26));
  }
  if (argc < 3) {
    arg3 = 0;
  }
  else {
    arg3 = instruction_ptr[0x28];
    instruction_ptr[0x28] = arg3 - 1;
    arg3 = *(uint *)((ulong)(arg3 - 1) * 4 + *(long *)(instruction_ptr + 0x26));
  }
  ret_val = syscall((ulong)syscall_no,(ulong)arg1,(ulong)arg2,(ulong)arg3);
  instruction_ptr[0x21] = (uint)ret_val;
  *instruction_ptr = *instruction_ptr + 6;
  return;
}
```

The only thing you really need to focus on is that line including `syscall()`. If we apply the values from our assembly, the line basically becomes:

```c
ret_val = syscall(0x65, 0x0, 0x0, 0x0);
```

Syscalls are essentially functions you can call to the operating system to do something. Every programmed function is a form of abstraction for these system calls. For instance, the `puts()` function is built on top of the `write` syscall in Linux. These calls are different from operating system to operating system, and architecture to architecture, so if you don't know what corresponds to what, you may want to look up a table. Luckily, the Chromium docs have this laid out nicely for us [here](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md), although it is weird that that's the spot where it was presented the best.

The syscall for `0x65` is `ptrace()`. If you're newer to more sophisticated reversing challenges (like myself), you've likely never encountered it before. According to the [man pages](https://man7.org/linux/man-pages/man2/ptrace.2.html)and , `ptrace` controls a process' ability to observe and view the execution of another process, and is fundamental to the ability to run stuff like `gdb`. We can get a sense of the real implications of this by attempting to run it in `gdb`.

```shell
pwndbg> r bin
Starting program: /home/kali/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur/vm bin
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Main Vessel Terminal]
< Enter keycode
> c0d3_r3d_5hutd0wn
Terminal blocked!
[Inferior 1 (process 66027) exited normally]
```

Although we gave the correct password, we were locked out of the system. If we run `strace`, we get an even better idea of what's going on.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ strace ./vm bin
...trim...
write(1, "[Main Vessel Terminal]\n", 23[Main Vessel Terminal]
) = 23
write(1, "< Enter keycode \n", 17< Enter keycode
)      = 17
newfstatat(0, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x2), ...}, AT_EMPTY_PATH) = 0
write(1, "> ", 2> )                       = 2
read(0, c0d3_r3d_5hutd0wn
"c0d3_r3d_5hutd0wn\n", 1024)    = 18
ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)
write(1, "Terminal blocked!\n", 18Terminal blocked!
)     = 18
exit_group(0)                           = ?
+++ exited with 0 +++
```

`ptrace` is blocking our ability to debug the binary. So far, this isn't really a problem, as we've just been doing static analysis, but in the event that we need to debug, I'd like to figure out a way around this. Luckily, the bytes dictating this are in `bin`, so we can just create a `patched-bin` with the relevant bytes changed. With some tweaking, I did this.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ diff bin-mod.hex bin.hex
33,34c33,34
< 00000200: 000a 0f00 0000 00[0d] 6503 0000 000c 1000  ........e.......
< 00000210: 0000 00[12] 1f10 6c00 0010 5400 0000 0010  ......l...T.....
---
> 00000200: 000a 0f00 0000 00[09] 6503 0000 000c 1000  ........e.......
> 00000210: 0000 00[11] 1f10 6c00 0010 5400 0000 0010  ......l...T.....
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ diff patched.log disasm.log
87c87
< 0x204: vm_nop 0x65 0x3
---
> 0x204: vm_inv 0x65 0x3
89c89
< 0x210: vm_jne 0x1f 0x10 0x6c
---
> 0x210: vm_je  0x1f 0x10 0x6c
```

The braces in the hexdump diff were added by my to highlight what bytes I changed. The `vm` binary has additional instructions that never actually get used. Instead of calling `vm_inv` for a syscall, we call `vm_nop` to skip the instruction. But, the program also checks for a successful `ptrace`, so instead of `jne`, we flip that to be the opposite `je`. Now, if we open the patched version in `gdb`, we should be able to debug as normal. 

```shell
pwndbg> r patched-bin
Starting program: /home/kali/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur/vm patched-bin
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Main Vessel Terminal]
< Enter keycode
> c0d3_r3d_5hutd0wn
< Enter secret phrase
> c0d3_r3d_5hutd0wnc0d3_r3d_5hutd0wnc0d3_r3d_5hutd0wn
Wrong!
[Inferior 1 (process 70901) exited normally]
```

#### Decrypting Stage 2
With that out of the way, we have one [last bit of assembly](https://artlogic-res.cloudinary.com/w_2560,h_1800,c_limit,f_auto,fl_lossy,q_60/artlogicstorage/jacksonfineart/images/view/27a59554839c03d5c7503d650a6fcf92p.png) to look at.

```c
0x288: vm_mov	0x1e 0x00000077
0x28e: vm_muli	0x1e 0x1e 0x6 
0x294: vm_mov	0x1c 0x00000000
0x29a: vm_mov	0x1d 0x000005dc
0x2a0: vm_mov	0x1b 0x00000045
0x2a6: vm_load	0x19 0x1e
0x2ac: vm_xor	0x19 0x19 0x1b 
0x2b2: vm_store	0x1e 0x19
0x2b8: vm_addi	0x1e 0x1e 0x1
0x2be: vm_addi	0x1c 0x1c 0x1
0x2c4: vm_jle	0x1c 0x1d 0x71 
```

This follows a very similar pattern to what we were seeing with the encrypted password. We're looping starting from where `0x1e` points to, which is `0x77 * 6 = 0x2ca`, and then XORing with the value stored in `0x1b`, that is, `0x45`. Looking at the hexdump, we see the relevant ciphertext.

```c
000002c0: 0001 1c1c 0100 0013 1c1d 7100 0055 7945  ..........q..UyE
000002d0: 4545 4555 6545 4545 4555 0045 4545 4555  EEEUeEEEEU.EEEEU
000002e0: 2b45 4545 4555 3145 4545 4555 2045 4545  +EEEEU1EEEEU EEE
000002f0: 4555 3745 4545 4555 6545 4545 4555 3645  EU7EEEEUeEEEEU6E
00000300: 4545 4555 2045 4545 4555 2645 4545 4555  EEEU EEEEU&EEEEU
00000310: 3745 4545 4555 2045 4545 4555 3145 4545  7EEEEU EEEEU1EEE
00000320: 4555 6545 4545 4555 3545 4545 4555 2d45  EUeEEEEU5EEEEU-E
00000330: 4545 4555 3745 4545 4555 2445 4545 4555  EEEU7EEEEU$EEEEU
00000340: 3645 4545 4555 2045 4545 4555 4f45 4545  6EEEEU EEEEUOEEE
00000350: 4555 7b45 4545 4555 6545 4545 4549 5b75  EU{EEEEUeEEEEI[u
00000360: 5445 4549 5945 4545 4549 5861 4545 455d  TEEIYEEEEIXaEEE]
...trim...
```

Knowing the properties of XOR, we can already see a lot of null bytes in between different bytes.

Which happens to be just like how the other opcodes were structured.

Which means this is probably just the beginning of the end.

Oh no.

![asdf](https://an00brektn.github.io/img/cyber-apocalypse-23/Pasted%20image%2020230325075612.png)

Shoot, there's more.

Well, we can add the decrypted bytes to our script, and run our disassembler on those new bytes.

```python
packed = bytes.fromhex("103c00000000...trim...e0000000000")

uwu = packed
vm_run(0)
```

```c
0x0: vm_putc    b'<'
0x6: vm_putc    b' '
0xc: vm_putc    b'E'
0x12: vm_putc    b'n'
0x18: vm_putc    b't'
0x1e: vm_putc    b'e'
0x24: vm_putc    b'r'
0x2a: vm_putc    b' '
0x30: vm_putc    b's'
0x36: vm_putc    b'e'
0x3c: vm_putc    b'c'
0x42: vm_putc    b'r'
0x48: vm_putc    b'e'
0x4e: vm_putc    b't'
0x54: vm_putc    b' '
0x5a: vm_putc    b'p'
0x60: vm_putc    b'h'
0x66: vm_putc    b'r'
0x6c: vm_putc    b'a'
0x72: vm_putc    b's'
0x78: vm_putc    b'e'
0x7e: vm_putc    b'\n'
0x84: vm_putc    b'>'
0x8a: vm_putc    b' '
...trim...
```

Welp, we're going to stage 2.

### Stage 2
#### Permutations
I'll modify my disassembler script to just add the location of the last instruction we were on for consistency, since I'm just running it on both distinct chunks. After the new phrase prompt, we see a single, unbroken chunk of instructions.

```c
0x360: vm_mov	0x1e 0x00001130
0x366: vm_mov	0x1c 0x00000000
0x36c: vm_mov	0x1d 0x00000024
0x372: vm_input	0x19 
0x378: vm_store	0x1e 0x19
0x37e: vm_addi	0x1e 0x1e 0x1
0x384: vm_addi	0x1c 0x1c 0x1
0x38a: vm_jle	0x1c 0x1d 0x92 
0x390: vm_mov	0x1c 0x00000000
0x396: vm_mov	0x1d 0x00000023
0x39c: vm_mov	0x1e 0x00001130
0x3a2: vm_mov	0x1f 0x00001194
0x3a8: vm_mov	0x1a 0x00000000
0x3ae: vm_mov	0x1b 0x00000023
0x3b4: vm_load	0x14 0x1e
0x3ba: vm_load	0x15 0x1f
0x3c0: vm_push	0x14
0x3c6: vm_pop	0x13 
0x3cc: vm_mov	0x12 0x00001130
0x3d2: vm_add	0x12 0x12 0x15 
0x3d8: vm_load	0x11 0x12
0x3de: vm_store	0x1e 0x11
0x3e4: vm_store	0x12 0x13
0x3ea: vm_addi	0x1a 0x1a 0x1
0x3f0: vm_addi	0x1e 0x1e 0x1
0x3f6: vm_addi	0x1f 0x1f 0x1
0x3fc: vm_jle	0x1a 0x1b 0x9d 
0x402: vm_mov	0x1e 0x00001130
0x408: vm_mov	0x1f 0x000011f8
0x40e: vm_mov	0x1a 0x00000000
0x414: vm_mov	0x1b 0x00000023
0x41a: vm_load	0x14 0x1e
0x420: vm_push	0x1f
0x426: vm_pop	0xf 
0x42c: vm_add	0xf 0xf 0x1c 
0x432: vm_load	0x10 0xf
0x438: vm_xor	0x14 0x14 0x10 
0x43e: vm_store	0x1e 0x14
0x444: vm_addi	0x1a 0x1a 0x1
0x44a: vm_addi	0x1e 0x1e 0x1
0x450: vm_jle	0x1a 0x1b 0xae 
0x456: vm_addi	0x1c 0x1c 0x1
0x45c: vm_jle	0x1c 0x1d 0x99 
0x462: vm_mov	0x1e 0x00001130
0x468: vm_mov	0x1f 0x0000125c
0x46e: vm_mov	0x1a 0x00000000
0x474: vm_mov	0x1b 0x00000023
0x47a: vm_load	0xf 0x1e
0x480: vm_load	0x10 0x1f
0x486: vm_je	0xf 0x10 0xc9 
```

As per usual, this writeup is going to make me look very intelligent because I can just tell you exactly what's happening now that I know the answer, but at this time, this took me 6+ hours to truly figure out, mainly due to a misunderstanding on how the jump instructions were working.

```c
0x360: vm_mov	0x1e 0x00001130
0x366: vm_mov	0x1c 0x00000000
0x36c: vm_mov	0x1d 0x00000024
0x372: vm_input	0x19 
0x378: vm_store	0x1e 0x19
0x37e: vm_addi	0x1e 0x1e 0x1
0x384: vm_addi	0x1c 0x1c 0x1
0x38a: vm_jle	0x1c 0x1d 0x92 
```

This first section is storing 36 bytes of user input into the location `0x1130` by looping over the set of bytes in the input.

```c
0x390: vm_mov	0x1c 0x00000000
0x396: vm_mov	0x1d 0x00000023
0x39c: vm_mov	0x1e 0x00001130
0x3a2: vm_mov	0x1f 0x00001194
0x3a8: vm_mov	0x1a 0x00000000
0x3ae: vm_mov	0x1b 0x00000023
0x3b4: vm_load	0x14 0x1e
0x3ba: vm_load	0x15 0x1f
0x3c0: vm_push	0x14
0x3c6: vm_pop	0x13 
0x3cc: vm_mov	0x12 0x00001130
0x3d2: vm_add	0x12 0x12 0x15 
0x3d8: vm_load	0x11 0x12
0x3de: vm_store	0x1e 0x11
0x3e4: vm_store	0x12 0x13
0x3ea: vm_addi	0x1a 0x1a 0x1
0x3f0: vm_addi	0x1e 0x1e 0x1
0x3f6: vm_addi	0x1f 0x1f 0x1
0x3fc: vm_jle	0x1a 0x1b 0x9d
```

This next section took me a long time to finally understand because of my inabililty to understand instructions `0x3c0` to `0x3d2`. We start off by initializing registers `0x1c` and `0x1a` at zero, acting as counter variables. For every character loaded in, we are moving it to the address `0x1130 + 0x15[0x1a]`. We repeat this 36 times.

If we look at the addresses pointed to by `0x1e` and `0x1f`, we get an idea of what the final task really is, and this movement will make more sense.

```c
00001130: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001140: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001160: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001170: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001180: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001190: 0000 0000 0000 0013 190f 0a07 001d 0e16  ................
000011a0: 100c 010b 1f18 1408 091c 1a21 0422 1205  ...........!."..
000011b0: 1b11 2006 0215 170d 1e23 0300 0000 0000  .. ......#......
000011c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000011d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000011e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000011f0: 0000 0000 0000 0000 0000 0016 b047 b201  .............G..
00001200: fbde eb82 5d5b 5d10 7c6e 215f e745 2a36  ....][].|n!_.E*6
00001210: 23d4 d726 d5a3 11ed e75e cbdb 9fdd e200  #..&.....^......
00001220: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001230: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001240: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001250: 0000 0000 0000 0000 0000 0000 0000 0065  ...............e
00001260: 5d77 4a33 4056 6c75 375d 356e 6e66 366c  ]wJ3@Vlu7]5nnf6l
00001270: 3670 6577 6a31 795d 3170 7f6c 6e33 3236  6pewj1y]1p.ln326
00001280: 3631 5d00 0000 0000 0000 0000 0000 0000  61].............
```

We see that we're probably going to be working with four byte arrays. From what we've already seen, we know that `0x1130` contains the value we input (at this point, probably the flag) and that the value around `0x1190` defines how we're moving characters around. If you notice, not one byte in those 36 bytes is greater than `0x24`, which we can reasonbly infer at this point must be the length of the flag. We can extract these bytes and convert them to a list of ints.

```python
>>> enc_1 = bytes.fromhex("13190f0a07001d0e16100c010b1f181408091c1a21042212051b1120060215170d1e2303")
>>> [x for x in enc_1]
[19, 25, 15, 10, 7, 0, 29, 14, 22, 16, 12, 1, 11, 31, 24, 20, 8, 9, 28, 26, 33, 4, 34, 18, 5, 27, 17, 32, 6, 2, 21, 23, 13, 30, 35, 3]
```

What's really happening here is that this list is defining a permutation. In the first loop, the first character of the flag gets moved to the 19th position, the second gets moved to the 25th position, so on and so forth. Since we know how the flag is being permuted, we can write functions in Python to permute and then "unpermute" the characters.

```python
enc_1 = bytes.fromhex("13190f0a07001d0e16100c010b1f181408091c1a21042212051b1120060215170d1e2303")
def forwards(arr):
    permuted = arr
    for i,p in enumerate(enc_1):
        tmp = permuted[i]
        permuted[i] = permuted[p]
        permuted[p] = tmp
    return permuted

def backwards(arr):
    key = [x for x in enc_1]
    key.reverse()
    unpermute = arr
    for i, p in enumerate(key):
        tmp = unpermute[35-i]
        unpermute[35-i] = unpermute[p]
        unpermute[p] = tmp
    return unpermute
```

We still need to figure out the next sections.

#### XOR
The next block we need to look at is this.
```c
0x402: vm_mov	0x1e 0x00001130
0x408: vm_mov	0x1f 0x000011f8
0x40e: vm_mov	0x1a 0x00000000
0x414: vm_mov	0x1b 0x00000023
0x41a: vm_load	0x14 0x1e
0x420: vm_push	0x1f
0x426: vm_pop	0xf 
0x42c: vm_add	0xf 0xf 0x1c 
0x432: vm_load	0x10 0xf
0x438: vm_xor	0x14 0x14 0x10 
0x43e: vm_store	0x1e 0x14
0x444: vm_addi	0x1a 0x1a 0x1
0x44a: vm_addi	0x1e 0x1e 0x1
0x450: vm_jle	0x1a 0x1b 0xae 
0x456: vm_addi	0x1c 0x1c 0x1
0x45c: vm_jle	0x1c 0x1d 0x99
```

Now we're working with the byte array located at `0x11f8`. Here, we actually have nested loops here, as we can we with the two `vm_jle` instructions. The `0x10` register will store a character at a point at `0x11f8`, and the `0x14` register is storing the current character/byte at the `0x1130` array. We XOR those two values together, and we first increment the register keeping track of `0x1130`. Once we have looped through all of the values of `0x1130`, *only then* do we move on in the bytes at `0x11f8`.

In summary, we are XORing each byte in our now permuted flag, with every single byte in the bytes stored at `0x11f8`. Instead of rewriting this in Python, we can simplify this by XORing all of the bytes in the `0x11f8` byte array together, and then XORing with our mixed flag.

```python
>>> key = enc_2[0]
>>> for b in enc_2[1:]:
...     key ^= b
...
>>> key
2
```

The final section just compares everything we've done to the final set of bytes.

```c
0x462: vm_mov	0x1e 0x00001130
0x468: vm_mov	0x1f 0x0000125c
0x46e: vm_mov	0x1a 0x00000000
0x474: vm_mov	0x1b 0x00000023
0x47a: vm_load	0xf 0x1e
0x480: vm_load	0x10 0x1f
0x486: vm_je	0xf 0x10 0xc9 
```

Let's summarize what we know:
- Our input is stored in `0x1130`, and goes through a permutation defined in `0x1194`.
- We then XOR every byte in `0x1130` with every byte stored at `0x11f8`
- The value at `0x1130` is compared to `0x125c`

#### Final Solve
Lucky for us, everything we've done is fully invertible, so we can just do the reverse of everything to find the flag.

```python
#!/usr/bin/env python3
from pwn import xor

# enc_1 = 0x1130
# enc_2 = 0x11f8
# enc_3 = 0x125c
enc_1 = bytes.fromhex("13190f0a07001d0e16100c010b1f181408091c1a21042212051b1120060215170d1e2303")
enc_2 = bytes.fromhex("16b047b201fbdeeb825d5b5d107c6e215fe7452a3623d4d726d5a311ede75ecbdb9fdde2")
enc_3 = bytes.fromhex("655d774a3340566c75375d356e6e66366c367065776a31795d31707f6c6e33323636315d")

# reverse permutation
def backwards(arr):
    key = [x for x in enc_1]
    key.reverse()
    unpermute = arr
    for i, p in enumerate(key):
        tmp = unpermute[35-i]
        unpermute[35-i] = unpermute[p]
        unpermute[p] = tmp
    return unpermute

# calculating the XOR
xor_key = enc_2[0]
for b in enc_2[1:]:
    xor_key ^= b

permuted_flag = xor(enc_3, xor_key)
print(f"[+] Scrambled: {permuted_flag}")

flag_bytes = [x for x in permuted_flag]
for _ in range(36):
    flag_bytes = backwards(flag_bytes)

print(f"[+] Flag: {bytes(flag_bytes).decode()}")
```
```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/rev/rev_alien_saboteur$ python3 decrypt.py
[+] Scrambled: b'g_uH1BTnw5_7lld4n4rguh3{_3r}nl10443_'
[+] Flag: HTB{5w1rl_4r0und_7h3_4l13n_l4ngu4g3}
```

**Flag**: `HTB{5w1rl_4r0und_7h3_4l13n_l4ngu4g3}`

This is probably the hardest rev challenge I've solved, so I'm super happy with how I pushed through and worked for this. I'm sure there are ways I could have used more dynamic analysis after patching `ptrace`, but static was the only thing that was really making sense until the very end, where debugging helped show me the permutation that was happening.
