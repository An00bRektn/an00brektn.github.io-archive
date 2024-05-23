---
layout: post
title: "HTB Business CTF 2024: Satellite Hijack"
image: ""
date: 2024-05-22 00:00:00
tags:
  - reverse-engineering
  - linux
  - hackthebox
  - xor
  - ghidra
  - ctf
description: Sorry hardware/iot folks, no satellites were harmed in the process of reversing this binary.
categories: 
published: true
comments: false
---

<img src="https://www.hackthebox.com/images/landingv3/og/og-htb-business-2024.jpg" style="width:60%;height:60%">

## Intro

It's certainly been a while, but turns out being full-time at a job takes away a lot of time you would have to write. Luckily, I had enough spare time this past weekend to do some challenges in the most recent HTB Business CTF, and while I wasn't able to get extremely sweaty with it, I did want to highlight my favorite solve I was able to do: Satellite Hijack (sponsored by Bugcrowd™®).

Satellite Hijack was the hardest rated reversing challenge in the CTF, and while it wasn't the hardest reversing challenge I've ever seen, I enjoyed it because of how I sped through the solve. I'll start by taking a look at the initial binary, but spend most of the time exploring the shared library it gets shipped with. The shared library does some interesting traversal in memory to overwrite a function with new code, which actually contains the password encrypted with a simple XOR cipher.

* buh
{:toc}

### Description
`The crew has located a dilapidated pre-war bunker. Deep within, a dusty control panel reveals that it was once used for communication with a low-orbit observation satellite. During the war, actors on all sides infiltrated and hacked each others systems and software, inserting backdoors to cripple or take control of critical machinery. It seems like this panel has been tampered with to prevent the control codes necessary to operate the satellite from being transmitted - can you recover the codes and take control of the satellite to locate enemy factions?`

## Initial Analysis
This challenge gets interesting as soon as we unzip the challenge folder.

```shell
kali@transistor:~/ctf/htb-biz-24/rev$ unzip rev_satellitehijack.zip
Archive:  rev_satellitehijack.zip
   creating: rev_satellitehijack/
  inflating: rev_satellitehijack/satellite
  inflating: rev_satellitehijack/library.so
```

These look like standard ELF files. There's no explicit RUNPATH added to the `satellite` binary, but the `library.so` is stripped, so it's very likely to be the focus of the challenge. 

```shell
kali@transistor:~/ctf/htb-biz-24/rev/rev_satellitehijack$ file satellite
satellite: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=10cc2ba53a9cb7ac49b751f3b210286665ca0386, for GNU/Linux 3.2.0, not stripped
kali@transistor:~/ctf/htb-biz-24/rev/rev_satellitehijack$ checksec --file satellite
[*] '/home/kali/ctf/htb-biz-24/rev/rev_satellitehijack/satellite'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
kali@transistor:~/ctf/htb-biz-24/rev/rev_satellitehijack$ file library.so
library.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=392d868b5f763513c8ad2838cd8476875f1f14ea, stripped
kali@transistor:~/ctf/htb-biz-24/rev/rev_satellitehijack$ checksec library.so
[*] '/home/kali/ctf/htb-biz-24/rev/rev_satellitehijack/library.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

There's nothing too remarkable in the strings of the `satellite` binary either, aside from a banner and the name of some functions. However, the `library.so` file has a section that looks extremely odd.

```shell
kali@transistor:~/ctf/htb-biz-24/rev/rev_satellitehijack$ strings -n 8 library.so
__gmon_start__
<...trim...>
"qwkvkwktku
qwkvkwkt
**********************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************<...trim...>
```

I would normally dismiss the stars as being some kind of banner, but without newline characters or anything else in the mix, their purpose is confusing. Following these observations, we can run the satellite binary to quickly notice we're in for a classic "crackme".

```shell
kali@transistor:~/ctf/htb-biz-24/rev/rev_satellitehijack$ ./satellite
         ,-.
        / \  `.  __..-,O ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈
       :   \ --''_..-'.'
       |    . .-' `. '.
       :     .     .`.'
        \     `.  /  ..
        \      `.   ' .
          `,       `.   \
         ,|,`.        `-.\
        '.||  ``-...__..-`
         |  |
         |__|
         /||\
        //||\\
       // || \\
    __//__||__\\__
   '--------------'
| READY TO TRANSMIT |
> HTB{f4k3_fl4g}
Sending `HTB{f4k3_fl4g}`
```

We could play around with `strace` and `ltrace` as well, but I found it much easier to just dive into Ghidra.

## satellite
Turns out the `satellite` binary is extremely simple. Ghidra only finds one function, and since the binary isn't stripped, it's clearly labeled as `main()`. Some light analysis and renaming variables leads us to this.

```c
void main(void)

{
  long index;
  undefined8 *puVar2;
  byte bVar3;
  undefined8 uStack_420;
  undefined8 user_input;
  undefined8 local_410;
  undefined8 buffer [127];
  ssize_t user_input_result;
  
  bVar3 = 0;
  uStack_420 = 0x1011a4;
  setbuf(stdout,(char *)0x0);
  uStack_420 = 0x1011b0;
  puts(banner);
  uStack_420 = 0x1011c1;
  send_satellite_message(0,"START");
  user_input = 0;
  local_410 = 0;
  puVar2 = buffer;
  for (index = 0x7e; index != 0; index = index + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + (ulong)bVar3 * -2 + 1;
  }
  do {
    while( true ) {
      uStack_420 = 0x1011f8;
      putchar(0x3e);
      uStack_420 = 0x101202;
      putchar(0x20);
      uStack_420 = 0x10121b;
      user_input_result = read(1,&user_input,0x400);
      if (-1 < user_input_result) break;
      uStack_420 = 0x101232;
      puts("ERROR READING DATA");
    }
    if (0 < user_input_result) {
      *(undefined *)((long)&uStack_420 + user_input_result + 7) = 0;
    }
    uStack_420 = 0x101266;
    printf("Sending `%s`\n",&user_input);
    uStack_420 = 0x10127a;
    send_satellite_message(0,&user_input);
  } while( true );
}
```

If we ignore any reference to `uStack_420`, this function is pretty straightforward. After calling `setbuf()` to clean up I/O and `puts()` to print out a banner, we make a call to `send_satellite_message()` with some kind of "START" message. Following this, I'm not entirely sure what the loop is for, but we seem to enter a loop where we call `read()` to grab user input, and then call `send_satellite_message()` with that input.

Though we don't fully understand what `puts("ERROR READING DATA")` and the loop are for yet, understanding this whole control flow likely hinges on what the `send_satellite_data()` function is doing, so we should jump to the shared object.

## library.so
### send_satellite_message
Though the library is stripped, Ghidra identifies the `send_satellite_message()` function for us. The raw output looks like this:

```c
code * send_satellite_message(void)

{
  char *pcVar1;
  long in_FS_OFFSET;
  uint local_2c;
  undefined8 local_28;
  undefined5 local_20;
  undefined3 uStack_1b;
  undefined5 uStack_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0x4550535160554254;
  local_20 = 0x4a574f4660;
  uStack_1b = 0x4f5053;
  uStack_18 = 0x554f464e;
  for (local_2c = 0; local_2c < 0x14; local_2c = local_2c + 1) {
    *(char *)((long)&local_28 + (long)(int)local_2c) =
         *(char *)((long)&local_28 + (long)(int)local_2c) + -1;
  }
  pcVar1 = getenv((char *)&local_28);
  if (pcVar1 != (char *)0x0) {
    FUN_001023e3();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return FUN_001024db;
}
```

On first glance, a few things immediately stand out. For one, `local_10` is a stack canary, we can disregard that variable. Continuing on, `local_28`, `local_20`, `uStack_1b`, and `uStack18` all look like random hexadecimal numbers. However, if you look at the numbers byte by byte (e.g. 0x45, 0x50, 0x53), you'll notice that these are all printable ASCII characters. 

After defining some variables, we have a for loop using `local_2c` as the index, and operating on `local_28`, which, as noted, contains printable bytes. Though Ghidra spits out some pointer nonsense within the loop, if you try to get the big picture, we're iterating on `local_28`, and subtracting 1 from each byte in the string, which is likely their way of encoding/obfuscating the string.

Finally, the new value of `local_28` gets passed into `getenv()`, which, as its name implies, retrieves an environment variable. We can rename all of these variables to get this, which is slightly more readable:

```c
code * send_satellite_message(void)

{
  char *envvar_SAT_PROD_ENVIRONMENT;
  long in_FS_OFFSET;
  uint index;
  undefined8 str_encoded_env_var;
  undefined5 local_20;
  undefined3 uStack_1b;
  undefined5 uStack_18;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  str_encoded_env_var = 0x4550535160554254;
  local_20 = 0x4a574f4660;
  uStack_1b = 0x4f5053;
  uStack_18 = 0x554f464e;
  for (index = 0; index < 0x14; index = index + 1) {
    *(char *)((long)&str_encoded_env_var + (long)(int)index) =
         *(char *)((long)&str_encoded_env_var + (long)(int)index) + -1;
  }
  envvar_val = getenv((char *)&str_encoded_env_var);
  if (envvar_val != (char *)0x0) {
    if_env_not_null();
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return after_send_satellite;
}
```

Having a better understanding of how this function works, we can try to decode the hex. I wouldn't recommend copying and pasting the hex from the decompiler, as it will often put variables out of order. But, if you look at the assembly view, you can see the order that they're placed in.

```c
        001025e7 48 b8 54        MOV        RAX,0x4550535160554254
                 42 55 60 
                 51 53 50 45
        001025f1 48 ba 60        MOV        RDX,0x4f50534a574f4660
                 46 4f 57 
                 4a 53 50 4f
        001025fb 48 89 45 e0     MOV        qword ptr [RBP + str_encoded_env_var],RAX
        001025ff 48 89 55 e8     MOV        qword ptr [RBP + local_20],RDX
        00102603 48 b8 53        MOV        RAX,0x554f464e4f5053
                 50 4f 4e 
                 46 4f 55 00
```

We can throw this into Python to see what the output is.

```python
>>> mystery = bytes.fromhex('45505351605542544f50534a574f4660554f464e4f5053')
>>> new = []
>>> for i in range(0x14):
...     new.append(mystery[i]-1)
...
>>> bytearray(new)
bytearray(b'DORP_TASNORIVNE_TNEM')
```

While that decoded to something, it certainly doesn't feel right. We need to account for endianness, i.e., the order in which bytes get stored. In x86, the architecture we're dealing with, we're working with little endian, meaning the least significant byte is at the lowest address. When I run into these errors, I'm a big fan of using [CyberChef](https://gchq.github.io) to solve my problems.

![asdf](https://an00brektn.github.io/img/htb-biz-24/Pasted%20image%2020240521010101.png)

Looking back at our relabeled function, we see that the program uses `getenv()` to retrieve the contents of that environment variable. As long as that value isn't null, we call what I labeled `if_env_not_null()`, and then proceed to the `after_send_satellite` in the return (great naming, I know).

### Diving Deeper
The `if_env_not_null()` function is much shorter, but the code is not as clear. I can relabel a reference to the .data section which contains the string "read", and another with all of the `*`'s we identified earlier, but it's not entirely clear what's happening.

```c
void if_env_not_null(void)

{
  ulong uVar1;
  void **ppvVar2;
  void *__dest;
  
  uVar1 = getauxval(3);
  ppvVar2 = (void **)FUN_001021a9(uVar1 & 0xfffffffffffff000,&str_read);
  __dest = mmap((void *)0x0,0x2000,7,0x22,-1,0);
  memcpy(__dest,&str_lots_of_stars,0x1000);
  memfrob(__dest,0x1000);
  *ppvVar2 = __dest;
  return;
}
```

In these reversing writeups, I will often glaze over lines and sections of code, because educated guesses can often save you more time on minutia that you're not particularly invested in. However, I don't know what `getauxval()`, the stripped function, and `memfrob()` do at all. Looking at the [documentation](https://man7.org/linux/man-pages/man3/getauxval.3.html), `getauxval()` is described as follows:

```
getauxval - retrieve a value from the auxiliary vector
<...trim...>
       The getauxval() function retrieves values from the auxiliary
       vector, a mechanism that the kernel's ELF binary loader uses to
       pass certain information to user space when a program is
       executed.
```

While we now have the rough idea that this function returns some metadata about the program's current state, I don't know what `getauxval(3)` is doing. The documentation uses declared constants, and no resources were giving me an explicit answer. However, scrolling further in the docs, we see:

```
       The auxiliary vector resides just above the argument list and
       environment in the process address space.  The auxiliary vector
       supplied to a program can be viewed by setting the LD_SHOW_AUXV
       environment variable when running a program:

           $ LD_SHOW_AUXV=1 sleep 1
```

I can write a quick C program to run `getauxval(3)`, and compare the output.
```shell
kali@transistor:~/ctf/htb-biz-24/rev_satellitehijack$ cat test.c
#include<sys/auxv.h>
#include<stdio.h>
void main() {
    unsigned long test;

    test = getauxval(3);

    printf("%ld", test);
}
kali@transistor:~/ctf/htb-biz-24/rev_satellitehijack$ gcc test.c -o test
kali@transistor:~/ctf/htb-biz-24/rev_satellitehijack$ LD_SHOW_AUXV=1 ./test ; echo
AT_SYSINFO_EHDR:      0x7ffcdbb40000
AT_MINSIGSTKSZ:       1776
AT_HWCAP:             178bfbff
AT_PAGESZ:            4096
AT_CLKTCK:            100
AT_PHDR:              0x559be40f7040
AT_PHENT:             56
AT_PHNUM:             13
AT_BASE:              0x7ff1ecdf0000
AT_FLAGS:             0x0
AT_ENTRY:             0x559be40f8060
AT_UID:               1000
AT_EUID:              1000
AT_GID:               1000
AT_EGID:              1000
AT_SECURE:            0
AT_RANDOM:            0x7ffcdbaf72e9
AT_HWCAP2:            0x2
AT_EXECFN:            ./test
AT_PLATFORM:          x86_64
AT_??? (0x1b): 0x1c
AT_??? (0x1c): 0x20
94128034508864
kali@transistor:~/ctf/htb-biz-24/rev_satellitehijack$ python3 -c 'print(hex(94128034508864))'
0x559be40f7040
```

Now we know that 3 corresponds to `AT_PHDR`, which the documentation says returns "the address of the program headers of the executable". This address then gets passed into another function, which looks *extremely* beefy.

```c
long FUN_001021a9(long hdr_address,char *str_read)

{
  int iVar1;
  long lVar2;
  uint *puVar3;
  int local_54;
  int local_50;
  int local_4c;
  long local_48;
  long *local_40;
  ulong local_38;
  long *local_30;
  
  lVar2 = hdr_address + *(long *)(hdr_address + 0x20);
  local_48 = 0;
  local_40 = (long *)0x0;
  local_38 = 0;
  for (local_54 = 0; local_54 < (int)(uint)*(ushort *)(hdr_address + 0x38); local_54 = local_54 + 1)
  {
    if (*(int *)(lVar2 + (long)local_54 * 0x38) == 2) {
      for (local_30 = (long *)(hdr_address + *(long *)(lVar2 + (long)local_54 * 0x38 + 8));
          *local_30 != 0; local_30 = local_30 + 2) {
        if (*local_30 == 6) {
          local_48 = hdr_address + local_30[1];
        }
        else if (*local_30 == 5) {
          local_38 = hdr_address + local_30[1];
        }
        else if (*local_30 == 0x17) {
          local_40 = (long *)(hdr_address + local_30[1]);
        }
      }
    }
  }
  if (((local_48 != 0) && (local_38 != 0)) && (local_40 != (long *)0x0)) {
    local_50 = -1;
    for (local_4c = 0; (ulong)(local_48 + (long)local_4c * 0x18) < local_38; local_4c = local_4c + 1
        ) {
      puVar3 = (uint *)(local_48 + (long)local_4c * 0x18);
      if ((*puVar3 != 0) && (iVar1 = strcmp((char *)(local_38 + *puVar3),str_read), iVar1 == 0)) {
        local_50 = local_4c;
        break;
      }
    }
    if (-1 < local_50) {
      for (; *local_40 != 0; local_40 = local_40 + 3) {
        if ((ulong)local_40[1] >> 0x20 == (long)local_50) {
          return hdr_address + *local_40;
        }
      }
    }
  }
  return 0;
}
```

If I was a good, patient reverse engineer, I'd go through and I'd relabel all of the variables and try and make sense of every line. That said, it would be extremely tedious to do so. Focusing on the only standard library call here, `strcmp()`, we can see that we're comparing some value to the string input, which, in this case, is `read`.

`read` is a standard function name, and we passed the base address of the program headers to this function. If we trace the values of `local_38` and `puVar3` back, we see that `local_38` is first defined as some addition of `hdr_address` to `local_30`, the latter of which is the index for the for loop. All of this is to say that we have sufficient reason, between the loops, variables, and parameters, to assume that this function is traversing the program headers to find the address of `read()` in memory. If our hypothesis is wrong, we can always revisit this and try to understand it better (which we do in Beyond the Flag).

Returning to the `if_env_not_null()` function, we can relabel the function to have it make more sense.

```c
void if_env_not_null(void)

{
  ulong hdr_address;
  void **addr_of_read;
  void *__dest;
  
  hdr_address = getauxval(3);
  addr_of_read = (void **)get_func_addr_maybe(hdr_address & 0xfffffffffffff000,&str_read);
  __dest = mmap((void *)0x0,0x2000,7,0x22,-1,0);
  memcpy(__dest,&str_lots_of_stars,0x1000);
  memfrob(__dest,0x1000);
  *addr_of_read = __dest;
  return;
}
```

To sum up what we have here:
- We get the base address of the program headers in memory
- We traverse the bytes in memory to find the location of the `read()` function
- `mmap()` is called to allocate a new mapping of virtual memory containing the bytestring of all of the starts (0x1000 bytes!)
- We call [`memfrob()`](https://man7.org/linux/man-pages/man3/memfrob.3.html), which, according to the docs, simply XORs the specified number of bytes with 42. Weird function, but at least this means we can figure out what those stars mean.
- We copy the decrypted bytes into where the code for the `read()` function would normally exist.

A very interesting way for the binary to modify itself! I can copy out the bytes of `str_lots_of_stars`, and then decrypt it in Python. 

```python
#!/usr/bin/env python3
lots_of_stars = '6b7d6b7c6b7f6b7e7f7962a9c622a3d163a3df62a3f<...trim...>'
read_obf = bytes.fromhex(lots_of_stars)

with open('hijacked.bin', 'wb') as fd:
    for b in read_obf:
        fd.write(bytes([b ^ 42]))
```

## A Hijacked Function
Knowing that these bytes get copied into where ever `read()` is defined, we can reasonably assume that this is a new function. To confirm this, we can throw these raw bytes into Ghidra- if we did our job right, we should get a decompile. We'll have to specify the language and compiler as Intel/AMD 64-bit x86, but once we do, we get some clean output.

```c
ulong FUN_00000000(int param_1,long param_2,long param_3)

{
  int iVar1;
  ulong uVar2;
  long lVar3;
  
  uVar2 = FUN_000001a4();
  if (((param_1 == 1) && (-1 < (long)uVar2)) && (4 < uVar2)) {
    lVar3 = param_2 + 4;
    do {
      if ((*(int *)(lVar3 + -4) == 0x7b425448) &&
         (iVar1 = FUN_0000008c(lVar3,(param_3 + param_2) - lVar3), iVar1 != 0)) {
        FUN_00000109(param_2,0,uVar2);
        return 0xffffffffffffffff;
      }
      lVar3 = lVar3 + 1;
    } while (lVar3 != param_2 + uVar2);
  }
  return uVar2;
}
```

While we do have three other functions within this main one, the `0x7b425448` in the if statement sticks out to me, as those are all printable bytes. `pwntools` comes with a nifty `unhex` script to decode hex on the command line:

```shell
kali@transistor:~/ctf/htb-biz-24/rev/rev_satellitehijack$ unhex 7b425448
{BTH
```

That is the beginning of our flag! Of course, we have to account for endianness again, but we're close. I'll skip `FUN_000001a4()` to dive right into `FUN_0000008c()`, which comes immediately after the if statement. As it's structured very similarly to the code that obfuscated the `SAT_PROD_ENVIRONMENT` variable, we can go ahead and relabel values to make some sense of the function.

```c
long check_flag(long param_1,long param_2)

{
  long index;
  undefined8 flag_enc1;
  undefined5 flag_enc3;
  undefined3 flag_enc2;
  undefined5 flag_enc5;
  undefined8 flag_enc4;
  
  flag_enc1 = 0x37593076307b356c;
  flag_enc3 = 0x753f665666;
  flag_enc2 = 0x3a7c3e;
  flag_enc5 = 0x784c7c214f;
  flag_enc4 = 0x663b2c6a246f21;
  index = 0;
  if (param_2 == 0) {
    return index;
  }
  while( true ) {
    if ((char)(*(byte *)(param_1 + index) ^ *(byte *)((long)&flag_enc1 + index)) != index) {
      return 0;
    }
    index = index + 1;
    if (param_2 == index) break;
    if (index == 0x1c) {
      return 1;
    }
  }
  return 0;
}
```

The flag is encrypted and contained across all of the `flag_enc*` variables, and it's compared to the user input passed in `param_1`. The while loop XORs the bytes together, and checks if the result is equal to the index, i.e. the XOR of the two strings should be `\x01\x02\x03\x04...` until we reach the end. Given the properties of XOR, we can simply XOR the bytes in this function with what we want the output to be (`\x01\x02\x03\x04...`) to recover the original flag. After finagling with the encrypted bytes, we get this.

```python
Python 3.11.7 (main, Dec  8 2023, 14:22:46) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> enc = bytes.fromhex('6c357b30763059376656663f753e7c3a4f217c4c78216f246a2c3b66')
>>> dec = []
>>> for i in range(len(enc)):
...     dec.append(i ^ enc[i])
...
>>> print(bytearray(dec))
bytearray(b'l4y3r5_0n_l4y3r5_0n_l4y3r5!}')
```

And that's it! There's our flag.

**flag**: `HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}`

## Beyond the Flag
Traversing memory is something I'm more familiar with in the malware development world, where, for example, people walk the PEB (process environment block) to do things like overwriting a specific section to masquerade as a different process. That said, I haven't really seen it done in Linux until now, so exploring the traversal function we skipped past earlier is something that interested me. Taking a look at the first part, we can (roughly) break it down like so:

```c
  base = addr_program_hdr + *(long *)(addr_program_hdr + 0x20);
  local_48 = 0;
  local_40 = (long *)0x0;
  local_38 = 0;
  for (index = 0; index < (int)(uint)*(ushort *)(addr_program_hdr + 0x38); index = index + 1) {
    if (*(int *)(base + (long)index * 0x38) == 2) {
      // ...trim...
    }
  }
```

This documentation from [Oracle](https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html) (which I'm 50% sure is copied from the Linux spec but this showed up first in Google) actually does a not so bad job of explaining a lot of the structure of program headers in the ELF file format. The `for` loops make it clear we're iterating off of whatever base we came from, which I'm inclined to say is the base of the program headers and not the base of the binary. However, we do end up making the comparison `*(int *)(base + (long)index * 0x38) == 2`.

This is likely some kind of constant we have to figure out. According to the Oracle documentation, a program header is defined as follows:
```c
typedef struct {
        Elf64_Word      p_type;
        Elf64_Word      p_flags;
        Elf64_Off       p_offset;
        Elf64_Addr      p_vaddr;
        Elf64_Addr      p_paddr;
        Elf64_Xword     p_filesz;
        Elf64_Xword     p_memsz;
        Elf64_Xword     p_align;
} Elf64_Phdr;
```

To make sense of this, let's think about what should probably happen based on our early analysis. We're pretty confident the ultimate goal of the binary is to hijack the `read()` function, which, if you're familiar with binary exploitation techniques, is easiest to do if you overwrite the Global Offset Table (GOT). If you're not as familiar with the technique, this [CryptoCat](https://www.youtube.com/watch?v=KgDeMJNK5BU&list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94&index=10) should give you a rough idea of what we're working with.

After looking at what possibilities '2' could correspond to in the struct's members, we can guess that this loop is looking for `p_type`, specifically the `PT_DYNAMIC` type. `PT_DYNAMIC` specifies dynamic linking information, which would make sense as libc is dynamically linked and accessed. Once we find a dynamic header, we enter another loop:

```c
	for (local_30 = (long *)(addr_program_hdr + *(long *)(base + (long)index * 0x38 + 8));
          *local_30 != 0; local_30 = local_30 + 2) {
        if (*local_30 == 6) {
          local_48 = addr_program_hdr + local_30[1];
        }
        else if (*local_30 == 5) {
          local_38 = addr_program_hdr + local_30[1];
        }
        else if (*local_30 == 0x17) {
          local_40 = (long *)(addr_program_hdr + local_30[1]);
        }
      }
```

Notice how the pointer nonsense is now accessing `index * 0x38 + 8` as opposed to `index * 0x38`- this means we're inspecting inside the structure of this dynamic section, which Oracle documents [here](https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblk/index.html#chapter6-42444). This structure looks like this:

```c
typedef struct {
        Elf64_Xword d_tag;
        union {
                Elf64_Xword     d_val;
                Elf64_Addr      d_ptr;
        } d_un;
} Elf64_Dyn;
```

`d_val` represents some constant that's interpreted, while `d_ptr` represents virtual addresses. The if-else statements are comparing single constants, so it look like we care about the values of `d_val`. Reading the docs, we can relabel like so:

```c
	for (local_30 = (long *)(addr_program_hdr + *(long *)(base + (long)index * 0x38 + 8));
          *local_30 != 0; local_30 = local_30 + 2) {
        if (*local_30 == DT_SYMTAB) {
          local_48 = addr_program_hdr + local_30[1];
        }
        else if (*local_30 == DT_STRTAB) {
          local_38 = addr_program_hdr + local_30[1];
        }
        else if (*local_30 == DT_JMPREL) {
          local_40 = (long *)(addr_program_hdr + local_30[1]);
        }
      }
```

- `DT_SYMTAB` refers to the address of the symbol table
- `DT_STRTAB` refers to the address of the string table, which stores names for symbols
- `DT_JMPREL` is the "address of relocation entries associated solely with the procedure linkage table", or in other words, the offset of the `.rela.plt` section.

The for loop ends when `local_30 != 0`, which corresponds to `DT_NULL`, which is the end of the dynamic array.

So, to recap what we have so far, is that we've located the program header that is of type `PT_DYNAMIC`, and pulled down the address of the symbol table, string table, and `.rela.plt` section. Keeping the goal of overwriting the GOT in mind (and the fact that the "read" string hasn't come into play yet), we probably need this information to actually find our way back to the GOT. Let's take a look at the next bit (having relabeled some local variables with our newfound information):

```c
  if (((symtab != 0) && (strtab != 0)) && (jmprel != (long *)0x0)) {
    local_50 = -1;
    for (index2 = 0; (ulong)(symtab + (long)index2 * 0x18) < strtab; index2 = index2 + 1) {
      puVar2 = (uint *)(symtab + (long)index2 * 0x18);
      if ((*puVar2 != 0) && (iVar1 = strcmp((char *)(strtab + *puVar2),str_read), iVar1 == 0)) {
        local_50 = index2;
        break;
      }
    }
// trim...
```

The very first if statement should be simpler to follow; as long as the addresses of those sections are not null, we continue. After declaring some `local_50`, we enter another for loop where we're reading through whatever the `symtab` has in it, and accessing some member of its struct, since Ghidra is throwing more weird pointer arithmetic at us. Docs on [symtab](https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblj/index.html#chapter6-79797) can be used to look at this once again, but based on the call to `strcmp` including the "read" string, I think we can reasonably assume this first loop is walking the symbol table and string table looking for "read". Once we find the string, `local_50 = index2`, which is probably the index of the symbol. But what happens to `jmprel`?

```c
    if (-1 < read_index) {
      for (; *jmprel != 0; jmprel = jmprel + 3) {
        if ((ulong)jmprel[1] >> 0x20 == (long)read_index) {
          return addr_program_hdr + *jmprel;
        }
      }
    }
  }
  return 0;
```

We iterate by adding 3 to `jmprel` and check if some right-shifted version of `jmprel` is equal to `read_index`. I'll be totally honest, I don't entirely know what the `>> 0x20` is for. It definitely means something, but in the time I had to investigate this, I wasn't able to put a precise definition on it.

***Edit:** There is an official writeup of this challenge [here](https://github.com/hackthebox/business-ctf-2024/tree/main/reversing/%5BHard%5D%20SatelliteHijack) that can tell you exactly what struct this is and what these numbers correspond to, I'm just giving the vibes based answer at this point.*

Ultimately, what we do know is that this section returns the address we need to hijack `read()`, which we have guessed is in the GOT. Recall that `jmprel` has to do with the Procedure Linkage Table (you can find a good, high-level explanation of that from [ir0nstone](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got#the-plt-and-got) ). The oversimplified answer is that when you run a binary and call a linked function, the PLT is responsible for redirecting execution to the GOT entry for the function, or resolving where that function is and then redirecting you to it. Knowing this, I'm very comfortable with sitting on my hypothesis that this section of code is what finally figures out where the GOT entry is.

Now, if you're someone who to truly understand why this works, you're already a much better reverse engineer than I am. The truth is, from the Ghidra output and assembly alone, I do not currently have the Linux internals knowledge to give a 100% correct answer as to how we go from PLT to GOT, and I would rather show ways that you can compensate for this than act like I just knew exactly how this worked.

To wrap this up, the reason I liked this challenge was because it's honestly extremely approachable. The technical details of what the binary does are extremely complex, but by striving to see the big picture instead of getting hooked on why a single assembly instruction is doing X instead of Y, we can spend our time more wisely, and then revisit the grittier "why-s" to go even deeper. The cycle, of course, continues after that.

If there are any technical inaccuracies here, please let me know! Until next time!

:D