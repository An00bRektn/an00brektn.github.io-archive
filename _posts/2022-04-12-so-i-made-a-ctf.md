---
layout: post
title: "How I Accidentally Made a CTF and Why You Should Too"
image: ''
date:   2022-04-12 00:00:00
tags:
- info
- ctf
- ctfd
- docker
- microsoft-azure
- event
description: ''
categories:
published: true
comments: false
---

![asdf](https://an00brektn.github.io/img/flyer-ctf/Pasted image 20220412145842.png)

## Intro
Welcome back to the blog, it's almost been 3 months since I posted last, but I have a good reason for doing so. In the last 3 months, I've done a lot of learning, a lot of developing, ~~a lot of procrastinating~~, but as the title would suggest, yeah, I made my own CTF.

At the beginning of the year, I told myself that I would spend this year getting into content creation, namely cyber content creation, and while that originally was planned to be machines for TryHackMe and HackTheBox, after playing in a few CTFs, I felt motivated to make my own, in the exact way that I would want to.

If you didn't hear about the event at all, there was a reason, I kept it within the bounds of my school, [UNIVERSITY_NAME].  There were a couple of reasons for this:
1. I am dumb and do not know how to make good challenges that would be considered "hard", while not being overly guessy/obscure/stupid.
2. I am poor and cannot afford servers to manage a load of potentially 50+ people, 5 of which I know for sure are going to try and use `nmap`, Metasploit, `gobuster`, etc. because all they know is point-and-shoot.

I wasn't even planning to make this a school-wide thing, it was just meant to be constrained to my local club's members. But, because I had invested so much time into it, I decided I should market and open it up to anybody on campus. This blog post is here to talk through the process of challenge creation and design, deployment, and any additional thoughts I may have. So, with the preface out of the way, let's talk about it!

![writer's block](https://c.tenor.com/V2V6vcJlnVcAAAAM/i-got-nothing-nick-miller.gif)

## Part I: Make it good, Make it great
When you first set out to make an event like this, and you're sitting down to start planning out what challenges you're going to make, there are a few things you need to keep in mind for your content to be successful.

### 1. Who's Playing?
As many of you may know, a CTF can have a wide, wide range of difficulty. You can have the simplest of challenges like decoding a basic substitution cipher, to insane 0day discoveries like you'd see in [Real World CTF](https://realworldctf.com/). Deciding what the difficulty will be is then heavily dependent on who is playing.

You could be working with complete beginners looking to get their toes wet with Computer Science and Security, and in that case, it would be inappropriate to try and drop some kind of crazy XSS challenge where you bypass a strict CSP and filter. On the other side of the spectrum, you could be working with people with multiple years in the field, and as a result, babying them with a simple base64 decoding challenge or basic SQL injection would also be inappropriate.

Now, that being said, you should not be afraid to push beginners outside of their comfort zone, and you also shouldn't be afraid to force experts to look back at the fundamentals. And with that in mind...

### 2. What are the things I want to teach/highlight?
Good CTF challenges, at the end of the day, should have the goal of teaching something. If you know your players are experts, throwing a simple buffer overflow with no twists is kind of a waste of time and energy. However, as mentioned eariler, fundamentals are not bad. Take this [Vader](https://www.youtube.com/watch?v=DRgpQvraTUo) challenge from the Space Heroes CTF that I saw recently. It's a spin on the classic ret2win challenge with paramters, but it makes it interesting for people who only know that basic challenge by introducing 5 parameters and making them pointers. There's no guarantee that this might be a fully original idea, but it certainly isn't seen very often, and is a good step up for a beginner that might have just learned about using gadgets to pass parameters into functions. 

### Putting it Together
If you have good ideas that are able to acknowledge and respect these two questions, your challenge is probably going to be pretty solid. In my case, I was dealing with a group of people who largely weren't that involved in the CTF scene, so while they had a decent academic background, they likely hadn't done real reverse engineering or really developed a methodology to discover vulnerabilities. 

![Pasted image 20220412173902.png](https://an00brektn.github.io/img/flyer-ctf/Pasted image 20220412173902.png)
<sup>Web development is "fun"</sup>

As a result, most of my challenges were pretty textbook for a CTF. However, I did make it a priority to make it possible for a person who was familiar with security/computer science concepts to be able to solve at least one challenge from every category, as long as they had the right mindset. For instance, the Cryptography category was structured like this:

- **(Easy) Two Time Pad**: A pcap file where when examined, shows a conversation between two criminals about a code word. Unfortunately, one of them reused the key in their One Time Pad, and the other accidentally sent back a decrypted version of one of the ciphertexts, so you basically XOR everything together to get the real flag.
- **(Medium) Uno Reverse Card**: The Affine Cipher. This one was just about using a modular inverse, or recognizing that you could run the encryption algorithm on the ciphertext repeatedly to eventually get to the flag again.
- **("Hard") Back to the Future:** This one wasn't really "hard", but I didn't want to throw RSA in there. The flag is encrypted using ChaCha20 (which if you know encryption, you know that you're probably not breaking it in 48 hours), but the seed used to generate the key is `int(time.time())` in Python, so you just bruteforce all previous times.

None of these challenges were remarkably new or novel, but they were fairly new to the people I was making them for, and that's what made them good. The people that knew encryption had fun trying to work backwards on Uno Reverse Card and Back to the Future because they didn't necessarily get to do that in their Encryption class, and the people who were new to Crypto learned something by doing Two Time Pad.

> Although Two Time Pad was intentionally made easier by providing two ciphertexts encrypted with the same pad, and a decrypted version of one of those ciphertexts, two people who solved the challenge actually ended up doing the crib drag anyway. This was overkill, but talking with them afterwards, they did learn a lot about the one time pad.

![asdf](https://an00brektn.github.io/img/flyer-ctf/Pasted image 20220412172608.png)
<sup>The resource graph of the deployments, minus the 6 different snapshots I took.</sup>
## Part II: All Systems Go!
Okay, so you've made your challenges, you've tested them thoroughly and made solutions, but you still need to get them deployed. This, for me, was one of the most rewarding parts of putting this project together, because I had never really had to deploy anything in my Computer Science career thus far. Big shoutout to [CSICTF](https://medium.com/csictf/self-hosting-a-ctf-platform-ctfd-90f3f1611587) for putting together a super solid series of posts on how to go about this. I highly recommend reading their posts on setting up the infrastructure, but I'll give a high-level overview of what I did.

Since our club's server was not in operation, I opted to make good use of my student status and use my [Azure for Students](https://azure.microsoft.com/en-us/free/students/) subscription to host the necessary infrastructure. I also used the [GitHub Student Developer Pack](https://education.github.com/pack) to get a domain for free, and I went to work.

![asdf](https://an00brektn.github.io/img/flyer-ctf/Pasted image 20220412172741.png)
<sup>No shot I could have put all of this together in less than 2 months</sup>

Thankfully, I did not have to develop an entire CTF website. The largest, open source CTF framework is [CTFd](https://ctfd.io/) and it's the largest for good reason (not sponsored but it would be cool to be :) ). The project on GitHub comes with basically everything ready to go, all you need is to install [Docker](https://docs.docker.com/engine/install/) and [docker-compose](https://docs.docker.com/compose/install/), and running `docker-compose up -d` in the cloned repo spins up everything for you. There's a Redis and MySQL container to manage accounts and caching, Nginx to do some load balancing and serve the web content, and the actual application itself. 

For any challenges that don't have a deployed instance, the set up is pretty easy from there, as the web front-end takes care of literally everything for you. You can upload challenge files, change the appearance of the page, manage point calculations, and literally anything else you could ever want.

![[Pasted image 20220412173623.png]]
<sup>It isn't pwn if there isn't some roleplaying...</sup>

For the deployed challenges (i.e. Web and Pwn), you'll need to do a little more work. CTFd doesn't have "deploy" buttons in their free version, so you'll have to do it yourself, unless you want to pay them (but I lack money). Now, if you're smart, you'll use Kubernetes and Docker to make a cluster that anyone can access and blah blah container container cloud blah blah.

I knew my event was going to be small so I just threw some docker containers up on some more Azure servers. 🙂

Is it a very extensible solution? No. But did it work? Yeah it did. And now we have a functioning CTF! (\**after we set up the domain to point to the appropriate IP addresses and use [Certbot](https://certbot.eff.org/) to generate a secure certificate and then redirect HTTP traffic to HTTPS and then spend about 3 hours having issues sending requests to the server until you realize that the guide you were reading used nginx on the host, but the repository today has nginx inside a container so you need to remove nginx from the docker-compose file and then remember to set up the network and host based firewalls since this is all public infrastructure and also pray to the infrastructure gods that this stuff doesn't just get found on Shodan and someone decides to DoS me*\* )

![this is fine](https://c.tenor.com/IhgLOL6tLFAAAAAC/this-is-fine-fire.gif)

Yeah so it took me a while to figure all of this out, but the infrastructure held up pretty well!

## Part III: Running the Event
<sup>Yeah I don't have anything witty here</sup>

If there's one thing that could have gone a lot better, it's the marketing for the event. I decided the event date on fairly short notice, and I was missing, arguably, the most important parts:
- **Marketing**: Literally no one knew about the event, and this was the first time anyone (as far as I know) had done something like this
- **Prizes**: Turns out no one really wants to sponsor your event when it's the first time you're doing it and it's not public (looking at you TryHackMe for not responding to my email). This is also, believe it or not, the one thing that would probably draw anyone to competing.
- **Appeal**: It is also hard to do any of the above things when the world is still dealing with COVID, and you've had little to no interaction with your classmates to get any kind of word of mouth going.

I realized I needed to get past these trials, and after a long, arduous journey to get prizes in place and having a logo/branding, and spamming my Computer Science discord nonstop, we had...

![asdf](https://an00brektn.github.io/img/flyer-ctf/Pasted image 20220412165309.png)

...only 13 people registered. Including myself because that's how CTFd works.

Am I upset about that statistic? A little bit. However, I do go to a relatively small school, and I think the more important thing was the "post-product impression". Everyone who participated had a great time and was interested in seeing the event again next year, which is honestly more than I could ask for (because now I have something better than [John the Child](https://github.com/An00bRektn/john-the-child) and [Cyberforce](https://cyberforcecompetition.com/) on my resume).

## Part IV: So what did we learn?
![the more you know](https://c.tenor.com/ZiLugTiVQNgAAAAC/the-more-you-know.gif)
I can definitely say, by the end of this whole ordeal, I have learned a lot of things, and am more excited to finally put together some more challenge content in the future. If I could go back and change a few things:

- **Have a team to work  on challenges.** I went on this mission solo because if nobody showed up to the event, at least the Cyber Defense Club would be able to participate without knowing solutions. Maybe if I had a team to work on things with, I could have spent more time marketing and getting sponsors, but it is what it is. It also would have helped because I know very little when it comes to web developement and cryptography, so having people who specialize in those things could have yielded better work.
- **Implementing CI/CD.** CI/CD is "Continuous Integration and Deployment", and it would have been very useful when patches needed to be applied to challenges and then redeployed. CTFd offers [ctfcli](https://github.com/CTFd/ctfcli) to help implement some kind of process, but I did not use it. However, it would have been in my best interest to keep things organized and standardized, because everything was very messy when I was working on things.
- **Making it Bigger and Better.** Based on the feedback I got, I honestly might consider putting togther a larger event, almost a mini-convention of sorts, with guest speakers and workshops. People would have definitely benefitted from some kind of instruction related to some of the challenges so they could apply that knowledge.

But overall, I'm really happy with how it went, and the amount of learning that happened on my end, and the players' ends, made my way more excited than I thought it would be. Setting up challenges and deploying a whole interface is a super rewarding project for anyone who's been doing CTF stuff for about a year or so, and while I may not do it again next year, I definitely have ideas in store going forward.

![asdf](https://an00brektn.github.io/img/flyer-ctf/Pasted image 20220412174012.png)

You can find the full repository of challenges and source code [here](https://github.com/An00bRektn/flyer-ctf). Since I didn't have a team to work on this, some of the challenges were stolen from other creators because I thought they were very well put together, and so those are put in encrypted zip files out of respect for those creators. Regardless, a majority of it is my own work.

As always, if you made it this far, thank you for reading, and I'll see you ~~in 2023~~ soon<sup>TM</sup> for my next post!