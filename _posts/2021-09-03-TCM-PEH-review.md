---
layout: post
title: Reviewing The Cyber Mentor's "Practical Ethical Hacking"
image: ''
date:   2021-09-03 12:00:00
tags:
- beginner
- tcms
- active-directory
- web
- binary-exploitation
- review
description: ''
categories:
published: true
comments: false
---

![Pasted image 20210902181454.png](https://an00brektn.github.io/img/peh/Pasted image 20210902181454.png)

Over this summer, I had the pleasure of going through The Cyber Mentor's **Practical Ethical Hacking** course found [here](https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course). Full disclosure before I continue: I recieved this course for free through a giveaway that he did a few months ago, and I had gone into this with fairly novice CTF skills. The TL;DR here is that I think the course is phenomenal and that **anyone wanting a straightforward, all-in-one-place introduction to the offensive side of security should go through this**. I will go through the major "arcs", so to speak, of this course, and give my final thoughts at the end.

### Table Of Contents
I did not realize that I was going to type a 3000+ word summary and review of the course but here we are.
* buh
{:toc}

## Act 1: CS Bootcamp - Nets, Penguins, and Snakes
The course, for the most part, assumes that you know very little about security. All you really need to know going into this is how to use a computer, how one works, and what a network looks like, which is a really good start for an introductory level course. After the initial proceedings and advice on notekeeping, the course launches into the following sections.
1. Networking Refresher
2. Introduction to Linux*
3. Introduction to Python
\* *A guide to setting up VirtualBox/VMWare is provided before this*

As someone who had very basic networking knowledge, the networking refresher really **reinforced some of the concepts that I didn't remember** as well (e.g. Subnetting, the OSI model). While it certainly isn't enough to get you to Network Engineering level, it certainly is a *practical* understanding of the subject matter, which is motif seen throughout the course. I did appreciate the subnetting cheat sheet though:

![Pasted image 20210902181454.png](https://an00brektn.github.io/img/peh/Pasted image 20210902195959.png)

I did not pay attention to the Linux and Python sections too much as I already had pretty foundational knowledge already with both. I can't comment too much on the linux section because I have yet to see anything that really makes me go "*Oh wow this actually covers every single base you would ever need to*", which is fine. The only way for people to get really good at Bash is by using it, which you will. 

I will add, the bash scripting video, although it's only 20 minutes, immediately made me so much better bash scripting. I know programming fundamentals, and I still don't like some of the bash syntax very much as compared to other languages. However, the way Heath approaches the task (making an ip sweeper), and his ability to verbally walk you through how to chain together commands like `cat`, `head`, `tr`, and `cut` make the process way more understandable.

Finally, I pretty much skimmed through the Python section because I was already pretty proficient, but I do appreciate the quantity and quality of topics discussed. Not only do primitives and control flow get discussed, but some of the data structures like dictionaries and tuples are added in, along with a brief lesson over socket programming.

Does this first section fully prepare you for the next sections? Yes, but you'll need to be fully engaged with the content if you want to be successful moving forward. All topics covered give a practical, working knowledge; **it's up to you to make the most of it.**

## Act 2: Donning the Hoodie

![hacker](https://an00brektn.github.io/img/peh/Pasted image 20210902215436.png)

The next couple of sections covered have to do with basic exploitation:
- The Ethical Hacker Methodology + Information Gathering
- Scanning and Enumeration + Nessus
- Exploitation Basics
- Capstone

Here, the course begins to get into the "hacking" side of things. It begins with an introduction to the methodology, which, simply put, is:
**Recon --> Enumeration --> Exploitation --> Persistence/Maintain Access --> Clean up**

This sections' lessons follow the same order. Beginning with recon, the course goes over finding emails, hunting breached credentials, subdomain enumeration, and other things you would normally use in an external pentest or bug bounty. Personally, I think this section could be improved upon. While the first half was very OSINT-focused and highlighted tools and methodologies pretty solidly, **I think the second half could use some touching up**. My main issue with it is that is kind of overlaps with the content brought up in the web app attack section, which isn't that big of a deal. Although it is a way to point students to another, more in-depth course, I feel like it is a little bit of filler.

Following this, the course begins to teach some of the enumeration and exploit concepts using the level 1 Kioptrix machine from VulnHub. Again, I skimmed this section having done some CTF content before (I definitely did a deeper dive in the later content, don't worry), but I think this was a very effective way to deliver the information. It was very focused on **documenting your findings, using Google effectively, and a small intro to Metasploit.**

I don't have much to comment on this section because it does what it sets out to do well. All of the basic info like staged vs unstaged, reverse vs bind, etc. was covered pretty well, the capstone is where some of the real learning will happen.

### Capstone
Previously, the capstone was made up of the following 10 Hack The Box machines: Legacy, Lame, Blue, Devel, Jerry, Nibbles, Optimum, Bashed, Grandpa, and Netmon.

These were all "Easy" rated machines, each with their own unique lesson to be learned. However, because relying on a 3rd party for an important part of the course is a little iffy, TCM created a new capstone of their own boxes:
- Blue
- Academy
- Dev
- Butler
- Blackpearl

I have gone and completed both of these, and **I HIGHLY encourage anyone taking the course to do both capstones.** The new capstone certainly has more directed lessons because they had full control over the development, but I think boxes like Optimum and Lame have some very valuable things that you don't always see. I'm not going to talk specifics because I don't want to spoil it, but it is a very good way to transition into being able to do some more complex stuff. You'll learn about handling public exploits, identifying footholds and privilege escalations, applying situational awareness (aka "common sense"), and more.

## Interlude: Ain't Enough Room in this Buffer for the Two of Us...

I had always heard about buffer overflows, but never knew how to do them. Most resources I could find were [theoretical](https://www.youtube.com/watch?v=1S0aBV-Waeo), which was good, but none that showed me the process that well. Enter the "Intro to Exploit Developement" section of the course.

This part of the course was one of my favorite parts (other than Active Directory). Not only was basic usage of Immunity Debugger covered, but automation and "shortcuts" with Mona were also included, which was very useful. The only criticism I have here is the suggestion to attack your host OS (which just isn't a good idea), but spinning up a Windows VM is not that hard.

The execution and process to do the overflow was put together very well. Do I think the theory could have been explained a little bit better? Yes, but there are other places for that.

## Act 3: Attacktive Directory
<sub>i'm sorry i ripped this right from thm but i had nothing else</sub>

![Pasted image 20210902224342.png](https://an00brektn.github.io/img/peh/Pasted image 20210902224342.png)

**I think this section alone is worth it to buy this course.** Active Directory is a very prevalent system in enterprise environments, so it is essential to understand how to abuse and leverage those features. TryHackMe and Hack The Box try their best to provide content on this, but I don't think I have seen anything better than what is covered in this course (as an introduction, obviously).

**Topics Covered, as of September 2021**
- Setting up an AD Lab
- Initial Attack Vectors
	- LLMNR Poisoning, mitm6, SMB Relay, Passback
- Post Exploitation Enumeration
	- Bloodhound and PowerView
- Post Compromise Attacks
	- Pass the Hash, Token Impersonation (although this one isn't really AD), Kerberoasting, GPP/cPassword, URL File Attacks, Golden Ticket, Mimikatz
	- PrintNightmare
	- ZeroLogon

I will talk about each of these sections separately and I'll try to keep it as brief as possible because this is already long as is.

### Making the Lab

I **thoroughly** enjoyed setting up the lab environment. I do all of my stuff from a moderately capable laptop, so I decided I would set up my network with Microsoft Azure in the cloud (my tuition has to be put to good use, ok?). It was a project I had a lot of fun doing, not only because I had guidance from this [blog post](https://kamran-bilgrami.medium.com/ethical-hacking-lessons-building-free-active-directory-lab-in-azure-6c67a7eddd7f), but because it felt like I was really doing some technical work. 

*We are going to ignore the fact that I almost certainly did not think about making a gateway subnet for VPN connections and had to remake the whole virtual network*

![Pasted image 20210902225832.png](https://an00brektn.github.io/img/peh/Pasted image 20210902225832.png)

Did I subnet this properly? Almost certainly not. Did I learn a lot about setting up a virtualized lab environment? ABSOLUTELY. I also enjoyed making my network themed after one of my favorite games of all time, [Transistor](https://www.supergiantgames.com/games/transistor/); I got to give each workstation and the domain controller its own little personality with passwords and notes left around.

### Initial Attack Vectors

This section, after I set up the lab, got me way more invested in Active Directory than anything I had seen before. Learning about LLMNR poisoning, relaying those captured hashes using SMB relays, etc. was something I could see happening very easily and very quietly. One thing Heath points out throughout this series of videos is that only a few things in this lab were actually configured to be vulnerable, and the rest is just default config, which really lets you appreciate the stuff being shown.

In addition to those details, I'm also very happy that he included sections on mitigations to these vectors. Too often do we just want to root a box and call it a day. A pen tester's job is to help improve security, by identifying vulnerabilities that aren't just 0days. 

The pacing was great, and the constant call backs to why certain attacks happened as a result of our configuration was very effective teaching.

### Post Exploitation Enumeration

![i hate jekyll](https://an00brektn.github.io/img/peh/Pasted image 20210903115413.png)

This section was a little bit shorter than the other two because the main focus is just two tools that are VERY good at what they do. I had already had some familiarity with using Bloodhound and PowerView after doing Forest on HackTheBox, but it was nice to learn a little bit more about how to use PowerView other than as an exploitation tool.

### Post Compromise Attacks

This section was *by far* the longest, the most thorough, and insanely informative. It's structured pretty similarly to the "Initial Attack Vectors" section, that is, talk about what the attack does, demonstrate the attack, and then talk about mitigations. The mitigations aren't nearly as "effective" as compared to the initial attack vectors because the attacker theoretically already has foothold, but they are still present. Still, the section is pretty dense with both AD-specific and general Windows privilege escalation content, and I also learned a lot from this section.

One thing that I thing a lot of people notice by this point is that this course is being actively updated and maintained with new developments in the offensive sphere. If you took this course 4 months ago, you would not be seeing the newly added video on PrintNightmare, which is something you don't normally see with online classes. 

Again, this beast of a section is what really made the course for me. I'm sure you can learn this Active Directory stuff by scavenging the internet for blog posts, but having it all in one place, and having it effectively explained is a big plus.

## Act 4: The Legal, the Web, and the Wireless
<sub>it's like the lion the witch and the wardrobe haha get it?</sub>
<sub>why do i even bother when only cs and infosec people are going to see this</sub>

![asdf](https://an00brektn.github.io/img/peh/Pasted image 20210903115502.png)

I've lumped the last few sections together because it mostly serves to tie up loose ends, and give a small introduction to other important things related to the field. The largest section in this last leg is Web App attacks, where the course teaches the OWASP Top 10 through using the OWASP Juice Shop application. This section could very honestly be a course of its own because of how deep web app attacks can go, so only providing an introduction to Injection, Broken Authentication, etc. is a good stopping point in my opinion.

The web app enumeration is a lot more fleshed out and walks you through the thought process when automating your own method. Mitigations are also discussed when going over the OWASP Top 10. It's a pretty good overview, and the course acknowledges that trying to go any deeper with this content would take a lot longer than just teaching the basic idea of SQL injection, or XXE.

The other three sections here are:
- Post Exploitation and Pivoting
- Wireless Hacking
- Legal Writing

Honest opinion, the post exploitation and pivoting lessons could be fleshed out a little bit more. It's only 5 minutes dedicated to file transfers and maintaining access, and then it gets into a pivoting section where all you really do is use `autoroute` from Metasploit. Is it practical? Yeah, I guess. I know that TCM Academy has a whole course on this topic as well, but I think maybe covering a manual tool like `sshuttle` or `chisel` would also be beneficial. I know using Metasploit is more stealthy, but I think having the knowledge to do it manually is just as important, which is why, for learning purposes, I avoid Metasploit. 

If you want to get a lot of pivoting practice in, I recommend trying out [Wreath](https://tryhackme.com/room/wreath), a small network on TryHackMe whose primary purpose is to teach pivoting methods.

As for the videos on wireless and legal documents, I felt like they were pretty good overviews. Wireless hacking isn't as important as it once was, so a quick overview looking at the aircrack-ng suite and using deauth attacks was sufficient enough for me. The legal documentation section was also pretty interesting as I am someone who likes to hear about that kind of stuff. The in-depth look at a real pentest report was pretty intriguing, and I also enjoy learning about the business aspect of things (which I kind of wish was talked about for a little bit longer.)

## Act 5: Final Thoughts

Throughout this summary and review, I have sung my praises, pointed out some flaws/gaps, and highlighted my favorite parts. That being said, I truly believe that this is a great place to begin learning about security. The course accomplishes exactly what it sets out to do, which is to be *practical*. As I've mentioned throughout this review, there are many things that I would have liked to see, but the reality is, a course cannot do everything, especially in a field that changes as much as infosec.

There is so much more to learn outside of the course (AV Evasion, C2 Frameworks, Container Escapes, more Active Directory), and I think the course accepts that, and does try to guide toward those things. All in all, the course sets you up so you can keep going; you cannot just expect that watching a bunch of videos will make you the next big security personality. I do not claim to be  that good; I haven't had a single infosec job yet. But, as a student who wanted to get ahead of a slow curriculum, this was a highly beneficial experience for me.

**Things I might have left out, but are still relevant**
- Amazing support staff on the TCM Discord. They're sticklers on what they will and won't help with (i.e. if it wasn't used in the course, they won't help), but when they do help, it's pretty great.
- **The course is only $30**, and discounts bring it to $15 at least once a month, so the value is actually kind of insane.
- Pretty quick updates to the course when something like PrintNightmare hits
- Transparency with how much depth each lesson goes into; if Heath knows that he's not an expert in a topic, he'll point you to someone who does it better
- Practice setting up infrastructure and lab environments is very cool, and giving people machines to work on locally is a nice plus for beginners
- **I have not taken the PNPT right now, but if I have the time and money after I plan on doing OSCP and/or CRTO, I will**

If you've stuck around for this long, thank you for taking the time to read this almost 3000+ word piece from someone who still has a lot to learn. Hopefully, this is a comprehensive enough look at the course to help sway your decision.

Until next time! (HTB and THM writeups coming soon)

:D
