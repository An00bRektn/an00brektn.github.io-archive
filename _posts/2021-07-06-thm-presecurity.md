---
layout: post
title:  So You Want to Hack? | TryHackMe Pre-Security Path
image: 'https://an00brektn.github.io/img/presecurity-header.png'
date: 2021-07-06
tags:
- tryhackme
- beginner
description: ''
categories:
published: true
comments: false
---

![THMLogo.png](https://an00brektn.github.io/img/thm-presecurity/THMlogo.png)

## Introduction

[TryHackMe](https://tryhackme.com) recently released the their "[Pre-Security Path](https://tryhackme.com/path/outline/presecurity)", a series of lessons intended to establish foundational knowledge for aspiring cyber security people. To celebrate, they've been running a "ticket" event (similar to the Monopoly events at fast-food chains and/or grocery stores) with ~$5,000 available in prizes. They're also asking people to review the path, which is definitely not a coincidence with me starting this blog.

## Act 1: But What is TryHackMe?

[TryHackMe](https://tryhackme.com) is a site that seeks to teach cybersecurity concepts by gameifying them. Rather than have a bunch of lectures that you listen to and take notes on, TryHackMe sets up "rooms" with different tasks to complete, most of which involve some kind of hands-on application. The site is community-driven, meaning anyone can make a room and contribute to the ever-growing catalog of topics (as long as you pass peer-review).

Now, I had already been using TryHackMe as a way to self-learn some of the concepts that I hadn't gotten to yet in university. I was brought in after hearing about their "[Advent of Cyber 2](https://tryhackme.com/room/adventofcyber2)" event, which was an advent calendar style series of tasks, intended to act as a "sampler" of what the infosec field had to offer. However, one of the biggest hurdles I encountered afterward was my lack of a solid CS foundation. I had been going to school for a semester at this point, but I was still trying to get general education requirements out of the way (*\*ahem\** "liberal arts school" *\*ahem\**). 
Eventually, I learned the basics of networking on my own and with TryHackMe, but at the time, it certainly hurt my ability to comprehend concepts fully. What *is* a port, really? Why are we using Linux? Who cares about the OSI model?

## Act 2: Introducing the Pre-Security Path

![presecurity-header.png](https://an00brektn.github.io/img/thm-presecurity/presecurity-header.png)

TL;DR: I honestly wish the pre-security path had come sooner.

The [Pre-Security Path](https://tryhackme.com/path/outline/presecurity) assumes you have basic computing knowledge (and by that I mean you know how to use a computer) and takes you from ground-zero, to having the foundational knowledge needed to begin learning about security. The course outline is as follows:

![presecurity-outline.png](https://an00brektn.github.io/img/thm-presecurity/presecurity-outline.png)

- Cyber Security Introduction
    - [Learning Cyber Security](https://tryhackme.com/room/beginnerpathintro)
- Network Fundamentals
    - [What is Networking?](https://tryhackme.com/room/whatisnetworking)
    - [Intro to LAN?](https://tryhackme.com/room/introtolan)
    - [OSI Model*](https://tryhackme.com/room/osimodelzi)
    - [Packets and Frames*](https://tryhackme.com/room/packetsframes)
    - [Extending Your Network*](https://tryhackme.com/room/extendingyournetwork)
- How the Web Works
    - [DNS in Detail](https://tryhackme.com/room/dnsindetail)
    - [HTTP in Detail](https://tryhackme.com/room/httpindetail)
    - [How the Web Works*](https://tryhackme.com/room/howwebsiteswork)
    - [Putting it All Together*](https://tryhackme.com/room/puttingitalltogether)
- Linux Fundamentals
    - [Linux Fundamentals Part 1](https://tryhackme.com/room/linuxfundamentalspart1)
    - [Linux Fundamentals Part 2](https://tryhackme.com/room/linuxfundamentalspart2)
    - [Linux Fundamentals Part 3](https://tryhackme.com/room/linuxfundamentalspart3)
- Windows Fundamentals
    - [Windows Fundamentals Part 1](https://tryhackme.com/room/windowsfundamentals1xbx)
    - [Windows Fundamentals Part 2](https://tryhackme.com/room/windowsfundamentals2x0x)

\**These rooms require a subscription to have access to. Thoughts on that will be at the end.*

While each room is pretty well designed in its own right, I will briefly touch on each of the modules, excluding the introduction, and then give my thoughts on the end.

## Act 3: Networking (not the LinkedIn kind)

This module takes you from understanding what a network is, introduces you to what framework has been set up to codify networking, and describes the function of networks *practically*. I've always struggled to remember and understand the purpose of each of the layers in the OSI model, and this section really hammers some of the main points home. Obviously, if you're a Network Administrator/Engineer, this is probably a pretty surface level look at what goes on. But, if you're just getting into security, this is a good base of information to build off of. One of my favorite bits was this OSI Dungeon game:

![osi-dungeon.png](https://an00brektn.github.io/img/thm-presecurity/osi-dungeon.png)

Another interactive demo that was especially helpful for someone like me to review was the network topologies viewer:

![ring-topology.png](https://an00brektn.github.io/img/thm-presecurity/ring-topology.png)

Being able to visually see any sort of model is a very useful way to make sure things stick.

## Act 4: 🎵 *We're Surfing on the Internet* 🎵

The Web module covers DNS, HTTP, basic web development, and put those concepts together. Like the network module, it also uses interactive demos to illustrate certain concept. While I personally would have liked to use a real command line to get results, I think having a prebuilt setup is less intimidating to those who aren't as comfortable with getting in the thick of things. I think one of the most effective lessons from this module is the final "Putting it All Together Room", which lightly touches on almost everything you've covered thus far in the course. Not only do you revisit some of the concepts from the web-related rooms, but it also makes you think about how networks play into it.

<p align="center">
    <img src="https://static-labs.tryhackme.cloud/sites/puttingittogether/puttingitalltogether.png" alt="This is where the Beatles famously got their song 'All Together' from" >
</p>


## Act 5: Noot Noot!

I think learning Linux on my own (before this released), was one of the more difficult parts of getting better at security for me. My (limited) programming experience had been exclusively on a Windows host, and breaking away from a GUI and using a command line was jarring at first. I completed the original Linux Fundamentals Rooms on TryHackMe before they were re-released, and then re-released again, but it still took me a while to really understand anything.
The newly redesigned rooms are VERY beginner friendly, and appropriately hold your hand through each new concept. I especially enjoyed the addition of the split screen machine, and then telling you to learn to use `ssh`. It's very nicely progressed, and while I did think the ctf placed at the end of the original rooms was cool, I think removing it for now is very good.

![linuxfund.png](https://an00brektn.github.io/img/thm-presecurity/linuxfund.png)

## Act 6: Windows (how do you make a witty title for this?)

The Windows Fundamentals rooms begin by introducing the main components of the Windows GUI, and then proceeds to get into the nitty gritty parts of things like the registry and UAC controls. While I think it does cover the important stuff associate with Windows, it feels slightly incomplete in certain areas. There is also an Intro To Windows room that's located in the "Complete Beginner" path that I feel belongs in the pre-security path as well, so hopefully it gets the additions that it needs. 
Furthermore, I think a section should be dedicated to navigating Windows' `cmd.exe`, because even now I forget that `dir` is what gets used instead of `ls`. I would also say that Powershell should be added, but there's already a room on that (that needs a little bit of fixing tbh).

## Act 7: Closing Thoughts

For a mostly free course, this is pretty much exactly what I was looking for back in December 2020. It hits just the right balance between holding your hand and making you work for it, and covers the essential topic neccessary to go onward with learning cybersecurity. From a content perspective, the only area that seemed lackluster was the Windows Fundamentals sections. There was a lot to be learned from it, but the importance of those things isn't very well established, so the content doesn't stick as well. If I'm being seriously nitpicky, I think that some sections' questions could have been written better to be a little more engaging (e.g. "What is this layer of the OSI model called?", when there's a huge picture telling you what the answer is), but it is still put together very well.  

As for the subscription model, I think there are a lot of people who will be upset that half of the networking and web sections are stuck behind paywalls. However, I really do not see it as a huge issue. Subscriptions allow the site to stay running, and in doing so, support more of the free content seen on the site. Subscriptions themselves are only $10 ($8 if you're a student), which is the equivalent of about one Chipotle burrito with guacamole. Many people might compare the value of this to a subscription to Hack The Box, but I think that comaprison falls apart very quickly. Yes, Hack the Box has their Academy, but at the end of the day, Hack the Box is mostly for practice, and TryHackMe is mostly for learning. **The value of a subscription largely depends on how you like to learn (e.g. taught course vs self-guided), how much time you can put into this, and how much $8-10 is worth to you.**

I am in no way sponsored or endorsed by TryHackMe, I just think what they're doing is very cool. At the end of they day, although it has its' flaws, the Pre-Security path is a solid choice for those who want to begin learning on their own without too much of a committment, or for experienced people to refresh on some foundational content.

*Update: While I am thankful to TryHackMe for motivating me to write a blog, I am kind of upset my submission was never reviewed. I think it's correct to tell people to relax about getting stuff for free, I didn't appreciate the fact that the fact I wasn't reviewed at all was swept under the table by THM Staff. I respect what they're trying to do, but man do they need to put more than one person on support or something.*
