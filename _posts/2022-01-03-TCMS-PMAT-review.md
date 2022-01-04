---
layout: post
title: Reviewing TCMS Practical Malware Analysis and Triage
image: ''
date:   2022-01-03 12:00:00
tags:
- beginner
- tcms
- malware-analysis
- reverse-engineering
- review
description: ''
categories:
published: true
comments: false
---

![asdf](https://an00brektn.github.io/img/pmat/Pasted image 20220103231305.png)

## Intro
Hello! It's been a hot minute. I guess you could said haven't said anything here since *last year*..

\*Cue Seinfeld [music](https://www.youtube.com/watch?v=_V2sBURgUBI)\*

But in all seriousness, it's a new year, and what better way to break it in than a new course review! Yes, that's right, I spent two weeks hunched over my laptop, grinding, to learn more about the wonderous world of malware analysis, and let me tell you, wonderous it is.

Since last time I wrote a course review, I have a better grasp on how I like to format things, so let's just jump right into the details.

* buh
{:toc}

## Before the Course
Looking at myself before the course and after, I can say, up front, that I've learned quite a bit. But before we get there, let's understand where I was at before PMAT. Let's say we're doing a CTF, and there's some forensics challenge that has to do with malware. Here's my methodology from maybe a month ago.

- Pray it's a maldoc
	- Use `olevba`
	- Get a headache from looking at obfuscated code and trying to deobfuscate by hand
- If not a maldoc...
	- `strings Malware.exe | grep "flag{"`
	- If the above doesn't work, shove it into Ghidra and pray the decompiled output looks nice.

So clearly, I was doing a lot of praying. I had a Windows machine from doing buffer overflows and trying to do Active Directory in a local lab, but even if I ran malware on that, I probably wouldn't know where to look for anything. My malware analysis knowledge was pretty much just the top two John Hammond videos on this [playlist](https://www.youtube.com/playlist?list=PL1H1sBF1VAKWMn_3QPddayIypbbITTGZv) (I should probably watch more), and it shows.

## Course Details
![asdf](https://an00brektn.github.io/img/pmat/Pasted image 20220104000134.png)
Enter [Practical Malware Analysis and Triage](https://academy.tcm-sec.com/p/practical-malware-analysis-triage), taught by [HuskyHacks](https://huskyhacks.dev/) (pictured above). Since its announcement and release around October 2021, I had been planning to pick it up at some point, but I was lucky enough to actually win it in a giveaway. So I guess **DISCLAIMER: I didn't pay for the course (but I was going to buy it anyway)**. Some additional notes:
- **Price**: $30, but TCM Academy frequently has sales for 25-50% off.
- **Length**: 9 Hours (obviously depends from person to person)
- **Misc.**: Like all TCMS courses, buying the course gives you lifetime access to all updates and lectures. 
	- There is also a Discord available so you can chat with other students and get support from HuskyHacks if you're having any issues

After going through great detail on setting up a safe lab environment (which I liked a lot), the course teaches malware analysis in progressing through a methodology: basic static analysis, basic dynamic analysis, advanced static analysis, and advanced dynamic analysis. It then introduces some modern trends in malware, including:
-   PowerShell and VBA
-   Golang binaries
-   Mobile applications
-   C# and the .NET Framework

After a bossfight (more on that later), the course covers the basics of report writing, YARA rules, and automation, and the course leaves you with some additional resources to pick up from. 

Unlike my [last review](https://an00brektn.github.io/TCM-PEH-review/), I'm not going to go through excruciating detail about each concept taught because I realize how painful that is to read (and for me to type).

## So What Did You Think?
It was really good. Yep. 

![drake](https://c.tenor.com/k4SFOI_3m30AAAAM/drake-clap.gif)

To be more specific, I think the idea of reverse engineering any kind of binary in general has always eluded me because of my lack of methodology and fear of assembly. Until taking the course, it didn't really appeal to me as it just seemed like it was for CTF players who were smarter than me, analysts and researchers who were smarter than me, or speedrunners looking to get code execution on Paper Mario (yes, this is a [real thing](https://www.youtube.com/watch?v=O9dTmzRAL_4)), who were smarter than me.

The real benefit of this course is how approachable it is. My lack of methodology was remedied by the fact that the course basically walks you through each of the major phases of analysis. You begin by simply looking at the hardcoded strings and structures in an executable (maybe there's a URL, an IP Address?), then learn how to execute and observe malware in action to get more info. This process is basically repeated in the "advanced" phases, where you then look at disassembled code and put malware through a debugger to get a more granular look at things.

![code](https://an00brektn.github.io/img/pmat/Pasted image 20220103233418.png)
<sup>hmm... yes... *a s s e m b l y*</sup>

From a beginner's perspective, this course works so well because of how it is paced and manages to treat its topics. It starts lightly, relating the analysis to concepts that anybody with some computer science knowledge should understand, and then slowly pushes you towards looking at the more "complex" and nuanced side of things, like assembly and architecture. Additionally, the course is benefitted by its video medium, allowing concepts to almost entirely be communicated via lab examples. It's the difference between reading about a portable executable, or actually looking at the components in something like PE Studio.

It's by no means all-encompassing. The topics like Powershell and Golang mentioned above are discussed for maybe 10-20 minutes each at most. However, the point of the course, at least how I see it, is to give you the tools, techniques, and ideas to be able to figure things out on your own. There's no better example of this than the "bossfight", [WannaCry](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack).

### Do I Hear Boss Music?
![asfd](https://an00brektn.github.io/img/pmat/Pasted image 20220103234243.png)
<sup>Cosmo's a real trooper for having to constantly get encrypted and stolen</sup>

At the beginning of the course, after setting up the lab, the first thing you do is detonate Wannacry, arguably the most infamous example of ransomware. As you set it off, you see everything on the VM get encrypted, the background change, and the ransom note pops up, and all you're really told is that "We will build up to this point." 

Originally, I imagined that by the time I reached reach Wannacry, I'll somehow be a full-on expert. As a student in university, you hear about stuff like ransomware all of the time without ever getting the chance to actually see it in action. You hear about how it devastated hundreds and thousands of computers, and it feels like myth because you've never actually seen it happen, and even if you did, you probably didn't know what to do about it. 

I write all this because I think the bossfight was the most impactful moment of the course for me. After learning how to use a debugger to gain futher insights, and being introduced to other non-portable executable samples, you're pretty much thrown headfirst into the analysis. The course had two challenges before this, but they were much smaller samples to parse through. While it is true that WannaCry is more complex than either of the two challenge binaries in the course, going through the "bossfight" gives one a deeper appreciation for the techniques learned in the course, as, if done correctly, they can help unearth a good majority of the secrets within the sample. All in all, it serves as a good way to mark the beginning of the end of the course, telling you "Hey, you know the basics, go do cool stuff now!"

## Wrapping Up
So when I say,

> "*It was really good. Yep.*" 

I mean it. My only criticism, if anything, is that there wasn't more content. Obviously, the field changes constantly, so there's a line to be towed between how much is and isn't covered. But, as Squiblydoo notes in their [review](https://squiblydoo.blog/2021/11/26/review-practical-malware-analysis-and-triage-pmat/), there's some more advanced concepts that PMAT doesn't cover, like anti-analysis techniques, malware beyond the user-level, etc. I would also add that the section on report writing could use an actual filled-in example to walkthrough rather than a general outline, but none of this really detracts too much from the actual course.

If it isn't already obvious, I had a blast going through this course, and I'm excited to do actual malware analysis going forward, armed with knowledge beyond just malicious scripts. Going forward, I plan on reading through [Practical Malware Analysis](https://nostarch.com/malware), the spiritual ancestor to this course, and will hopefully have some more blog posts here on real samples (or maybe reports at my [repository](https://github.com/An00bRektn/malware-analysis-reports)?).

I **highly recommend** this course to pretty much anyone in a security field who isn't familiar with the subject. If you're a blue teamer, the benefits are pretty obvious. Learning the basics of what malware looks like and how to identify it will only make it easier to defend and respond to incidents, and do better risk assessment. If you're on the offensive side of things, doing malware analysis is also beneficial, not only because it will inform your evasion techniques, but it will also probably end up teaching you more about certain TTPs in practice. And to those in cyber-related management/policy/law, if you have any interest in computer science, this will teach you about what threats actually look like. It's one thing to hear "a ransomware cryptoworm" compromised critical infrastructure, it's another thing to understand the impact it may have on a computer-level, so you can make better informed policy decisions.

In conclusion, malware analysis is pretty neat, and I like it. :D