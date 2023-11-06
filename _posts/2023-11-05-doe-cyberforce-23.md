---
layout: post
title: "I didn't win a national cyber competition, here's why"
image: '/img/cyberforce23/newcfclogo.png'
date: 2023-11-05 00:00:00
tags:
  - cyberforce
  - dfir
  - hardening
  - event
description: "🎶 I'm a, I'm a, I'm an-I'm an anomaly, I turned into a defender ironically"
categories: 
published: true
comments: false
---

<img src="https://an00brektn.github.io/img/cyberforce23/newcfclogo.jpg" style="width:60%;height:60%">

## Intro

It's been a hell of a month. If you follow me at all (if you do, thank you), you'll know that [last year](https://notateamserver.xyz/doe-cyberforce-22/) I "almost won" a national cyber competition, or that I've been [doing this for a while](https://notateamserver.xyz/doe-cyberforce-2021/). For the unaware, every November, the Department of Energy runs a collegiate cyber competition called Cyberforce, where teams from across the US compete to secure infrastructure related to some energy sector related service. This year, the event was exclusively in person, so while it had less attendance (~150-160 last year to ~100 this year), it was far and away the hardest it's ever been.

With it being the third time I competed in this event, and the fifth time I've done a Cyberforce-affiliated event, it's become tradition here to go over the event, the highs, the lows, and everything in between, and let me tell you, there was a lot of all of those things.

* buh
{:toc}

## Part 1: From a Sprint to a Marathon
### Last Time on Cyberforce...
Cyberforce is not like any other Attack-Defense/Red v Blue/Cyber event. For one, since it's run by the Department of Energy, the fictional company you represent is in the energy sector, which means a couple of things. For one, unlike competitions like CCDC or DEFCON CTF, you're not only protecting any old network, but you have Industrial Control Systems (ICS) to take care of. Additionally, there's more than just attack and defense. Cyberforce features scoring in 6 different areas, those areas being:

- **White Team Scoring** - Teams had to fill out documentation including: Statement of Purpose/Scope, a network diagram, a full list of vulnerabilities/findings on 6 machines with remediation steps, and a detailed writeup on how machines were hardened.
- **Orange Team (C-Suite) Scoring** - Teams were required to make a five minute presentation for a fictional C-Suite related to risks with ongoing attacks and what steps your team plans to take to lessen said risks.
- **Green Team Scoring** - Each team had to maintain a company website located on a machine that was in scope of Red Team attacks that volunteers would periodically check in on to make sure it was up. The site was also (supposed to be) integrated with other services on the network, meaning you could be double penalized depending on how you kept services up.
- **Anomaly Scoring** - ~60 CTF-style challenges were also there to be completed on the day of competition, worth about 20% of your team's total score.
- **Blue Team Scoring** - The classic "keep services up" kind of scoring, just make sure the network doesn't die.
- **Red Team Scoring** - Split into two different categories
	- **Traditional** - Half of the network was being attacked both black box-style (meaning hackers actively trying to break in) and by scripted playbooks, you score points for how well you wall them out.
	- **Assume Breach** - The other half was an assume breach exercise, where a red team scorekeeper would already have access to your network, state that an attack has happened, and it was our job to do the IR and tell them what happened.

If words aren't your thing, here's a picture:
![diagram](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221109194018.png)

The network we got was six machines, three of them Windows, three of them Linux. Below is a picture of our topology.

![Pasted_image_20231105182108.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105182108.png)

- **TaskBox (Windows Server 2022)** - Hosted the company website and general services like FTP
- **PublicDB (OpenSUSE 15)** - Not actually a database, hosted NFS and SNMP (both were required to have up, I know)
- **AD/DNS (Windows Server 2019)** - Domain controller for `energy.local`, also had VNC up because they said so
- **CNC (Windows Server 2016)** - Domain controller for `edr.energy.local`, also hosted a Human Management Interface (HMI) to interact with Distributed Energy Resources (DER), which could provide bonus points
- **WebServer (CentOS 7)** - Hosted a duplicate company website and mail services (I'm only now realizing that SMTP is on there twice and we totally got docked points for that)
- **PLC (Ubuntu 18.04)** - Industrial Control System which simulated the communication for DER units that you would read in the HMI

The increased Active Directory usage, as well as requiring services such as SNMP or VNC that I would normally just not use in a network make managing everything even harder than it's been in past years. Speaking of things that got harder, let's talk about how things changed.
### Becoming a Salaryman (Minus the Salary)
Another unique aspect of Cyberforce is that everything is slightly different every year, for better or for worse. Normally, we get two to three weeks of prep time, where security documentation is due in two weeks, but everything can basically be done at the team's leisure and you just have to be ready for game day.

✨ *Not this year!* ✨

Work was trickled out on a per-week basis. For the first week, we were given a short blurb about the business (DER8.9), and then had a week to prepare a risk assessment presentation without knowing the network topology at all. The next week, we finally got access to our machines in AWS, so we had to then write the documentation and finish that in a week (ours was 18 pages\*). Finally, for the last week leading up to the competition, we actually finally had time to not only harden and configure machines, but to also set up logging and monitoring software (a lesson we learned from last year).

If words aren't your thing, here's a picture that's as equally professional as the diagram from before:
![Pasted_image_20231105180516.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105180516.png)

<sub>\*  This doesn't include a bunch of Active Directory vulns we forgot to add because one of the machines had zero disk space and we then forgot to check stuff after that got fixes.</sub>

Professors, if you're reading this and wondering why the quality of my work tanked (or I was showing up to research meetings with basically nothing), this is why.

I'm not going to say it was a bad thing to have the work stretched out like this. For a competition to be as ambitious and give people the full, all-round experience, there is inherently going to be a lot of work. The trickiest part of this is that it's really only brutal for mid to advanced level teams. The beginner teams don't know enough to realize how much work there is to do, and the advanced teams usually have a pretty good spread of skill where everyone can contribute and be efficient. If your team has three beginners and three experienced people, it becomes way more difficult to coordinate and delegate. We definitely got through it in the end, but not without me wanting to hunt people down a few times.

Still, we managed to get through it. There's a reason this section is called "From A Sprint to a Marathon", though. We had spent so much time trying to hone in the C-Suite presentation and documentation that by the time we got around to hardening machines, we were all so exhausted from it already. If you wanted to win, you had to be locked in. And if you wanted to be locked in, time management was harder than it had ever been. 

### No Stone Unturned
In my reflection last year, I shared some tools last year that our team used to automate the process of checking for vulnerabilities. Those were still useful, however, a change I'd like to note is the decreased use of CVEs for vulnerabilities. In previous years, boxes had SLMail 5.5, the pwnkit vulnerability I did a [whole blog on](https://notateamserver.xyz/pwnkit/), and more. This year, unless we missed something obvious, there were definitely a lot less of that, which meant spotting misconfigured services was key.

Here are some highlights:
- The [`zam64.sys`](https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c/) driver installed on every Windows machine could have been (and was used in Assume Breach) to get a `NT AUTHORITY\SYSTEM` shell immediately
- The "Authenticated Users" group was able to DCSync the `energy.local` domain
- A typo-squatted package on the webservers. Both [bcrypt](https://www.npmjs.com/package/bcrypt) and [brcypt](https://www.npmjs.com/package/brcypt) were installed.
- A backdoored Linux PAM module on the OpenSUSE machine allowed access into any account with the password "REDRULZ"

![Pasted_image_20231105185620.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105185620.png)
<sup>everything is fine, this is fine :lemonthink:</sup>

One thing that irks me, and it's entirely my fault, is that when we got the Windows 2016 machine was given to us, the disk was almost full with SQL data. Since it was Assume Breach, we weren't allowed to modify any data that would be used in Assume Breach chains, and we weren't told until about half of the week in how to save some space without getting in trouble. Because of the low disk space, I couldn't run SharpHound, and I didn't want to query LDAP, so we just forgot to audit the second domain altogether, which significantly hurt our documentation score. It's absolutely our fault for not remembering, but that disk issue was irritating and I'm airing it now because I know someone who has the power to fix it will read this.

Aside from the rant, there were a lot of vulnerabilities, so many so that I found a backdoor 20 minutes before documentation was due. Regardless, once documentation was done, it was time to actually build up defenses.

![rake gif](https://media.tenor.com/MOIs-LNQcb4AAAAM/sideshow-bob-rakes.gif)
## Part 2: Learning From Mistakes (and making new ones)
In last year's post, I made a point to say that our logging and monitoring was terrible last year, which it was. We used Sysmon, and basic Linux logging, and that was it. Our responses were slow, because we spent so much time trying to search for things that we didn't know happened. As such, we made it a point to improve.

- We installed [Splunk](https://www.splunk.com/) on all of the Assume Breach machines so we could filter logs fairly quickly, including having Linux add ons to check some basic information.
- We had [Suricata](https://suricata.io/), an intrusion detection system, to check for network level scanning that we got dinged for missing multiple times last year.
- Many of us prepared queries or got much better at filtering events in Splunk or Windows Event Viewer so we didn't deal with as much noise.
- Wireshark and/or `tcpdump` were available in the event we needed to collect some last minute packet data of ongoing attacks.

Thankfully, our work did pay off and we had a much better time scoring assume breach points than we did last year. We picked up Active Directory attacks like it was nothing, and managed to catch a number of ICS related issues when one of our teammates stepped up to dig into how that worked a bit more. Still, we later realized we left ourselves open to a number of issues.

- Since we rushed to get stuff setup (working until 2 am of the competition day), we forgot to install something like [Sysmon For Linux](https://github.com/Sysinternals/SysmonForLinux) to have something better than the default `syslog`.
- The CentOS webserver had basic `httpd` logs, but we forgot to configure anything to log actual request data in the event of web-based attacks. I was able to fib my way through a scenario that involved it by showing vulnerable source code, but that was definitely a problem.
- Resources were upped this year, but between the amount of activity on all of our machines and the under-resourced venue internet, our ability to actually use Splunk was greatly hindered. Even with good indexing, results from queries looked a PowerPoint. 

Overall though, there was significant improvement. With the amount of work we put in prior to the event, some assume breach exercises went down like it was nothing.

![Pasted_image_20231105192242.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105192242.png)
<sup>sometimes you just know</sup>

Other times, even with all of the logging, we just did not know.

![Pasted_image_20231105192608.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105192608.png)
<sup>he was very upset about this on the drive home</sup>

But we're getting ahead of ourselves, what happened on game day?

## Part 3: Ocean Wide, Canyon Deep
### This is Fine
Maybe I don't have that dog in me, but I was absolutely stressed in the days leading up to the competition. Last year it was because we were so far behind, this year it was because things were actually going fairly well and on schedule. As a result, I was *extremely* paranoid. Did we miss vulnerabilities in our documentation? Does everyone know enough that I don't need to be asked questions over and over again? Did we patch all of the vulnerabilities? Are we going to crash Splunk?

![asdf](https://an00brektn.github.io/img/cyberforce23/F9-Y6FeXoAA7rgC.jpg)

Once we got to the venue, though, those concerns had to be thrown out the window. We were back. Same venue. Many same faces, many new. After hanging out and catching up with some people, we headed back to our AirBnB ready to prepare for the event. 

Admittedly, the AirBnB was packed. Nine guys in a one floor house with two bedrooms and one bathroom is not something that I was expecting to happen a month ago. Although I wanted to get to work right away, after everyone trying a Reaper-spicy chicken sandwich, playing some rounds of Smash Ultimate, and struggling to get into the ping pong room, we were back to the grind. No eggnog this time because *someone* decided not to pick it up, but the feeling of determination was in the room once again, albeit a bit spread out with both teams having different priorities. If you're someone who's just trying to get into any kind of computer field, I will tell you right now that very few things beat the feeling of having a LAN party with the common goal being to do great things.


![Pasted_image_20231105194203.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105194203.png)
<sup>If you're ever in Elburn, IL, Paisano's Pizza is pretty good (not sponsored).</sup>

We installed Suricata, Splunk, figured out ICS, and called it a night at 2 am.

### Round 2
We ate breakfast at the Q Center (great food btw, any place with lox and cream cheese bagels is great in my book), and it was time to do the thing, just way more packed this year.

![1699132376280.jpg](https://an00brektn.github.io/img/cyberforce23/1699132376280.jpg)

In fact, it was so packed, that when the event finally started, the bandwidth was completely eaten up. Our primary goals were to (1) handle assume breach exercises, (2) solve anomalies, and (3) defend traditional infrastructure, but we could barely do (1) or (3) because of the internet problems. I don't know if issues ever got better, because one our team members was basically unable to access AWS infrastructure consistently over the course of the whole competition, which sucked.

Eventually, internet issues became tolerable for the rest of us, and it was time to game. If the story of last year was struggling to do Assume Breach, then the story of this year was to solve anomalies. I have previously gone on record to say that the anomalies are usually pretty easy and/or guess-y, but I guess they took great offense to that because this year's were ***brutal***.

It felt as if most of the challenges were either reverse engineering or steganography, and I would have been more than happy to do these if I wasn't bogged down trying to do assume breach. As it turns out, when you know the most about Active Directory and reverse engineering on your team, you've got a ocean's worth of work cut out for you and get spread so thin in the process. A friend of mine who wrote anomalies for the event had an entire four-part Nim reversing challenge for ~200 points, and I was barely able to touch it because of how busy I was trying to coordinate other things. 

![Pasted_image_20231105202107.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105202107.png)
<sup>Do you think we could form a union to demand less steg puzzles?</sup>

That said, it was clear that these anomalies were brutal. Last year, we got about 1400 points doing anomalies, which is ~75-80% completion. The winning team last year had ~95% anomaly completion. This year, there were only maybe 3 or 4 teams that cracked 1000/2000 points on anomalies, my team getting 814 points. The winning team only got 1588 points from anomalies, which says a lot.

Needless to say, the mental stack this year was hard. Bouncing around between anomalies, answering questions, assume breach, and back to anomalies is the most intense multitasking I've had to do in a while. I'm writing this the Sunday after the competition, and to be totally honest, the events of those 8 hours between 10 am and 6 pm were a blur. 

## Part 4: Fin.
#### The moky of Cyberforce
But when the dust finally settled, it appeared that things did not go how I wanted them to.

![Pasted_image_20231105203220.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105203220.png)

Our peak placement was 6th, and we just barely made it by to stay in the top 10 at the very end. I'm trying to get this out as soon as possible, so I don't have the specifics on how our sub-scores compared to others. 

For most people who came to this event, getting top 10 would be something to celebrate about, call a job well done, and be excited for the next one (which, not to discredit anyone, 10th is a high placing that is well above the average). However, there's a huge difference between wanting to place high, and wanting to close it out and win the whole thing, and I wanted the latter.

The reason I was proud of a 10th place finish in 2021 and a 5th place finish in 2022 was because both felt like Cinderella runs. 2021 was the first year I really began contributing and participating in Red v Blue competitions, and seeing that work pay off felt nice. In 2022, we were woefully underprepared until literally hours before the event, and managed to clutch a higher position than I thought we ever could with how we prepared. This year, with our team's varied strengths, I thought, and knew, we could do so much better than 10th. 

Am I happy about the consistency over the last few years? Yeah, I'm glad we didn't have a year where we completely got owned and lost it. Am I really happy with 10th? No. Being happy with 10th feels like settling. I came here to win, and we just didn't close.

So what went wrong? My thoughts:
- **Documentation**: We missed many vulnerabilities by not checking the other domain controller as thoroughly amid the disk issues. There was absolutely time to find workarounds or scan later on, but we just didn't. I also found some typos in the documentation later, which definitely did not help.
- **C-Suite**: I actually thought we kind of cooked with our presentation, so maybe this comes down to judge opinions, but I think there are places to improve. Maybe our recommendations could have been better, maybe we needed to explain how a DER management company works and that we used too much jargon (which, if that's the issue, feels like a C-Suite issue), or maybe when we gave a cost-benefit analysis, the C-Suite thought that was actual money that needed to be spent as opposed to just basic economic costs.
- **Anomalies**: I've been out of the CTF game for a little bit while trying to do math research and finish my degrees, but I could have been so much quicker with some of these reversing challenges. I'm especially mad at myself for not getting at least a little bit of the Nim challenge (which I will absolutely writeup later).
- **Red Team**: Had we had better Linux logging, I think we could have gotten ~100 more points. Talking with the red teamer afterwards, there were things I knew were vulnerable that got used during assume breach, that we simply could not identify because we weren't looking at those things, either through logs or manually.

Shout out to the rest of Order of the Purple Flamingo. Regardless of how I felt about the event, I'm happy people who were new to cyber competitions got a good experience from this and have a much better understanding on what to improve on. Also shouts out to the Cyber Flyers team. We had enough sign ups for Cyberforce this year that we sent two teams, and I put most of the good people on my team. Even though they got 58th (I think), I know many of them outperformed what they thought they could do, which is a great thing.

#### Final Thoughts
This is (probably) the end of me competing as a blue teamer for Cyberforce, unless I decide to go to graduate school, which I don't even know if I want to be in the US for. It's a bittersweet end, and no matter how I feel about how it went, I have to thank the organizers for putting on a solid event yet again. I keep making bulleted lists of things, but I know a few people actually read this part last year, and I was a little tilted at 6:00 pm when we had to fill out post surveys and filled mine with fake, useless answers, so here's some extra stuff:

- The Q Center is such a great venue and I will take any excuse to come back again.
- Something something internet problems something something AAAAAAAAAAAAA (it's ok it happens)
- I wanted to lose it after the 5th time someone from white or orange team stopped by to talk to us because I was *pressed* but that was just me
- I'm so glad that me mentioning my qualms with how green team went last year actually manifested into exactly what I wanted, which was great.
- I will still fight any green teamer in the Denny's parking lot over "Everything on the checklist was there, but there was an extra thing so I'm going to say false."
- Mixed feelings about how assume breach was done, specifically related to how descriptions would give hints. Last year, it was pretty much just "System's been hacked, go figure it out", which incentivized having good, real-world logging and monitoring. However, with some of the descriptions, I didn't need to do actual IR and could just figure out what the TTP was based on the description.
- I've just accepted at this point that I'm just never going to get hired anywhere to write challenges, maybe it's my anti-steg punditry, maybe it's my cryptography-not-cryptocurrency propaganda.

![Pasted_image_20231105214401.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105214401.png)
<sup>That Club Penguin black hoodie pfp is the only acceptable use of a black hoodie person on Discord or any social media.</sup>

That about sums up my thoughts on the event. Like last time, no regional awards or anything, just recognition of the top 3. It's okay though, we make do.

![Pasted_image_20231105214812.png](https://an00brektn.github.io/img/cyberforce23/Pasted%20image%2020231105214812.png)
<sup>listen I'm just trying to save the environment, saying I'm a thief is just a government psyop</sup>

ggs we go next