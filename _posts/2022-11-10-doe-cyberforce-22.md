---
layout: post
title: "How I Almost Won a National Cyber Competition"
image: '/img/cyberforce22/Pasted_image_20221109200128.png'
date:   2022-11-10 00:00:00
tags:
- cyberforce
- dfir
- hardening
- event
description: "Almost is the key word here."
categories:
published: true
comments: false
---

![logo](https://an00brektn.github.io/img/cyberforce22/Pasted_image_20221109200128.png)

## Intro
Last year, I attended my first (online) Cyberforce competition, run by the Department of Energy, featuring 100+ different schools across the United States competing to secure infrastructure, write documentation, and complete security challenges. I recounted my experience from that event in [this post](https://notateamserver.xyz/doe-cyberforce-2021/), where I mostly reflected on the experience, where I could improve, where I did well, and where the event itself could improve. That was my very first hands-on red v blue experience, at a point where my hacking skills were fairly novice and my blue teaming skills were non-existent. Long story short, we got 10th, I popped off, and all was good.

But this time, I wanted to win. As opposed to last year's blog post, I'll not only walkthough the overall experience, but I'll dive into some of the technical details that might help other teams going forward (but don't expect me to give away all of my secrets 😉).

* buh
{:toc}

## Part 1: Building it Up
### Last Time on Cyberforce...
For the <10 of you that read this blog consistently, you'll remember that one of the biggest issues I had with last year's event was the conflict of interest between external pentesting and the "assume breach" scoring. For the uninitiated, Cyberforce features 2 primary ways to do red team scoring:
1. **Traditional Pentesting** - This is the classic Red v Blue format most people are familiar with. Red team hacks blue team, blue team stops red team from doing that and shutting down systems. Simple. 
2. **Assume Breach** - Here, red team is already given access to a machine, and is tasked with executing various, predetermined attack chains. You aren't punished for being attacked, rather, you're scored for how well you can identify indicators of compromise and follow incident response protocols.

Last year, we were tasked with hardening all 6-7 machines on our network, which was great for the Traditional Pentesting scoring. But when it came time for assume breach, chat logs were basically:

```
redteam: Hey could you disable antivirus so we can do this assume breach?
redteam: Hey could you disable the firewall so we can do this assume breach?
redteam: Oh did you patch this? Well I guess we skip this one then.
```

Admittedly, we had pretty bad incident response when it came to actually doing it, but you see the problem here. *This time*, however, machines were specifically split into Traditional and Assume Breach, where we would only be allowed to harden the former and could only enumerate the latter.

This was a very, very good change. Some teams were confused, but I'll call that a reading-comprehension issue since it's pretty clear what is what from the rules. Outside of the red team scoring, there was scoring in a few other areas as well:

- **White Team Scoring** - Security Documentation had to be filled out with the following information: Statement of Purpose and Scope, Network Diagram, a full list of vulnerabilities found on all machines with remediation steps, and a detailed writeup as to how we hardened our machines.
- **Orange Team Scoring (C-Suite)** - A 5-7 minute presentation had to be recorded for a fictional C-Suite panel detailing an initial security risk assessment, risks of integrating new networks, and a summary of the hardening.
- **Green Team Scoring** - We had to develop a full stack website from scratch for the fictional company we were representing for volunteer end users to access throughout the event. It was out of scope for Red Team to attack, but with some of the required integrations (e.g. SQL, Mail, LDAP), Red Team attacks could easily impact this. 
- **Anomalies** - Basically a mini 8-hour CTF happening at the same time as everything else

To clarify:
![Pasted_image_20221109194018.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221109194018.png)

The worst part about all of this is that we only had two weeks to get all of the technical things done (i.e. hardening, green team), but only one week to get the White Team documentation and the Orange Team presentation turned in. So, naturally, I ~~neglected all life responsibilities~~ committed myself to trying to complete everything to its fullest extent. Teams were made up of 4-6 people, although I've heard it almost a million times now, working in a team is hard. It's especially hard when you have people at varying levels of expertise. I would love to have 6 clones of me take care of everything, but there are things that I need to focus on, and things that I need to trust other people to do, which I found very difficult. But, such is life and we move on.

Here was the network that we had because I couldn't find a better place to put it.
![Pasted_image_20221109223153.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221109223153.png)

- TaskBox (Windows Server 2022) - Administrative server hosting internal services such as email and file uploads
- ICS CNC (Windows Server 2016) - Hosts the HMI for Solar systems and runs the sunpartners.local domain
- ICS PLC (Ubuntu 18.04) - Acts as a modbus master for Industrial Control System operations (ICS)
- PublicDB (Debian 10) - Runs a MariaDB server for, uh, things
- WebServer (CentOS 7) - Hosts a website for a fictional iSolr mobile app (no mobile security here though)
- WebSolar (Ubuntu 20.04) - Hosts the company website for Sole-Zon-Solis which Vita Vehiculum recently acquired

### The Game Plan
After ~~the most stressful two weeks of my life~~ a busy two weeks, and a (honestly soothing) late night work session, we were ready for the day of. So, how did we approach this?

Short Answer: Poorly.  
Long Answer: All of us had fairly good fundamentals when it came to hardening machines, that was not the hard part. Here's some of the tools that we used for scouting out vulnerabilities and misconfigurations:

- [OpenVAS](https://github.com/immauss/openvas) is an open source vulnerability scanner that we used instead of Nessus, mainly because I didn't want to install Nessus and open source is pog.
- [PEASS-ng](https://github.com/carlospolop/PEASS-ng) is technically designed for penetration testers to find quick wins when trying to escalate privileges on Linux and Windows machines, but it's also just as useful when trying to find vulnerabilities.
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) is an absolutely goated tool for Active Directory enumeration. Since the domain controller was set up using [BadBlood](https://github.com/davidprowe/BadBlood), I was able to witness such beautiful graphs like this one for AS-REP Roastable users.

![Pasted_image_20221109200215.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221109200215.png)
<sup>Yes. Every one of these users was AS-REP Roastable. I couldn't believe it either, trust me.</sup>

After scanning, we got to work documenting, and documenting, and documenting, and then maybe some hardening. Talking about hardening and putting the C-Suite Brief together is like talking about code, it's very boring. However, implementing monitoring tools is something I'd like to dedicate an entire section to.

## Part 2: You Can't See Me
<sup>aka "If a meterpreter shell spawns in an AD Forest, and no one's around to see it, did it really happen?"</sup>

There's a reason [Insufficient Monitoring and Logging](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) is part of the OWASP Top 10. If you get hacked, that sucks, but it's understandable. If you don't know what happened and hence cannot properly remediate issues, then that's when you get fired (although these days who knows if big tech can even afford you in the first place). This is especially important here where over half of the points we get are from being able to respond to incidents quickly and accurately.

This is where we should have spent more time. Hardening is not very hard if you know your operating systems, but I had almost zero experience with tools like Splunk or LogESP, which are Security Information and Event Management tools that can aggregate logs all over a network in a central place for deeper analysis. Not only did that mean one of us would have to learn the usage in only a few days, but also figure out how to install it in an environment that had limited resources. All of the machines were t1.medium EC2 instances on AWS, which means they each had about 2 virtual cores with 4 GB of RAM. If too many requests came in at once to be logged, a machine would definitely crash if it was running more services (totally didn't blow up the Green team server like 3 times).

With all of this, this was our subpar setup:
- We used [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) on both Windows machines with the good old [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) config file (although I only learned Florian Roth had a much better one afterwards).
- On Linux, we used the `/var/log` directory.
- And, as a "hail mary", we attempted to use [Wazuh](https://wazuh.com/), an opensource EDR/SIEM in lieu of our lack of understanding of Splunk at the time.

If you're looking at this and thinking "They deserve to get last place", you're right! Sysmon, if you haven't used it, is an absolutely phenomenal tool to identify activity on the machine, and is great to guide you with what other logs you look at on Windows. But aside from that, our logging was absolutely terrible, and here's why.

- No Linux-specific logging tools -  You can learn a lot more than you'd originally think from `/var/log` but we're barely catching most things
- No network-level logging - We could not tell if we were being scanned or not, which isn't a good thing.
- Wazuh, out of the box, is not really good at all - All it can really do is detect logon and logoff events in Linux and then maybe a little bit more on Windows. I'm sure there's more I could have done there, and I welcome any links to learn more, but we should have just used Splunk.
- Many, many blind spots - Due to the nature of our logging, we found that in many cases, we were getting certain events confused for noise and vice versa. It helped hone our ability to spot the fine details, but that's not really something you want to be doing in the moment.

But, you're reading the title and you'll notice I said we almost won. What happened?

## Part 3: Game Day

![fine](https://an00brektn.github.io/img/cyberforce22/thisisfine.gif)

### "This is Fine"
It is the day before the competition. I'm stressed. Green team site is not done. Windows 2022 has not been hardened. I still don't know how Splunk works. We do our red team check-in where they give us a test scenario to make sure everything is working, and we choke very hard. Morale, at least for me, is slowly trending downward.

![Pasted_image_20221109233039.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221109233039.png)
<sup>We only found Trevor because they told us the name was Trevor :(</sup>

But then we leave the venue for the hotel, and the air begins to change. We ate at some Asian place because we like getting sushi before events (food was a 5/10) and it was fun. At the hotel, I'm stressed and start working on the green team site right away because I know it's going to take me a while. The others go for a pool party. Once everyone gets back, however, we all meet in one of our rooms, and we just get to work. You have Lofi Girl in the background, a bunch of laptops out on a table that's way too small, the smell of burnt popcorn because *someone* left it in the microwave for too long, a carton of eggnog, and most importantly, determined, yet calm vibes. It's probably a top 3 college moment for me, but there was something really peaceful in that moment. It's just being with a group of people you enjoy being around all working toward a common goal, and I don't think I've really had the opportunity to feel that since the pandemic started.

We make cheatsheets, we harden machines, we finish web dev and we go to sleep at 12:30 am ready for a 10 am - 6 pm day ahead of us.

### Wait, This is Actually Fine
Fast forward past breakfast, we're greeted with the sheer volume of college students all vying for first place. Not everyone was there when we were at the venue for check-in for the day before, but when everyone is here, the scale of the whole thing becomes much more real:

![Pasted_image_20221109234445.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221109234445.png)
<sup>This does not include the other ~120 teams that were fully online.</sup>

After a ~~grueling~~ very informative 30 minutes of talking from National Labs people giving the usual "oh no we need people in cyber", the day begins. Documentation is long behind us. Our objectives are now (1) defend against external pentesting, (2) solve CTF challenges, and (3) incident response.

![Pasted_image_20221109235106.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221109235106.png)
<sup>Red teamer, if you're reading this, please reach out to me. You never accepted my discord friend request. :(</sup>

I spent most of my time flipping between incident response and CTF solving depending on my ability to focus on either. Our score started off in a pretty good place as well; we scored ~1875/2000 points on documentation and the C-Suite combined, which is solid, and put us in the top 20 to begin with. Not bad.

We go through our first incident response chain. We choke the bag pretty hard, only scoring 30 of the 150 possible points.

![Pasted_image_20221109235802.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221109235802.png)

Not a great start. But then we start understanding what we need to look for. If we don't have solid logging, we better be catching this stuff in the moment. With our eyes glued to TCPView, Process Hacker, and some custom scripts, our incident response starts to get kind of nice. We get 120 on the next chain. Then we get 60 (this one was also a choke). Then a 150. Then two more 90's. I also attempted to social engineer the red teamer to no luck but that's aside the point.

![Pasted_image_20221110001200.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221110001200.png)

Was this the best incident response in the world? No. As I said earlier, you need good logging and monitoring if you want to be able to respond to incidents. We're somewhat lucky we're being told when things are going down. However, what we couldn't do in incident response, we could make up for in anomaly points.

Now, I keep saying anomalies are like CTF challenges, but they're not like the "Bypass strict CSP into an 0day into reflected XSS via bad error handling into prototype pollution + DOM clobbering" [type of challenges](https://www.hackthebox.com/blog/UNI-CTF-21-complex-web-exploit-chain-0day-bypass-impossible-CSP). These ones were all on the easy to *maybe* medium side of things, but the main problem is that you're trying to secure a network and help your teammates all over the course of 8 hours. On top of this, the challenges are supposed to align to the [NIST NICE](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center) framework, so there's a decent amount of policy, administrative, etc., related challenges (*read as:* reading challenges). Again, not very easy trying to read an intel report while your friend is asking you what a random Windows binary is because they're all named weirdly. All in all, we got about 80-90% of the anomalies done.

## Part 4: The End
By the time 6:00 pm rolls around, the team is schmooving. Everyone managed to solve or contribute to at least one anomaly, which was really motivating for the people on the team who weren't as technically skilled. I spent my time hunting for threats until the very last second, at which point it was time to wrap up. And the final scoreboard?

![scoreboard](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221118114839.png)

Looking back at the screenshots, we actually peaked at 2nd place around 40 minutes before the end of the competition, but I'm okay with 5th. The event used to do regional awards for the highest scoring team from each region, but I guess they stopped doing that. Also, according to our score breakdown sheet, we apparently had the 3rd best documentation, and the 8th best incident response, which, (a) surprising, and (b) pog.

So what did we learn?

- Logging and monitoring is extremely important and I should go learn Splunk and Suricata or Snort
- Windows makes a lot of noise, but that noise has a pattern, and anything that deviates from that pattern is worth taking a glance at
- A team with good chemistry/communication but an okay skillset will almost always outperform a team with bad chemistry/communication but great skillset
- People know much more than they let on, and it's much more productive to cultivate a person rather than make demands
- Argonne should let me make some anomalies for them

I know someone from Argonne will probably read this, so here's a quick list of things I think about the event that I might have forgotten to include in my feedback form.

- Venue was great. It probably costs a lot of money, but in-person events are just so much more fun than online ones.
- I would rather have green team website be in-scope and patch the website of vulnerabilities than have to build it from scratch and not have it be in scope, knowing we only had two weeks. I'm already busy enough with life, trying to secure boxes, and my own software engineering class.
	- Additional note, if we were given like a week extra to work on it, I'd be happy. Two weeks is just really short for a website of that scale and with only a few people.
- We really don't need more steganography challenges. Why not more reverse engineering or cryptography?

And with that, our Cyberforce story ends here, for now. I genuinely like this event way more than CCDC, and I will most likely be back next year. Weird thing though, the only award was this big poster board thing for first, second, and third. With how big this event is, I think acknowledging the top 5 or 10 would be cool, so I ended up grabbing my own award on the way back.

![Pasted_image_20221110004615.png](https://an00brektn.github.io/img/cyberforce22/Pasted%20image%2020221110004615.png)
<sup>Honestly a miracle how this fit perfectly into a small car with 5 people in it</sup>

Until next time! :D
