---
layout: post
title: "H@cktivitycon Writeup: Oh-SINT it's OSINT"
image: ''
date:   2021-09-18 12:00:00
tags:
description: ''
categories:
- ctf
- osint
- h@cktivitycon
published: True
comments: false
---

![logo](https://an00brektn.github.io/img/Pasted image 20210918214829.png)

## Intro
I have devoted the past 48 hours to the **H@cktivitycon CTF**, run by [John Hammond](https://www.youtube.com/channel/UCVeW9qkBjo3zosnqUbG7CFw), [congon4tor](https://twitter.com/congon4tor?lang=en), [M_alpha](https://twitter.com/M_alphaaa), [fumenoid](https://twitter.com/fumenoid?lang=en), [NightWolf](https://twitter.com/nightwolf780), [Blacknote](https://twitter.com/BlacknoteSec), and [CalebStewart](https://twitter.com/calebjstewart), and boy howdy was it a great experience.

This post, specifically, is dedicated to the OSINT category's challenges. You'd think they'd be easy, but they were not. Locating Jed Sheeran was easy, but decrypting the stego-ed audio was not (until John Hammond just put the flag next to the file). Don T. Mason was full of rabbit holes, but some smart thinking leads us to an obscure social media site where we can create a burner account to grab his flag. And finally, finding Mike Shallot will force us to the most hacker-y of sites (just Pastebin), but then we'll take a quick peek into the Dark Web to get his flag.

## Target 1: Jed Sheeran
### Description
`Oh we have another fan with a budding music career! Jed Sheeran is seemingly trying to produce new songs based off of his number one favorite artist... but it doesn't all sound so good. Can you find him?`

### The Search
Jed Sheeran, as I said in the introduction, was the easiest target. A simple google search yields the following:
![image](https://an00brektn.github.io/img/Pasted image 20210918184736.png)

The description mentioned something about his music, Soundcloud is probably a good place to check.
![image](https://an00brektn.github.io/img/Pasted image 20210918184900.png)

Based on the "bread sheeran" banner and the single song release, this is probably the guy. If we take a listen to his song, we hear a lot of garbled beeps and boops. If you've ever done any steganography, you'll know that this is probably going to call for a spectogram. *HOWEVER*, by the time I got around to doing this challenge, John Hammond nerfed it because people were complaining too much, and you can find the flag by looking in the description of the song.

![imgage](https://an00brektn.github.io/img/Pasted image 20210918185148.png)

All my homies hate steganography I guess. If you did go ahead and try and decode the stego, you'd find that it was a Slow-Scan Television signal ([SSTV](https://www.sigidwiki.com/wiki/Slow-Scan_Television_(SSTV))), but it was so hard to read the flag they just threw it in the description.

![image](https://an00brektn.github.io/img/Pasted image 20210918210724.png)

## Target 2: Don T. Mason
### Description
`So this is a weird one. We've been having trouble tracking down Don because of the name conflict between some baseball player or something? All we know is that he likes elephants. Like, he reaalllyy likes elephants.`

### The Search
This one was not easy, and had some people searching for hours. In the discord chat, people were ending in rabbit holes with an unethical "ethical" elephant safari in Bali, achievement on a particular "-hub", and a very Republican anti-vaxxer\*.
<sub>\* do not go out and dox or harass people</sub>

I will not be going into those rabbit holes because I want to keep this blog friendly for all. My approach to this made use of the tool [sherlock](https://github.com/sherlock-project/sherlock), which attempts to scour the internet based on the usernames you supply. I generated a list of possible usernames (I keep promising myself I'll automate it but I haven't done that yet):
```text
donmason
dontmason
don.mason
masondon
dmason
masond
masontd
mason.don
```

Now let's try running it!
```bash
kali@kali~ python3 sherlock/sherlock/sherlock.py donmason dontmason don.mason masondon dmason masond masontd mason.don
[+] Checking username donmason on:
```

Aaaand it's too slow. Kind of expected when you think about it. But, Sherlock does give us a list of the websites it looks at [here](https://github.com/sherlock-project/sherlock/blob/master/sites.md). As I scrolled through the list, a couple links caught my eye:

```markdown
[websites]
-   [mastodon.cloud](https://mastodon.cloud/)
-   [mastodon.social](https://chaos.social/)
-   [mastodon.technology](https://mastodon.xyz/)
-   [mastodon.xyz](https://mastodon.xyz/)
[websites]
```

A couple things that unify these findings.
1. A mastodon is a fancy way of saying "Manfred from the 2002 hit movie Ice Age", or alternatively, a wooly mammoth, which is related to elephants
2. The websites' names are "mastodon.\*"
3. Don T. Mason, as someone pointed out in chat, is an anagram for "mastodon"

If Mr. Don T. Mason wants to show his passion for elephants, he has to be on `mastodon.social`, so I'll try that first. I tried finding his account without making my own, but I finally settled to making a burner account. If I search for "Don Mason", I find this.
![asdf](https://an00brektn.github.io/img/Pasted image 20210918191115.png)

This *HAS* to be our guy. Scrolling down, we find our flag.
![asdf](https://an00brektn.github.io/img/Pasted image 20210918191400.png)

I do encourage anyone reading to try finding him for yourself, because the filler posts that John Hammond wrote are worth the search.

## Target 3: Mike Shallot

### Description
`Mike Shallot is one shady fella. We are aware of him trying to share some specific intel, but hide it amongst the corners and crevices of internet. Can you find his secret?`

### The Search
Excluded are the hours I spent looking at onion-related recipes, but I eventually used the exact same approach I used when looking for the Don. I tried Sherlock, but it was too slow. I was going to look through the list of websites again when I remembered what CTF organizers mean when someone is "leaking information".

He's on Pastebin. 

I told Sherlock to look for a bunch of variations on "Mike Shallot", specifically on Pastebin, and I get the url `https://pastebin.com/u/mikeshallot`. There we find the following.
![img](https://an00brektn.github.io/img/Pasted image 20210918191839.png)

Well that's a little cryptic. If we look at his profile picture, we notice the logo for Tor, the means people take when using the "Dark Web". I am by no means an expert on how the internet is structured, but here are a couple of sources were you can learn more about Tor, and what we'll use to navigate the "Dark Web", [Tails Linux](https://tails.boum.org/)

- [Brandon Skerrit (aka Bee) on Tor](https://skerritt.blog/how-does-tor-really-work/)
- [Tor Project Website](https://www.torproject.org/)
- [John Hammond's Dark Web Documentary Series](https://youtube.com/playlist?list=PL1H1sBF1VAKU8aP5FC-makTTBknb1EWYC)

I will be using Tails Linux to do the search (because I'm terribly paranoid about making a wrong turn and then getting doxxed), but I will not be covering the installation here, because John Hammond does a much better job of it. 

### Dark Web
 Once we have our Tails Linux VM set up, we can disable all Javascript and media on websites to prevent any unexpected attacks, and begin the search. I'll start by looking up "Dark Web"-specific browsers, because we specificially want to look for a `.onion` site (otherwise we wouldn't need to use tor). I'll just throw that first long string into the search bar and see what pops up.

![asdf](https://an00brektn.github.io/img/Pasted image 20210918213314.png)

 Interesting. Based on how these first few urls are formatted, I assume the next cryptic string is probably the specific location of the flag on the `strongerw2ise74v3duebgsvug4mehyhlpa7f6kfwnas7zofs3kov7yd.onion.my/pduplowzp/nndw79` site. After navigating to this URL, we find the flag.
 
 ![asdf](https://an00brektn.github.io/img/Pasted image 20210918213616.png)