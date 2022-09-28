---
layout: post
title: So You Want to Learn to Code?
image: ''
date:   2021-07-08 12:00:00
tags:
- beginner
- programming
- info
description: 'hear about programming from someone who is just okay at programming'
categories:
published: true
comments: true
---

<p align="center">
    <img src="https://live.staticflickr.com/3912/15090961835_c4f26e4890_b.jpg" style="width: 50%; height: 50%" alt="Would you believe me if I said C++ is like C but upgraded and C# really has nothing to do with either?">
</p>

Growing up, the idea of programming was one of the most elusive concepts I had ever heard of. For most people, it's this mysterious black box that does some magic to make their electronic devices work. For the longest time, I wanted to learn to program, but had no idea how. Most people would immediately say, "Use the internet to learn!", but it's not as easy as it's cracked up to be. My experience of trying to use the internet to learn was being stuck in a loop between "simplified" teaching tools like Scratch and Khan Academy, and the jargon put out by random people on the internet.

In this post, I will be going over the resources and lessons that I have found over time to help me get better at programming, and what didn't help at all. **This list is not all-encompassing, and I encourage you to continue to seek out what works for you.**

## What Did Not Work At All

We're just going to start with a list for this one:
- [Scratch](https://scratch.mit.edu)
- [Khan Academy](https://www.khanacademy.org/computing/computer-programming)
- [code.org](https://code.org/)
- Literally anything to do with the "Hour of Code" thing

When I initially tried to teach myself as a middle schooler to high schooler, these were the resources that I heard about the most. After toying with them for a couple of weeks and then proceeding to get very bored, I soon realized:

**These are programming languages for children.**

<p align="center">
    <img src="https://www.publicdomainpictures.net/pictures/10000/nahled/2642-12745437615W13.jpg" style="width: 50%; height: 50%" alt="The average Scratch user (just a joke)">
</p>

Do I think they're bad? Not necessarily. Realistically, they are made for an age group that is maybe just entering middle school. I think the Khan Academy stuff has changed since I last saw it to be more focused on practical languages like Javascript and SQL, so that might actually be viable now. Regardless, the big problem sites like Scratch and code.org suffer from is that they are glorified children's toys. They teach you nothing more than the pure basics, which, honestly speaking, can be covered in one week if you're dedicated, 2-3 weeks if you want to take your time.

## So What Does Work?

This is where things get a little trickier, because everybody learns a little bit differently. My big breakthrough was going to a small summer camp at a university where I first learned about Python, Cryptography, and Virtual Machines. But, not everyone has access to that, and there are some steps that I think everyone should take to get started seriously.  

### Step 1: What to learn?

Ask yourself what you want to program for. This [FAQ](https://www.reddit.com/r/learnprogramming/wiki/faq#wiki_getting_started) from r/learnprogramming does a very good job of clarifiying some of the questions people have about programming. I think one of the most important parts for me was seeing this table:

![codetable.png](https://an00brektn.github.io/img/thm-presecurity/codetable.png)

This table is obviously not all encompassing, but it's a good way to get an understanding of what you're working towards. If you're really ambivalent of what language you want to choose, I **HIGHLY** recommend Python, because of how versatile it is.  

Many people might tell you that it's better to pick one language over another (mainly the people who think everyone should learn C first). To those people, I say that all modern programming languages are very powerful and can do great things with a good mindset. All programming languages have similarities at their very core, so the most important thing is ***LEARNING***.  

### Step 2: The Basics

One of the best pieces of advice that I've heard was from a Corridor Crew video (can't remember which one), in which one of the guys says something like:

"*First you need to learn how to do it the hard way, fully completing every step along the way. Then, start taking shortcuts*"

To be an effective programmer, you cannot dive head first into trying to make the next Skyrim. You MUST understand the basics, which are:

- Good Programming Style
- Data Types and Variables
    - Strings, integers, floating point, Booleans
    - Comparisons and Operations (e.g. >,<,==,+,-)
- Conditional/Selection Statements
    - if, else, nested if else
- Iteration/Loops
    - while, for
- Functions/Methods
- Data Structures
    - Lists, Arrays, etc.
- Methods/Functions
- Exceptions
- File I/O

If none of that made sense to you, that's okay! This is just a list of what I think everyone who wants to program should learn within the first year of starting. It's hard for me to be able to link something that can work for every language someone wants to learn, but I'll throw out a couple here that are good for learning basics.

- [W3Schools](https://www.w3schools.com/) - HTML, CSS, JS, Python, Java, etc.
- [freeCodeCamp](https://www.youtube.com/c/Freecodecamp/playlists) - A lot.
- [learncpp](https://www.learncpp.com/) - C/C++
- [Jabrils](https://www.youtube.com/playlist?list=PL0nQ4vmdWaA3GLsZESEkBiIAEvnDEge8D) - C# and Python
- [Brackeys](https://www.youtube.com/c/Brackeys/playlists) - C# and Game Design
- [This Random Reddit Thread](https://www.reddit.com/r/learnprogramming/comments/j9napy/im_deleting_my_account_here_is_a_list_of/g8limoh/?utm_source=share&utm_medium=ios_app&utm_name=iossmf&context=3) - Mostly Python
- [Many, Many More YouTube Channels](https://github.com/JoseDeFreitas/awesome-youtubers) - A lot.

You're also going to need to install an Integrated Development Environment (IDE) or a nicer text editor to write code, along with your respective language itself. For a program to write code, I personally recommend [Visual Studio Code](https://code.visualstudio.com/) (even though it's not really an IDE), unless you're trying to write applications for phones, in which case you may or may not want something a bit more specialized like [Android Studio](https://developer.android.com/studio). If that's too much, there are also IDEs in-browser that you can use while starting out:

- [repl.it](https://repl.it/)  
- [codepen.io](https://codepen.io/)  
- [fiddle](https://jsfiddle.net/)  
- [AWS Cloud9](https://aws.amazon.com/cloud9/)  
- [Octave](https://octave-online.net/) - open-source, free version of MATLAB

<p align="center">
    <img src="https://imgs.xkcd.com/comics/real_programmers.png" alt="xkcd.com/378/">
</p>

Language Installs:
- [Python](https://www.python.org/downloads/) - Install Python3, Python2 has been discontinued
- [Java](https://java.com/en/download/help/download_options.html) - VS Code has an alternative way to do this
- [Swift](https://swift.org/download/#releases)
- C# - recommend installing [Visual Studio](https://visualstudio.microsoft.com/) and work out of that. You could also install `mono` on Linux but why would you ever actually do that.
- [Go](https://golang.org/doc/install)
- [C++/C](https://www.guru99.com/c-gcc-install.html) - If you use Linux, `apt install gcc` and `apt install g++` should have you covered with compiling these languages (Mac should also be able to do something similar with xcode)
- [Ruby](https://www.ruby-lang.org/en/downloads/)
- [MATLAB](https://www.mathworks.com/help/install/install-products.html) - Note: I don't believe MATLAB is free, so you'll probably have a better time using the aforementioned Octave

### Step 3: I have the tools, now what?

Simple Answer: Go out and learn. Use the tutorials I've linked (and others you may have found) and follow along with them. This isn't school, so don't try and commit everything to memory. Learn the methodology, understand the big picture, and work your way up slowly but surely. There are plenty of forums online where people just like you are learning to program, so don't be afraid to ask questions. Join a programming discord or subreddit. You probably know someone who programs, or know someone who knows someone who programs, and they might also be another resource.

At the end of the day, learn at your own pace, but consistency is key.

<p align="center">
    <img src="https://miro.medium.com/max/275/1*gO_CqAETq7aHUNfSdZRCPA.gif" alt="The learning process, visualized">
</p>

## Where to go from here?

It really depends on if you want to transition into something professional or keep it as a hobby. In both cases, making your own projects is pretty important. I would also recommend you begin to learn using [Git](https://docs.github.com/en/get-started/quickstart/set-up-git) and host your projects on [GitHub](https://github.com/). But what projects should you make? Again, you have full control here, but here are some ideas:

- [100 Projects of Code](https://github.com/aceking007/100ProjectsOfCode)
- Web Scraper - Build a tool that takes a URL as input and returns the content of the URL as HTML or XML.
- Literally anything in life you want to automate - Do you need to organize things into a spreadsheet, write a program to do that for you?
- Raspberry Pi Projects - A Raspberry Pi is a small, inexpensive computer. Many people have used them to make things like automatic plant waterers or Magic Mirrors. This will also get you involved with hardware stuff if that's what you're into

Having a good background in Computer Science also helps. Here are some topics that you should take a look at once you feel more comfortable with programming.

- Time and Space Complexity
    - Search and Sort Algorithms
- Recursion
- Data Structures
    - Stacks, Queues, Trees, Heaps
- Programming Paradigms (namely functional programming and OOP because those are the most common)
- Multithreading
    - Operating System Concepts as a whole, [link](https://www.youtube.com/watch?v=dv4mXBsv6TI) to UMass Lectures
- Software Development (e.g. Agile Workflow, Architecture, SOLID Principles, Patterns)
- Low Level Programming (Assembly)
- Using Virtual Machines (VMs)
- [Computerphile](https://www.youtube.com/channel/UC9-y-6csu5WGm29I7JiwpnA) - YouTube channel focused on CS topics

Additionally, if you want to move into Computer Science for a job, don't feel like you need to go to college (especially if you're in the US). There are plenty of great resources out there like the [Open Source Society University](https://github.com/ossu/computer-science) to help teach you these things on your own. I would recommend looking at job postings and using those as guidelines for what you should be learning.

## Conclusion

Hopefully this post has given you a brief tour of all things programming (as I know it). I'm just a university student, so I'm sure there's important things I missed along the way. If there's only one thing you take away from this, I hope it's that there's no one way to go about this, and different methods help different people. I might come back to this later and update it with more resources if I find them.

:D
