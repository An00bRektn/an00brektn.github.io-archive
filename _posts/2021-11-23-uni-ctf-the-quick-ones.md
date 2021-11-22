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
description: ''
categories:
published: false
comments: false
---

![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121130152.png)

## Intro
Surprisingly, this year's HackTheBox University CTF had a few challenges that I knocked out in under 20 minutes. "Upgrades" was the easy-rated reversing challenge, and "Peel Back The Layers" was the easy-rated forensics challenge, and both simply required you look in the right spot. I'll walk through both in this post since neither was that long.

For "Upgrades", we're given a .pptm file, which is just a macro-enabled powerpoint file. We use olevba from the oletools toolkit to extract the code for the macros, and, to be thorough, recreate the script in Python to see what strings are in the file.

For "Peel Back The Layers", we're given the name of a Docker registry, and asked to find some new file that was inserted into it. We'll pull down the image and load it into dive, a super useful tool for docker reverse engineering. Looking though the layers, we find a shared object file added to the image, which we can extract and find the hardcoded flag.

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

I'll switch over to my Remnux machine to show exactly how it's done.