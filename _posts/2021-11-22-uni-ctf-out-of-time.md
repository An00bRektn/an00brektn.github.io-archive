---
layout: post
title: "HTB University CTF Writeups: Out of Time"
image: ''
date:   2021-11-22 12:00:00
tags:
- hackthebox
- htb-uni-ctf
- hardware
- power-analysis
- python
description: ''
categories:
published: false
comments: false
---

![intro](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121130152.png)

## Intro
This is probably the challenge I was proudest of completing since I don't have a background in computer engineering. Out of Time was an easy-rated hardware challenge in this year's Hack The Box University CTF. We're given a python script to talk to the hardware running on the other side, and everytime we submit a password, we're given a NumPy array of the power trace. We can leverage this to "brute-force" the password, by means of a power analysis, observing irregular spikes when we input something correct.

* buh
{:toc}

### Description
`Quick we need to get access to the bunker and we are running out of time! The door is using an advanced steam-powered door locking mechanism which we cannot breach. One of our scientists managed to make a tool that measures the mechanical stress of the pipes moving steam during the verification of the password and created a power consumption model but it looks like just random signals. Can you find anything useful in the data?`

## Initial Observations
When we open the downloadable component, we're given a python scipt called `socket_interface.py`.
```python
import time
import socket
import base64
import numpy as np

HOST = '0.0.0.0' # This must be changed to the corresponding value of the live instance
PORT = 1337  # This must be changed to the corresponding value of the live instance

# This function is used to decode the base64 transmitted power trace (which is a NumPy array)
def b64_decode_trace(leakage):
	byte_data = base64.b64decode(leakage) # decode base64
	return np.frombuffer(byte_data) # convert binary data into a NumPy array

# This function is used to communicate with the remote interface via socket
# The socket connection is also accessible with the use of netcat (nc)
def connect_to_socket(option, data):
	data = data.encode()
	# Initialize a socket connection 
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		# Connect to the HOST machine on the provided PORT
		s.connect((HOST, PORT))
		
		# Receive initial message
		resp_1 = s.recv(1024)

		# Select one of the two available options of this interface
		s.sendall(option) 	

		# Receive response
		resp_2 = s.recv(1024)

		# Send the data 
		s.sendall(data) 

		# Receive response
		# receive base64 encoded binary data 
		# that represented the power traces as a Numpy array 
		# use loop to avoid missing packets due to high latency 
		resp_data = b''
		tmp = s.recv(8096)
		while tmp != b'':
			resp_data += tmp
			tmp = s.recv(8096)
		s.close()

		# The print commands can be used for debugging in order to observe the responses
		# The following print commands can be commented out.
		print(resp_1.decode('ascii'))
		print(option)
		print(resp_2.decode('ascii'))
		print(data)

		return resp_data

# Sample plaintext 
password_guess = 'password_guess'

# Example use 
print("Option 1:")
leakage = connect_to_socket(b'1', password_guess)
print(leakage)
power_trace = b64_decode_trace(leakage)

print("Length of power trace: {}".format(power_trace.shape))

# Always use a delay between each connection 
# in order to have a stable communication with the remote instance
time.sleep(0.1)
```

This basically simplifies the process of accessing what's on the other side; it's just some basic socket programming to send a password, and then receive the power trace. I'll add a line to print out the numpy array and see what happens on an initial connection.

```bash
kali@transistor:~/ctf/htb_uni/hw_out_of_time$ python3 socket_interface.py
Option 1:
Remote Lab Interface
1. Try password (Returns power trace): 
b'1'
Give a password guess: 
b'password_guess'
b'7HL2rmiR0b9SXkmagMS1vyhttHu5kci/E7tex2f137+KmmB2oKzGvyQt340828S/y7PibPBR2b8k1up2
...[A LOT OF BASE64]...
fFvbv7GrnUm+yt2/HhDUposm07/uLXn8wyzIv+BDdDXo/d6/igw6muxXxr/WdIQ606nTv4fip0h0WOC/xBJTqNTUyr8='
Length of power trace: (1000,)
[-0.27450006 -0.08502964 -0.19194716 -0.49935336 -0.17714315 -0.16294057
 -0.39562617 -0.20039779 -0.16867863 -0.25927103 -0.46770861 -0.49555924
 ...[about 980 float values]...
 -0.27593647 -0.36658975 -0.56537644 -0.14139505 -0.33289043 -0.14056442
 -0.25464094 -0.42745878 -0.46549947 -0.29922763 -0.18886614 -0.48424726
 -0.17455823 -0.3072403  -0.51079764 -0.20962008]
```

What does this mean? I see numbers, but they don't really mean much. The base64 is just another representation of the array, so that doesn't help. At this point in time, I turned back to the description.

> "The door is using an advanced steam-powered door locking mechanism which we cannot breach [...] during the verification of the password and created a power consumption model but it looks like just random signals [...]"

In the code, this "power consumption model" is referred to as "power_trace". There must be something to do with this.

## Research
### Google FTW
My favorite thing about "easy" hardware challenges is that the research is not obscure and really interesting to read through. In this case, I began my search looking for "power consumption model and power trace" on Google.

![asdf](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121171531.png)

I saw a lot of things related to "power analysis", and that paper that had to do with cryptography was a nice indicator that I might be on the right track. I didn't read the paper (out of sheer laziness). I then searched for "power analysis hardware" and found this.

![asdf](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121171716.png)

Naturally, I went to videos and found the following videos, which guided me through this challenge. 

- [LiveOverflow - Breaking AES with ChipWhisperer](https://www.youtube.com/watch?v=FktI4qSjzaE)
- [Collin O'Flynn - Introduction to Side-Channel Power Analysis](https://www.youtube.com/watch?v=OlX-p4AGhWs)
- [Collin O'Flynn - 0x501 Power Analysis Attacks](https://www.youtube.com/watch?v=2iDLfuEBcs8)

I found the LiveOverflow video first, which introduced me to the idea of Side Channel Analysis, but the lectures I found next solidified the process. So let's talk about some theory.

### No Security Without Physical Security
For the completely uninitiated, meaning absolutely no knowledge on how circuits work, I'll give a quick run down. It's not fully necessary to understand this part, but I think it helps demystify some stuff.

![asdf](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121172857.png)

The above diagram can be broken down like so:
- The red box highlights the battery/power supply along with its voltage
- The yellow highlights the current flowing through the circuit
- The purple highlights the resistor, which "slows down" the current, which is an oversimplification, but I don't want to dive too deep.

Simply put, when a current travels through a resistor, there is a drop in voltage. Power is calculated using voltage, so the two values are related. I'm not a computer/embedded systems engineer, so I don't know the specifics about how something using a password is constructed, but we can imagine it. If a correct password is submitted, the voltages will probably drop one way (buttons, lightbulbs, and any device connected to a circuit acts as a resistor), but if something incorrect happens, the voltage goes another way. 

When we measure what's going on in the machine with an oscilloscope, we can get a power trace. If it's not very secure, we will visibly be able to see a noticably different jump in the trace, allowing to conclude if something is correct or incorrect simply on a character to character basis.

![asdf](https://an00brektn.github.io/img/uni-ctf/Pasted image 20211121173919.png)
<sup>Credit: Collin O'Flynn</sup>

### ChipWhisperer
Collin O'Flynn actually has worked on a project, [ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/index.html), that helps to perform these kinds of attacks. If you have a physical device that you're trying to do this on, it's probably a solid library to work from. However, we're already recieving data as a numpy array, so we really only care about the process.

Luckily, he's actually posted a step-by-step tutorial on performing the attack at [this link](https://chipwhisperer.readthedocs.io/en/latest/tutorials/courses_sca101_soln_lab%202_1b%20-openadc-cwlitearm.html#tutorial-courses-sca101-soln-lab-2-1b-openadc-cwlitearm). And it turns out it works perfectly for this challenge.

## Grabbing the Flag
I'm not going to go step by step through the tutorial here because half of it is just exploring the concept using matplotlib, so I'll just walk through my final script, which I ran out of a Jupyter Notebook (because I wanted to see the matplotlib stuff).

```python
import time
import socket
import base64
import numpy as np
import pandas as pd
import seaborn as sns

import matplotlib.pyplot as plt
%matplotlib inline

HOST = '64.227.40.93' # This must be changed to the corresponding value of the live instance
PORT = 30965  # This must be changed to the corresponding value of the live instance

# This function is used to decode the base64 transmitted power trace (which is a NumPy array)
def b64_decode_trace(leakage):
	byte_data = base64.b64decode(leakage) # decode base64
	return np.frombuffer(byte_data) # convert binary data into a NumPy array


# This function is used to communicate with the remote interface via socket
# The socket connection is also accessible with the use of netcat (nc)
def connect_to_socket(option, data):
	data = data.encode()
	# Initialize a socket connection 
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		# Connect to the HOST machine on the provided PORT
		s.connect((HOST, PORT))
		
		# Receive initial message
		resp_1 = s.recv(1024)

		# Select one of the two available options of this interface
		s.sendall(option) 	

		# Receive response
		resp_2 = s.recv(1024)

		# Send the data 
		s.sendall(data) 

		# Receive response
		# receive base64 encoded binary data 
		# that represented the power traces as a Numpy array 
		# use loop to avoid missing packets due to high latency 
		resp_data = b''
		tmp = s.recv(8096)
		while tmp != b'':
			resp_data += tmp
			tmp = s.recv(8096)
		s.close()

		# The print commands can be used for debugging in order to observe the responses
		# The following print commands can be commented out.
		#print(resp_1.decode('ascii'))
		#print(option)
		#print(resp_2.decode('ascii'))
		#print(data)

		return resp_data

def testing(password_guess):
    # Example use 
    #print("Option 1:")
    leakage = connect_to_socket(b'1', password_guess)
    #print(leakage)
    power_trace = b64_decode_trace(leakage)
    #print(power_trace)
    #print("Length of power trace: {}".format(power_trace.shape))
    time.sleep(0.1)
    return power_trace

"""
id = [x for x in range(1000)]
data = {"id":id, "power":power_trace}
df = pd.DataFrame(data)
plot=sns.lineplot(data=df, y="power", x="id")
plot.get_figure().savefig("powerplot2.png")
"""

if __name__ == "__main__":
	VALID_CHARS = [chr(x) for x in range(33, 126)]
	THRESHOLD = 100
	plt.figure(figsize=(12, 4))
	ref_trace = testing("\x00")
	"""
	for c in VALID_CHARS:
		try:
			trace = testing(c)
			diff = np.sum(np.abs(trace - ref_trace))
			print("{:1} diff = {:2}".format(c, diff))
		except:
			pass 
	"""
	guessed_pw = "HTB{"
	while True:
		ref_trace = testing(guessed_pw + "\x00")
		for c in VALID_CHARS:
			trace = testing(guessed_pw+c)
			diff = np.sum(np.abs(trace - ref_trace))

			if diff > THRESHOLD:
				guessed_pw += c
				print(guessed_pw)
				break
```

So what's going on? The attack goes as follows:
- I go through each ASCII character in the range of 33 to 125 checking how the power trace responds
- I take the difference between this power trace, and the trace of when I just send a null byte at the end, and add up the absolute values of the entries in the resulting array
- If this value is above a predetermined threshold (I concluded mine to be 100 empirically), we add this to our guessed password and repeat

The character that is correct will always cause a spike in the power trace, that is how we distinguish the right from the wrong. I have my loop run forever because I didn't know how long the password was.

Once we run our program, we get the following output and can submit the flag.
```
HTB{c 
HTB{c4 
HTB{c4n 
HTB{c4n7 
HTB{c4n7_ 
HTB{c4n7_h 
HTB{c4n7_h1 
HTB{c4n7_h1d 
HTB{c4n7_h1d3 
HTB{c4n7_h1d3_ 
HTB{c4n7_h1d3_f 
HTB{c4n7_h1d3_f2 
HTB{c4n7_h1d3_f20 
HTB{c4n7_h1d3_f20m 
HTB{c4n7_h1d3_f20m_ 
HTB{c4n7_h1d3_f20m_7 
HTB{c4n7_h1d3_f20m_71 
HTB{c4n7_h1d3_f20m_71m 
HTB{c4n7_h1d3_f20m_71m3 
HTB{c4n7_h1d3_f20m_71m3}
```