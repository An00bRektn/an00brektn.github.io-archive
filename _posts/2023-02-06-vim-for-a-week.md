---
layout: post
title: "Using Vim for a Week, Intentionally" 
image: '' 
date:   2023-02-06 00:00:00 
tags:
- vim
- linux
- info
description: 'This is not a joke. I have entered and exited Vim in one piece.' 
categories: 
published: true
comments: false 
---

![intro](https://cdn.sanity.io/images/92ui5egz/production/5e7832d4d05c2946112abde3143fabf7735f0412-1080x1080.jpg?w=375&h=375&fit=crop&auto=format)
<sup>Oh wait wrong one</sup>

## Intro

I like Vim. But I'm not very *good* at Vim. I know how to exit (that's `:q!` for you by the way), I can delete single lines with `dd`, you can do regex stuff with `/`, but that's about all I really know. I used to be one of those adamant `nano` users, but as soon as you learn how insert mode works, the syntax highlighting on vim is just better.

So, when I learned that the [Taggart Institute](https://taggartinstitute.org) released a new course called [Vim for Everyone](https://taggartinstitute.org/p/vim-for-everyone), I was interested. The course is pretty short and has a "pay what you can" model, but the very last component of the course was an interesting challenge.

![challenge](https://notateamserver.xyz/img/vim-week/challenge-vim.png)

Use Vim for a whole week. Hm.

This post is a shorter one than my usual, but will document the 5 days (a normal school week, because I'm not putting myself through this on the weekend) that I spend to do **everything** in Vim. That means writing this very post, programming for school, my job, maybe even eating and sleeping (if there's a plugin for that).

## Day 1
Since I didn't do too much this day, I'll spend a little bit of time explaining my set up here. I am currently on a Windows 11 host using [Neovim](https://neovim.io/) out of Windows Terminal. Out of sheer laziness, I'll be referring to Vim and Neovim interchangeably. These days, I do all of my dev work out of an Ubuntu virtual machine, so I'll have to get some more plugins set up on there. If you're wondering why Neovim, it's just because I already had it installed when I wanted Vim, but struggled to find the Windows installer, because it was probably 1 am.

My `.vimrc`, rather, my `init.vim` file currently looks like this:

```vim
set number
set tabstop
set shiftwidth=4
set expandtab
set clipboard=unnamed
syntax on

call plug#begin()

Plug 'scrooloose/nerdtree'

Plug 'reedes/vim-pencil'

Plug 'ghifarit53/tokyonight-vim'

call plug#end()

let g:tokyonight_style = 'night'
let g:tokyonight_enable_italic = 0

colorscheme tokyonight
```

Not too much going on. We've got some line numbers, tabs that expand to four spaces, two very basic plugins, and a nice color scheme. Once I have to do some serious programming, I imagine this list will grow.

As far as initial observations go, it's very strange to be doing this on Windows. Most of my notes and all of my blogs are written in Markdown, so I'm usually using [Obsidian](https://obsidian.md) to do all of the editing, but now I'm in Vim. I don't have WSL, so I can't use Tmux like I normally would, so having to remember and search for all of the window management keybinds is a bit of a pain. As far as writing blogs are concerned, I would say the overall experience is worse, simply because Obsidian is WYSIWYG ("what you see is what you get"), and Vim isn't. Or maybe there's a plugin that I'm unaware of, who knows. Anytime I want to insert an image into my post, I have to take a screenshot, save the picture to the folder in Explorer, come back to Vim, and type out something like `![picture](https://notateamserver.xyz/img/vim-week/epic.png)`. In Obsidian, I could just take the screenshot, then CTRL+V and the picture just shows up, and then I can use a Python script I have to fix up the formatting. Alas, I must go through writing this post like this:

![day1](https://an00brektn.github.io/img/vim-week/vim-day1.png)

As far as actually using Vim goes, it really hasn't been that big of a struggle. Learning about how buffers and registers work has helped make things much simpler for me, mostly copying and pasting. I find myself primarily using Insert mode as opposed to taking advantage of Command mode as much as possible. Maybe it's a comfort thing, maybe this is just how most people end up using Vim, I don't really know. I already get the feeling that once I'm going to have to hop into dev work, I'm going to be very, very slow, but the suffering will be good good, I hope. My other major prediction for the rest of the week is that I'll get better with Vim, but it's just not ideal for the way I work. I typically use Vim if I want to stay on the terminal the whole time, but that's just now how I really roll on Windows. It'll be much nicer when I'm on Linux and can take advantage of the command line a bit better (Windows CMD and PowerShell have always felt slightly clunky to me compared to Bash), but I still long for my GUI text editors for regular usage.

I figure I should probably leave a few notes behind on each day in case someone is new to Vim and wants to learn something:
- To split the screen, use `:split` for a horizontal split, and `:vsplit` for a vertical split.
- To navigate between windows, use `CTRL+W` followed by a direction. You can use the arrow keys, or HJKL.
- Exiting a window is the same as exiting Vim. Just use `:q`.
- I have genuinely forgotten how to resize windows and will need to look that one up.

See you all in Day 2.

## Day 2

So I may have already caved by using VS Code a little bit. But it was for good reason! In a class on Programming Languages, we were covering the topic of compilers, and so an in-class assignment was to put together a very rudimentary program to parse the tokens out of a sample C++ program. Aside from the fact that I very stupidly overcomplicated the assignment, I have also challenged myself to exclusively complete assignments in that class in Rust, when applicable. In summary, I'm using Vim and Rust at the same time, which is not a sentence I'd think I'd be saying a year ago.

![vim2](https://an00brektn.github.io/img/vim-week/vim-day2.png)
<sup>please ignore my overcomplicated code I know there's a better way to do this, and I'm going to refactor when I have time</sup>

Here's where the `.vimrc` was by the end of that day. Note that this is coming from my Ubuntu VM as opposed to my Windows host.

```vim
call plug#begin()
Plug 'scrooloose/nerdtree'

Plug 'reedes/vim-pencil'

Plug 'nvim-lua/plenary.nvim'

Plug 'nvim-telescope/telescope.nvim', { 'tag': '0.1.1' }

Plug 'ghifarit53/tokyonight-vim'

Plug 'voldikss/vim-floaterm'

Plug 'rust-lang/rust.vim'

Plug 'dense-analysis/ale'
call plug#end()

set number
set tabstop=4
set shiftwidth=4
set expandtab
set clipboard=unnamedplus
:imap <C-s> <C-w> " idk why this doesn't really work
syntax on

let g:tokyonight_style = 'storm' " available: night, storm
let g:tokyonight_enable_italic = 0

" https://stackoverflow.com/questions/2514445/turning-off-auto-indent-when-pasting-text-into-vim/38258720#38258720
" Mostly a tmux+alacritty fix, you don't really need this
let &t_SI .= "\<Esc>[?2004h"
let &t_EI .= "\<Esc>[?2004l"

inoremap <special> <expr> <Esc>[200~ XTermPasteBegin()

function! XTermPasteBegin()
  set pastetoggle=<Esc>[201~
  set paste
  return ""
endfunction

colorscheme tokyonight
let g:ale_linters = {'rust': ['analyzer']}
```

The [Floaterm](https://github.com/voldikss/vim-floaterm) plugin has been super useful to access the terminal from Vim as opposed to constantly have to do something like `!ls -la` from the command mode. I usually end up running and testing my Rust programs with `cargo run` so this is especially nice to see it from the terminal as opposed to some weird Vim thing.

[Telescope](https://github.com/nvim-telescope/telescope.nvim) is a nice plugin specifically for Neovim that lets you search for files in a given directory, and it works pretty quickly. I'm realizing I might need to settle on whether or not I commit to Neovim or Vim, as this doesn't seem to work with Vim (maybe I'm just missing something). That being said, very useful in larger projects where you remember a file being somewhere, but don't remember exactly where it is.

The [Rust](https://github.com/rust-lang/rust.vim) plugin is very minimalistic for Rust development in Vim, but at least presents specific enough errors when coupled with the [Ale](https://github.com/dense-analysis/ale) linter. The `let g:ale_linters` line is actually what sets up `rust-analyzer` as far as I'm aware. 

Coming back to the topic of Rust development, while I am still definitely a novice, I think it was healthy for me to go through at least once. With the `rust-analyzer` plugin in VS Code, I didn't really find a need to reference the actual docs when I could just go to Stack Overflow or read the compiler error. Without all of the niceties of the VS Code extension showing me all of the types and relevant docs, I had to get good at finding things in the documentation, which is a good skill to have. When I said I caved at the beginning, it was because when I was finishing my program, I ran into a bracket error where there was a missing one or an extra one. I hope you can forgive the 1 AM version of me for quickly looking at VS Code to find the bracket. I'm sure I could have found it with some Vim wizardry, but I just did not have the mental capacity to.

That being said, I find myself throwing in an `A` to get to the end of a line, or a `11e` to skip ahead 11 words, or a `3p` to paste something 3 times. I haven't really been using visual mode all too much, but incorporating some stuff from command mode has gotten a bit more comfortable. I find development in Vim, as of right now, to be slower from having to actively remember what keys do what in command mode. However, it is abundantly clear that if you exclusively put yourself through developing in Vim, you could be crazy fast. 

As for the window comment yesterday, I remember how to use windows consistently, but I find the resizing keybinds to be a bit annoying, having to press `CTRL+W` followed by a special character. For some reason, when I tried to mess with key mappings in Vim, they just weren't working. I might spend time later to actually read the documentation and learn what the right command is, but I will say that customizing Tmux keybinds is way easier.

My tips for today:
- Assuming you have your system clipboard set up correctly with Vim, you can use `"+yy` or `"*yy` to copy a line to your clipboard. You can copy the entire buffer using `"+yG` assuming you're at the top of the page, or use `:%y`.
- If you're using Neovim, it comes with a spell checker. Add `set spelllang=en,cjk` and `set spellsuggest=best,9` to your `init.vim`, then use `:set spell` and `:set spell!` to toggle the spell checker on and off. You can then use `z=` to see what the best options are. I recommend looking at this post from [jdhao](https://jdhao.github.io/2019/04/29/nvim_spell_check/) to get a bit more info on that. 
- When you open a file in Vim (and many other text editors), you will also see a new `.file.swp` file in the directory where the edited file is. This is to store a recovery version of the file, mainly to make sure there isn't multiple writes happening at the same time. The reason I bring this up is that it goes along the point of making sure to save with `:w` often. VS Code's Autosave feature has spoiled me, and it definitely took me at least a few minutes to remember to save before compiling.

## Day 3

No Rust today, but we're still coding nonetheless. I can say that I'm not feeling *as* miserable as I was last night, but I do feel a little guilty about how fast I'm able to do stuff. It gets better with each day, but having to spend a minute or two longer every time I need multiple windows up, or I need to search through the file system, or something else adds up over time. It could also be the fact that I'm spending too much time trying to get good at Super Smash Bros. Melee, but I'll blame Vim to take the heat off of me. 

After playing with plugins a little bit more, I realize that I should probably pay attention to what's designed for Neovim, and what's just designed for Vim. Most things that work in Vim tend to work in Neovim, but the opposite isn't always true. I haven't done too much digging, but it seems to be that Neovim has a more fleshed out environment for plugins, given the greater importance of the Lua programming language surrounding the tool. That's not to say one is better than the other, they both function pretty similarly, it's just more of a preference thing. All in all, the `init.vim` that I have on my Windows host versus my `.vimrc` on my Ubuntu VM are slightly different from each other.

To add on to the plugin experimentation, I figured out the issue with my colorscheme that I didn't really acknowledge. After switching to Tmux, I also switched terminal emulators to [Alacritty](https://github.com/alacritty/alacritty) (mostly for the colors if we're being honest) on Ubuntu. I mostly stole [xct's](https://github.com/xct/kali-clean/blob/main/.config/alacritty/alacritty.yml) config for it, but didn't realize the TERM variable needed to be set to `xterm-256color` in the config file, so there's that fix. The colors are still slightly off when I'm in tmux, but I don't really care about that issue too much right now.

Here's the config file for today, and we'll be sticking to the Linux `.vimrc` config from now on since that's where I'm using Vim the most.

```vim
call plug#begin()
Plug 'scrooloose/nerdtree'

Plug 'reedes/vim-pencil'

Plug 'ghifarit53/tokyonight-vim'

Plug 'voldikss/vim-floaterm'

Plug 'airblade/vim-gitgutter'

Plug 'bling/vim-airline'

Plug 'sheerun/vim-polyglot'

Plug 'rust-lang/rust.vim'

Plug 'dense-analysis/ale'
call plug#end()

set number
set tabstop=4
set shiftwidth=4
set expandtab
set clipboard=unnamedplus
:imap <C-s> <C-w>

set termguicolors
let g:tokyonight_style = 'night' " available: night, storm
let g:tokyonight_enable_italic = 0
colorscheme tokyonight
syntax on

" https://stackoverflow.com/questions/2514445/turning-off-auto-indent-when-pasting-text-into-vim/38258720#38258720
let &t_SI .= "\<Esc>[?2004h"
let &t_EI .= "\<Esc>[?2004l"

inoremap <special> <expr> <Esc>[200~ XTermPasteBegin()

function! XTermPasteBegin()
  set pastetoggle=<Esc>[201~
  set paste
  return ""
endfunction

" code stuffs
" I think pylint is making vim extra slow - need to figure that one out
" also the fact that the error window is so annoying, I'd rather just see the
" in-line error message when I visit a bad line
let g:ale_linters = {'rust': ['analyzer'], 'python': ['pylint']}
```

Trying to get linters and syntax checkers to work nicely in Vim is proving to be more challenging than I'd like it to be. I don't have a full grasp on where exactly it's coming from, but any time I save my Python file, I get a new window at the bottom screaming at me, which takes up space, and I could just visit each error individually instead. This wasn't the case with Rust, so I'll have to look into it. I was originally using [Syntastic](https://vimawesome.com/plugin/syntastic), but then removed it due to performance issues.

![syntastic](https://github.com/vim-syntastic/syntastic/raw/master/_assets/screenshot_1.png)
<sup>I despise that error window. Courtesy: [vim-syntastic/syntastic](https://github.com/vim-syntastic/syntastic)</sup>

I think the trickiest thing about managing your own set of plugins as opposed to using a prebuilt setup like [SpaceVim](https://github.com/SpaceVim/SpaceVim) is identifying what exactly it is you want at any given point, and making sure you don't install too many. At first, I didn't think I wanted a fancy bottom line like [powerline](https://github.com/powerline/powerline) or [airline](https://github.com/vim-airline/vim-airline), but now that I have one, it's significantly more pleasing to look at Vim than it was before. I've also acknowledged the fact that I generally only use tools where the defaults are already nice and I don't have to go in and twist every single knob the way I want it. And before you ask "then why do you use Tmux instead of [Terminator](https://www.youtube.com/watch?v=5-_bUD6oMok)?" it's because (a) I was [bullied](https://twitter.com/shubakki) into it (this is a joke) and (b) I can use it without a desktop environment, which is nice.

It's a very weird balancing act. More plugins help abstract and simplify certain things you might want to do. But, more plugins, or at the very least, improperly configured plugins, lead to slowness when trying to have multiple windows or write files. That's not to say this isn't true for other text editors, I've felt the CPU drain while using VS Code many times, but you'd think you'd be able to get away with more on a terminal application. Maybe it is just my linter that's being a pain and Vim is way faster than I'm percieving it to be, but the time sink into learning Vim, followed by the time sink to get it just the way I want it is significant. None of this is to say that Vim isn't good at what it does, but it's just a lot.

Today's tips/lessons:
- If you need a word count, press `g` then `CTRL+g`. You'll get a clean display of where you are in the file and how many words you've written so far.
- When you're looking to install plugins, keep an eye out for any very Unix-specific instructions. Plugins like [nvim-treesitter](https://github.com/nvim-treesitter/nvim-treesitter) are pretty easy to install on any flavor of Linux, but have much weirder instructions for Windows that will likely require a lot more work depending on how your environment is setup.
- Neovim's plugin system can either be configured through a `init.vim` for Vim script or `init.lua` for Lua code. Many README files will mention stuff like `require()`- these will not work in an `init.vim`. You'll need to use `init.lua` and handle that accordingly.

![conti](https://an00brektn.github.io/img/vim-week/conti.jpg)
<sup>Turns out I'm *slightly* smarter than a ransomware operator. Source: Conti Leaks</sup>

## Day 4 and 5

I'm combining both of these days because they mostly went the same. For an internship right now, I'm working with some Python code, so the last two days have just been using it in the same way I would use Visual Studio Code. At this point, I think the `.vimrc` is about as good as I want it to be, so there's no updates there. 

Aside from that, I found the regex and text processing features to be somewhat useful when working with larger files. I don't formally work in an environment where I'm processing a lot of data or changing configuration files that often, but being able to quickly find and replace certain variable names is neat, and a lot faster to do in Vim as compared to the graphical equivalent. The most challenging part of using Vim right now is just speed. If I'm in VS Code, I can quickly click through the project files, right click, and split right. In Vim, I have to `:vsplit` and then think about where the file is, and then type `:e /path/to/file`. I'm sure there's a faster way to do it, but gaining that level of fluency feels like it requires more time than I'm putting in right now.

I also have to give a big shoutout to the [Ale](https://github.com/dense-analysis/ale) plugin for providing minimalistic but sufficient linting. I think the weird error I was having last time with the error window was due to some kind of caching, because cleaning out my plugins and updating left me with a similar set up I did with Rust. It's also nice because all you have to do is give it the name of the executable that does the linting, and it's all good to go. If I was writing in Golang, I'd just add `golang: ['gopls']` and it would probably work just fine.

I don't have much else to report back on that I haven't already said. I slightly improved in my usage of commands, but still longed for my return to VS Code.

My final set of tips:
- This one isn't really a tip but more just basic functionality. If I wanted to find and replace all instances of "Windows" with "Linux" in my file, I can use `:%s/Windows/Linux/g`. The command takes the format `:[range]s/[find]/[replace]/[flags] [count]`. If you wanted to specify a range of lines, you could do `:4,20s/Windows/Linux/g` to specify lines 4 through 20.
- To exit all windows at once, you can do `:qa`. Yes, I only remembered this one on day 4.
- I can't believe I haven't said this yet, but you can do `:h [word/letter]` in Vim to open a new window with help information about that command, i.e. `man` pages for Vim. If you ever forget what a key does, this is much faster than Googling, although that's certainly not off the table.

## Conclusion
Looking back on everything I've written so far, I realize I might be coming off a bit negative overall. However, I still like Vim, just not for the things that I have to do as a Computer Science student. My experience from a developer standpoint was suboptimal, as I ended up spending a lot of time trying to make sure things were just right as opposed to getting more work done. However, if I'm at the terminal and need to read through a file, or make quick changes to some configuration, or need to put together a quick script, or anything else along these lines, my go-to is probably going to be Vim (not that it wasn't already).

For me, Vim is at its best when I'm working with one file with some kind of text processing that's necessary. During my week of exclusively using Vim, I didn't really take advantage of the shell commands, or the great ability of using shell commands with the buffer and vice versa, because I just did not need to. One example of this that's covered in the course is having Vim be a hex editor.

Suppose I wanted to change the raw bytes of some file. Instead of opening some separate hex editor tool, I can do the following:
- `:e /path/to/file` to edit the file
- `%!xxd` to send the entire buffer to the `xxd` command, which turns it into a hex dump
- Use your preferred way to edit the relevant bytes in the dump (not the ASCII bit to the right, the actual bytes)
- `%!xxd -r` to turn the newly edited hex dump back into the raw bytes.

TL;DR: Vim is a powerful tool that regularly gets installed on systems, and can do very cool things!

Hopefully, with that clarification, I have encouraged at least one person to give Vim and/or the [Vim for Everyone](https://taggartinstitute.org/p/vim-for-everyone) course a shot. Special thanks to the Taggart Institute for pushing me out of my comfort zone, it was a fun experiment! Happy to return to my usual environment, but at least I'm better at Vim than I was before.

![final](https://an00brektn.github.io/img/vim-week/final.png)

Until next time!

