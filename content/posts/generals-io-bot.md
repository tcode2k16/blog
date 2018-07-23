---
title: "Generals.io game bot"
date: 2018-07-23T16:55:46+08:00
draft: false
tags: [
  "project",
  "javascript",
  "google",
  "nodejs",
  "chrome"
]
description: making a generals.io game bot using chrome headless and nodejs
---

{{< figure src="/blog/generals-io-bot/replay.gif" attr="Credit: dev.generals.io" >}}

# What is Generals.io?

Generals.io is a turn-based strategy game that can be played in the browser. Each player starts out with one grid on a large map that is called the general. The goal of the game is to expand and eliminate other players' generals. Once a player's general gets taken, the player loses the game, and in the end, the last player standing wins the game.

# Idea number 1: let's build a chrome extension!

One day when I was playing the game, I found myself repeating similar actions over and over. These actions include expanding my territory and conquering neighboring lands. I wondered if I could write a sweet chrome extension to map these actions to some special shortcuts which helps me gain an advantage over my opponent.

After three hours of tinkering, I managed to accomplish two goals. First, my extension was able to read the map and determine different types of cells such as: friendly troops, enemy troops, mountains and etc. Second, my extension can then formulate game moves based on the current map and my intended action. I was confident that the extension can be finished soon, and the only feature left to implement was to simulation human clicks. *How hard can that be?*

**Very!** As it turned out.

To prevent malicious websites from faking clicks, the major browsers including firefox and chrome have made it now nearly impossible to simulate multiple clicks at once. I tried all kinds of methods: emitting all kinds of different events, using browser specific APIs, and **even jquery**! Yes, I tried **jquery**! None of these things worked.

After a total of six hours of development, this idea turned out to be not feasible; however, a new idea popped in my mind.

# Idea number 2: let's build a game helper!

If the **website** can't simulate a click, the **browser** must be able to do it. I fired up nodejs and installed [puppeteer](https://github.com/GoogleChrome/puppeteer) -- a nodejs API for controlling headless chrome.

```bash
> npm init
> npm i puppeteer
```

The new idea was to script the browser instead of the website and split my program into two parts:

* an injected script that runs in the website that is in charge of all the logic (reading the map and coming up with the moves)

* a nodejs script that launches chrome, clicks all the game buttons, injects the script above, and exposes an API that handles all the clicking

Two more hours flew by, and finally, I created a general.io helper that can preform tasks for me. Now, with the click of a key, my game helper will plan and execute available game moves for me.

{{< figure src="/blog/generals-io-bot/helper.gif" attr="game helper in action" >}}

# Idea number 3: let's build a bot!

Well, after I built the game helper, I realized that I was very close to building a bot. Using the game helper shortcuts, I was able to play a game without using any regular controls, and if I build a bot just to click the buttons, I would have a bot!

That is exactly what I did. Combining simple behaviors such as *expand*, *attack*, and *defend*, I was able to build a bot within an hour.

But we can do even better! **What is the fun of building one bot, if we can have eight bots fighting each other?**

Here I present you [the replay of eight bots fighting each other](http://generals.io/replays/B5coA8nXX)!

> Just as a bonus, here is [two of my bots defeating human](http://generals.io/replays/HdAVQDnm7)

# Extra

Here are some other things I learned about puppeteer in the process of building this project:

* `browser.createIncognitoBrowserContext` is helpful in creating multiple chrome sessions where each have its own local storage eliminating the need for launching more than one chrome instance.
* The `pageerror` and `console` events of the `page` object are useful in debugging injected javascript.
* `page.exposeFunction` allows you to expose nodejs functions to website context.

If you are interested in the code, you can find it on [github](https://github.com/tcode2k16/generals_helper).