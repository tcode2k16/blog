---
title: "Base 62 and My First Open Source Contribution"
date: 2019-01-27T18:34:27+09:00
draft: true
tags: [
  "ctf",
  "cyber-security",
  "open-source"
]
description: 0x00sec CTF, Base 62, and open source
---

# 0x00sec CTF

Last year in December, I participated in a mini-ctf called 0x00sec where there's only five questions in total. I, among a few other people, was able to solve four of the problems in the first 5-6 hours with some easy effort; however, one problem remained unsolved for a long time and was only solved close to the 24 hours mark.

This challenge asks you to decode the message: ``alzzN-hEwjUk-jmHf0zk-xJ5QXl-7H7BbL-twYhko`.

At first, I though it was some strange cipher that I never heard of. I did a ton of google searches trying to find the cipher that is used, but nothing came up. The idea of base encoding also came acrossed my mind, but it was dismissed after I tried the few base encoding methods provided in [CyberChef](https://gchq.github.io/CyberChef). The `-` in the message further enforced my belief that it got to be some other cipher instead of just a plain base encoding. After a few more hours, I finally gave up and went to sleep.

# Solution and reflection

The CTF ended the next day, and I discovered that it was just a simple base encoding. The only twist is that it is using "base 62" instead of a common base such as "base 64" or "base 85", and the `-` can be ignored

I was somewhat disappointed in myself (could have gotten a prize if I solved it) and asked the question: what went wrong? and how can I solve it next time?

I landed on the conclusion that I didn't solve the challenge because of both a lack of experience and bad tooling. If I used "base 62" more or if tools like CyberChef provided the option of "base 62", i would have solved the challenge.

By trying the challenge, I already improved on the first point, but I also want to do something about the second point.

# First open source contribution

I remembered that CyberChef is a open source tool on Github which means that I have the chance to add  "base 62" as a feature.

Luckily, the project uses javascript which I already know quite well at this point, and I though how hard can it be to implement a base encoding?

The first thing I did after forking the git repository is to look at the overall structure of the code base and the implementation details of "base 64" and "base 85" which are similiar to the thing that I am trying to implement.

After I gotten a hang of the code base, I started writing my implementation. The automation scripts included are very helpful, and the process took a little bit over an hour to complete.

I finished the implementation and tried to decode the string from the challenge. It worked as intended! But instead of making a pull request straight way, I reminded myself to write tests.

Following the tests for "base 64", I implemented a similar set of checks covering ascii, empty case, utf-8, and etc.

After writing and running the test, I finally made the pull request. I was quite nervous as it is my first time doing this, and I don't want to mess it up.

In the end, however, the entire process went smoothly. I signed the contributor form, the maintainer looked at my code, made some slight changes and merged it to master.

I felt a huge joy when my charges went live and I can use "base 62" in CyberChef.

# Conclusion

In conclusion, it was quite a experience for me, and I learned a lot about how to contribute to open source project. If I have to do it again, I will be more confident in myself.

In addition, now I can solve base 62 challenges in CyberChef ;)