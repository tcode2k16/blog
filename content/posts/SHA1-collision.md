---
title: "SHA1 Collision"
date: 2018-05-16T11:32:16+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "hash"
]
description: Creating a SHA1 collision with PDF files
---

### Introduction

When I was doing the [DEF CON CTF Qualifier](https://www.oooverflow.io/) last weekend, I came across an interesting question where you need to create two pdf files with the same SHA1 hash.

### Research

I know SHA1 hash was already broken when google blogged about [creating the first SHA1 collision](https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html), but I was not sure that I can reproduce the process with limited hardware.

### Result

In the end, I came across [this website](http://alf.nu/SHA1) that is able to generate two PDF files with the same SHA1 hash using two JPG images based on [this paper](https://shattered.io/). This helps demonstrate how SHA1 is no longer secure and developers should start using other hashing algorithms such as SHA256
