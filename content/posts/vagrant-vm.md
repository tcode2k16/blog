---
title: "Vagrant virtual machine for CTF competitions"
date: 2018-05-18T11:28:59+08:00
draft: false
tags: [
  "project",
  "vagrant",
  "ctf",
  "cyber-security"
]
description: Creating a virtual machine with all the tools for CTF competition pre-installed
---

### Introduction

I am running a cyber security club at my school. One of the club activities is to learn binary exploitation, most of my fellow club members don't have linux installed on their computers and have little experience installing all the needed tools.

To make binary exploitation more accessible, I created this vagrant file that will setup all the necessary tools within a ubuntu virtual machine.

### Method

I picked vagrant over docker because of the follow reasons:

* my prior experience
* no obvious performance difference compared to docker (docker also runs in a vm for macOS and windows)
* different providers (virtual box, kvm...)

The vagrant script consist of a simple bash script for the installation, virtual box configs and general configs.

### Result

[Here](https://github.com/tcode2k16/vagrant_vm/tree/master/ubuntu_ctf) is the github repository.

Here is a (maybe outdated) list of tools included:

* x86 binary libs
* gdb with peda
* binwalk
* exiftool
* imagemagick
* socat
* unzip
* python2
* nodejs
* radare2
* pwntools
* ipython
* masscan
* featherduster


