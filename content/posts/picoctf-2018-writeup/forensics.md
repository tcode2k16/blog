---
title: "PicoCTF 2018 Writeup: Forensics"
date: 2018-10-13T08:56:02+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "picoctf",
  "forensics"
]
description: solves for picoCTF 2018 Forensics challenges
---

# Forensics Warmup 1

## Problem

Can you unzip this [file](/blog/picoctf-2018-writeup/Forensics/Forensics Warmup 1/flag.zip) for me and retreive the flag?

## Solution

Just unzip the file.

flag: `picoCTF{welcome_to_forensics}`

# Forensics Warmup 2

## Problem

Hmm for some reason I can't open this [PNG](/blog/picoctf-2018-writeup/Forensics/Forensics Warmup 2/flag.png)? Any ideas?

## Solution

Using the `file` command, you can see that the image is, in fact, in `jpeg` format not `png`:

```bash
❯ file flag.png
flag.png: JPEG image data, JFIF standard 1.01
```

Open the image as a `jpeg` file to get the file.

flag: `picoCTF{extensions_are_a_lie}`

# Desrouleaux

## Problem

Our network administrator is having some trouble handling the tickets for all of of our incidents. Can you help him out by answering all the questions? Connect with `nc 2018shell2.picoctf.com 10493`. [incidents.json](/blog/picoctf-2018-writeup/Forensics/Desrouleaux/incidents.json)

## Solution

Here is the solution script:

```python
from sets import Set
from pwn import *
import json

sh = remote('2018shell2.picoctf.com', 10493)

with open('./incidents.json') as f:
  data = json.loads(f.read())

# question 1
src = {}

for each in data[u'tickets']:
  src_ip = each[u'src_ip']
  if src_ip in src:
    src[src_ip] += 1
  else:
    src[src_ip] = 1

print sh.recvuntil('ones.\n')
sh.sendline(max(src, key=src.get))

# question 2
target = sh.recvuntil('?\n').split(' ')[-1][:-2]
target_ls = {}
count = 0
for each in data[u'tickets']:
  if each[u'src_ip'] == target and each[u'dst_ip'] not in target_ls:
    target_ls[each[u'dst_ip']] = True
    count += 1

sh.sendline(str(count))

# question 3
hashes = {}
for each in data[u'tickets']:
  hash = each[u'file_hash']
  if hash not in hashes:
    hashes[hash] = Set()
  hashes[hash].add(each[u'dst_ip'])

avg = 0
for each in hashes:
  e = hashes[each]
  avg += len(e)
avg = (avg * 1.0) / len(hashes)

print sh.recvuntil('.\n')
sh.sendline(str(avg))

sh.interactive()
```

flag: `picoCTF{J4y_s0n_d3rUUUULo_a062e5f8}`

# Reading Between the Eyes

## Problem

Stego-Saurus hid a message for you in this [image](/blog/picoctf-2018-writeup/Forensics/Reading Between the Eyes/husky.png), can you retreive it?

## Solution

This problem is about using the [Least Significant Bit algorithm for image steganography](http://ijact.org/volume3issue4/IJ0340004.pdf). It can be solved using an [online decoder](http://stylesuxx.github.io/steganography/).

{{< figure src="/blog/picoctf-2018-writeup/Forensics/Reading Between the Eyes/image.png" >}}

flag: `picoCTF{r34d1ng_b37w33n_7h3_by73s}`

# Recovering From the Snap

## Problem

There used to be a bunch of [animals](/blog/picoctf-2018-writeup/Forensics/Recovering From the Snap/animals.dd) here, what did Dr. Xernon do to them?

## Solution

This problem is about recovering files from a FAT filesystem. It can be done using [TestDisk] (https://www.cgsecurity.org/wiki/TestDisk), a powerful free data recovery software.

You can follow [this guide](https://www.cgsecurity.org/wiki/TestDisk:_undelete_file_for_FAT) to recover the `theflag.jpg` file.

<script src="https://asciinema.org/a/kNPluVGT6AmxVuv0R4XstIm0c.js" id="asciicast-kNPluVGT6AmxVuv0R4XstIm0c" async></script>

{{< figure src="/blog/picoctf-2018-writeup/Forensics/Recovering From the Snap/theflag.jpg" attr="theflag.jpg" >}}

flag: `picoCTF{th3_5n4p_happ3n3d}`

# admin panel

## Problem

We captured some [traffic](/blog/picoctf-2018-writeup/Forensics/admin panel/data.pcap) logging into the admin panel, can you find the password?

## Solution

{{< figure src="/blog/picoctf-2018-writeup/Forensics/admin panel/image.png" >}}

If you look for `http` requests, you will see two login attempts, and the second request contains the flag:

```
POST /login HTTP/1.1
Host: 192.168.3.128
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.3.128/
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Connection: keep-alive
Upgrade-Insecure-Requests: 1

user=admin&password=picoCTF{n0ts3cur3_9feedfbc}
```

flag: `picoCTF{n0ts3cur3_9feedfbc}`

# hex editor

## Problem

This [cat](/blog/picoctf-2018-writeup/Forensics/hex editor/hex_editor.jpg) has a secret to teach you. You can also find the file in /problems/hex-editor_4_0a7282b29fa47d68c3e2917a5a0d726b on the shell server.

## Solution

You can get the flag by looking at the hex hump of the image or just print out all the readable parts of the file:

```bash
❯ strings hex_editor.jpg | grep pico
Your flag is: "picoCTF{and_thats_how_u_edit_hex_kittos_dF817ec5}"
```

flag: `picoCTF{and_thats_how_u_edit_hex_kittos_dF817ec5}`

# Truly an Artist 

## Problem

Can you help us find the flag in this [Meta-Material](/blog/picoctf-2018-writeup/Forensics/Truly an Artist/2018.png)? You can also find the file in /problems/truly-an-artist_3_066d6319e350c1d579e5cf32e326ba02.

## Solution

The flag is in the EXIF meta-data of the image:

```bash
❯ exiftool 2018.png
ExifTool Version Number         : 11.01
File Name                       : 2018.png
Directory                       : .
File Size                       : 13 kB
File Modification Date/Time     : 2018:10:09 23:34:05+08:00
File Access Date/Time           : 2018:10:10 09:15:07+08:00
File Inode Change Date/Time     : 2018:10:09 23:34:06+08:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1200
Image Height                    : 630
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Artist                          : picoCTF{look_in_image_eeea129e}
Image Size                      : 1200x630
Megapixels                      : 0.756
```

flag: `picoCTF{look_in_image_eeea129e}`

# now you don't

## Problem

We heard that there is something hidden in this [picture](/blog/picoctf-2018-writeup/Forensics/now you dont/nowYouDont.png). Can you find it?

## Solution

You can create another image with only one shade of red and diff that image with the one provided to get the flag:


```bash
❯ convert -size 857x703 canvas:"#912020" pure.png
❯ compare nowYouDont.png pure.png diff.png
```

{{< figure src="/blog/picoctf-2018-writeup/Forensics/now you dont/diff.png" attr="diff.png" >}}

flag: `picoCTF{n0w_y0u_533_m3}`

# Ext Super Magic

## Problem

We salvaged a ruined Ext SuperMagic II-class mech recently and pulled the [filesystem](/blog/picoctf-2018-writeup/Forensics/Ext Super Magic/ext-super-magic.img) out of the black box. It looks a bit corrupted, but maybe there's something interesting in there. You can also find it in /problems/ext-super-magic_4_f196e59a80c3fdac37cc2f331692ef13 on the shell server.

## Solution

You are given a ext3 file image that is broken. To fix the image, you have to correct the magic number of the file. You can read more about the ext3 file format over [here](http://www.nongnu.org/ext2-doc/ext2.html).

Here is the script that writes the magic number `0xEF53` into the file:

```python
# flag: picoCTF{a7DB29eCf7dB9960f0A19Fdde9d00Af0}nc 2018shell2.picoctf.com 2651

from pwn import *

with open('./ext-super-magic.img', 'rb') as f:
  data = f.read()

print enhex(data[1024:1024+82])
print enhex(data[1024+56:1024+56+2])

data = data[:1024+56] + p16(0xEF53) + data[1024+56+2:]

with open('fixed.img', 'wb') as f:
  f.write(data)
```

flag: `picoCTF{a7DB29eCf7dB9960f0A19Fdde9d00Af0}`

# Lying Out

## Problem

Some odd [traffic](/blog/picoctf-2018-writeup/Forensics/Lying Out/traffic.png) has been detected on the network, can you identify it? More [info](/blog/picoctf-2018-writeup/Forensics/Lying Out/info.txt) here. Connect with `nc 2018shell2.picoctf.com 27108` to help us answer some questions.

## Solution

Just read the graph and do this problem by hand.

flag: `picoCTF{w4y_0ut_de051415}`

# What's My Name?

## Problem

Say my name, say [my name](/blog/picoctf-2018-writeup/Forensics/Whats My Name/myname.pcap).

## Solution

The hint is very helpful. It asks `If you visited a website at an IP address, how does it know the name of the domain?`.

The answer to this question is that a domain is resolved through `DNS` packets.

If we only look for `DNS` packets in wireshark, we will find the flag.

{{< figure src="/blog/picoctf-2018-writeup/Forensics/Whats My Name/image.png" >}}

flag: `picoCTF{w4lt3r_wh1t3_33ddc9bcc77f22a319515c59736f64a2}`

# core

## Problem

This [program](/blog/picoctf-2018-writeup/Forensics/core/print_flag) was about to print the flag when it died. Maybe the flag is still in this [core](/blog/picoctf-2018-writeup/Forensics/core/core) file that it dumped? Also available at /problems/core_1_722685357ac5a814524ee76a3dcd1521 on the shell server.

## Solution

Let's first take a look at the program using radare2:

```
[0x080484c0]> s sym.print_flag
[0x080487c1]> pdf
┌ (fcn) sym.print_flag 43
│   sym.print_flag ();
│           ; var int local_ch @ ebp-0xc
│           ; CALL XREF from sym.main (0x8048802)
│           0x080487c1      55             push ebp                    ; ./print_flag.c:90
│           0x080487c2      89e5           ebp = esp
│           0x080487c4      83ec18         esp -= 0x18
│           0x080487c7      c745f4390500.  dword [local_ch] = 0x539    ; ./print_flag.c:91 ; 1337
│           0x080487ce      8b45f4         eax = dword [local_ch]      ; ./print_flag.c:92
│           0x080487d1      8b048580a004.  eax = dword [eax*4 + obj.strs] ; [0x804a080:4]=0
│           0x080487d8      83ec08         esp -= 8
│           0x080487db      50             push eax
│           0x080487dc      684c890408     push str.your_flag_is:_picoCTF__s ; 0x804894c ; "your flag is: picoCTF{%s}\n" ; const char *format
│           0x080487e1      e82afcffff     sym.imp.printf ()           ; int printf(const char *format)
│           0x080487e6      83c410         esp += 0x10
│           0x080487e9      90                                         ; ./print_flag.c:93
│           0x080487ea      c9             leave
└           0x080487eb      c3             return
```

As you can see, the flag pointer is located at `eax*4 + obj.strs` or `0x804a080+0x539*4` in memory:

```
❯ python
>>> hex(0x804a080+0x539*4)
'0x804b564'
```

Now, we can use gdb and the core file to restore the application state and extract the flag from that address:

```
$ gdb ./print_flag ./core
...
gef➤  x 0x804b564
0x804b564 <strs+5348>:	0x080610f0
gef➤  x 0x080610f0
0x80610f0:	"e52f4714963eb207ae54fd424ce3c7d4"
```

flag: `picoCTF{e52f4714963eb207ae54fd424ce3c7d4}`

# Malware Shops

## Problem

There has been some [malware](/blog/picoctf-2018-writeup/Forensics/Malware Shops/plot.png) detected, can you help with the analysis? More [info](/blog/picoctf-2018-writeup/Forensics/Malware Shops/info.txt) here. Connect with `nc 2018shell2.picoctf.com 46168`.

## Solution

Just read the graph and do this problem by hand.

```
❯ nc 2018shell2.picoctf.com 46168
You'll need to consult the file `clusters.png` to answer the following questions.


How many attackers created the malware in this dataset?
5
Correct!


In the following sample of files from the larger dataset, which file was made by the same attacker who made the file 3ce8eb6f? Indicate your answer by entering that file's hash.
       hash  jmp_count  add_count
0  3ce8eb6f       33.0       28.0
1  55489271       40.0        2.0
2  33d91680       39.0       29.0
3  ebaf5ccd        9.0       17.0
4  e9c0ac07       17.0       61.0
5  628e79cf        9.0       18.0
6  b3ae7861       41.0       10.0
7  cc251d4b       16.0       41.0
8  0c91a83b       17.0       65.0
9  97a0fc46       10.0       38.0
33d91680
Correct!


Great job. You've earned the flag: picoCTF{w4y_0ut_dea1794b}
```

flag: `picoCTF{w4y_0ut_dea1794b}`

# LoadSomeBits

## Problem

Can you find the flag encoded inside this image? You can also find the file in /problems/loadsomebits_2_c5bba4da53a839fcdda89e5203ac44d0 on the shell server.

## Solution

Ryan Jung on our team solved this challenge. It is about looking at the least significant bit of each pixel value.

flag: `picoCTF{st0r3d_iN_th3_l345t_s1gn1f1c4nT_b1t5_2705826400}`