---
title: "PicoCTF 2019 Writeup: Forensics"
date: 2019-10-12T00:00:05+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "picoctf",
  "forensics"
]
description: solves for picoCTF 2019 Forensics challenges
---

# Glory of the Garden

## Problem

This garden contains more than it seems. You can also find the file in /problems/glory-of-the-garden_5_eeb712a9a3bc1998ffcd626af9d63f98 on the shell server.

[file](/blog/picoctf-2019-writeup/forensics/Glory of the Garden/garden.jpg)


## Solution

There's addition text in the file that can be extracted with `strings`.

```
$ strings garden.jpg | grep pico
Here is a flag "picoCTF{more_than_m33ts_the_3y3cD8bA96C}"
```

flag: `picoCTF{more_than_m33ts_the_3y3cD8bA96C}`

# unzip

## Problem

Can you unzip this file and get the flag?

[file](/blog/picoctf-2019-writeup/forensics/unzip/flag.zip)

## Solution

just unzip the file to get [flag.png](/blog/picoctf-2019-writeup/forensics/unzip/flag.png)

{{< figure src="/blog/picoctf-2019-writeup/forensics/unzip/flag.png" >}}

flag: `unz1pp1ng_1s_3a5y`

# So Meta

## Problem

Find the flag in this picture. You can also find the file in /problems/so-meta_1_ab9d99603935344b81d7f07973e70155.

[file](/blog/picoctf-2019-writeup/forensics/So Meta/pico_img.png)

## Solution

The flag is hidden in the EXIF data of the image. It can be extracted with the `exiftool`:

```
$ exiftool pico_img.png | grep Artist
Artist                          : picoCTF{s0_m3ta_368a0341}
```

flag: `picoCTF{s0_m3ta_368a0341}`

# What Lies Within

## Problem

Theres something in the building. Can you retrieve the flag?

[file](/blog/picoctf-2019-writeup/forensics/What Lies Within/buildings.png)


## Solution

This is a challenge where [the flag is hidden in the least significant bit of each pixel value](https://www.boiteaklou.fr/Steganography-Least-Significant-Bit.html). It can be extracted with `zsteg`:

```
$ zsteg buildings.png 
b1,r,lsb,xy         .. text: "^5>R5YZrG"
b1,rgb,lsb,xy       .. text: "picoCTF{h1d1ng_1n_th3_b1t5}"
b1,abgr,msb,xy      .. file: PGP\011Secret Sub-key -
b2,b,lsb,xy         .. text: "XuH}p#8Iy="
b3,abgr,msb,xy      .. text: "t@Wp-_tH_v\r"
b4,r,lsb,xy         .. text: "fdD\"\"\"\" "
b4,r,msb,xy         .. text: "%Q#gpSv0c05"
b4,g,lsb,xy         .. text: "fDfffDD\"\""
b4,g,msb,xy         .. text: "f\"fff\"\"DD"
b4,b,lsb,xy         .. text: "\"$BDDDDf"
b4,b,msb,xy         .. text: "wwBDDDfUU53w"
b4,rgb,msb,xy       .. text: "dUcv%F#A`"
b4,bgr,msb,xy       .. text: " V\"c7Ga4"
b4,abgr,msb,xy      .. text: "gOC_$_@o"
```

flag: `picoCTF{h1d1ng_1n_th3_b1t5}`

# extensions

## Problem

This is a really weird text file TXT? Can you find the flag?

[file](/blog/picoctf-2019-writeup/forensics/extensions/flag.txt)

## Solution

A quick file type check with `file` reveals that we have a PNG file instead of a TXT file:

```
$ file flag.txt 
flag.txt: PNG image data, 1697 x 608, 8-bit/color RGB, non-interlaced
```

Simply changing the filename to [flag.png](/blog/picoctf-2019-writeup/forensics/extensions/flag.png) yields the flag.

{{< figure src="/blog/picoctf-2019-writeup/forensics/extensions/flag.png" >}}

flag: `picoCTF{now_you_know_about_extensions}`

# shark on wire 1

## Problem

We found this packet capture. Recover the flag. You can also find the file in /problems/shark-on-wire-1_0_13d709ec13952807e477ba1b5404e620.

[file](/blog/picoctf-2019-writeup/forensics/shark on wire 1/capture.pcap)

## Solution

We are given a pcap network capture that can be opened in wireshark. When we ope the file, we see many udp packets. By following udp streams, we can obtain the flag. Specifically, apply the filter `udp.stream eq 6` and then right-click the follow udp option:

{{< figure src="/blog/picoctf-2019-writeup/forensics/shark on wire 1/screen.png" >}}

flag: `picoCTF{StaT31355_636f6e6e}`

# WhitePages

## Problem

I stopped using YellowPages and moved onto WhitePages... but the page they gave me is all blank!

[file](/blog/picoctf-2019-writeup/forensics/WhitePages/whitepages.txt)


## Solution

A quick hexdump with `xxd` shows that there are two different patterns: `e28083` and `20`:

```
s$ xxd whitepages.txt 
00000000: e280 83e2 8083 e280 83e2 8083 20e2 8083  ............ ...
00000010: 20e2 8083 e280 83e2 8083 e280 83e2 8083   ...............
00000020: 20e2 8083 e280 8320 e280 83e2 8083 e280   ...... ........
00000030: 83e2 8083 20e2 8083 e280 8320 e280 8320  .... ...... ... 
00000040: 2020 e280 83e2 8083 e280 83e2 8083 e280    ..............
00000050: 8320 20e2 8083 20e2 8083 e280 8320 e280  .  ... ...... ..
...
```

Treating `e28083` as `0` and `20` as `1` gives us the flag in binary:

```python
from pwn import *

with open('./whitepages.txt', 'rb') as f:
  data = f.read()

data  = data.replace('e28083'.decode('hex'), '0').replace(' ', '1')

print unbits(data)
```

```
$ python main.py 

        picoCTF

        SEE PUBLIC RECORDS & BACKGROUND REPORT
        5000 Forbes Ave, Pittsburgh, PA 15213
        picoCTF{not_all_spaces_are_created_equal_dd5c2e2f77f89f3051c82bfee7d996ef}
        
```

flag: `picoCTF{not_all_spaces_are_created_equal_dd5c2e2f77f89f3051c82bfee7d996ef}`

# like1000

## Problem

This .tar file got tarred alot. Also available at /problems/like1000_0_369bbdba2af17750ddf10cc415672f1c.

[file](/blog/picoctf-2019-writeup/forensics/like1000/1000.tar)

## Solution

I solved this with a short python script and the unzipping utility [unar](https://theunarchiver.com/command-line):

```python
from os import system

system('unar ./1000.tar')
for i in range(999, -1, -1):
  system('unar ./{}/{}.tar'.format(i+1, i))
```

We obtain the [flag.png](/blog/picoctf-2019-writeup/forensics/like1000/flag.png) nested in 1000 tar file which has the flag.

{{< figure src="/blog/picoctf-2019-writeup/forensics/like1000/flag.png" >}}


flag: `picoCTF{l0t5_0f_TAR5}`

# Investigative Reversing 0

## Problem

We have recovered a binary and an image. See what you can make of it. There should be a flag somewhere. Its also found in /problems/investigative-reversing-0_6_2d92ee3bac4838493cb68ec16e086ac6 on the shell server.

[image](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 0/mystery.png)

[binary](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 0/mystery)

## Solution

Reversing the binary shows that the flag is encoded and then appended to the image:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int i; // [rsp+4h] [rbp-4Ch]
  signed int j; // [rsp+8h] [rbp-48h]
  FILE *stream; // [rsp+10h] [rbp-40h]
  FILE *v7; // [rsp+18h] [rbp-38h]
  char ptr; // [rsp+20h] [rbp-30h]
  char v9; // [rsp+21h] [rbp-2Fh]
  char v10; // [rsp+22h] [rbp-2Eh]
  char v11; // [rsp+23h] [rbp-2Dh]
  char v12; // [rsp+24h] [rbp-2Ch]
  char v13; // [rsp+25h] [rbp-2Bh]
  char v14; // [rsp+2Fh] [rbp-21h]
  unsigned __int64 v15; // [rsp+48h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  stream = fopen("flag.txt", "r");
  v7 = fopen("mystery.png", "a");
  if ( !stream )
    puts("No flag found, please make sure this is run on the server");
  if ( !v7 )
    puts("mystery.png is missing, please run this on the server");
  if ( (signed int)fread(&ptr, 0x1AuLL, 1uLL, stream) <= 0 )
    exit(0);
  puts("at insert");
  fputc(ptr, v7);
  fputc(v9, v7);
  fputc(v10, v7);
  fputc(v11, v7);
  fputc(v12, v7);
  fputc(v13, v7);
  for ( i = 6; i <= 14; ++i )
    fputc((char)(*(&ptr + i) + 5), v7);
  fputc((char)(v14 - 3), v7);
  for ( j = 16; j <= 25; ++j )
    fputc(*(&ptr + j), v7);
  fclose(v7);
  fclose(stream);
  return __readfsqword(0x28u) ^ v15;
}
```

As shown above, the 6th to 14th byte are added by 5 and the 15th byte is subtracted by 3. We can used `xxd` to extract the encoded hex and decode it with a short python script:

```python
data = '7069636f43544b806b357a73696436715f65656165633438627d'.decode('hex')
data = bytearray(data)

for i in range(6, 15):
  data[i] -= 5

data[15] += 3

print data
```

flag: `picoCTF{f0und_1t_eeaec48b}`

# Investigative Reversing 1

## Problem

We have recovered a binary and a few images: image, image2, image3. See what you can make of it. There should be a flag somewhere. Its also found in /problems/investigative-reversing-1_0_329e7a12e90f3f127c8ab2489b08bcf1 on the shell server.

[binary](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 1/mystery)

[image1](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 1/mystery.png)

[image2](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 1/mystery2.png)

[image3](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 1/mystery3.png)

## Solution

Similar to [Investigative Reversing 0](#investigative-reversing-0), we need to reverse the binary and decode the flag:

```python
from pwn import *
s1 = unhex('43467b416e315f62313739313135657d')
s2 = unhex('8573')
s3 = unhex('696354307468615f')

out = bytearray('0'*0x1a)

out[1] = s3[0]
out[21] = s2[0]
out[2] = s3[1]
out[5] = s3[2]
out[4] = s1[0]

for i in range(6,10):
  out[i] = s1[i-5]

out[3] = chr(ord(s2[1])-4)

for i in range(10, 15):
  out[i] = s3[i-7]

for i in range(15,26):
  out[i] = s1[i-10]

print out
```

flag: `picoCTF{An0tha_1_b179115e}`

# Investigative Reversing 2

## Problem

We have recovered a binary and an image See what you can make of it. There should be a flag somewhere. Its also found in /problems/investigative-reversing-2_5_b294e24c9063edbf722b9554e7750d19 on the shell server.

[binary](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 2/mystery)


[image](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 2/encoded.bmp)


## Solution

Same concept as before, we need to reverse the binary and decode the flag:

```python
with open('./encoded.bmp', 'rb') as f:
  data = f.read()

data = data[2000:2000+(50*8)]

out = ''

for i in range(50):
  c = 0
  for j in range(8):
    c = c | (ord(data[i*8+(7-j)])&1)
    c = c << 1
  c = c >> 1
  out += chr(c+5)
  print c
  print out

```

flag: `picoCTF{n3xt_0n30000000000000000000000000f69eb8c8}` 

# pastaAAA

## Problem

This pasta is up to no good. There MUST be something behind it.

[file](/blog/picoctf-2019-writeup/forensics/pastaAAA/ctf.png)


## Solution

Flag is hidden in one of the RGB planes and can be extracted with stegsolve:

{{< figure src="/blog/picoctf-2019-writeup/forensics/pastaAAA/screen.png" >}}


flag: `picoCTF{pa$ta_1s_lyf3}`

# Investigative Reversing 3

## Problem

We have recovered a binary and an image See what you can make of it. There should be a flag somewhere. Its also found in /problems/investigative-reversing-3_5_bb1b39c0e6a6ea43ea4f44c5b6f44200 on the shell server.

[binary](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 3/mystery)

[image](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 2/encoded.bmp)

## Solution

This challenge is building on top of [Investigative Reversing 2](#investigative-reversing-2). Here is the decode script:

```python
with open('./encoded.bmp', 'rb') as f:
  data = f.read()

data = data[723:723+(50*9)]

out = ''

for i in range(50):
  c = 0
  for j in range(8):
    c = c | (ord(data[i*9+(7-j)])&1)
    c = c << 1
  c = c >> 1
  out += chr(c)
  print c
  print out
```

flag: `picoCTF{4n0th3r_L5b_pr0bl3m_0000000000000aa9faea3}`


# Investigative Reversing 4

## Problem

We have recovered a binary and 5 images: image01, image02, image03, image04, image05. See what you can make of it. There should be a flag somewhere. Its also found in /problems/investigative-reversing-4_5_908aeadf9411ff79b32829c8651b185a on the shell server.

[binary](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 4/mystery)

[image01](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 4/Iterm01_cp.bmp)

[image02](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 4/Iterm02_cp.bmp)

[image03](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 4/Iterm03_cp.bmp)

[image04](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 4/Iterm04_cp.bmp)

[image05](/blog/picoctf-2019-writeup/forensics/Investigative Reversing 4/Iterm05_cp.bmp)


## Solution

LSB but with different images. Here is decode script:

```python
arr = []
for i in range(5, 0, -1):
  with open('./Item0{}_cp.bmp'.format(i), 'rb') as f:
    data = f.read()[2019:2019+10*8+40*1]
    arr.extend(data)

out = ''

for i in range(50):
  c = 0
  for j in range(8):
    c = c | (ord(arr[i*12+(7-j)])&1)
    c = c << 1
  c = c >> 1
  out += chr(c)
  print c
  print out
 
```

flag: `picoCTF{N1c3_R3ver51ng_5k1115_00000000000ade0499b}`

# investigation_encoded_1

## Problem

We have recovered a binary and 1 file: image01. See what you can make of it. Its also found in /problems/investigation-encoded-1_6_172edc378b5282150ec24be19ff8342b on the shell server. NOTE: The flag is not in the normal picoCTF{XXX} format.

[binary](/blog/picoctf-2019-writeup/forensics/investigation_encoded_1/mystery)

[image](/blog/picoctf-2019-writeup/forensics/investigation_encoded_1/output)


## Solution

The program maps each character to a stream of n bits. By reversing the program, we can recover this mapping, therefore, obtain the flag:

```python
import string
from pwn import *

context.log_level = 'error'

v1 = '000000000C000000080000000E000000140000000A00000022000000040000002C0000000C000000300000000C0000003C0000000A00000048000000060000005200000010000000580000000C000000680000000C000000740000000A00000080000000080000008A0000000E000000920000000E000000A000000010000000AE0000000A000000BE00000008000000C800000006000000D00000000A000000D60000000C000000E00000000C000000EC0000000E000000F800000010000000060100000E000000160100000400000024010000'
v1 = unhex(v1)
temp = []
for i in range(0, len(v1), 4):
  temp.append(u32(v1[i:i+4]))
temp = temp[::2]
print len(temp)
v1 = temp

v2 = '08000000000000000C000000080000000E000000140000000A00000022000000040000002C0000000C000000300000000C0000003C0000000A00000048000000060000005200000010000000580000000C000000680000000C000000740000000A00000080000000080000008A0000000E000000920000000E000000A000000010000000AE0000000A000000BE00000008000000C800000006000000D00000000A000000D60000000C000000E00000000C000000EC0000000E000000F800000010000000060100000E000000160100000400000024010000'
v2 = unhex(v2)
temp = []
for i in range(0, len(v2), 4):
  temp.append(u32(v2[i:i+4]))
temp = temp[::2]
print len(temp)
v2 = temp
print v2

secret = 'B8EA8EBA3A88AE8EE8AA28BBB8EB8BA8EE3A3BB8BBA3BAE2E8A8E2B8AB8BB8EAE3AEE3BA8000000000000000000000000000000000000000000000000000000008'
secret = unhex(secret)

def getValue(a1):
  return (ord(secret[a1 // 8]) >> (7 - a1 % 8)) & 1;

d = []

for each in range(27):
  out = []
  for i in range(v1[each], v2[each]+v1[each]):
    out.append(getValue(i))
  d.append([each, ''.join(map(str, out))])

d.sort(key=lambda x: len(x[1]), reverse=True)

print d

with open('./output', 'rb') as f:
  data = ''.join(map(str,bits(f.read())))

i = 0
flag = ''
while i < len(data):
  for index, enc in d:
    
    if data[i:i+len(enc)] == enc:
      flag += chr(ord('a')+index)
      i += len(enc)
      print flag
print flag
```

flag: `encodedgxmurhtuou`

# investigation_encoded_2

## Problem

We have recovered a binary and 1 file: image01. See what you can make of it. Its also found in /problems/investigation-encoded-2_2_4d97294fc1696ff16af8ce3c0e6b3b95 on the shell server. NOTE: The flag is not in the normal picoCTF{XXX} format.

[binary](/blog/picoctf-2019-writeup/forensics/investigation_encoded_12mystery)

[image](/blog/picoctf-2019-writeup/forensics/investigation_encoded_2/output)


## Solution

Similar to [investigation_encoded_1](#investigation_encoded_1) but with more characters.

```python
import string
from pwn import *

context.log_level = 'error'

v1 = '000000000400000012000000280000003C0000005200000064000000780000008E0000009E000000B4000000C8000000DA000000EA000000FC0000000E0100001E01000034010000480100005A0100006A01000072010000800100008C0100009A010000AA010000BC010000C8010000D6010000E0010000EA010000F0010000000200000A02000016020000220200003002000034020000'
v1 = unhex(v1)
print len(v1)
temp = []
for i in range(0, len(v1), 4):
  temp.append(u32(v1[i:i+4]))
# temp = temp[::2]
print len(temp)
v1 = temp
print v1

secret = '8BAA2EEEE8BBAE8EBBAE3AEE8EEEA8EEAEE3AAE3AEBB8BAEB8EAAE2EBA2EAE8AEEA3ABA3BBBB8BBBB8AEEE2AEE2E2AB8AA8EAA3BAA3BBA8EA8EBA3A8AA28BBB8AE2AE2EE3AB80000000000000000000000000000000000000000000000000000'
secret = unhex(secret)

def getValue(a1):
  return (ord(secret[a1 // 8]) >> (7 - a1 % 8)) & 1;

def enc(v):
  v = ord(v)
  if v == 32:
    v = 133
  if v > 47 and v <= 57:
    v += 75
  v -= 97
  if v != 36:
    v = (v+18)%36
  out = []
  for i in range(v1[v], v1[v+1]):
    out.append(getValue(i))
  return out

d = []

str_list = string.lowercase+' '+string.digits
print 'start'
for each in str_list:
  out = enc(each)
  print 'expect {}'.format(out)
  # print '       {}'.format(test(str_list[each]))
  d.append([each, ''.join(map(str, out))])
print 'end'

d.sort(key=lambda x: len(x[1]), reverse=True)

print d

with open('./real_output', 'rb') as f:
  data = ''.join(map(str,bits(f.read())))
print data
i = 0
flag = ''
while i < len(data):
  for char, enc in d:
    # print index
    # print enc
    if data[i:i+len(enc)] == enc:
      flag += char
      i += len(enc)
      print flag
print flag

```

flag: `t1m3f1i3500000000000501af001`