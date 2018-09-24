---
title: "DCTF 2018 Writeup"
date: 2018-09-24T15:18:47+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: My solves for DCTF 2018 challenges
---


# Ransomware (Reverse - 50 pcts.)

## Problem

Someone encrypted my homework with this rude [script](/blog/dctf-2018-writeup/Ransomware/ransomware.zip). HELP! 

Author: Lucian Nitescu

## Solution

There are two files for this challenge: `ransomware.pyc` and `youfool!.exe`.

By doing `file` on both files, we get this:

```
❯ file ransomware.pyc
ransomware.pyc: DBase 3 data file (1536068111 records)

~/Documents/ctf/2018/dctf/Ransomware
❯ file youfool\!.exe
youfool!.exe: data
```

So `youfool!.exe` is apparently encrypted and `ransomware.pyc` is the only one executable.

By using [uncompyle6](https://github.com/rocky/python-uncompyle6), we can then decompile the `pyc` file and get the source code:

```python
# uncompyle6 version 3.2.3
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.15rc1 (default, Apr 15 2018, 21:51:34)
# [GCC 7.3.0]
# Embedded file name: ransomware.py
# Compiled at: 2018-09-04 13:35:11
import string
from random import *
import itertools

def caesar_cipher(buf, password):
    password = password * (len(buf) / len(password) + 1)
    return ('').join((chr(ord(x) ^ ord(y)) for x, y in itertools.izip(buf, password)))


f = open('./FlagDCTF.pdf', 'r')
buf = f.read()
f.close()
allchar = string.ascii_letters + string.punctuation + string.digits
password = ('').join((choice(allchar) for _ in range(60)))
buf = caesar_cipher(buf, password)
f = open('./youfool!.exe', 'w')
buf = f.write(buf)
f.close()
# okay decompiling ransomware.pyc
```

Just by looking at this code, we can see that `youfool!.exe` is, in fact, an encrypted pdf file, and the file is encrypted by xoring the original file with a key of 60 characters.

Now we just have to find the 60 characters xor key to decrypt the file since encryption and decryption is the same when it comes to xor.

We can get the first few bytes just by knowing that a pdf file starts with `%PDF-1.5`. After that, we can using a tool such as [xortool](https://github.com/hellman/xortool) or [this](https://wiremask.eu/tools/xor-cracker/) to find the rest of the key. The result from these tools are not perfect, so I have to manually change a few bytes to make it correct (I know that `?` in `/DecodePa?ms` is a `r` for sure).

In the end, we get a readable [pdf](/blog/dctf-2018-writeup/Ransomware/out.pdf) that contains the flag.

Flag: `DCTF{d915b5e076215c3efb92e5844ac20d0620d19b15d427e207fae6a3b894f91333}`

# Exfil (Misc - 330 pcts.)

## Problem

An experienced hacker gained unauthorised access into a facility with limited options to exfiltrate data but he managed to launch a backdoor to solve this issue. However, he got arrested before intercepting the confidential data. Can you recover the information and maybe do some profits on his behalf? Flag format: DCTF\{[A-Za-z0-9\-]+\} 
For this challenge you are allowed to scan using nmap, but it won't help you too much :)

Target: 104.248.38.191

Author: Andrei A

## Solution

For this challenge, we are given a ip with no running services for us to attack, but when you try to ping the server, you get this:

```
64 bytes from 104.248.38.191: icmp_seq=1 ttl=63 time=0.525 ms
64 bytes from 104.248.38.191: icmp_seq=2 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=3 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=4 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=5 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=6 ttl=63 time=0.595 ms
64 bytes from 104.248.38.191: icmp_seq=7 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=8 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=9 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=10 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=11 ttl=63 time=0.483 ms
64 bytes from 104.248.38.191: icmp_seq=12 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=13 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=14 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=15 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=16 ttl=63 time=0.368 ms
64 bytes from 104.248.38.191: icmp_seq=17 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=18 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=19 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=20 ttl=63 time=401 ms
64 bytes from 104.248.38.191: icmp_seq=21 ttl=63 time=0.408 ms
64 bytes from 104.248.38.191: icmp_seq=22 ttl=63 time=1000 ms
64 bytes from 104.248.38.191: icmp_seq=23 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=24 ttl=63 time=1001 ms
64 bytes from 104.248.38.191: icmp_seq=25 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=26 ttl=63 time=0.623 ms
64 bytes from 104.248.38.191: icmp_seq=27 ttl=63 time=0.478 ms
64 bytes from 104.248.38.191: icmp_seq=28 ttl=63 time=0.474 ms
64 bytes from 104.248.38.191: icmp_seq=29 ttl=63 time=0.480 ms
64 bytes from 104.248.38.191: icmp_seq=30 ttl=63 time=0.489 ms
64 bytes from 104.248.38.191: icmp_seq=31 ttl=63 time=400 ms
64 bytes from 104.248.38.191: icmp_seq=32 ttl=63 time=1000 ms
...
```

As you can see, the packet delay is following a pattern alternating between `0.5 ms`, `400 ms` and `1000 ms`.

My first attempt is to decode the message as morse code; however, there are patterns that are not valid morse codes.

Later, I discovered that there is a `0.5 ms` packet for every four other packets.

Then I just focused on the `400 ms` and the `1000 ms` packets and converted the list to packets to a binary string which yields the flag.

```python
from pwn import *

# Hard-coded driver function to run the program 
def main(): 
    data = ''
    with open('log3') as f:
      for e in f.read().split('\n'):
        v = float(e.split(' ')[-2].split('=')[-1])
        if v < 300:
          data += ''
        elif v < 600:
          data += '0'
        else:
          data += '1'
    print data.split('     ')

    for e in data.split('     '):
      # result = decrypt(e.strip()) 
      # print (result) 
      result = ''
      for x in e.split(' '):
        if len(x) != 4:
          result += ''
        result += x
      print unbits(result)
      # print result
# Executes the main function 
if __name__ == '__main__': 
    main()
```

> Tip: get a server in the continent where the CTF is hosted to minimized network delays and errors.

Flag: `DCTF{EXF1LTRAT3-L1K3-4-PR0-1S-4W3S0M3}`

# Extra

My team, HATS Singapore, actually made it into the top 10 teams at the last minute, and we are now going to the final in Bucharest, Romania! :)

{{< figure src="/blog/dctf-2018-writeup/rank.png" >}}