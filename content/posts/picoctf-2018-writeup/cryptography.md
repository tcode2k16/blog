---
title: "PicoCTF 2018 Writeup: Cryptography"
date: 2018-10-14T11:38:43+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "picoctf",
  "cryptography"
]
description: solves for picoCTF 2018 Cryptography challenges
---

# Crypto Warmup 1

## Problem

Crpyto can often be done by hand, here's a message you got from a friend, `llkjmlmpadkkc` with the key of `thisisalilkey`. Can you use this [table](/blog/picoctf-2018-writeup/Cryptography/Crypto Warmup 1/table.txt) to solve it?.

## Solution

This is a classic [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher). You can use [this](https://www.dcode.fr/vigenere-cipher) to decode the message.

flag: `picoCTF{SECRETMESSAGE}`


# Crypto Warmup 2

## Problem

Cryptography doesn't have to be complicated, have you ever heard of something called rot13? `cvpbPGS{guvf_vf_pelcgb!}`

## Solution

The meesage is encoded using [rot13](https://en.wikipedia.org/wiki/ROT13) where every character is rotated by 13. You can use [this](https://www.rot13.com/) to decode it.

flag: `picoCTF{this_is_crypto!}`

# HEEEEEEERE'S Johnny!

## Problem

Okay, so we found some important looking files on a linux computer. Maybe they can be used to get a password to the process. Connect with `nc 2018shell2.picoctf.com 40157`. Files can be found here: [passwd](/blog/picoctf-2018-writeup/Cryptography/HEEEEEEERES Johnny/passwd) [shadow](/blog/picoctf-2018-writeup/Cryptography/HEEEEEEERES Johnny/shadow).

## Solution

This problem can be solved using [John the Ripper](https://www.openwall.com/john/), a password cracking tool. Our goal is to brute force the password of the root user.

This is the cracking process on mac:

```
❯ /usr/local/Cellar/john-jumbo/1.8.0/share/john/unshadow passwd shadow > crack.db
❯ john crack.db
Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Warning: hash encoding string length 98, type id $6
appears to be unsupported on this system; will not load such hashes.
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 64/64 OpenSSL])
Press 'q' or Ctrl-C to abort, almost any other key for status
kissme           (root)
1g 0:00:00:06 DONE 2/3 (2018-10-14 11:56) 0.1529g/s 361.6p/s 361.6c/s 361.6C/s kissme
Use the "--show" option to display all of the cracked passwords reliably
Session completed
❯ nc 2018shell2.picoctf.com 40157
Username: root
Password: kissme
picoCTF{J0hn_1$_R1pp3d_1b25af80}
```

flag: `picoCTF{J0hn_1$_R1pp3d_1b25af80}`

# caesar cipher 1

## Problem

This is one of the older ciphers in the books, can you decrypt the [message](/blog/picoctf-2018-writeup/Cryptography/caesar cipher 1/ciphertext)? You can find the ciphertext in /problems/caesar-cipher-1_0_931ac10f43e4d2ee03d76f6914a07507 on the shell server.

## Solution

Similar to `rot13`, caesar cipher is also about rotating characters. I used [this](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,11)&input=eWpoaXB2ZGRzZGFzcnB0aHBncnhld3RnZHFuanl0dG8) tool to solve the challenge.

flag: `picoCTF{justagoodoldcaesarcipherobyujeez}`

# hertz

## Problem

Here's another simple cipher for you where we made a bunch of substitutions. Can you decrypt it? Connect with `nc 2018shell2.picoctf.com 43324`.

## Solution

This is a substitution cipher challenge where each character is replaced with another one. It can be decrypted using statistical analysis. Here is a [tool](https://www.guballa.de/substitution-solver) that can decrypt the message.

flag: `substitution_ciphers_are_solvable_fuosdblgwv`

# blaise's cipher

## Problem

My buddy Blaise told me he learned about this cool cipher invented by a guy also named Blaise! Can you figure out what it says? Connect with `nc 2018shell2.picoctf.com 26039`.

## Solution

The is a problem about the [Vigenère Cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) (the inventor is called Blaise de Vigenère). This problem differs from [Crypto Warmup 1](#crypto-warmup-1) because the key is not provided; however, we can use statistical analysis to find the key because the cipher is quite long. The key turns out to be `FLAG` and we can use [this](https://www.dcode.fr/vigenere-cipher) to decrypt the message.

flag: `picoCTF{v1gn3r3_c1ph3rs_ar3n7_bad_901e13a1}`

# hertz 2

## Problem

This flag has been encrypted with some kind of cipher, can you decrypt it? Connect with `nc 2018shell2.picoctf.com 18990`.

## Solution

Same as [hertz](#hertz), we can use a [substitution solver](https://www.guballa.de/substitution-solver) to crack the message using statistical analysis.

flag: `picoCTF{substitution_ciphers_are_too_easy_vpyydylnns}`

# Safe RSA

## Problem

Now that you know about RSA can you help us decrypt this [ciphertext](/blog/picoctf-2018-writeup/Cryptography/Safe RSA/ciphertext)? We don't have the decryption key but something about those values looks funky..

## Solution

Let's take a look at the values:

```plain
N: 374159235470172130988938196520880526947952521620932362050308663243595788308583992120881
359365258949723819911758198013202644666489247987314025169670926273213367237020188587742716
017314320191350666762541039238241984934473188656610615918474673963331992408750047451253205
158436452814354564283003696666945950908549197175404580533132142111356931324330631843602412
540295482841975783884766801266552337129105407869020730226041538750535628619717708838029286
366761470986056335230171148734027536820544543251801093230809186222940806718221638845816521
738601843083746103374974120575519418797642878012234163709518203946599836959811
e: 3

ciphertext (c): 22053164139311340310464407676205419848010912163512227891805938753738299508
605427921103643257280885044797808037145614642505897959610976708842748132614961128825808920
20487261058118157619586156815531561455215290361274334977137261636930849125
```

As you can see the N value is way larger than the c value; therefore, the `mod N` operation is basically useless in the encryption process and the m value would just equal the cube-root of the c value.

I wrote a simple python script to find the plaintext, m value:

```python
from pwn import *

lower = 10**79
upper = 10**80

v = (lower+upper)/2
c = 2205316413931134031046440767620541984801091216351222789180593875373829950860542792110364325728088504479780803714561464250589795961097670884274813261496112882580892020487261058118157619586156815531561455215290361274334977137261636930849125
while True:
  p = pow(v, 3)
  if p < c:
    lower = v
  elif p > c:
    upper = v
  else:
    print v
    print unhex(hex(v)[2:])
    exit()
  v = (lower+upper)/2
```

flag: `picoCTF{e_w4y_t00_sm411_9f5d2464}`

# caesar cipher 2

## Problem

Can you help us decrypt this [message](/blog/picoctf-2018-writeup/Cryptography/caesar cipher 2/ciphertext)? We believe it is a form of a caesar cipher. You can find the ciphertext in /problems/caesar-cipher-2_1_ac88f1b12e9dbca252d450d374c4a087 on the shell server.

## Solution

Instead of rotating characters, this problem needs you to rotate the ascii values.

Here is a one line python expression that gives you the flag:

```
>>> ''.join([chr(ord(i)+11) for i in 'e^Xd8I;pX6ZhVGT8^E]:gHT_jHITVG:cITh:XJg:r'])
'picoCTF{cAesaR_CiPhErS_juST_aREnT_sEcUrE}'
```

flag: `picoCTF{cAesaR_CiPhErS_juST_aREnT_sEcUrE}`

# rsa-madlibs

## Problem

We ran into some weird puzzles we think may mean something, can you help me solve one? Connect with `nc 2018shell2.picoctf.com 40440`

## Solution

This challenge is an introduction to RSA encryption and decryption. Here is a python script that solves the challenge:

```python
from pwn import *

sh = remote('2018shell2.picoctf.com', 40440)

# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# question 1
q1 = sh.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):').split('\n')
q = int(q1[-5].split(' : ')[1])
p = int(q1[-4].split(' : ')[1])

sh.sendline('y')
sh.sendlineafter('n: ', str(p*q))

print 'question 1 done'

# question 2
q2 = sh.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):').split('\n')
p = int(q2[-5].split(' : ')[1])
n = int(q2[-4].split(' : ')[1])

sh.sendline('y')
sh.sendlineafter('q: ', str(n/p))

print 'question 2 done'

# question 3
q3 = sh.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):').split('\n')

sh.sendline('n')

print 'question 3 done'

# question 4
q4 = sh.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):').split('\n')

q = int(q4[-5].split(' : ')[1])
p = int(q4[-4].split(' : ')[1])

sh.sendline('y')
sh.sendlineafter('totient(n): ', str((p-1)*(q-1)))

print 'question 4 done'

# question 5
q5 = sh.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):').split('\n')

plaintext = int(q5[-6].split(' : ')[1])
e = int(q5[-5].split(' : ')[1])
n = int(q5[-4].split(' : ')[1])

sh.sendline('y')
sh.sendlineafter('ciphertext: ', str(pow(plaintext, e, n)))

print 'question 5 done'

# question 6
q6 = sh.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):')

sh.sendline('n')

print 'question 6 done'

# question 7
q7 = sh.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):').split('\n')

q = int(q7[-6].split(' : ')[1])
p = int(q7[-5].split(' : ')[1])
e = int(q7[-4].split(' : ')[1])

sh.sendline('y')
sh.sendlineafter('d: ', str(modinv(e, (p-1)*(q-1))))

print 'question 7 done'

# question 8
q8 = sh.recvuntil('IS THIS POSSIBLE and FEASIBLE? (Y/N):').split('\n')

p = int(q8[-7].split(' : ')[1])
ciphertext = int(q8[-6].split(' : ')[1])
e = int(q8[-5].split(' : ')[1])
n = int(q8[-4].split(' : ')[1])

q = n/p
d = modinv(e, (p-1)*(q-1))
m = pow(ciphertext, d, n)

sh.sendline('y')
sh.sendlineafter('plaintext: ', str(m))

print 'question 8 done'

flag = unhex(hex(m)[2:])

print 'flag: {}'.format(flag)

sh.interactive()
```

flag: `picoCTF{d0_u_kn0w_th3_w@y_2_RS@_5d383e10}`

# SpyFi

## Problem

James Brahm, James Bond's less-franchised cousin, has left his secure communication with HQ running, but we couldn't find a way to steal his agent identification code. Can you? Conect with `nc 2018shell2.picoctf.com 37131`. [Source](/blog/picoctf-2018-writeup/Cryptography/SpyFi/spy_terminal_no_flag.py).

## Solution

Because the server is using ECB encryption, the same 16 bytes of plaintext will always result in the same 16 bytes of ciphertext; therefore, by padding the message in a certain way, we are able to brute force the flag, one character at a time.

To learn more about this type of attack, read [this](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher/Attack-ECB-Byte-at-a-Time).

Here is my final solution in python:

```python
from pwn import *
import string

context.log_level = 'error'

def serverTest(p):
  sh = remote('2018shell2.picoctf.com', 37131)
  # sh = process('./spy_terminal_no_flag.py')

  payload = p
  print payload

  sh.sendlineafter(': ', payload)

  data = sh.recvall()

  blocks = []
  for i in range(0, len(data), 32):
    blocks.append(data[i:i+32])
  return blocks

output = ''
n = 30-15 + len(output)

while True:
  sample = serverTest('a'*10+'a'*(128-n))[12]
  for e in string.printable:
    if e != '\n':
      pass
    if len(output) < 15:
      payload = 'a'*11+'My agent identifying code is: '[-15-15+n:]+output+e
    else:
      payload = 'a'*11+output[-15:]+e
    if serverTest(payload)[4] == sample:
      output += e
      n += 1
      print output
```

flag: `picoCTF{@g3nt6_1$_th3_c00l3$t_8124762}`

# Super Safe RSA

## Problem

Dr. Xernon made the mistake of rolling his own crypto.. Can you find the bug and decrypt the message? Connect with `nc 2018shell2.picoctf.com 59208`.

## Solution

This challenge is quite straight forward. Because the `N` value is not too large, we are able to factor it to get `p` and `q`. I used [this tool](https://www.alpertron.com.ar/ECM.HTM) to do the factoring.

Here is the python script to get the flag after obtaining `p` and `q`:

```python
from __future__ import print_function
from pwn import *

# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

c = 7809610400898349286016926488565269274365598971524364832027129569226461267979193
n = 13735142797987182957549971502203881356968575526307443768628820859348208821399459

p = 110380683891444775871975228832971138237
q = 124434296959920777019712641638067872701407

e = 65537

phi = (p-1)*(q-1)

d = modinv(e, phi)
m = pow(c, d, n)

flag = unhex(hex(m)[2:])

print('flag: {}'.format(flag))
```

flag: `picoCTF{us3_l@rg3r_pr1m3$_2461}`

# eleCTRic

## Problem

You came across a custom server that Dr Xernon's company eleCTRic Ltd uses. It seems to be storing some encrypted files. Can you get us the flag? Connect with `nc 2018shell2.picoctf.com 61333`. [Source](/blog/picoctf-2018-writeup/Cryptography/eleCTRic/eleCTRic.py).

## Solution

This challenge is about the AES CTR mode. In CTR mode, any xor operation performed to the ciphertext will be carried onto the plaintext. Using this knowledge, we are able to modify the message without needing the key.

The basic concept is to create a file has the same name as the flag file. The way we do this is to first get a ciphertext of the filename that includes `=` instead of `_`. Then we take this ciphertext xor it with `xor('=', '_')` and we will end up with the encrypted ciphertext of the flag file.

Here is the python script that does what I just described:

```python
from pwn import *

# context.log_level = 'debug'

sh = remote('2018shell2.picoctf.com', 61333)
sh.recvuntil(': ')

sh.sendline('i')
output = sh.recvuntil(': ')

output = output.split('\n')
filename = output[2][2:].replace('_', '=')

sh.sendline('n')

sh.recvuntil('? ')
sh.sendline(filename[:-4])

sh.recvuntil('? ')
sh.sendline('a')

output = sh.recvuntil(': ')

cipher = output.split('\n')[1].decode('base64')
cipher = cipher[:4] + xor(cipher[4], ord('=')^ord('_')) + cipher[5:]

sh.sendline('e')
sh.sendlineafter('? ', cipher.encode('base64'))

sh.interactive()
```

Also, you can read [this](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher/Attack-CTR-Bit-Flipping) for a more in depth explanation.

flag: `picoCTF{alw4ys_4lways_Always_check_int3grity_6c094576}`

# Super Safe RSA 2

## Problem

Wow, he made the exponent really large so the encryption MUST be safe, right?! Connect with `nc 2018shell2.picoctf.com 29483`.

## Solution

In this challenge, the person reversed `e` and `d`, so to decrypted the message, we can just do `c^65537 mod n`:

```python
from pwn import *

c = 30394370149759212198890840428414236786655674109325891191350493321712697438922739334663116599397574665360416587587711563826194604609207464884152903279386999940109942806781380836801321403426790154669760790190082695198875071931065372288669049953607880618416120048336060436979322160477751362460672558320766626587
n = 92205116676018887176867813286733136394495920330692931184516189936304670934380052548516913246329623354703800136286716700832485032108427805169988509373317053799059710440809689076002155662155935477022410755032307236321849694147304551315643687446596734617134000488809831033483070776414206710187814979169402139499
e = 7916721722629328137452663157673487625186208457830067347838207436586758370809719024223029293942304203990391433341247766537748039667273803495605922490252146934549935921342696781604312653510665308247669291870450177590005874066949677321617392137269198880301687419383335476286399520139444931303766840062104155929

m = pow(c, 65537, n)

print unhex(hex(m)[2:])
```

flag: `picoCTF{w@tch_y0ur_Xp0n3nt$_c@r3fu11y_5495627}`

# Super Safe RSA 3

## Problem

The more primes, the safer.. right.?.? Connect with `nc 2018shell2.picoctf.com 35072`.

## Solution

This challenge shows that the `n` value doesn't have to be the mutiple of just two prime numbers. I factored the `n` value and found the `phi(n)` using this [tool](https://www.alpertron.com.ar/ECM.HTM) and wrote the python script below to get the flag:

```python
from pwn import *

# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


ciphertext = 7512217998848901312202638979218158691612883027081568421771860786115546570347302183096084933102268944745166062334604744940892668950454851058683768661732472738221907788563223184199915410542421721333897314670212015510439259507977932596381492348531615719838018042905229363380396995067598129185691436480279821
n = 8919945455751331309970361365050981590832639828430345099988153696563483960544960537357777359992859549013853491261288798421988417350887598351074340483939033241736792384778344935922718837375058568359012567739857063296616143055608450694262267918774425372243084321330360860178923459385149898318997404529994523
e = 65537

phi = 8919945363333354406871752543500501513755577489123174151308992397436045664878067691065866493123674240815052865464496545807559835062509051860896266119562768119066818022580513745114186926803396678674388906281542836080266568283345906623450619555089908329316975517887404652387401054529443078340608000000000000

d = modinv(e, phi)
m = pow(ciphertext, d, n)

flag = unhex(hex(m)[2:])

print 'flag: {}'.format(flag)
```

flag: `picoCTF{p_&_q_n0_r_$_t!!_6725536}`

> Feel free to leave a comment if any of the challenges is not well explained.