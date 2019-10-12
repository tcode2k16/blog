---
title: "PicoCTF 2019 Writeup: General Skills"
date: 2019-10-12T13:06:10+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "picoctf"
]
description: solves for picoCTF 2019 General Skills challenges
---

# 2Warm

## Problem

Can you convert the number 42 (base 10) to binary (base 2)?

## Solution

```
$ python
>>> bin(42)
'0b101010'
```

flag: `picoCTF{101010}`

# Lets Warm Up

## Problem

If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII?

## Solution

```
$ python
>>> chr(0x70)
'p'
```

flag: `picoCTF{p}`

# Warmed Up

## Problem

What is 0x3D (base 16) in decimal (base 10).

## Solution

```
$ python
>>> 0x3d
61
```

flag: `picoCTF{61}`

# Bases

## Problem

What does this `bDNhcm5fdGgzX3IwcDM1`mean? I think it has something to do with bases.

## Solution

The flag is encoded with [base64](https://en.wikipedia.org/wiki/Base64).

```
$ echo "bDNhcm5fdGgzX3IwcDM1" | base64 -d -
l3arn_th3_r0p35
```

flag: `picoCTF{l3arn_th3_r0p35}`

# First Grep

## Problem

Can you find the flag in file? This would be really tedious to look through manually, something tells me there is a better way. You can also find the file in /problems/first-grep_3_2e09f586a51352180a37e25913f5e5d9 on the shell server.

[file](/blog/picoctf-2019-writeup/general-skills/First Grep/file)

## Solution

As suggested by the challenge name, we can use the bash command [grep](https://tldr.ostera.io/grep) to search for the flag:

```
$ grep pico file 
picoCTF{grep_is_good_to_find_things_eda8911c}
```

flag: `picoCTF{grep_is_good_to_find_things_eda8911c}`

# Resources

## Problem

We put together a bunch of resources to help you out on our website! If you go over there, you might even find a flag! https://picoctf.com/resources (link)

## Solution

The flag is on the resources page.

flag: `picoCTF{r3source_pag3_f1ag}`

# strings it

## Problem

Can you find the flag in file without running it? You can also find the file in /problems/strings-it_5_1fd17da9526a76a4fffce289dee10fbb on the shell server.

[file](/blog/picoctf-2019-writeup/general-skills/strings it/)


## Solution

We can find the flag with a combination of [strings](https://tldr.ostera.io/strings) and [grep](https://tldr.ostera.io/grep):

```
$ strings strings | grep pico
picoCTF{5tRIng5_1T_dd38f284}
```

flag: `picoCTF{5tRIng5_1T_dd38f284}`

# what's a net cat?

## Problem

Using netcat (nc) is going to be pretty important. Can you connect to `2019shell1.picoctf.com` at port `4158` to get the flag?

## Solution

Use the netcat or [nc](https://tldr.ostera.io/nc) command:

```
$ nc 2019shell1.picoctf.com 4158
You're on your way to becoming the net cat master
picoCTF{nEtCat_Mast3ry_700da9c7}
```

flag: `picoCTF{nEtCat_Mast3ry_700da9c7}`

# Based

## Problem

To get truly 1337, you must understand different data encodings, such as hexadecimal or binary. Can you get the flag from this program to prove you are on the way to becoming 1337? Connect with `nc 2019shell1.picoctf.com 20836`.

## Solution

For this challenge, you have to decode base2, base8, and base16 data. I wrote a short script to automate the process:

```python
from pwn import *

sh = remote('2019shell1.picoctf.com', 20836)

binary_data = sh.recvuntil('Input:\n').split('\n')[2].split(' ')[3:-3]
binary_data = ''.join(map(lambda x: chr(int(x, 2)), binary_data))
sh.sendline(binary_data)

oct_data = sh.recvuntil('Input:\n').split('\n')[0].split('the  ')[-1].split(' as')[0].split(' ')
oct_data = ''.join(map(lambda x: chr(int(x, 8)), oct_data))
sh.sendline(oct_data)

hex_data = sh.recvuntil('Input:\n').split('\n')[0].split('the ')[-1].split(' as')[0]
hex_data = hex_data.decode('hex')
sh.sendline(hex_data)

sh.interactive()
```

flag: `picoCTF{learning_about_converting_values_6cdcad0d}`

# First Grep: Part II

## Problem

Can you find the flag in /problems/first-grep--part-ii_4_ca16fbcd16c92f0cb1e376a6c188d58f/files on the shell server? Remember to use grep.

## Solution

We can use the `-r` option in `grep` to search recursively for the flag:

```
alanc@pico-2019-shell1:/problems/first-grep--part-ii_4_ca16fbcd16c92f0cb1e376a6c188d58f/files$ grep -r pico .
./files6/file5:picoCTF{grep_r_to_find_this_0e28f3ee}
```

flag: `picoCTF{grep_r_to_find_this_0e28f3ee}`

# plumbing

## Problem

Sometimes you need to handle process data outside of a file. Can you find a way to keep the output from this program and search for the flag? Connect to `2019shell1.picoctf.com 57911`.

## Solution

We can use the pipe operator to `grep` for the flag:

```
$ nc 2019shell1.picoctf.com 57911 | grep pico
picoCTF{digital_plumb3r_931b2271}
```

flag: `picoCTF{digital_plumb3r_931b2271}`

# whats-the-difference

## Problem

Can you spot the difference? kitters cattos. They are also available at /problems/whats-the-difference_0_00862749a2aeb45993f36cc9cf98a47a on the shell server

[kitters](/blog/picoctf-2019-writeup/general-skills/whats-the-difference/kitters.jpg)

[cattos](/blog/picoctf-2019-writeup/general-skills/whats-the-difference/cattos.jpg)

## Solution

The flag is all the bytes that differ between the two files. It can be extracted with a python script:

```python
with open('./kitters.jpg', 'rb') as f:
  kitters = f.read()

with open('./cattos.jpg', 'rb') as f:
  cattos = f.read()

flag = ''
for i in range(min(len(kitters), len(cattos))):
  if kitters[i] != cattos[i]:
    flag += cattos[i]
print flag
```

flag: `picoCTF{th3yr3_a5_d1ff3r3nt_4s_bu773r_4nd_j311y_aslkjfdsalkfslkflkjdsfdszmz10548}`

# where-is-the-file

## Problem

I've used a super secret mind trick to hide this file. Maybe something lies in /problems/where-is-the-file_4_f26b413d005c16c61f127740ab242b35.

## Solution

On unix systems, files that start with a `.` are hidden by default. We can see these files by using the `-a` option in `ls`:

```
alanc@pico-2019-shell1:/problems/where-is-the-file_4_f26b413d005c16c61f127740ab242b35$ ls -a
.  ..  .cant_see_me
alanc@pico-2019-shell1:/problems/where-is-the-file_4_f26b413d005c16c61f127740ab242b35$ cat .cant_see_me 
picoCTF{w3ll_that_d1dnt_w0RK_cb4a5081}
```

flag: `picoCTF{w3ll_that_d1dnt_w0RK_cb4a5081}`

# flag_shop

## Problem

There's a flag shop selling stuff, can you buy a flag? Source. Connect with `nc 2019shell1.picoctf.com 3967`.

[source](/blog/picoctf-2019-writeup/general-skills/flag_shop/store.c)


## Solution

By reading the source code, we see that the `total_cost` is stored as a 4 byte signed integer:

```c
if(number_flags > 0){
    int total_cost = 0;
    total_cost = 900*number_flags;
    printf("\nThe final cost is: %d\n", total_cost);
    if(total_cost <= account_balance){
        account_balance = account_balance - total_cost;
        printf("\nYour current balance after transaction: %d\n\n", account_balance);
    }
    else{
        printf("Not enough funds to complete purchase\n");
    }
}
```

If we enter a large number for `number_flags`, `900*number_flags` would overflow and turn into a large negative number:

```
$ python
>>> ((1<<31)//900)*1.5
3579138.0
```

```
$ nc 2019shell1.picoctf.com 3967
Welcome to the flag exchange
We sell flags

1. Check Account Balance

2. Buy Flags

3. Exit

 Enter a menu selection
2
Currently for sale
1. Defintely not the flag Flag
2. 1337 Flag
1
These knockoff Flags cost 900 each, enter desired quantity
3579138

The final cost is: -1073743096

Your current balance after transaction: 1073744196

Welcome to the flag exchange
We sell flags

1. Check Account Balance

2. Buy Flags

3. Exit

 Enter a menu selection
2
Currently for sale
1. Defintely not the flag Flag
2. 1337 Flag
2
1337 flags cost 100000 dollars, and we only have 1 in stock
Enter 1 to buy one1
YOUR FLAG IS: picoCTF{m0n3y_bag5_cd0ead78}
```

flag: `picoCTF{m0n3y_bag5_cd0ead78}`

# mus1c

## Problem

I wrote you a song. Put it in the picoCTF{} flag format

[file](/blog/picoctf-2019-writeup/general-skills/mus1c/lyrics.txt)


## Solution

The given file is a program written in the esoteric language [rockstar](https://esolangs.org/wiki/Rockstar). We can run the program using [this website](https://codewithrockstar.com/online):

```
Output:
114
114
114
111
99
107
110
114
110
48
49
49
51
114
```

A quick conversion from decimal to ascii gives us the flag:

```
$ python
>>> '''114
... 114
... 114
... 111
... 99
... 107
... 110
... 114
... 110
... 48
... 49
... 49
... 51
... 114'''.strip().split('\n')
['114', '114', '114', '111', '99', '107', '110', '114', '110', '48', '49', '49', '51', '114']
>>> ''.join(map(chr,map(int,_)))
'rrrocknrn0113r'
```

flag: `picoCTF{rrrocknrn0113r}`

# 1_wanna_b3_a_r0ck5tar

## Problem

I wrote you another song. Put the flag in the picoCTF{} flag format

[file](/blog/picoctf-2019-writeup/general-skills/1_wanna_b3_a_r0ck5tar/lyrics.txt)


## Solution

This time the program requires some input. We can simply remove these input checks to get to the flag.


Remove these lines:

```
Listen to the music             
If the music is a guitar                  
Say "Keep on rocking!"                
Listen to the rhythm
If the rhythm without Music is nothing
...
Else Whisper "That ain't it, Chief"
```

Output:

```
66
79
78
74
79
86
73
```

Converting it to ASCII:

```
$ python
>>> ''.join(map(chr,[66,79,78,74,79,86,73]))
'BONJOVI'
```

flag: `picoCTF{BONJOVI}`