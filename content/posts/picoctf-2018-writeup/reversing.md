---
title: "PicoCTF 2018 Writeup: Reversing"
date: 2018-10-13T08:56:01+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "picoctf",
  "reversing"
]
description: solves for picoCTF 2018 Reversing challenges
---

# Reversing Warmup 1

## Problem

Throughout your journey you will have to run many programs. Can you navigate to /problems/reversing-warmup-1_0_f99f89de33522c93964bdec49fb2b838 on the shell server and run this [program](/blog/picoctf-2018-writeup/reversing/Reversing Warmup 1/run) to retreive the flag?

## Solution

The problem `run` is known as a [ELF binary](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format). It is the most common program format on Linux. Here are the steps to run the program:

```bash
alanc@pico-2018-shell-2:~$ cd /problems/reversing-warmup-1_0_f99f89de33522c93964bdec49fb2b838
alanc@pico-2018-shell-2:/problems/reversing-warmup-1_0_f99f89de33522c93964bdec49fb2b838$ ls
run
alanc@pico-2018-shell-2:/problems/reversing-warmup-1_0_f99f89de33522c93964bdec49fb2b838$ ./run
picoCTF{welc0m3_t0_r3VeRs1nG}
```

flag: `picoCTF{welc0m3_t0_r3VeRs1nG}`

# Reversing Warmup 2

## Problem

Can you decode the following string `dGg0dF93NHNfczFtcEwz` from base64 format to ASCII?

## Solution

[Base64](https://en.wikipedia.org/wiki/Base64) is a common encoding format. You can read more about the distinction between encoding and encryption [here](https://stackoverflow.com/questions/4657416/difference-between-encoding-and-encryption).

To decoee the string, we can use [python](https://www.python.org/), a handy programming language for hackers:


```python
Python 2.7.15 (default, Jun 17 2018, 12:51:03)
[GCC 4.2.1 Compatible Apple LLVM 8.0.0 (clang-800.0.42.1)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> 'dGg0dF93NHNfczFtcEwz'.decode('base64')
'th4t_w4s_s1mpL3'
```

flag: `picoCTF{th4t_w4s_s1mpL3}`

# assembly-0

## Problem

What does asm0(0xb6,0xc6) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](/blog/picoctf-2018-writeup/reversing/assembly-0/intro_asm_rev.S) located in the directory at /problems/assembly-0_0_5a220faedfaf4fbf26e6771960d4a359.

## Solution

Read about assembly language or assembly code [here](https://en.wikipedia.org/wiki/Assembly_language). Also, you can watch [this](https://www.youtube.com/watch?v=wLXIWKUWpSs) youtube series which is helpful.

Let's take a look at the assembly code:

```
.intel_syntax noprefix
.bits 32
	
.global asm0

asm0:
	push	ebp
	mov	ebp,esp
	mov	eax,DWORD PTR [ebp+0x8]
	mov	ebx,DWORD PTR [ebp+0xc]
	mov	eax,ebx
	mov	esp,ebp
	pop	ebp	
	ret
```

As you can see, there's a function named `asm0` that is being exported by the line `.global asm0`, and the content of the function is right below the `asm0:` label. We know that the function is called with the argument of `0xb6` and `0xc6` which are at `ebp+0x8` and `ebp+0xc` respectively.

By converting the assembly code to preduo-code, we can the logic of the function:

```
eax = arg1
ebx = arg2
eax = ebx
```

Because we know that an assembly function always returns the value than is in the `eax` register, the `asm0` should always return the second argument passed to it; therefore, the return value is `0xc6`.

If you find this explanation hard to understand or you want more practice with reading assembly code, take a look at [microcorruption](https://microcorruption.com/login) which is a great place to get started with reverse engineering. Also, you can find my writeup for `microcorruption` [here](/blog/posts/microcorruption-writeup/)

Flag: `0xc6`

# assembly-1

## Problem

What does asm1(0x76) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](/blog/picoctf-2018-writeup/reversing/assembly-1/eq_asm_rev.S) located in the directory at /problems/assembly-1_0_cfb59ef3b257335ee403035a6e42c2ed.

## Solution

This problem is similar to the last one. Let's take a look at the code:

```
.intel_syntax noprefix
.bits 32
	
.global asm1

asm1:
	push	ebp
	mov	ebp,esp
	cmp	DWORD PTR [ebp+0x8],0x98
	jg 	part_a	
	cmp	DWORD PTR [ebp+0x8],0x8
	jne	part_b
	mov	eax,DWORD PTR [ebp+0x8]
	add	eax,0x3
	jmp	part_d
part_a:
	cmp	DWORD PTR [ebp+0x8],0x16
	jne	part_c
	mov	eax,DWORD PTR [ebp+0x8]
	sub	eax,0x3
	jmp	part_d
part_b:
	mov	eax,DWORD PTR [ebp+0x8]
	sub	eax,0x3
	jmp	part_d
	cmp	DWORD PTR [ebp+0x8],0xbc
	jne	part_c
	mov	eax,DWORD PTR [ebp+0x8]
	sub	eax,0x3
	jmp	part_d
part_c:
	mov	eax,DWORD PTR [ebp+0x8]
	add	eax,0x3
part_d:
	pop	ebp
	ret
```

For this challenge, control flow is being introduced. We know than `[ebp+0x8]` is the argument that we passed in (`0x76` in this case). Because `0x76` is not larger than `0x98`, we will not follow the first `jg` (jumo greater than) to `part_a`. For the second comparison, because `0x76` does not equal `0x8`, we are going to jump to `part_b` (`jne` means jump not equal). In `part_b`, the argument is loaded into `eax` and `3` is subtracted from it. After that, the function returns; therefore, we just have to take `0x76` and subtract `0x3` from it to get the flag (`0x73`).

flag: `0x73`

# be-quick-or-be-dead-1

## Problem

You find [this](https://www.youtube.com/watch?v=CTt1vk9nM9c) when searching for some music, which leads you to [be-quick-or-be-dead-1](/blog/picoctf-2018-writeup/reversing/be-quick-or-be-dead-1/be-quick-or-be-dead-1). Can you run it fast enough? You can also find the executable in /problems/be-quick-or-be-dead-1_3_aeb48854203a88fb1da963f41ae06a1c.

## Solution

Playing around with the program, you can see that it will exit after a while before the key is calculated. Now, let's take a look at the code that competes the key with [radare2](https://rada.re/r/):

```
[0x004005a0]> aaaa
[0x00400827]> pdf @ sym.calculate_key
/ (fcn) sym.calculate_key 29
|   sym.calculate_key ();
|           ; var unsigned int local_4h @ rbp-0x4
|           ; CALL XREF from sym.get_key (0x4007a9)
|           0x00400706      55             push rbp
|           0x00400707      4889e5         mov rbp, rsp
|           0x0040070a      c745fc3c7ed4.  mov dword [local_4h], 0x6fd47e3c
|           ; CODE XREF from sym.calculate_key (0x40071c)
|       .-> 0x00400711      8345fc01       add dword [local_4h], 1
|       :   0x00400715      817dfc78fca8.  cmp dword [local_4h], 0xdfa8fc78 ; [0xdfa8fc78:4]=-1
|       `=< 0x0040071c      75f3           jne 0x400711
|           0x0040071e      8b45fc         mov eax, dword [local_4h]
|           0x00400721      5d             pop rbp
\           0x00400722      c3             ret
```

As you can see, the function starts witht the value `0x6fd47e3c` and decrements it each time until it is equal to `0xdfa8fc78`. To speed up this function we can change the initial value to the final value minus 1. Here is how the patching is done in radare2:

```
[0x00400827]> oo+
[0x00400827]> s 0x0040070a
[0x0040070a]> pd 1
|           0x0040070a      c745fc3c7ed4.  mov dword [local_4h], 0x6fd47e3c
[0x0040070a]> wa mov dword [rbp-0x4], 0xdfa8fc77
Written 7 byte(s) (mov dword [rbp-0x4], 0xdfa8fc77) = wx c745fc77fca8df
[0x0040070a]> q
```

Now if you run the program, it will happily print out the flag.

flag: `picoCTF{why_bother_doing_unnecessary_computation_27f28e71}`

# quackme

## Problem

Can you deal with the Duck Web? Get us the flag from this [program](/blog/picoctf-2018-writeup/reversing/quackme/main). You can also find the program in /problems/quackme_1_374d85dc071ada50a08b36597288bcfd.

## Solution

Let's first take a look at the core function of the program, `do_magic`:

```
int do_magic()
{
  int result; // eax
  int v1; // [esp+Ch] [ebp-1Ch]
  int i; // [esp+10h] [ebp-18h]
  char *s; // [esp+14h] [ebp-14h]
  signed int v4; // [esp+18h] [ebp-10h]
  void *v5; // [esp+1Ch] [ebp-Ch]

  s = (char *)read_input();
  v4 = strlen(s);
  v5 = malloc(v4 + 1);
  if ( !v5 )
  {
    puts("malloc() returned NULL. Out of Memory\n");
    exit(-1);
  }
  memset(v5, 0, v4 + 1);
  v1 = 0;
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= v4 )
      break;
    if ( greetingMessage[i] == (*(_BYTE *)(i + 0x8048858) ^ (unsigned __int8)s[i]) )
      ++v1;
    if ( v1 == 25 )
      return puts("You are winner!");
  }
  return result;
}
```

As you can see, the input when xored with the data at the offset of `0x8048858` should be equal to the greeting message, in order for the program to print out the flag. We can quickly extract the data at that offset and write a python script to solve the challenge:

```
$ r2 main
 -- What has been executed cannot be unexecuted
[0x080484e0]> ps @ 0x8048858
)\x06\x16O+50\x1eQ\x1b[\x14K\x08]+S\x10TQCM\\T]
```

```python
import string

message = "You have now entered the Duck Web, and you're in for a honkin' good time.\nCan you figure out my trick?"
key = ')\x06\x16O+50\x1eQ\x1b[\x14K\x08]+S\x10TQCM\T]'  # data extracted from the binary

output = ''
for i in range(len(key)):
  v = chr(ord(key[i])^ord(message[i]))
  if v in string.printable:
    output += v
  else:
    output += '_'

print output  # picoCTF{qu4ckm3_6b15c941}
```

flag: `picoCTF{qu4ckm3_6b15c941}`

# assembly-2

## Problem

What does asm2(0x8,0x21) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](picoctf-2018-writeup/reversing/assembly-2/loop_asm_rev.S) located in the directory at /problems/assembly-2_1_c1900e7d33989b0191c51ef927b24f37.

## Solution


This problem is an introduction to loops in assembly.

```
.intel_syntax noprefix
.bits 32
	
.global asm2

; asm2(0x8,0x21)
; flag: 0x78
asm2:
	push   	ebp
	mov    	ebp,esp
	sub    	esp,0x10
	mov    	eax,DWORD PTR [ebp+0xc]
	mov 	  DWORD PTR [ebp-0x4],eax		  ; temp = 0x21
	mov    	eax,DWORD PTR [ebp+0x8]
	mov     DWORD PTR [ebp-0x8],eax			; temp2 = 0x8
	jmp    	part_b
part_a:	
	add    	DWORD PTR [ebp-0x4],0x1     ; temp += 1
	add	    DWORD PTR [ebp+0x8],0xa9		; arg1 += 0xa9
part_b:	
	cmp    	DWORD PTR [ebp+0x8],0x3923
	jle    	part_a
	mov    	eax,DWORD PTR [ebp-0x4]
	mov	    esp,ebp
	pop	    ebp
	ret
```

As you can see, `arg1` is incremented by `0xa9` each time until it reaches `0x3923` while `temp` increments by `1` each time; therefore, the flag is `0x21 + ((0x3923-0x8)/0xa9+1)` which is `0x78`.

flag: `0x78`

# be-quick-or-be-dead-2

## Problem

As you enjoy this [music](https://www.youtube.com/watch?v=CTt1vk9nM9c) even more, another executable [be-quick-or-be-dead-2](/blog/picoctf-2018-writeup/reversing/be-quick-or-be-dead-2/be-quick-or-be-dead-2) shows up. Can you run this fast enough too? You can also find the executable in /problems/be-quick-or-be-dead-2_1_0e5d7acd1fd33f2f0f6e215637a8d3bd.

## Solution

This challenge is similar to `be-quick-or-be-dead-1` where we have to make the `sym.calculate_key` function run faster. Let's take a look at the functions first:

```
__int64 calculate_key()
{
  return fib(1067LL);
}
```

```
__int64 __fastcall fib(unsigned int a1)
{
  int v1; // ebx
  unsigned int v3; // [rsp+1Ch] [rbp-14h]

  if ( a1 > 1 )
  {
    v1 = fib(a1 - 1);
    v3 = v1 + (unsigned __int64)fib(a1 - 2);
  }
  else
  {
    v3 = a1;
  }
  return v3;
}
```

As you can see, it is a fibonacci algorithm in assembly. Now, we can just pre-compute the 1067th value of the fibonacci sequence and substitute in the result at runtime.

Step one, we need to find the 1067th value of the fibonacci sequence while keeping in mind that it is a `unsigned int`:

```python
a = 1
b = 1

for i in range(1, 0x42b):
  a, b = b, a+b
  if a >= 4294967296:
    a -= 4294967296
  
  if b >= 4294967296:
    b -= 4294967296

print hex(a) # 0x2e8e4d99
```

Now, we have to pass in this value at runtime and skip the computing phase. We can do this by changing both the `eax` and `rip` register. Here is the process being done with radare2:


```
[0x004005a0]> aaaa
[0x004005a0]> ood
[0x7f797b9f1090]> s sym.calculate_key
[0x0040074b]> pdf
/ (fcn) sym.calculate_key 16
|   sym.calculate_key ();
|           ; CALL XREF from sym.get_key (0x4007e1)
|           0x0040074b      55             push rbp
|           0x0040074c      4889e5         mov rbp, rsp
|           0x0040074f      bf2b040000     mov edi, 0x42b              ; 1067
|           0x00400754      e8adffffff     call sym.fib
|           0x00400759      5d             pop rbp
\           0x0040075a      c3             ret
[0x0040074b]> db 0x0040074b
[0x7f5ca266c090]> dc
Be Quick Or Be Dead 2
=====================

Calculating key...
hit breakpoint at: 40074b
[0x0040074b]> dr rip=0x0040075a
0x0040074b ->0x0040075a
[0x0040074b]> dr eax=0x2e8e4d99
0x00000000 ->0x2e8e4d99
[0x0040074b]> dc
child stopped with signal 14
[+] SIGNAL 14 errno=0 addr=0x00000000 code=128 ret=0
Done calculating key
Printing flag:
picoCTF{the_fibonacci_sequence_can_be_done_fast_ec58967b}
[+] signal 14 aka SIGALRM received 0
```

flag: `flag: picoCTF{the_fibonacci_sequence_can_be_done_fast_ec58967b}`

# be-quick-or-be-dead-3

## Problem

As the [song](https://www.youtube.com/watch?v=CTt1vk9nM9c) draws closer to the end, another executable [be-quick-or-be-dead-3](/blog/picoctf-2018-writeup/reversing/be-quick-or-be-dead-3/be-quick-or-be-dead-3) suddenly pops up. This one requires even faster machines. Can you run it fast enough too? You can also find the executable in /problems/be-quick-or-be-dead-3_1_036263621db6b07c874d55f1e0bba59d.

## Solution

Following the same theme as the first two problems, we still have to speed up the `sym.calculate_key` function. Let's take a look at the function:

```
__int64 calculate_key()
{
  return calc(0x186B5u);
}
```

```
__int64 __fastcall calc(unsigned int a1)
{
  int v1; // ebx
  int v2; // ebx
  int v3; // er12
  int v4; // ebx
  unsigned int v6; // [rsp+1Ch] [rbp-14h]

  if ( a1 > 4 )
  {
    v1 = calc(a1 - 1);
    v2 = v1 - (unsigned __int64)calc(a1 - 2);
    v3 = calc(a1 - 3);
    v4 = v3 - (unsigned __int64)calc(a1 - 4) + v2;
    v6 = v4 + 4660 * (unsigned __int64)calc(a1 - 5);
  }
  else
  {
    v6 = a1 * a1 + 9029;
  }
  return v6;
}
```

As you can see, this time the `sym.calculate_key` is using a custom algorithm that is also recursive. Let's try to pre-compute the value again with python. To make the code run faster and prevent stack overflow, we are going to compute and store the return values for `calc` which is a common tactics in [dynamic programming](https://en.wikipedia.org/wiki/Dynamic_programming):

```python
import sys

l = 100030
mem = [None]*l


def calc(a1):
  if a1 < l and mem[a1] != None:
    return mem[a1]

  if a1 > 4:
    v1 = calc(a1 - 1)
    v2 = v1 - calc(a1 - 2)
    v3 = calc(a1 - 3)
    v4 = v3 - calc(a1 - 4) + v2
    v6 = v4 + 4660 * calc(a1 - 5)
  else:
    v6 = a1 * a1 + 9029
  
  if v6 >= 4294967296:
    v6 = v6 % 4294967296

  while v6 < 0:
    v6 += 4294967296

  if a1 < l and mem[a1] == None:
    mem[a1] = v6

  return v6


for i in range(l):
  calc(i)

print calc(0x186B5) # 0x221d8eea
```

Now with the output value, we can do the same thing as we did for `be-quick-or-be-dead-2` and substitute in the values at runtime:

```
[0x004005a0]> aaaa
[0x004005a0]> pdf @ sym.calculate_key
/ (fcn) sym.calculate_key 16
|   sym.calculate_key ();
|           ; CALL XREF from sym.get_key (0x400828)
|           0x00400792      55             push rbp
|           0x00400793      4889e5         mov rbp, rsp
|           0x00400796      bfb5860100     mov edi, 0x186b5
|           0x0040079b      e866ffffff     call sym.calc
|           0x004007a0      5d             pop rbp
\           0x004007a1      c3             ret
[0x004005a0]> ood
[0x7f977ebb1090]> db 0x00400792
[0x7f977ebb1090]> dc
Be Quick Or Be Dead 3
=====================

Calculating key...
hit breakpoint at: 400792
[0x00400792]> dr rip=0x004007a1
0x00400792 ->0x004007a1
[0x00400792]> dr eax=0x221d8eea
0x00000000 ->0x221d8eea
[0x00400792]> dc
child stopped with signal 14
[+] SIGNAL 14 errno=0 addr=0x00000000 code=128 ret=0
Done calculating key
Printing flag:
picoCTF{dynamic_pr0gramming_ftw_a0b0b7f8}
[+] signal 14 aka SIGALRM received 0
```

flag: `picoCTF{dynamic_pr0gramming_ftw_a0b0b7f8}`

# quackme up

## Problem

The duck puns continue. Can you crack, I mean quack this program as well? You can find the [program](/blog/picoctf-2018-writeup/reversing/quackme up/main) in /problems/quackme-up_4_5cc9019c8499d6d124cd8e8109a0f95b on the shell server.

## Solution

For this challenge, you have to reverse the `encrypt` function and decrypt the flag. Let's first look at the `encrypt` function:

```
int __cdecl encrypt(char *s)
{
  char v1; // al
  signed int i; // [esp+8h] [ebp-10h]
  signed int v4; // [esp+Ch] [ebp-Ch]

  v4 = strlen(s);
  for ( i = 0; i < v4; ++i )
  {
    v1 = rol4(s[i]);
    s[i] = ror8((char)(v1 ^ 0x16));
  }
  return v4;
}
```

As you can see, the function performs two actions: `rol4` and `ror8`. To decrypt it, we just have to go in the reverse order. There is the decrypt method in python:

```python
cipher = '11 80 20 E0 22 53 72 A1 01 41 55 20 A0 C0 25 E3 35 40 55 30 85 55 70 20 C1'.replace(' ', '').decode('hex')

# https://gist.github.com/c633/a7a5cde5ce1b679d3c0a
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
 

output = ''
for e in cipher:
  output += chr(ror((rol(ord(e), 8, 8) ^ 0x16), 4, 8))
print output
```

flag: `picoCTF{qu4ckm3_2e4b94fc}`

# Radix's Terminal

## Problem

Can you find the password to [Radix's login](/blog/picoctf-2018-writeup/reversing/Radix's Terminal/radix)? You can also find the executable in /problems/radix-s-terminal_0_b6b476e9952f39511155a2e64fb75248?

## Solution

The hint is super helpful for this challenge. By reversing the program, we can see that it's just an implementation of the base64 encoding in assembly.

Now knowing the encoding algorithm, we can decode the string quite quickly:

```python
>>> 'cGljb0NURntiQXNFXzY0X2VOQ29EaU5nX2lTX0VBc1lfNDE3OTk0NTF9'.decode('base64')
'picoCTF{bAsE_64_eNCoDiNg_iS_EAsY_41799451}'
```

flag: `picoCTF{bAsE_64_eNCoDiNg_iS_EAsY_41799451}`

# assembly-3

## Problem

What does asm3(0xb5e8e971,0xc6b58a95,0xe20737e9) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](/blog/picoctf-2018-writeup/reversing/assembly-3/end_asm_rev.S) located in the directory at /problems/assembly-3_3_bfab45ee7af9befc86795220ffa362f4.

## Solution

For this challenge, you are suppose to learn about the different size accessors in assembly.


{{< figure src="/blog/picoctf-2018-writeup/reversing/assembly-3/img.png" attr="Source: stackoverflow" attrlink="https://stackoverflow.com/questions/28429609/why-arent-the-higher-16-bits-in-eax-accessible-by-name-like-ax-ah-and-al">}}

However, because I am tired at this point, I decided to let a computer do this one for me.

I used this assembly emulator for python called [unicorn](https://www.unicorn-engine.org/), and here is my code:

```python
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from pwn import *

X86_CODE32 = asm('mov eax, 0x19; xor al, al; mov ah, BYTE PTR [ebp+0xa]; sal ax, 0x10; sub al, BYTE PTR [ebp+0xd]; add ah, BYTE PTR [ebp+0xc]; xor ax, WORD PTR [ebp+0x12]', arch = 'i386', os = 'linux')

ADDRESS = 0x1000000
STACK = 0x2000000
print("Emulate i386 code")
try:
  mu = Uc(UC_ARCH_X86, UC_MODE_32)

  mu.mem_map(ADDRESS, 2 * 1024 * 1024)
  mu.mem_map(STACK, 2 * 1024 * 1024)

  mu.mem_write(ADDRESS, X86_CODE32)
  mu.mem_write(STACK, '\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a'+p32(0xb5e8e971)+p32(0xc6b58a95)+p32(0xe20737e9))
 
  mu.reg_write(UC_X86_REG_EBP, STACK)
  
  mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

  print("Emulation done. Below is the CPU context")

  r_eax = mu.reg_read(UC_X86_REG_EAX)
  r_ebx = mu.reg_read(UC_X86_REG_EBX)
  print(">>> EAX = 0x%x" % r_eax) # 0x7771
except UcError as e:
  print("ERROR: %s" % e)
```

flag: `0x7771`

# keygen-me-1

## Problem

Can you generate a valid product key for the validation [program](/blog/picoctf-2018-writeup/reversing/keygen-me-1/activate) in /problems/keygen-me-1_1_8eb35cc7858ff1d2f55d30e5428f30a7

## Solution

Let's start by looking at the main function:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax

  setvbuf(_bss_start, 0, 2, 0);
  if ( argc > 1 )
  {
    if ( (unsigned __int8)check_valid_key((char *)argv[1]) )// 16 char of uppercase letters or numbers
    {
      if ( validate_key((char *)argv[1]) )
      {
        printf("Product Activated Successfully: ");
        print_flag(&argc);
        result = 0;
      }
      else
      {
        puts("INVALID Product Key.");
        result = -1;
      }
    }
    else
    {
      puts("Please Provide a VALID 16 byte Product Key.");
      result = -1;
    }
  }
  else
  {
    puts("Usage: ./activate <PRODUCT_KEY>");
    result = -1;
  }
  return result;
}
```

As you can see, we need to input a 16 byte key that will make `check_valid_key` return true. Let's look at `check_valid_key` then:

```
signed int __cdecl check_valid_key(char *a1)
{
  signed int result; // eax
  char v2; // [esp+Bh] [ebp-5h]
  int v3; // [esp+Ch] [ebp-4h]

  if ( !a1 )
    return 0;
  v2 = *a1;
  v3 = 0;
  while ( v2 )
  {
    if ( !(unsigned __int8)check_valid_char(v2) )
      return 0;
    v2 = a1[++v3];
  }
  if ( v3 == 16 )
    result = 16;
  else
    result = 0;
  return result;
}
```

As you can see, it is a pretty easy algorithm. I then translated the function into python:

```python
def isValid(key):
  s = 0
  for i in range(len(key)-1):
    s += (o(key[i])+1)*(i+1)
  print s%0x24
  return s % 0x24 == o(key[len(key)-1])

def o(c):
  v = ord(c)
  if v > 0x2f and v <= 0x39:
    return v-0x30
  if v <= 0x40 or v > 0x5a:
    print 'wrong'
    exit()
  return v - 0x37
```

Now it is just about tinkering with the function to get a valid key. In the end, I land on this:

```python
key = 'Z'*14+'A'+'L'
print isValid(key) # True
print key # ZZZZZZZZZZZZZZAL
```

After this, you just have to input the key to get the flag.

flag: `picoCTF{k3yg3n5_4r3_s0_s1mp13_3718231394}`

# assembly-4

## Problem

Can you find the flag using the following assembly [source](/blog/picoctf-2018-writeup/reversing/assembly-4/comp.nasm)? WARNING: It is VERY long...

## Solution

Because the source code is so long this time, it becomes easier to just build and run the code compared to read it.

The `.nasm` extension reveals that it is a [nasm](https://www.nasm.us/) assembly file.

Here are the step to build and run it:

```
$ nasm -f elf32 comp.nasm
$ gcc -m32 comp.o -o comp
$ ./comp
picoCTF{1_h0p3_y0u_c0mP1l3d_tH15_3205858729}
```

flag: `picoCTF{1_h0p3_y0u_c0mP1l3d_tH15_3205858729}`

# special-pw

## Problem

Can you figure out the right argument to this program to login? We couldn't manage to get a copy of the binary but we did manage to [dump](/blog/picoctf-2018-writeup/reversing/special-pw/special_pw.S) some machine code and memory from the running process.

## Solution

Again, it is totally possible to reverse the assembly code by hand; however, I am lazy...

Because I want tools such as radare2 to help me view the code, I need to first build the assembly (remember to remove the memory dump at the end first):

```
$ gcc -m32 -c original.S -o original.o
$ gcc -m32 ./original.o -o original
$ chmod +x ./original
```

Now with a proper elf binary, I can load up the binary in any tool that I prefer. Here is the main function:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *character; // ST0C_4
  signed int ref; // [esp+0h] [ebp-10h]
  int length; // [esp+4h] [ebp-Ch]
  int counter; // [esp+8h] [ebp-8h]
  const char *i; // [esp+Ch] [ebp-4h]
  const char *input; // [esp+Ch] [ebp-4h]

  length = 0;
  for ( i = argv[1]; *i; ++i )
    ++length;
  for ( counter = 0; length - 3 > counter; ++counter )
  {
    character = (char *)&argv[1][counter];
    *character ^= 0xDEu;
    *(_WORD *)character = __ROR2__(*(_WORD *)character, 13);
    *(_DWORD *)character = __ROL4__(*(_DWORD *)character, 15);
  }
  input = argv[1];
  for ( ref = 56212325; *(_BYTE *)ref; ++ref )
  {
    if ( *input != *(_BYTE *)ref )
      return 0;
    ++input;
  }
  return argv[1][ref - 0x359BB65] == 0;
}
```

Much better. Now, I have to implement the decryption algorithm in python:

```python
from struct import unpack, pack

# https://gist.github.com/c633/a7a5cde5ce1b679d3c0a
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

data = 'b1d3324cfce6ef5eede466cd57f5e17fcd7f55f6e964e7c97f75e954e64df779fcfc5171f93e18d900'.decode('hex')
data = data[:-1]


for i in range(len(data)-3-1, -1, -1):
  v, = unpack('<I', data[i:i+4])
  data = data[:i] + pack('<I', ror(v, 15, 4*8)) + data[i+4:]

  v, = unpack('<H', data[i:i+2])
  data = data[:i] + pack('<H', rol(v, 13, 2*8)) + data[i+2:]
  
  v, = unpack('<B', data[i:i+1])
  data = data[:i] + pack('<B', v ^ 0xde) + data[i+1:]

print data # picoCTF{gEt_y0Ur_sH1fT5_r1gHt_0cb381c60}
```

One thing to note in the code above is that the null byte at the end have to be removed. Also, the [endianness](https://en.wikipedia.org/wiki/Endianness) have to be correct.

flag: `picoCTF{gEt_y0Ur_sH1fT5_r1gHt_0cb381c60}`

# keygen-me-2

## Problem

The software has been updated. Can you find us a new product key for the [program](/blog/picoctf-2018-writeup/reversing/keygen-me-2/activate) in /problems/keygen-me-2_0_ac2a45bc27456d666f2bbb6921829203

## Solution

This time the `validate_key` function is a lot more complex:

```
_BOOL4 __cdecl validate_key(char *key)
{
  strlen(key);
  return key_constraint_01(key)
      && key_constraint_02((int)key)
      && key_constraint_03((unsigned __int8 *)key)
      && key_constraint_04((unsigned __int8 *)key)
      && key_constraint_05((unsigned __int8 *)key)
      && key_constraint_06((unsigned __int8 *)key)
      && key_constraint_07((unsigned __int8 *)key)
      && key_constraint_08((unsigned __int8 *)key)
      && key_constraint_09((unsigned __int8 *)key)
      && key_constraint_10((unsigned __int8 *)key)
      && key_constraint_11((unsigned __int8 *)key)
      && key_constraint_12((unsigned __int8 *)key);
}
```

As you can see, 12 different constraints have to be met. This makes the process of generating a valid key by hand basicly impossible. This is when [z3 prover](https://github.com/Z3Prover/z3) comes in. z3 is a [SAT solver](https://en.wikipedia.org/wiki/Boolean_satisfiability_problem) that outputs possible inputs that meets certain constraints. We can easily use z3 with python:

```python
from z3 import *

def m(a, b):
  return If(a % b >= 0,
    a % b,
    a % b + b)

s = Solver()

v = []
for i in range(16):
  e = Int('v'+str(i))
  v.append(e)
  s.add(e >= 0)
  s.add(e <= 35)

s.add(m(v[0] + v[1], 36) == 14)
s.add(m(v[2] + v[3], 36) == 24)
s.add(m(v[2] - v[0], 36) == 6)
s.add(m(v[1] + v[3] + v[5], 36) == 4)
s.add(m(v[2] + v[4] + v[6], 36) == 13)
s.add(m(v[3] + v[4] + v[5], 36) == 22)
s.add(m(v[6] + v[8] + v[10], 36) == 31)
s.add(m(v[1] + v[4] + v[7], 36) == 7)
s.add(m(v[9] + v[12] + v[15], 36) == 20)
s.add(m(v[13] + v[14] + v[15], 36) == 12)
s.add(m(v[8] + v[9] + v[10], 36) == 27)
s.add(m(v[7] + v[12] + v[13], 36) == 23)
   
# print(s.check())
# m = s.model()
# print m

values = [31, 19, 1, 23, 1, 34, 11, 23, 8, 7, 12, 0, 16, 20, 31, 33]

output = ''
for i in range(0, 16):
  v = values[i]
  print v
  if v < 10:
    output += chr(v+0x30)
  else:
    output += chr(v+0x37)
print output # VJ1N1YBN87C0GKVX
```

Using this script, we can generate a valid key, and by inputing the key, we are able to obtain the flag.

flag: `picoCTF{c0n5tr41nt_50lv1nG_15_W4y_f45t3r_783243818}`

# circuit123

## Problem

Can you crack the key to [decrypt](/blog/picoctf-2018-writeup/reversing/circuit123/decrypt.py) [map2](/blog/picoctf-2018-writeup/reversing/circuit123/map2.txt) for us? The key to [map1](/blog/picoctf-2018-writeup/reversing/circuit123/map1.txt) is 11443513758266689915.

## Solution

Similar to `keygen-me-2`, we can solve this problem using a SAT solver (z3 in this case).

```python
from z3 import *

s = Solver()

with open('./map2.txt', 'r') as f:
  cipher, chalbox = eval(f.read())

length, gates, check = chalbox

v = []
for i in range(length):
  e = Bool('v'+str(i))
  v.append(e)

for name, args in gates:
  if name == 'true':
    v.append(True)
  else:
    u1 = Xor(v[args[0][0]], args[0][1])
    u2 = Xor(v[args[1][0]], args[1][1])
    if name == 'or':
      v.append(Or(u1, u2))
    elif name == 'xor':
      v.append(Xor(u1, u2))

s.add(Xor(v[check[0]], check[1]) == True)

# print s.check()
# print s.model()

# values = [1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1]
values = [1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1]
values = values[::-1]
output = 0
for i in values:
  print i
  if i == 1:
    output += 1
  output <<= 1
print output >> 1 # 219465169949186335766963147192904921805
```

flag: `picoCTF{36cc0cc10d273941c34694abdb21580d__aw350m3_ari7hm37ic__}`

> Feel free to leave a comment if any of the challenges is not well explained.