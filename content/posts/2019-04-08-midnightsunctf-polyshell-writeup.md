---
title: "Midnightsun CTF 2019 Polyshell Writeup"
date: 2019-04-08T10:33:06+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  'polyglot',
  'shellcoding'
]
description: Solution for the "Polyshell" challenge in Midnightsun CTF 2019
---

# Problem

**Category**: programming

**Points**: 482

**Solves**: 22

You might be cool, but are you 5 popped shells cool?

settings Service: `nc polyshell-01.play.midnightsunctf.se 30000`

**Author**: ZetaTwo

# Solution

## Getting started

Let's first connect to the service to see what the challenge is about:

```text
$ nc polyshell-01.play.midnightsunctf.se 30000

Welcome to the polyglot challenge!
Your task is to create a shellcode that can run on the following architectures:
x86
x86-64
ARM
ARM64
MIPS-LE

The shellcode must run within 1 second(s) and may run for at most 100000 cycles.
The code must perform a syscall on each platform according to the following paramters:
Syscall number: 222
Argument 1: 6072
Argument 2: A pointer to the string "measure"

You submit your code as a hex encoded string of max 4096 characters (2048 bytes)

Your shellcode:
```

So in order to get the flag, we need to write a polyglot shellcode with a max length of 2048 bytes that can be executed on x86, x86-64, ARM, ARM64, and MIPS-LE. The shellcode has to call a syscall with both a number and a pointer to a string that we need to load into memory.

## Shellcode mania

The first part of the challenge is to implement the same program in all five of the assembly architectures. I started out with x86 and x86-64 since these are the two that I know best:

```python
def get_i386(sys_num, arg1, arg2):
  p1 = '0x'+pack_str(arg2[:4])
  p2 = '0x'+pack_str(arg2[4:])

  payload = asm('''
    call start
  start:
    pop eax  
    mov ebx, {p1}
    add eax, 0x5000
    mov ecx, eax
    mov [eax], ebx

    mov ebx, {p2}
    mov [eax+0x4], ebx

    mov ecx, ecx
    mov ebx, {arg1}
    mov eax, {sys_num}
    int 0x80
  '''.format(arg1=arg1, sys_num=sys_num, p1=p1, p2=p2), arch = 'i386', os = 'linux')

  print disasm(payload, arch = 'i386', os = 'linux')

  return payload

def get_amd64(sys_num, arg1, arg2):
  p = '0x'+pack_str(arg2, 8)

  payload = asm('''
    call start
  start:
    pop rax  
    mov rbx, {p}
    add rax, 0x5000
    mov rcx, rax
    mov [rax], rbx

    mov rsi, rcx
    mov rdi, {arg1}
    mov rax, {sys_num}
    syscall
  '''.format(arg1=arg1, sys_num=sys_num, p=p), arch = 'amd64', os = 'linux')

  print disasm(payload, arch = 'amd64', os = 'linux')

  return payload
```

For my implementation, I loaded the string into the same region as the shellcode with an offset of `0x5000` from the instruction pointer, but looking back at it, loading string onto the stack might be easier.

The next architecture to conquer is ARM32:

```python
def get_arm32(sys_num, arg1, arg2):
  p1 = int(pack_str(arg2[:4]),16)
  p2 = int(pack_str(arg2[4:]),16)

  payload = asm('''
    add r0, pc, #0x5000
    mov r3, r0

    ldr r1, =#{p1}
    str r1, [r0]
    
    add r0, r0, #4
    ldr r1, =#{p2}
    str r1, [r0]


    mov r1, r3
    mov r0, {arg1}
    mov r7, {sys_num}
    SWI 0
  '''.format(arg1=arg1, sys_num=sys_num, p1=p1, p2=p2), arch = 'arm', os = 'linux')

  print disasm(payload, arch = 'arm', os = 'linux')

  return payload
```

One thing that I found interesting about ARM is the fact that you can directly access the instruction pointer which is quite different from x86.

After implementing ARM32, ARM64 becomes quite easy:

```python
def get_arm64(sys_num, arg1, arg2):
  p = int(pack_str(arg2, 8),16)

  payload = asm('''
    adr x0, .
    add x0, x0, #20480
    mov x3, x0

    ldr x1, ={p}
    str x1, [x0]

    mov x1, x3
    mov x0, {arg1}
    mov x8, {sys_num}
    svc #0
  '''.format(arg1=arg1, sys_num=sys_num, p=p), arch = 'aarch64', os = 'linux')

  print disasm(payload, arch = 'aarch64', os = 'linux')

  return payload
```

As you can see, it's basically the same thing where the register `rN` is replaced with `xN` and the syscall number is stored in `x8` instead of `r7`.

Lastly, we have MIPS left:

```python
def get_mips(sys_num, arg1, arg2):
  p1 = int(pack_str(arg2[:4]),16)
  p2 = int(pack_str(arg2[4:]),16)

  payload = asm('''
    sub $sp, $sp, 8
    add $t2, $sp, 0
    add $a1, $t2, 0

    li $t1, {p1}
    sw $t1, ($t2)
    
    add $t2, $t2, 4
    li $t1, {p2}
    sw $t1, ($t2)
    
    
    li $a0, {arg1}
    li $v0, {sys_num}

    syscall
  '''.format(arg1=arg1, sys_num=sys_num, p1=p1, p2=p2), arch = 'mips', os = 'linux')

  print disasm(payload, arch = 'mips', os = 'linux')

  return payload
```

This is the one that took the longest to complete because of two reasons. One, I made a stupid mistake of writing `return ''` instead of `return payload` (that took a while to figure out). Second, I was not able to get the instruction pointer in MIPS and had to load the string onto the stack in the end.

## The FUN part

Now, after 2-3 (maybe more) hours of hard work, I finally got all five shellcodes to work individually, and now I have to integrate all of them into one.

### The weird trick for x86 and x86-64

So the magic opcode `31c941e2XX` will be interpreted by x86 as:

```python
0x00000000: xor ecx, ecx
0x00000002: inc ecx
0x00000003: loop XX+5
```

but x86-64 will interpret it as:

```python
0x0000000000000000: xor ecx, ecx
0x0000000000000002: loop XX+5
```

What this means is that when running this opcode, x86-64 will follow the jump while x86 will ignore it, and we can essentially separate out x86 and x86-64 code execution with something like this:

```python
payload += unhex('31c941e22a')
payload += get_i386(sys_num, arg1, arg2)
payload += get_amd64(sys_num, arg1, arg2)
```

### Dealing with ARM and ARM64

After figuring out the x86 trick, I was stuck for quite a while until I came across [this](https://github.com/ixty/xarch_shellcode) cool project on github. The project `xarch_shellcode` is able to create shellcode that supports x86, x86_64, arm, and arm_64, and in its [readme page](https://github.com/ixty/xarch_shellcode/tree/master/stage0), it includes this:

```text
For the x86 / arm branching we use the following:
0xEB 0xXX 0x00 0x32     (with XX being the offset to x86 code)
    arm       andlo   r0, r0, #0xeb000
    arm64     orr     w11, w23, #7
    x86       jmp     $+0xa / junk
    x86_64    jmp     $+0xa / junk

For the arm / arm64 branching we use:
0xXX 0xXX 0xXX 0xEA
    arm       b       XXX
    arm64     ands    x1, x0, x0
```

Great, so with the two opcodes mentioned above, we can integrate x86, x86-64, arm, and arm64:

```python
payload = unhex('EB700032')
# arm / aarch64
payload += unhex('0b0000ea')
payload += get_arm64(sys_num, arg1, arg2)
payload += get_arm32(sys_num, arg1, arg2)
payload += '.'*(0x70-2-0x64-0x4)
# x86 / x86-64
payload += unhex('31c941e22a')
payload += get_i386(sys_num, arg1, arg2)
payload += get_amd64(sys_num, arg1, arg2)

# Results:
# x86: Success
# x86-64: Success
# ARM: Success
# ARM64: Success
# MIPS: Failure
```

### Last challenge

Now, we just need MIPS to play well with the current shellcode. How hard can that be? **Very**, as it turns out...

The opcode `EB700032` that is used to split ARM and x86 turns out to be a valid MIPS instruction which is convenient. We can also swap the ARM32 jump to a ARM64 jump with the opcode `78000014` that would be happily ignored by MIPS. This leaves us with the task to write a MIPS jump statement that is valid ARM32 or an ARM32 jump statement that is valid MIPS.

One of the options is quickly eliminated because an ARM32 jump statement is almost always a memory write in MIPS which would segfault the MIPS code. This leaves us with only one option: write a MIPS jump statement that is valid ARM32.

This is when the weirdness began. I made a payload that looks something like this:

* 4 bytes MIPS jump
* ARM32 shellcode
* MIPS nop slide
* MIPS shellcode

But when we ran the payload, the **MIPS** code failed. What?

I played with different jump/branch instructions in MIPS and none of them worked. This is when I regressed a bit and started to look for ARM32 jumps which turned out to be fruitless.

At 10 minutes before the end of the CTF, one of my teammates mentioned the fact that MIPS executes the instruction right after the jump statement for performance reasons (**WTF**) which explains why the previous payload is not working because the first ARM32 instruction in the shellcode is definitely not valid MIPS. This means a modified payload like is would work:

* 4 bytes MIPS jump
* 4 null bytes - MIPS nop / ARM32 random valid instruction
* ARM32 shellcode
* MIPS nop slide
* MIPS shellcode

Now with the final challenge resolved, I just need to put everything together.

Here are a few things to keep in mind during that process:

* The shellcode lengths vary slightly depending on the size of the string that we have to load into memory; therefore, I just brute force the service until I get a string with size 6 before running the code.
* The ARM32, ARM64, and MIPS code have to be 4 bytes aligned, so I have to pad the x86 and x86-64 code to a multiple of 4.

Finally, with the details out of the way, we get:

```
Results:
x86: Success
x86-64: Success
ARM: Success
ARM64: Success
MIPS: Success

Congratulations! Here is your flag: midnight{Its_shellz_all_the_w4y_d0wn}
```

> I got the flag 4 minutes after the CTF had ended... :(

flag: `{Its_shellz_all_the_w4y_d0wn}`

## Credits

* Thanks Ariana for finding the x86 / x86-64 jump trick
* Thanks Creastery for mentioning the xarch_shellcode repo and the MIPS branching weirdness
* Thanks all my teammates for the mental support

## Full exploit

```python
from pwn import *

context.log_level = 'debug'

sh = remote('polyshell-01.play.midnightsunctf.se', 30000)

data = sh.recvuntil('shellcode: ').split('\n')
sys_num = int(data[-7].split(': ')[-1])
print sys_num

arg1 = int(data[-6].split(': ')[-1])
print arg1
arg2 = data[-5].split('"')[-2]
print arg2

while len(arg2) != 6:
  sh.close()
  sh = remote('polyshell-01.play.midnightsunctf.se', 30000)

  data = sh.recvuntil('shellcode: ').split('\n')
  sys_num = int(data[-7].split(': ')[-1])
  print sys_num

  arg1 = int(data[-6].split(': ')[-1])
  print arg1
  arg2 = data[-5].split('"')[-2]
  print arg2

def pack_str(str, length=4):
  r = enhex(str)
  f = ''
  for i in range(len(r), 0, -2):
    f += r[i-2:i]
  return f.rjust(length*2, '0')

def get_i386(sys_num, arg1, arg2):
  p1 = '0x'+pack_str(arg2[:4])
  p2 = '0x'+pack_str(arg2[4:])

  payload = asm('''
    call start
  start:
    pop eax  
    mov ebx, {p1}
    add eax, 0x5000
    mov ecx, eax
    mov [eax], ebx

    mov ebx, {p2}
    mov [eax+0x4], ebx

    mov ecx, ecx
    mov ebx, {arg1}
    mov eax, {sys_num}
    int 0x80
  '''.format(arg1=arg1, sys_num=sys_num, p1=p1, p2=p2), arch = 'i386', os = 'linux')

  print disasm(payload, arch = 'i386', os = 'linux')

  return payload

def get_amd64(sys_num, arg1, arg2):
  p = '0x'+pack_str(arg2, 8)

  payload = asm('''
    call start
  start:
    pop rax  
    mov rbx, {p}
    add rax, 0x5000
    mov rcx, rax
    mov [rax], rbx

    mov rsi, rcx
    mov rdi, {arg1}
    mov rax, {sys_num}
    syscall
  '''.format(arg1=arg1, sys_num=sys_num, p=p), arch = 'amd64', os = 'linux')

  print disasm(payload, arch = 'amd64', os = 'linux')

  return payload

def get_arm32(sys_num, arg1, arg2):
  p1 = int(pack_str(arg2[:4]),16)
  p2 = int(pack_str(arg2[4:]),16)

  payload = asm('''
    add r0, pc, #0x5000
    mov r3, r0

    ldr r1, =#{p1}
    str r1, [r0]
    
    add r0, r0, #4
    ldr r1, =#{p2}
    str r1, [r0]


    mov r1, r3
    mov r0, {arg1}
    mov r7, {sys_num}
    SWI 0
  '''.format(arg1=arg1, sys_num=sys_num, p1=p1, p2=p2), arch = 'arm', os = 'linux')

  print disasm(payload, arch = 'arm', os = 'linux')

  return payload

def get_arm64(sys_num, arg1, arg2):
  p = int(pack_str(arg2, 8),16)

  payload = asm('''
    adr x0, .
    add x0, x0, #20480
    mov x3, x0

    ldr x1, ={p}
    str x1, [x0]

    mov x1, x3
    mov x0, {arg1}
    mov x8, {sys_num}
    svc #0
  '''.format(arg1=arg1, sys_num=sys_num, p=p), arch = 'aarch64', os = 'linux')

  print disasm(payload, arch = 'aarch64', os = 'linux')

  return payload

def get_mips(sys_num, arg1, arg2):
  p1 = int(pack_str(arg2[:4]),16)
  p2 = int(pack_str(arg2[4:]),16)

  payload = asm('''
    sub $sp, $sp, 8
    add $t2, $sp, 0
    add $a1, $t2, 0

    li $t1, {p1}
    sw $t1, ($t2)
    
    add $t2, $t2, 4
    li $t1, {p2}
    sw $t1, ($t2)
    
    
    li $a0, {arg1}
    li $v0, {sys_num}

    syscall
  '''.format(arg1=arg1, sys_num=sys_num, p1=p1, p2=p2), arch = 'mips', os = 'linux')

  print disasm(payload, arch = 'mips', os = 'linux')

  return payload

payload = unhex('EB780032')
# arm / aarch64 / MIPS
payload += "\x78\x00\x00\x14"
payload += "\x0d\x00\x00\x1a\x00\x00\x00\x00"
payload += get_arm32(sys_num, arg1, arg2)
payload += get_mips(sys_num, arg1, arg2)
payload += "\x3c\x00\x00\x14"
# x86 / x86-64
payload += '\x90'*0x100
payload += unhex('31c941e22a')
payload += get_i386(sys_num, arg1, arg2)
payload += get_amd64(sys_num, arg1, arg2)
payload += 'AA'
payload += unhex('1f2003d5')*300
payload += get_arm64(sys_num, arg1, arg2)

print payload.encode('hex')

sh.sendline(payload.encode('hex'))

sh.interactive()
```