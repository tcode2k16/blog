---
title: "HSCTF 2019 Writeup: Reversal"
date: 2019-06-08T11:00:08+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "reversing",
  "hsctf"
]
description: My solves for HSCTF 2019 Reversal challenges
---

# A Byte

## Problem

Written by: ItzSomebody

Just one byte makes all the difference.

[a-byte](/blog/2019-06-08-hsctf-writeup-rev/A Byte/a-byte)

## Solution

Looking at the code, we see that the flag has a length of 35:

```c
if ( (unsigned int)strlen(argv[1]) != 35 )
    goto LABEL_11;
...
LABEL_11:
    puts("u do not know da wae");
    result = 0xFFFFFFFFLL;
```

If the length is correct, the user input will be xored with 1 and then compared with a string loaded on the stack.

We can extract out the string on the stack and xor it with 1 to get the flag:

```python
>>> a = [105, 114, 98, 117, 103, 122, 118, 49, 118, 94, 120, 49, 116, 94, 106, 111, 49, 118, 94, 101, 53, 94, 118, 64, 50, 94, 57, 105, 51, 99, 64, 49, 51, 56, 124, 0]
>>> map(lambda x: chr(x^1),a)
['h', 's', 'c', 't', 'f', '{', 'w', '0', 'w', '_', 'y', '0', 'u', '_', 'k', 'n', '0', 'w', '_', 'd', '4', '_', 'w', 'A', '3', '_', '8', 'h', '2', 'b', 'A', '0', '2', '9', '}', '\x01']
>>> ''.join(_)
'hsctf{w0w_y0u_kn0w_d4_wA3_8h2bA029}\x01'
```

flag: `hsctf{w0w_y0u_kn0w_d4_wA3_8h2bA029}`


# License

## Problem

Written by: ItzSomebody

Description: Keith made a cool license-checking program but he forgot the flag he used to create the key! To make matters worse, he lost the source code and stripped the binary for his license-generator program. Can you help Keith recover his flag? All he knows is:

The license key is 4-EZF2M-7O5F4-V9P7O-EVFDP-E4VDO-O
He put his name (in the form of 'k3ith') as the first part of the flag
There are 3 underscores
The flag is in the format hsctf{}
The flag doesn't have random character sequences (you should be able to read the entire flag easily).
The flag only contains lowercase English letters and numbers.
The generator might produce the same keys for different inputs because Keith was too lazy to write the algorithm properly.

[license](/blog/2019-06-08-hsctf-writeup-rev/License/license)

## Solution

I am too lazy to reverse this one... I found out that there's a one-to-one match between the input and output of the program, so I just repeatedly ran the program to guess the flag one character at a time.

Here is the script:

```python
from pwn import *
import string
context.log_level='error'
char_set = string.letters+string.digits+'_'
flag = 'hsctf{'

real = '4-EZF2M-7O5F4-V9P7O-EVFDP-E4VDO-O'.replace('-','')

l = len(flag)

def check(real, out):
  return out in real

def try_input(flag):
  sh = process('./license')
  sh.sendlineafter(': ', flag)
  out = sh.recvall().strip().split('\n')[-1].replace('-','')
  sh.close()
  return check(real, out)

while l <= len(real):
  for c in char_set:
    if try_input(flag+c):
      l += 1
      flag += c
      break
  print flag
```

flag: `hsctf{k3ith_m4k3s_tr4sh_r3}`

# DaHeck

## Problem

Written by: ItzSomebody

Unicode? ...da heck?

[DaHeck.java](2019-06-08-hsctf-writeup-rev/DaHeck/DaHeck.java)

## Solution

Simple reversing challenge. Just reverse the algo.

```python
output = [65480, 65469, 65486, 65468, 65482, 65463, 65477, 65483, 5, 65477, 65493, 65473, 65535, 65473, 65496, 65489, 65476, 65483, 16, 65491, 65476, 1, 65471, 65471, 65489, 65472, 65477, 65467, 65493, 65470, 3, 65482, 65535, 65498, 65475, 7, 65474, 1, 65492, 65472, 4, 65470, 65535, 65470, 65473, 65533, 65461]
start = '001002939948347799120432047441372907443274204020958757273'
temp = []
for e in start:
  temp.append(ord(e))
start = temp
print output
print start
print len(output)
print len(start)

flag = ''

i = 0
for each in output:
  flag += chr((start[i]+(0x10000-each))%256)
  i += 1
print flag
```

flag: `hsctf{th4t_w4s_fun!_l3ts_try_s0m3_m0r3_r3v3rs3}`

# VirtualJava

## Problem

Written by: ItzSomebody

There's nothing like executing my own code in Java in my own special way.

[VirtualJava.java](2019-06-08-hsctf-writeup-rev/VirtualJava/VirtualJava.java)

## Solution

This is a stack-based vm implemented in Java. I edited the source code to dump both the instructions and the stack:

```java
public class VirtualJava {
    private static final String[] owo = {"ur too pro for this", "Hmmmm... I don't think so ;D"};
    private int[] regs;
    private int[] stack;
    private int sp;
    private int ip;
    private boolean running;
    private int[] instructions;

    private VirtualJava(int[] instructions) {
        this.regs = new int[10];
        this.stack = new int[10];
        this.sp = 0;
        this.ip = 0;
        this.running = true;
        this.instructions = instructions;
    }

    private void push(int n) {
        this.stack[this.sp++] = n;
    }

    private int pop() {
        return this.stack[--this.sp];
    }

    private int run(int... params) {
        if (params != null) for (int i = 0; i < params.length; i++) this.regs[i] = params[i];
        while (this.running) {
            int opc = readByte();
            int opn = readByte();
            switch (opc) {
                case 0x0: {
                    int y = pop();
                    int x = pop();
                    System.out.println("add: "+x+" + "+y);
                    push(x+y);
                    break;
                } case 0x1: {
                    int y = pop();
                    int x = pop();
                    System.out.println("sub: "+x+" - "+y);
                    push(x - y);
                    break;
                } case 0x2: {
                    int y = pop();
                    int x = pop();
                    System.out.println("mul: "+x+" * "+y);
                    push(x*y);
                    break;
                } case 0x3: {
                    int y = pop();
                    int x = pop();
                    System.out.println("div: "+x+" / "+y);
                    push(x / y);
                    break;
                } case 0x4: {
                    int x = pop();
                    if (x == 0) {
                        System.out.println("je: "+x+" (taken)");
                        this.ip = opn;
                    } else {
                        System.out.println("je: "+x+" (NOT taken)");
                    }
                    break;
                } case 0x5:{
                    int x = pop();
                    if (x != 0) {
                        System.out.println("jne: "+x+" (taken)");
                        this.ip = opn;
                    } else {
                        System.out.println("jne: "+x+" (NOT taken)");
                    }
                    break;
                } case 0x6: {
                    System.out.println("push: "+opn);
                    push(opn);
                    break;
                } case 0x7: {
                    int y = pop();
                    int x = pop();
                    System.out.println("and: "+x+" & "+y);
                    push(x & y);
                    break;
                } case 0x8: {
                    int y = pop();
                    int x = pop();
                    System.out.println("or: "+x+" | "+y);
                    push(x | y);
                    break;
                } case 0x9: {
                    int y = pop();
                    int x = pop();
                    System.out.println("xor: "+x+" ^ "+y);
                    push(x ^ y);
                    break;
                } case 0xa: {
                    int a = pop();
                    System.out.println("dup: "+a);
                    push(a);
                    push(a);
                    break;
                } case 0xb: {
                    System.out.println("push: regs["+opn+"] = "+this.regs[opn]);
                    push(this.regs[opn]);
                    break;
                } case 0xc: {
                    System.out.println("exit");
                    this.running = false;
                    break;
                }
            }
            printStack();
        }
        System.out.println("call ended");
        this.running = true;
        return this.stack[--this.sp];
    }

    private void printStack() {
        String output = "[ ";
        for (int i : this.stack) {
            output += i+", ";
        }

        System.out.println(output+"]");
    }

    private int readByte() {
        return this.instructions[this.ip++] & 0xFF;
    }

    private static String getOutput(int n) {
        return n == 0 ? owo[n] : owo[1];
    }

    public static void main(String... args) {
        if (args.length != 1 || args[0].toCharArray().length != 31) {
            System.out.println(getOutput(1));
            System.exit(0);
        }
        VirtualJava java = new VirtualJava(new int[]{0xb, 0x0, 0x6, 0x0, 0x1, 0x64, 0x5, 0x14, 0xb, 0x1, 0x6,
                0x65, 0x9, -0xf3, 0x6, 0xd, 0x1, -0xdd, 0xc, -0x70, 0xb, 0x0, 0x6, 0x1, 0x1, -0xed, 0x5, 0x28,
                0xb, 0x1, 0x6, -0xee, 0x9, 0x89, 0x6, -0x9f, 0x1, -0xc5, 0xc, 0xd8, 0xb, 0x0, 0x6, 0x2, 0x1,
                0xe, 0x5, 0x3c, 0xb, 0x1, 0x6, -0x7d, 0x9, 0xb8, 0x6, -0x20, 0x1, 0x50, 0xc, -0x9f, 0xb, 0x0,
                0x6, 0x3, 0x1, 0x23, 0x5, 0x50, 0xb, 0x1, 0x6, -0x48, 0x9, -0xc0, 0x6, -0x34, 0x1, -0x52, 0xc,
                -0x6c, 0xb, 0x0, 0x6, 0x4, 0x1, -0xb7, 0x5, 0x64, 0xb, 0x1, 0x6, 0x73, 0x9, 0x6d, 0x6, 0x15,
                0x1, -0x48, 0xc, -0x5e, 0xb, 0x0, 0x6, 0x5, 0x1, 0xe, 0x5, 0x78, 0xb, 0x1, 0x6, 0x7, 0x9,
                -0x3e, 0x6, 0x7c, 0x1, 0x98, 0xc, 0x7a, 0xb, 0x0, 0x6, 0x6, 0x1, -0xa3, 0x5, 0x8c, 0xb,
                0x1, 0x6, -0x22, 0x9, 0x4, 0x6, -0x59, 0x1, -0xda, 0xc, -0x47, 0xb, 0x0, 0x6, 0x7, 0x1,
                -0xc6, 0x5, 0xa0, 0xb, 0x1, 0x6, 0x2c, 0x9, -0xee, 0x6, 0x1c, 0x1, -0x8e, 0xc, -0x90, 0xb,
                0x0, 0x6, 0x8, 0x1, -0x6f, 0x5, 0xb4, 0xb, 0x1, 0x6, -0x63, 0x9, -0x4a, 0x6, -0x18, 0x1, 0x3c,
                0xc, 0x9b, 0xb, 0x0, 0x6, 0x9, 0x1, -0x89, 0x5, 0xc8, 0xb, 0x1, 0x6, 0x93, 0x9, 0x3f, 0x6, 0xcc,
                0x1, -0xd7, 0xc, -0x61, 0xb, 0x0, 0x6, 0xa, 0x1, 0x7f, 0x5, 0xdc, 0xb, 0x1, 0x6, 0x5b, 0x9, 0x27,
                0x6, 0x3f, 0x1, 0xc2, 0xc, -0x5c, 0xb, 0x0, 0x6, 0xb, 0x1, -0x29, 0x5, 0xf0, 0xb, 0x1, 0x6,
                0x2e, 0x9, 0xf8, 0x6, 0x1d, 0x1, 0xae, 0xc, -0xb6, 0xb, 0x0, 0x6, 0xc, 0x1, 0x7a, 0x5, 0x104,
                0xb, 0x1, 0x6, 0x30, 0x9, -0xb8, 0x6, 0x56, 0x1, 0xed, 0xc, -0x23, 0xb, 0x0, 0x6, 0xd, 0x1,
                0xee, 0x5, 0x118, 0xb, 0x1, 0x6, -0x52, 0x9, -0x72, 0x6, -0x63, 0x1, 0xcf, 0xc, -0xae, 0xb,
                0x0, 0x6, 0xe, 0x1, 0x4d, 0x5, 0x12c, 0xb, 0x1, 0x6, -0xae, 0x9, 0xc8, 0x6, -0x9a, 0x1, -0xc8,
                0xc, -0xc3, 0xb, 0x0, 0x6, 0xf, 0x1, 0x1, 0x5, 0x140, 0xb, 0x1, 0x6, -0xae, 0x9, -0xc8, 0x6,
                -0xda, 0x1, 0xdb, 0xc, 0xc3, 0xb, 0x0, 0x6, 0x10, 0x1, 0xf6, 0x5, 0x154, 0xb, 0x1, 0x6, 0x3d,
                0x9, -0x48, 0x6, 0xe, 0x1, 0xea, 0xc, 0xda, 0xb, 0x0, 0x6, 0x11, 0x1, 0x5e, 0x5, 0x168, 0xb,
                0x1, 0x6, -0x10, 0x9, 0xcc, 0x6, -0x6c, 0x1, 0x1d, 0xc, -0x4c, 0xb, 0x0, 0x6, 0x12, 0x1, 0x5b,
                0x5, 0x17c, 0xb, 0x1, 0x6, 0xd3, 0x9, -0xfa, 0x6, 0x8c, 0x1, 0x6a, 0xc, -0x9e, 0xb, 0x0, 0x6,
                0x13, 0x1, 0x7d, 0x5, 0x190, 0xb, 0x1, 0x6, -0x22, 0x9, -0x6b, 0x6, -0x56, 0x1, -0xc6, 0xc,
                0xba, 0xb, 0x0, 0x6, 0x14, 0x1, -0x45, 0x5, 0x1a4, 0xb, 0x1, 0x6, -0xe8, 0x9, 0x69, 0x6, -0x90,
                0x1, 0x44, 0xc, 0x29, 0xb, 0x0, 0x6, 0x15, 0x1, -0x3c, 0x5, 0x1b8, 0xb, 0x1, 0x6, -0x8e, 0x9,
                0xa, 0x6, -0xbf, 0x1, 0xaf, 0xc, 0x38, 0xb, 0x0, 0x6, 0x16, 0x1, 0x5d, 0x5, 0x1cc, 0xb, 0x1,
                0x6, -0x93, 0x9, -0x62, 0x6, -0xce, 0x1, -0x20, 0xc, 0x2f, 0xb, 0x0, 0x6, 0x17, 0x1, -0x8a,
                0x5, 0x1e0, 0xb, 0x1, 0x6, 0x11, 0x9, 0xeb, 0x6, 0x73, 0x1, -0xc1, 0xc, 0x4e, 0xb, 0x0, 0x6,
                0x18, 0x1, 0x9b, 0x5, 0x1f4, 0xb, 0x1, 0x6, -0x7a, 0x9, 0x59, 0x6, -0x4e, 0x1, 0xc, 0xc,
                -0x5f, 0xb, 0x0, 0x6, 0x19, 0x1, -0xf6, 0x5, 0x208, 0xb, 0x1, 0x6, 0x93, 0x9, 0x76, 0x6,
                0xf1, 0x1, -0x74, 0xc, 0xfb, 0xb, 0x0, 0x6, 0x1a, 0x1, 0xdb, 0x5, 0x21c, 0xb, 0x1, 0x6,
                0x77, 0x9, -0x69, 0x6, 0xe, 0x1, 0x14, 0xc, -0x81, 0xb, 0x0, 0x6, 0x1b, 0x1, -0xfa, 0x5,
                0x230, 0xb, 0x1, 0x6, 0xdf, 0x9, -0x4b, 0x6, 0x80, 0x1, -0xc9, 0xc, -0xc8, 0xb, 0x0, 0x6, 0x1c,
                0x1, -0xbd, 0x5, 0x244, 0xb, 0x1, 0x6, 0xd6, 0x9, 0x47, 0x6, 0xa0, 0x1, 0xb9, 0xc, 0xb5, 0xb,
                0x0, 0x6, 0x1d, 0x1, 0xe2, 0x5, 0x258, 0xb, 0x1, 0x6, -0x50, 0x9, -0xe0, 0x6, -0x23, 0x1, 0xfa,
                0xc, 0xb8, 0xb, 0x0, 0x6, 0x1e, 0x1, 0xd6, 0x5, 0x26c, 0xb, 0x1, 0x6, 0x7e, 0x9, 0xf4, 0x6,
                0x3, 0x1, -0xec, 0xc, 0xf5, 0x6, 0x88, 0xc, 0xae,});
        char[] c = args[0].toCharArray();
        for (int i = 0; i < c.length; i++) {
            String s = getOutput(Math.abs(java.run(i, (int) c[i])));
            if (s.equals(owo[1])) {
                System.out.println(s);
                System.exit(0);
            }
        }
        System.out.println(getOutput(Math.abs(java.run(0, (int) c[0]) % 2)));
    }
}
```

Then when running the program, we can see each character is xored with a number and then compared with another one. If the two numbers are not equal, the program terminates. To find the flag, you can xor the two numbers together to get one character of the flag, and just keep on doing that until you end up with the complete flag.

flag: `hsctf{y0u_d3f34t3d_th3_b4by_vm}`

# Tux Talk Show 2019

## Problem

Written by: Tux

Tux Talk Show 2019. Yes, this is trash.

`nc rev.hsctf.com 6767`

[trash](/blog/2019-06-08-hsctf-writeup-rev/Tux Talk Show 2019/trash)

## Solution

This is a classic guess-the-random-number challenge:

```python
from pwn import *
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc-2.27.so')
LIBC.srand(LIBC.time(0))

sh = remote('rev.hsctf.com', 6767)

number = sum([121, 1231231, 20312312, 122342342, 90988878, -30])
for i in range(6):
  number -= LIBC.rand() % 10 -1

print number
sh.interactive()
```

flag: `hsctf{n1ce_j0b_w4th_r4ndom_gue33ing}`

# Paint

## Problem

Written by: dwang

Windows? :thonk:

[paint.dll](/blog/2019-06-08-hsctf-writeup-rev/Paint/paint.dll)

## Solution

I looked at all the xref to `strcmp` and found the `StartAddress` function where the flag is generated.

The flag is generated from data stored in two xmm 128 bit registers. I <a href="https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR_Brute_Force(1,100,0,'Standard',false,true,false,'ftc')Reverse('Character')&input=NjE1RjYxNTA1NzYxNEQ0OTUxNUE1MDU3NDk2MTUwNUI1QjRENjE0QTUwNUI0ODVGNTY0NTU4NEE1RDRENTYzRQo">played around</a> with the values for a bit and got `hsctf{havent_seen_windows_in_a_`. Then I just guessed the last part and got the flag.

flag: `hsctf{havent_seen_windows_in_a_while}`