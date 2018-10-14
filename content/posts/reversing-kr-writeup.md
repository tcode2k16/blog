---
title: "reversing.kr Writeup"
date: 2018-10-13T12:59:59+08:00
draft: true
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "reversing"
]
description: solves for reversing.kr challenges
---

# Easy Crack - 100pts

We can take a quick look at the verification function:

```c
int __cdecl sub_401080(HWND hDlg)
{
  CHAR String; // [esp+4h] [ebp-64h]
  char v3; // [esp+5h] [ebp-63h]
  char v4; // [esp+6h] [ebp-62h]
  char v5; // [esp+8h] [ebp-60h]
  __int16 v6; // [esp+65h] [ebp-3h]
  char v7; // [esp+67h] [ebp-1h]

  String = 0;
  memset(&v3, 0, 0x60u);
  v6 = 0;
  v7 = 0;
  GetDlgItemTextA(hDlg, 1000, &String, 100);
  if ( v3 != 'a' || strncmp(&v4, a5y, 2u) || strcmp(&v5, aR3versing) || String != 'E' )
    return MessageBoxA(hDlg, aIncorrectPassw, Caption, 0x10u);
  MessageBoxA(hDlg, Text, Caption, 0x40u);
  return EndDialog(hDlg, 0);
}
```

As you can see `v3 != 'a' || strncmp(&v4, a5y, 2u) || strcmp(&v5, aR3versing) || String != 'E'` have to evaluate to false, in order for us to get the flag.

Because how the stack is organized, `String` is the first char of the string, `v3` is the second, `v4` is the third, and `v5` is the fifth. The condition statement above basically checks all the individual parts, and we can get the flag by piecing the parts together.

flag: `Ea5yR3versing`

# Easy Keygen - 100pts

Let's take a look at the main function:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int v3; // ebp
  signed int i; // esi
  char v6; // [esp+Ch] [ebp-130h]
  char v7; // [esp+Dh] [ebp-12Fh]
  char v8; // [esp+Eh] [ebp-12Eh]
  char name; // [esp+10h] [ebp-12Ch]
  char v10; // [esp+11h] [ebp-12Bh]
  __int16 v11; // [esp+71h] [ebp-CBh]
  char v12; // [esp+73h] [ebp-C9h]
  char validSerial; // [esp+74h] [ebp-C8h]
  char v14; // [esp+75h] [ebp-C7h]
  __int16 v15; // [esp+139h] [ebp-3h]
  char v16; // [esp+13Bh] [ebp-1h]

  name = 0;
  validSerial = 0;
  memset(&v10, 0, 0x60u);
  v11 = 0;
  v12 = 0;
  memset(&v14, 0, 0xC4u);
  v15 = 0;
  v16 = 0;
  v6 = 16;
  v7 = 32;
  v8 = 48;
  print((int)aInputName);
  scanf(aS, &name);
  v3 = 0;
  for ( i = 0; v3 < (signed int)strlen(&name); ++i )
  {
    if ( i >= 3 )
      i = 0;
    sprintf(&validSerial, aS02x, &validSerial, *(&name + v3++) ^ *(&v6 + i));
  }
  memset(&name, 0, 0x64u);
  print((int)aInputSerial);
  scanf(aS, &name);
  if ( !strcmp(&name, &validSerial) )
    print((int)aCorrect);
  else
    print((int)aWrong);
  return 0;
}
```

As you can see, the serial number is generated from the the name, and we have to go backwards to find the name of the user given the serial number.

The algorithm used here is not that complex. All the input characters are xored with `16`, `32`, and `48` in rotating order. Because xor is a symmetrical, you can just xor each value by the same number to decrypt the message. 

Here is a simple python script to find the username:

```python
from pwn import *

serial = '5B134977135E7D13'.decode('hex')

key = ['\x10', '\x20', '\x30']

for i in range(len(serial)):
  serial = serial[:i] + xor(serial[i], key[i%3]) + serial[i+1:]

print serial
```

flag: `K3yg3nm3`

# Easy ELF - 100pts

Let's take a look at the main function:

```c
int __cdecl main()
{
  write(1, "Reversing.Kr Easy ELF\n\n", 0x17u);
  get_input();
  if ( check() == 1 )
    win();
  else
    write(1, "Wrong\n", 6u);
  return 0;
}
```

So we need the `check` function to return 1:

```c
_BOOL4 check()
{
  if ( char1 != '1' )
    return 0;
  input ^= 0x34u;
  char2 ^= 0x32u;
  char3 ^= 0x88u;
  if ( char4 != 'X' )
    return 0;
  if ( char5 )
    return 0;
  if ( char2 != 124 )
    return 0;
  if ( input == 120 )
    return char3 == 0xDDu;
  return 0;
}
```

Go over each character and find the value that make the check function **not** return 0:

```
flag[0] == chr(120^0x34) == 'L'
flag[1] == '1'
flag[2] == chr(124^0x32) == 'N'
flag[3] == chr(0x88^0xDD) == 'U'
flag[4] == 'X'
flag[5] == '\x00'
```

flag: `L1NUX`

# Multiplicative - 170pts

Let's look at the java bytecodes:

```
...
  .line 10
    aload_0 ; input
    iconst_0
    aaload
    invokestatic java/lang/Long.decode (Ljava/lang/String;)Ljava/lang/Long;
    invokevirtual java/lang/Long.longValue()J
    lstore_1 ; input_num
  .line 11
    lload_1 ; input_num
    ldc2_w 26729
    lmul
    lstore_1 ; input_num
  .line 13
    lload_1 ; input_num
    ldc2_w -1536092243306511225
    lcmp
    ifne wrong
...
```

So we need to input a long value that equals `-1536092243306511225` when timed by `26729`.

Because `26729` is not a factor of `-1536092243306511225`, we need to find a value that is both a multiple of `26729` and its lower eight bytes have to be the same as `-1536092243306511225`.

Step one would to find the lower eight bytes of `-1536092243306511225`:

```
>>> hex((1 << 64)-1536092243306511225)
'0xeaaeb43e477b8487'
```

As you can see, the lower bytes have to equal `0xeaaeb43e477b8487`.

Next, we need to find a a multiple of `26729` that have the same lower eight bytes:

```
>>> for i in range(26729):
...     if ((i * 1 << 64)+0xeaaeb43e477b8487)%26729 == 0:
...             print i
...
13719
>>> hex(((13719 * 1 << 64)+0xeaaeb43e477b8487)/26729)
'0x83676f67696c676f'
```

Therefore, the number we are looking for is `0x83676f67696c676f`. Because the first bit is set, this is a negative number, so the final decimal value is `-8978084842198767761`.

```
❯ java -jar JavaCrackMe.jar -8978084842198767761
Reversing.Kr CrackMe!!
-----------------------------
The idea came out of the warsaw's crackme
-----------------------------

Correct!
```

flag: `-8978084842198767761`


# HateIntel - 150pts

Let's see the check function:

```c
int sub_2224()
{
  char input; // [sp+4h] [bp-5Ch]
  int v; // [sp+54h] [bp-Ch]
  int input_len; // [sp+58h] [bp-8h]
  int i; // [sp+5Ch] [bp-4h]
  char vars0; // [sp+60h] [bp+0h]

  v = 4;
  printf("Input key : ");
  scanf("%s", &input);
  input_len = strlen(&input);
  encrypt((signed __int32)&input, v);
  for ( i = 0; i < input_len; ++i )
  {
    if ( *(&vars0 + i - 92) != encrypted_key[i] )
    {
      puts("Wrong Key! ");
      return 0;
    }
  }
  puts("Correct Key! ");
  return 0;
}

signed __int32 __fastcall encrypt(signed __int32 input_len, int key)
{
  int key_1; // [sp+0h] [bp-14h]
  char *input; // [sp+4h] [bp-10h]
  int i; // [sp+8h] [bp-Ch]
  signed __int32 j; // [sp+Ch] [bp-8h]

  input = (char *)input_len;
  key_1 = key;
  for ( i = 0; i < key_1; ++i )
  {
    for ( j = 0; ; ++j )
    {
      input_len = strlen(input);
      if ( input_len <= j )
        break;
      input[j] = sub_2494(input[j], 1);
    }
  }
  return input_len;
}

int __fastcall sub_2494(unsigned __int8 character, int n)
{
  int character_1; // [sp+8h] [bp-8h]
  int i; // [sp+Ch] [bp-4h]

  character_1 = character;
  for ( i = 0; i < n; ++i )
  {
    character_1 *= 2;
    if ( character_1 & 0x100 )
      character_1 |= 1u;
  }
  return (unsigned __int8)character_1;
}
```

Basically `sub_2494` is called for each character four times, and we have to construct a function to undo it.

Here is the decryption function in python to recover the flag:

```python
encrypted = '44F6F557F5C696B656F51425D4F596E63747275736479603E6F3A392'.decode('hex')
encrypted = bytearray(encrypted)

def decrypt(data, key):
  for i in range(key):
    for j in range(len(data)):
      e = data[j]
      if e & 0x1:
        e += 0x100
        e -= 1
      e //= 2
      data[j] = e

decrypt(encrypted, 4)
print str(encrypted)
```

flag: `Do_u_like_ARM_instructi0n?:)`