---
title: "Codegate CTF Qualifier 2019 Writeup"
date: 2019-01-27T10:32:13+09:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: My solves for codegate ctf qualifier 2019 challenges
---

# MIC check

## Problem

Let the hacking begins ~ 

Decode it : 
9P&;gFD,5.BOPCdBl7Q+@V'1dDK?qL

## Solution

The text is encoded with base85, and you can decode it using tools such as [CyberChef](https://gchq.github.io/CyberChef).

flag: `Let the hacking begins ~`

# 20000

## Problem

nc 110.10.147.106 15959 

[Download](/blog/2019-01-27-codegate-qualifier-writeup/c1e3a33d8932a4a61b0e0e0e49d6c9bc.zip)

## Solution

For this problem, you are given a single binary along with 20000 `.so` libraries.

A quick look at the binary reveals that it is just a wrapper for calling the `.so` libraries using dlopen:

```c
signed __int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v3; // rax
  signed __int64 result; // rax
  void *v5; // rdi
  char *v6; // rax
  int v7; // [rsp+Ch] [rbp-94h]
  void (__fastcall *v8)(void *, const char *); // [rsp+10h] [rbp-90h]
  void *handle; // [rsp+18h] [rbp-88h]
  char s; // [rsp+20h] [rbp-80h]
  int v11; // [rsp+80h] [rbp-20h]
  int v12; // [rsp+84h] [rbp-1Ch]
  unsigned __int64 v13; // [rsp+88h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  sub_400A06(a1, a2, a3);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  memset(&s, 0, 0x60uLL);
  v11 = 0;
  printf("INPUT : ", 0LL, &v12);
  __isoc99_scanf("%d", &v7);
  if ( v7 <= 0 && v7 > 20000 )
  {
    printf("Invalid Input");
    exit(-1);
  }
  sprintf(&s, "./20000_so/lib_%d.so", (unsigned int)v7);
  handle = dlopen(&s, 1);
  if ( handle )
  {
    v5 = handle;
    v8 = (void (__fastcall *)(void *, const char *))dlsym(handle, "test");
    if ( v8 )
    {
      v8(v5, "test");
      dlclose(handle);
      result = 0LL;
    }
    else
    {
      v6 = dlerror();
      fprintf(stderr, "Error: %s\n", v6);
      dlclose(handle);
      result = 1LL;
    }
  }
  else
  {
    v3 = dlerror();
    fprintf(stderr, "Error: %s\n", v3);
    result = 1LL;
  }
  return result;
}
```

At this point, I started analyzing the 20000 `.so` libraries. There are three symbols that are present in the binaries: `test`, `filter1`, and `filter2`. `test` is the function the main program is going to invoke, it is either a empty shell with only a read function or a function that reads input, filters it with `filter1` and `filter2` from two other binaries, and call system with the input if it passes the filters. `filter1` and `filter2`, on the other hand, are similar as they each detect a certain set of characters/words.

I decided to generate a list of the binaries that contain each symbol using r2pipe:

```python
import r2pipe

test = []
filter1 = []
filter2 = []

for i in range(1, 20000+1):
  r2 = r2pipe.open('./20000_so/lib_{}.so'.format(i))
  if 'dlopen' in r2.cmd('ii'):
    test.append(i)
  if 'filter1' in r2.cmd('is'):
    filter1.append(i)
  if 'filter2' in r2.cmd('is'):
    filter2.append(i)
  if i % 12 == 0:
    print i
  r2.quit()

print test
print filter1
print filter2
```

Now with the generated list, I begin to look for anomalies:

```python
for i in filter1:
  r2 = r2pipe.open('./20000_so/lib_{}.so'.format(i))
  r2.cmd('aaa')
  keys = ['0x3b', '0x2a', '0x7c', '0x26', '0x24', '0x60', '0x3e', '0x3c', '0x72']
  out = r2.cmd('pdf @ sym.filter1')

  same = True
  for k in keys:
    if k not in out:
      same = False
  
  if not same:
    print str(i)

  if i % 12 == 0:
    print '.'
  r2.quit()
```

In the end, I landed on `lib_4323.so`, the only anomaly. Here its `filter1` function compared to a normal `filter1` function:

> `filter1` in `lib_4323.so`:

```c
char *__fastcall filter1(const char *a1)
{
  char *result; // rax

  if ( strchr(a1, ';') )
    exit(0);
  if ( strchr(a1, '*') )
    exit(0);
  if ( strchr(a1, '`') )
    exit(0);
  if ( strchr(a1, '&') )
    exit(0);
  if ( strchr(a1, '$') )
    exit(0);
  if ( strchr(a1, '>') )
    exit(0);
  if ( strchr(a1, '<') )
    exit(0);
  result = strchr(a1, 'r');
  if ( result )
    exit(0);
  return result;
}
```

> `filter1` in `lib_5091.so`:

```c
char *__fastcall filter1(const char *a1)
{
  char *result; // rax

  if ( strchr(a1, ';') )
    exit(0);
  if ( strchr(a1, '*') )
    exit(0);
  if ( strchr(a1, '|') )
    exit(0);
  if ( strchr(a1, '&') )
    exit(0);
  if ( strchr(a1, '$') )
    exit(0);
  if ( strchr(a1, '`') )
    exit(0);
  if ( strchr(a1, '>') )
    exit(0);
  if ( strchr(a1, '<') )
    exit(0);
  result = strchr(a1, 'r');
  if ( result )
    exit(0);
  return result;
}
```

You can see that there's less restrictions. Now, I just have to look for the library that uses this filter:

```python
for i in test:
  r2 = r2pipe.open('./20000_so/lib_{}.so'.format(i))

  if len(r2.cmd('iz~./20000_so/lib_4323.so')) > 0:
    print i

  if i % 12 == 0:
    print '.'
  r2.quit()
```

That leads me to `lib_17394.so`, the vulnerable library. I examined the `filter2` used by `lib_17394.so` and discovered that it doesn't filter out `sh` which is different from all other `filter2` functions.

Now knowing the vulnerable library and what command to use, I am able to get the flag:

```
❯ nc 110.10.147.106 15959

   /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$
  /$$__  $$ /$$$_  $$ /$$$_  $$ /$$$_  $$ /$$$_  $$
 |__/  \ $$| $$$$\ $$| $$$$\ $$| $$$$\ $$| $$$$\ $$
   /$$$$$$/| $$ $$ $$| $$ $$ $$| $$ $$ $$| $$ $$ $$
  /$$____/ | $$\ $$$$| $$\ $$$$| $$\ $$$$| $$\ $$$$
 | $$      | $$ \ $$$| $$ \ $$$| $$ \ $$$| $$ \ $$$
 | $$$$$$$$|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$/
 |________/ \______/  \______/  \______/  \______/

INPUT : 17394
This is lib_17394 file.
How do you find vulnerable file?
sh
cat flag
flag{Are_y0u_A_h@cker_in_real-word?}
```

flag: `Are_y0u_A_h@cker_in_real-word?`

# algo_auth

## Problem

I like an algorithm 

nc 110.10.147.104 15712 

## Solution

This is a classic programming problem where you have to find the least cost path from the left column to the the right column of a 7x7 matrix.

Because of the time limitation, I decided to search for existing solutions instead of writing one on the the spot. I quickly found [this article](https://www.geeksforgeeks.org/minimum-cost-path-left-right-bottom-moves-allowed/) describing the same problem with only slight variations.

I took the code and altered it a bit to fit my need, and here is the final version:

```c++
// https://www.geeksforgeeks.org/minimum-cost-path-left-right-bottom-moves-allowed/
#include <bits/stdc++.h> 
using namespace std; 
  
#define ROW 7
#define COL 7 
  
// structure for information of each cell 
struct cell 
{ 
    int x, y; 
    int distance; 
    cell(int x, int y, int distance) : 
        x(x), y(y), distance(distance) {} 
}; 
  
// Utility method for comparing two cells 
bool operator<(const cell& a, const cell& b) 
{ 
    if (a.distance == b.distance) 
    { 
        if (a.x != b.x) 
            return (a.x < b.x); 
        else
            return (a.y < b.y); 
    } 
    return (a.distance < b.distance); 
}

// Utility method to check whether a point is 
// inside the grid or not 
bool isInsideGrid(int i, int j) 
{ 
    return (i >= 0 && i < COL && j >= 0 && j < ROW); 
} 
  
// Method returns minimum cost to reach bottom 
// right from top left 
int shortest(int grid[ROW][COL], int row, int col, int sx, int sy) 
{ 
    int dis[row][col]; 
  
    // initializing distance array by INT_MAX 
    for (int i = 0; i < row; i++) 
        for (int j = 0; j < col; j++) 
            dis[i][j] = INT_MAX; 
  
    // direction arrays for simplification of getting 
    // neighbour 
    int dx[] = {-1, 0, 1, 0}; 
    int dy[] = {0, 1, 0, -1}; 
  
    set<cell> st; 
  
    // insert (0, 0) cell with 0 distance 
    st.insert(cell(sx, sy, 0)); 
  
    // initialize distance of (0, 0) with its grid value 
    dis[sx][sy] = grid[sx][sy]; 
  
    // loop for standard dijkstra's algorithm 
    while (!st.empty()) 
    { 
        // get the cell with minimum distance and delete 
        // it from the set 
        cell k = *st.begin(); 
        st.erase(st.begin()); 
  
        // looping through all neighbours 
        for (int i = 0; i < 4; i++) 
        { 
            int x = k.x + dx[i]; 
            int y = k.y + dy[i]; 
  
            // if not inside boundry, ignore them 
            if (!isInsideGrid(x, y)) 
                continue; 
  
            // If distance from current cell is smaller, then 
            // update distance of neighbour cell 
            if (dis[x][y] > dis[k.x][k.y] + grid[x][y]) 
            { 
                // If cell is already there in set, then 
                // remove its previous entry 
                if (dis[x][y] != INT_MAX) 
                    st.erase(st.find(cell(x, y, dis[x][y]))); 
  
                // update the distance and insert new updated 
                // cell in set 
                dis[x][y] = dis[k.x][k.y] + grid[x][y]; 
                st.insert(cell(x, y, dis[x][y])); 
            } 
        } 
    } 
  
    // uncomment below code to print distance 
    // of each cell from (0, 0) 
    for (int i = 0; i < row; i++, cout << endl) 
        for (int j = 0; j < col; j++) 
            cout << dis[i][j] << " "; 
    // dis[row - 1][col - 1] will represent final 
    // distance of bottom right cell from top left cell 
    return dis[row - 1][col - 1]; 
} 
  
// Driver code to test above methods 
int main() 
{ 
    int sx, sy;
    cin >> sx >> sy;
    int grid[ROW][COL];
    for (int i = 0; i < ROW; i++) {
        for (int j = 0; j < COL; j++) {
            cin >> grid[i][j];
        }
    }
    // for (int i = 0; i < ROW; i++) {
    //     for (int j = 0; j < COL; j++) {
    //         cout << grid[i][j] << endl;
    //     }
    // }



    shortest(grid, ROW, COL, sy, sx);
    return 0; 
}
```

Now able to solve any 7x7 matrix, I wrote a short script in python to communicate with the server and extract the flag:

```python
from pwn import *

context.log_level = 'error'

r = remote('110.10.147.104', 15712)

r.sendlineafter('>>', 'G')

answers = []
for count in range(100):
  output = r.recvuntil('>>').strip().split('\n')[1:8]
  sols = []
  for i in range(7):
    sh = process('./solve')
    sh.sendline('0 {}'.format(i))
    for each in output:
      sh.sendline(each)
    sol = min(map(lambda x: int(x.strip().split(' ')[-1]), sh.recvall().strip().split('\n')))
    sols.append(sol)
    sh.close()
  answers.append(min(sols))
  r.sendlineafter('>', str(min(sols)))
  print 'stage{} done'.format(count+1)
print answers
r.interactive()
```

After completing all 100 stages, you are told that the answers for all 100 matrixes form the flag. It turns out to be a simple base64 encoded string, and here is a python snippet to decode it:

```python
code = [82, 107, 120, 66, 82, 121, 65, 54, 73, 71, 99, 119, 77, 71, 57, 118, 84, 48, 57, 107, 88, 50, 111, 119, 81, 105, 69, 104, 73, 86, 57, 102, 88, 51, 86, 117, 89, 50, 57, 116, 90, 109, 57, 121, 100, 68, 82, 105, 98, 71, 86, 102, 88, 51, 77, 122, 89, 51, 86, 121, 97, 88, 82, 53, 88, 49, 57, 112, 99, 49, 57, 102, 98, 106, 66, 48, 88, 49, 56, 48, 88, 49, 57, 122, 90, 87, 78, 49, 99, 109, 108, 48, 101, 83, 69, 104, 73, 83, 69, 104]
code = map(chr, code)
print ''.join(code).decode('base64')
```

```
❯ python decode.py
FLAG : g00ooOOd_j0B!!!___uncomfort4ble__s3curity__is__n0t__4__security!!!!!
```

flag: `g00ooOOd_j0B!!!___uncomfort4ble__s3curity__is__n0t__4__security!!!!!`

# KingMaker

## Problem

nc 110.10.147.104 13152 

[Download](/blog/2019-01-27-codegate-qualifier-writeup/6e7267a7f88c9fd2734dc89de972d103.zip)

## Solution

This is the problem that I spent the most amount of time on. The binary is a text-based adventure game that is divided into 5 stages. The code for each stage is xor encrypted with a different key with either a length of 4 or 10. Here is the decryption function:

```c
_BYTE *__fastcall xor(_BYTE *start_addr, int end_addr, const char *key)
{
  _BYTE *result; // rax
  char *s; // [rsp+8h] [rbp-28h]
  signed int counter; // [rsp+20h] [rbp-10h]
  unsigned int length; // [rsp+24h] [rbp-Ch]
  _BYTE *addr; // [rsp+28h] [rbp-8h]

  s = (char *)key;
  counter = 0;
  length = strlen(key);
  for ( addr = start_addr; ; ++addr )
  {
    result = &start_addr[end_addr];
    if ( result <= addr )
      break;
    *addr ^= s[counter];
    counter = (counter + 1) % length;
  }
  return result;
}
```

I am able to crack the first four bytes of the xor key by knowing that almost all 64 bit binary functions start with `push rbp; mov rbp, rsp;` which is `554889e5` in hex. Using this method, I am able to get the keys for the first two stages which both have a key length of 4.

For the last three stage, I have to use another fact that the first function of each stage always print out `SYSTEM : We will start test NUMBER\n`. Knowing that plus the location of the string, I am able to recover all ten bytes of the xor key.

With all 5 keys, I can now patch the binary. For this CTF, I did all the patching manually with a python script although better solutions definitely exist (put your suggestions in the comment section below). Here is the patching script:

```python
import string
from pwn import *
context.arch='amd64'

main_key = 'lOv3'
main_key_2 = 'D0l1'
main_key_3 = 'HuNgRYT1m3'
main_key_4 = 'F0uRS3aS0n'
main_key_5 = 'T1kT4kT0Kk'

patches = [
  (0x341D, 0xf0, main_key),
  (0x33FF, 0x1e, main_key),
  (0x330F, 0xf0, main_key),
  (0x32DE, 0x31, main_key),
  (0x32C0, 0x1e, main_key),
  (0x3197, 0x129, main_key),
  (0x30D4, 0x0C3, main_key),

  (0x2D55, 0x0FA, main_key_2),
  (0x2C25, 0x112, main_key_2),
  (0x2D37, 0x1e, main_key_2),
  (0x27E9, 0x44, main_key_2),
  (0x29B9, 0x0E6, main_key_2),
  (0x2B2B,0x0FA, main_key_2),
  (0x271C, 0x0CD, main_key_2),
  (0x28B5, 0xe6, main_key_2),
  (0x299B, 0x1e, main_key_2),
  (0x2A9F, 0x4E, main_key_2),
  (0x2AED, 0x3e, main_key_2),
  (0x282D, 0x44, main_key_2),
  (0x2871, 0x44, main_key_2),

  (0x20E2, 0x18d, main_key_3),
  (0x201F, 0xc3, main_key_3),

  (0x1B0A, 0xf0, main_key_4),
  (0x19F2, 0x0FA, main_key_4),
  (0x1AEC, 0x1e, main_key_4),
  (0x192C, 0xa8, main_key_4),
  (0x19D4, 0x1e, main_key_4),
  (0x16D0, 0xc3, main_key_4),

  (0x11BB, 0x131, main_key_5),
  (0x0F25, 0x0DC, main_key_5),
  (0x108B, 0x130, main_key_5),
  (0x0DE7, 0x120, main_key_5),
  (0x0F07, 0x1e, main_key_5),
  (0x1001, 0x1e, main_key_5),
  (0x101F, 0x4e, main_key_5),
  (0x106D, 0x1e, main_key_5),
  (0x0C8C, 0x158, main_key_5)
]

with open('patched', 'wb') as patched:
  with open('./KingMaker', 'rb') as binary:
    data = bytearray(binary.read())
    
    for offset, size, key in patches:
      data[offset:offset+size] = xor(data[offset:offset+size], key)

    patched.write(data)
    patched.close()
```

Now with the decrypted binary, I just have to find the path through the game that will lead to the attribute `5/5/5/5/5` in the end. Again for time sake, I did a nested for loop to find the correct path (not the best code that I have written, but it works ;) ):

```python
t1 = ['20010', '20100', '20210']
t2 = ['00102','0x00x','02000']
t3 = ['x0x10','12000','11000']
t4 = ['11112', '12212', '11020', '11120']
t5 = ['00110','0x200','0x110']
t6 = ['1xx22','00000','10001']
t7 = ['01120']
t8 = ['01110','01000']
t9 = ['x0011', '00121', '00022']

def toNum(e):
  i = []
  for c in e:
    if c == '1':
      i.append(1)
    if c == '2':
      i.append(2)
    if c == '0':
      i.append(0)
    if c == 'x':
      i.append(-1)
  return i

def check(e1, e2, e3, e4, e5, e6, e7, e8, e9):
  i1 = toNum(e1)
  i2 = toNum(e2)
  i3 = toNum(e3)
  i4 = toNum(e4)
  i5 = toNum(e5)
  i6 = toNum(e6)
  i7 = toNum(e7)
  i8 = toNum(e8)
  i9 = toNum(e9)

  correct = True
  for i in range(5):
    if i1[i]+i2[i]+i3[i]+i4[i]+i5[i]+i6[i]+i7[i]+i8[i]+i9[i] != 5:
      correct = False
      break
  
  return correct
    
for e1 in t1:
  for e2 in t2:
    for e3 in t3:
      for e4 in t4:
        for e5 in t5:
          for e6 in t6:
            for e7 in t7:
              for e8 in t8:
                for e9 in t9:
                  if check(e1, e2, e3, e4, e5, e6, e7, e8, e9):
                    print e1, e2, e3, e4, e5, e6, e7, e8, e9

# 20100 02000 11000 11112 0x200 10001 01120 01000 00022
```

In addition, the challenge also includes a cipher text to decrypt. I reversed the verification function and recovered the plain text. Here is the script for that:

```python
from pwn import *
cipher1 = p64(5208208757389214273)
cipher1 += p64(5786930140093827657)
cipher1 += p64(6365651522798441041)
cipher1 += p64(23129)

print cipher1

cipher2 = p64(6077397987897199681)
cipher2 += p64(5788062684281653841)
cipher2 += p64(5856724921871653456)
cipher2 += p64(5783551345105850969)

print cipher2.encode('hex')

key = 'ALICE'
count = 0
text = ''
for e in cipher2[5:]:
  c = ord(e) - 0x41 - (ord(key[count])-0x41)
  s = 0x41+c
  if s >= 0x41+26:
    s -= 26
  if s < 0x41:
    s += 26
  text += chr(s)
  count = (count + 1) % 5

print text

# ALICEALLOFMYPROPERTYISYOURS
```

Now with both the sequence generated above and the plain text decrypted, I wrote another script to interact with the server and retrieve the flag:

```python
import string
from pwn import *
import sys
argv = sys.argv

DEBUG = True
context.binary = './KingMaker' 

if DEBUG:
  context.log_level = 'debug'

if len(argv) > 1:
  BINARY = argv[1]

  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)
else:
  sh = remote('110.10.147.104', 13152)

sh.sendlineafter('around\n', '1')

sh.sendlineafter('1\n', 'lOv3')
sh.sendlineafter('not\n', '1')
sh.sendlineafter('.\n', '2')
sh.sendlineafter('release\n', '2')
sh.sendlineafter('.\n', '3')

sh.sendlineafter('2\n', 'D0l1')
sh.sendlineafter('not\n', '1')
sh.sendlineafter('.\n', '2')
sh.sendlineafter('.\n', '1')
sh.sendlineafter('cleary.\n', '1')
sh.sendlineafter('brother.\n', '2')
sh.sendlineafter('you.\n', '1')

sh.sendlineafter('3\n', 'HuNgRYT1m3')
sh.sendlineafter('exile.\n', '2')
sh.sendlineafter('Nope!\n', '2')
sh.sendlineafter('first.\n', '3')

sh.sendlineafter('4\n', 'F0uRS3aS0n')
sh.sendlineafter('not.\n', '1')
sh.sendlineafter('can\'t\n', '1')
sh.sendlineafter('chance.\n', 'ALICEALLOFMYPROPERTYISYOURS')
sh.sendlineafter('room\n', '2')

sh.sendlineafter('5\n', 'T1kT4kT0Kk')
sh.sendlineafter('country.\n', '3')
sh.sendlineafter('together\n', '2')

sh.interactive()
```

flag: `He_C@N'T_see_the_f0rest_foR_TH3_TRee$`