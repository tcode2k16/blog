---
title: "CyBRICS CTF 2020 Crcrcr Writeup"
date: 2020-07-27T19:23:51+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  'cpython',
  'rc4'
]
description: My Crcrcr task writeup for CyBRICS CTF 2020
---

# Problem

(rebyC, Hard, 406 pts)

Author: Egor Zaytsev (@groke)

I created a simple service that encrypts flag (and your data) with RC4! I bet you can't the extract flag from there :)

crcrcr-cybrics2020.ctf.su/

Source code: [crcrcr.tar.gz](/blog/2020-07-27-cybrics-writeup/crcrcr.tar.gz)

Hint at 20:00 — When I wanna know how Python objects are stored in memory, I can do:

```
terminal1:
python3
>>> s = b"qweqweqweqwe";
terminal2: gcore `pidof python3`
```

And then look at resulting core file, get xref to qweqweqeqwe, and try to find out how Python objects are stored in memory.

And I guess I will be happy to find cipher.S (rc4 state) in the coredump

# Diving in

The source code for this task is provided, so the logical first step would be to read it.

The server is made up of two components the flask part that handles user interaction and an encryption program named `cryptor.py`.

First, let's look at the flask component:

```python
from flask import render_template, flash, redirect,url_for, request, session, send_file
from Crypto.Cipher import ARC4
from app import app
from app.forms import CreateForm
import hashlib
import os

root_dir = "/app"

@app.route('/')
@app.route('/index')
def index():
    form = CreateForm()
    return render_template('home.html', title='Make your try', form=form)

@app.route('/get_files', methods=['GET', 'POST'])
def login():
    form = CreateForm()
    try:
        foldername = f"data/upload/{hashlib.sha1(os.urandom(32)).hexdigest()}"

        curr_dir = os.getcwd()
        os.mkdir(foldername)
        os.chdir(foldername)
        input_file = open("input", "w")
        input_file.write(form.user_data.data)
        input_file.close()
        os.system("echo 0x3f > /proc/self/coredump_filter && python3.8 %s/cryptor.py %s/flag.png < input" % (curr_dir, curr_dir))
        os.system("rm input")
        files = filter(lambda x: os.path.isfile(x), os.listdir('.'))
        lst = [f"{foldername}/{x}" for x in files]        

    except Exception as e:
        print(e)
        os.chdir(root_dir)
        foldername = "Error!"
        return redirect(url_for('index'))
    os.chdir(root_dir)
    for i in lst:
        data_file = open(i, "rb")
        data = data_file.read()
        data_file.close()
        data_file = open(i, "wb")
        cipher = ARC4.new(app.config['RC4_KEY'])
        data = cipher.encrypt(data)
        data_file.write(data)
        data_file.close()
    return render_template('files.html', title='Link', fn = lst)


from flask import send_from_directory

@app.route('/data/<path:filename>')
def serve_static(filename):
    
    return send_file(os.path.join(root_dir,"data", filename))
```

The flask component has two important functionalities.

One, it takes the post data sent by the user, writes it to a file, and pipes it to `cryptor.py` through stdin.

Two, it performs a RC4 operation on all the resultant files produced by `cryptor.py` and serves them back to the user. One thing to note is that a new RC4 object is constructed for each file and the same key is used. We will come back to this point later.

Now, let's take a look at `cryptor.py`:

```python
import sys
import os
import random
import ast

class RC4:
    def __init__(self, key):
        S = list(range(0x100))
        j = 0
        for i in range(0x100):
            j = (S[i] + key[i % len(key)] + j) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S = S
        self.keystream = self._keystream_generator()

    def crypt_file(self, data):
        res = []
        while (i := data.read(1)):
            res.append(ord(i) ^ next(self.keystream))
        return bytes(res)

    def crypt_string(self, data):
        res = []
        for i in data:
            res.append(ord(i) ^ next(self.keystream))
        return bytes(res)

    def _keystream_generator(self):
        x = y = 0
        while True:
            x = (x + 1) & 0xff
            y = (self.S[x] + y) & 0xff
            self.S[x], self.S[y] = self.S[y], self.S[x]
            i = (self.S[x] + self.S[y]) & 0xff
            yield self.S[i]


if __name__ == "__main__":
    rc4_key = os.urandom(1024)
    cipher = RC4(rc4_key)
    del rc4_key
    data = open(sys.argv[1], "rb")
    res = cipher.crypt_file(data)
    f = open("res2.bin", "wb")
    f.write(res)
    f.close()
    del data
    K1 = [random.randrange(0, 256, 1) for i in range(256)] 
    K2 = [random.randrange(0, 256, 1) for i in range(256)] 
    K3 = [random.randrange(0, 256, 1) for i in range(256)] 
    K4 = [random.randrange(0, 256, 1) for i in range(256)] 
    K5 = [random.randrange(0, 256, 1) for i in range(256)] 
    K6 = [random.randrange(0, 256, 1) for i in range(256)] 
    user_input = input()
    enc_dict = ast.literal_eval(user_input)
    to_encrypt = enc_dict['to_enc']
    if enc_dict['need_enc'] == 1:
        output = open("user.enc", "wb")
        encrypted = cipher.crypt_string(to_encrypt)
        output.write(output)
        output.close()
    else:
        output = open("user.enc", "wb")
        output.write(to_encrypt)
        output.close()
```

This part also does two things.

One, it encrypts the flag using rc4 with 1024 bytes of randomness as key in contrast to the fixed key used in the flask component.

Two, it takes the user input, parses it into a dictionary using `ast.literal_eval`, and either writes it directly to disk or encrypts it with rc4 then writes to disk based on a flag.

# Halt and Catch Fire

The challenge code and the hint in the description clearly suggest us to obtain a coredump of the python process. So, we need to figure out a way to crash python by manipulating the input to `ast.literal_eval`.

A quick google search later, we found exactly [that](https://stackoverflow.com/a/54763776/6711781). As it turns out, the input `'()' * 1000000` causes the python parsing logic to go into multiple layers of recursion and will eventually lead to a crash.

```python
import requests

s = requests.Session()

# core dump
print s.post('http://crcrcr-cybrics2020.ctf.su/get_files',data={
  'user_data': '()' * 1000000,
  'submit': 'Get my files'
}).text
```

Part of the output that we care about:

```
<h3>
    <a href=data/upload/cfae2f668f31fb0e4f6705f505c33e339a4f68f1/core>core</a></br>
</h3>

<h3>
    <a href=data/upload/cfae2f668f31fb0e4f6705f505c33e339a4f68f1/res2.bin>res2.bin</a></br>
</h3>
```
> coredump and the encrypted data

Now we have a coredump, time for reversing right?

Not so fast, remember from before both files are encrypted by the flask component. This in fact makes `res2.bin` doubly encrypted. So we need a way of defeating this first layer of encryption

# RC4 and Key Reuse

Time to brush up on the basics of rc4 encryption. The process is quite simple. The key helps the algorithm initialize its internal state. Then the algorithm can start producing an infinitely long key stream. The encryption process would just be to xor this newly produced key stream with our input.

With this in mind, it is not hard to see why reusing the same key for multiple encryptions is a bad idea. The same key always leads to the same key stream. So if we encrypt an unknown file A with the key stream K to produce B and then encrypt a known file C with the same key stream K to produce D, we get the property below:

```plain
C, B, and D are known
trying to find A

# encrypt
B = xor(A, K)
D = xor(C, K)

# decrypt
K = xor(D, C)
A = xor(K, B)
```

In other words, we can recover the full key stream by encrypting a known file, and with the key stream in hand, we can recover all other files encrypted by the same key.

This is precisely the scenario we have on hand. By turning off encryption on user input, `cryptor.py` allows us to write anything we want to disk and that will later be encrypted using rc4 by the flask component.

```python
import requests
import urllib
s = requests.Session()

additional_headers = {
  'Content-Type': 'application/x-www-form-urlencoded'
}

# 75698176 is the size of the core dump

post_data ={
  'user_data': '{"need_enc":0, "to_enc":b"'+('a'*75698176)+'"}',
  'submit': 'Get my files'
}

print s.post('http://crcrcr-cybrics2020.ctf.su/get_files',data=urllib.urlencode(post_data), headers=additional_headers).text
```

Part of the output that we care about:

```
<h3>
    <a href=data/upload/4861eb51e2c18861f5111b63c92cd809b924eea1/user.enc>user.enc</a></br>
</h3>
```

With this new `user.enc` file, we can xor it with its original content to recover the full key stream and decrypt the other files:

```python
from pwn import *

with open('./dumps/core', 'rb') as f:
  enc_core = f.read()
with open('./dumps/res2.bin', 'rb') as f:
  enc_bin = f.read()
with open('./dumps/user.enc', 'rb') as f:
  enc_user = f.read()

key_stream = xor(enc_user, 'a'*len(enc_user))

assert len(key_stream) >= len(enc_core)
plain_core = xor(key_stream, enc_core)
with open('./dumps/plain_core','wb') as f:
  f.write(plain_core)

plain_bin = xor(key_stream[:len(enc_bin)], enc_bin)
with open('./dumps/plain_bin','wb') as f:
  f.write(plain_bin)
```

# Cpython Internals and Coredump Analysis

Now is finally time for some reversing. We need to extract `cipher.S` (rc4 state) from the coredump. The best way to approach this would be to look at some cpython source code and find out how the state would look like in memory.

```c
typedef struct _object {
    _PyObject_HEAD_EXTRA
    Py_ssize_t ob_refcnt;
    struct _typeobject *ob_type;
} PyObject;
```
> [source](https://github.com/python/cpython/blob/f7d72e48fb235684e17668a1e5107e6b0dab7b80/Include/object.h#L104)

First, we learned that all objects in python (yes including numbers) are represented with a `PyObject` struct.

This struct keeps track of the `ob_refcnt` or the number of references a certain object has. This is useful for the garbage collector to know what objects need to be freed.

The struct also contains `ob_type` which is a pointer to the object type. This is how the program differentiates a string from an array.



In our case, we are interested in two particular structs: `PyLongObject` which represents a number and `PyListObject` which represents a list.

Let's focus on `PyLongObject` first:

```c
typedef struct _longobject PyLongObject;
```
> [source](https://github.com/python/cpython/blob/f7d72e48fb/Include/longobject.h#L10)

So, a `PyLongObject` is a `_longobject`. Not very helpful... Let's go deeper

```c
#if PYLONG_BITS_IN_DIGIT == 30
typedef uint32_t digit;
typedef int32_t sdigit; /* signed variant of digit */
typedef uint64_t twodigits;
typedef int64_t stwodigits; /* signed variant of twodigits */
#define PyLong_SHIFT    30
#define _PyLong_DECIMAL_SHIFT   9 /* max(e such that 10**e fits in a digit) */
#define _PyLong_DECIMAL_BASE    ((digit)1000000000) /* 10 ** DECIMAL_SHIFT */
#elif PYLONG_BITS_IN_DIGIT == 15
typedef unsigned short digit;
typedef short sdigit; /* signed variant of digit */
typedef unsigned long twodigits;
typedef long stwodigits; /* signed variant of twodigits */
#define PyLong_SHIFT    15
#define _PyLong_DECIMAL_SHIFT   4 /* max(e such that 10**e fits in a digit) */
#define _PyLong_DECIMAL_BASE    ((digit)10000) /* 10 ** DECIMAL_SHIFT */
#else
#error "PYLONG_BITS_IN_DIGIT should be 15 or 30"
#endif
#define PyLong_BASE     ((digit)1 << PyLong_SHIFT)
#define PyLong_MASK     ((digit)(PyLong_BASE - 1))

#if PyLong_SHIFT % 5 != 0
#error "longobject.c requires that PyLong_SHIFT be divisible by 5"
#endif

/* Long integer representation.
   The absolute value of a number is equal to
        SUM(for i=0 through abs(ob_size)-1) ob_digit[i] * 2**(SHIFT*i)
   Negative numbers are represented with ob_size < 0;
   zero is represented by ob_size == 0.
   In a normalized number, ob_digit[abs(ob_size)-1] (the most significant
   digit) is never zero.  Also, in all cases, for all valid i,
        0 <= ob_digit[i] <= MASK.
   The allocation function takes care of allocating extra memory
   so that ob_digit[0] ... ob_digit[abs(ob_size)-1] are actually available.
   CAUTION:  Generic code manipulating subtypes of PyVarObject has to
   aware that ints abuse  ob_size's sign bit.
*/
struct _longobject {
    PyObject_VAR_HEAD
    digit ob_digit[1];
};
```
> [source](https://github.com/python/cpython/blob/f7d72e48fb/Include/longintrepr.h#L85)


```c
PyLongObject *
_PyLong_New(Py_ssize_t size)
{
    PyLongObject *result;
    /* Number of bytes needed is: offsetof(PyLongObject, ob_digit) +
       sizeof(digit)*size.  Previous incarnations of this code used
       sizeof(PyVarObject) instead of the offsetof, but this risks being
       incorrect in the presence of padding between the PyVarObject header
       and the digits. */
    if (size > (Py_ssize_t)MAX_LONG_DIGITS) {
        PyErr_SetString(PyExc_OverflowError,
                        "too many digits in integer");
        return NULL;
    }
    result = PyObject_MALLOC(offsetof(PyLongObject, ob_digit) +
                             size*sizeof(digit));
    if (!result) {
        PyErr_NoMemory();
        return NULL;
    }
    _PyObject_InitVar((PyVarObject*)result, &PyLong_Type, size);
    return result;
}
```
> [source](https://github.com/python/cpython/blob/5a2bac7fe0e7a2b67fd57c7a9176a50feed0d7a0/Objects/longobject.c#L130)


Now, we are getting somewhere. By reading the comments inlined as well as the constructor function, we see that in order to support arbitrary precision integers. The `PyLongObject` struct has a dynamic length. The `ob_digit` can grow to fit the number that it contains.

Let's look into `PyObject_VAR_HEAD` some more.

```c
#define PyObject_VAR_HEAD      PyVarObject ob_base;
```
> [source](https://github.com/python/cpython/blob/f7d72e48fb235684e17668a1e5107e6b0dab7b80/Include/object.h#L96)

```c
typedef struct {
    PyObject ob_base;
    Py_ssize_t ob_size; /* Number of items in variable part */
} PyVarObject;
```
> [source](https://github.com/python/cpython/blob/f7d72e48fb235684e17668a1e5107e6b0dab7b80/Include/object.h#L113)

This gives us another piece of the puzzle. The `ob_size` field of the `PyVarObject` is necessary here as it helps us store the length of the `ob_digit` array.

After many layers of nested definitions, we are now able to slowly piece together how a `PyLongObject` looks like in memory. If we flatten all the structs, we will get something like this:

```c
PyLongObject {
  Py_ssize_t ob_refcnt;
  struct _typeobject *ob_type;
  Py_ssize_t ob_size; /* Number of items in variable part */
  digit ob_digit[1];
}
```

For this challenge, we are hunting for the internal states of the rc4 algorithm. This allows us to make some assumptions. One of them being the fact that the items of the target array go from 0x00 to 0xff with no repeats.

```python
class RC4:
    def __init__(self, key):
        S = list(range(0x100))
        j = 0
        for i in range(0x100):
            j = (S[i] + key[i % len(key)] + j) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S = S
        self.keystream = self._keystream_generator()
```

With this information, we are able to know `ob_size` must be 0x1 or `0100000000000000` in memory as the numbers themselves are only one byte long. Next, we also know the `ob_digit` field directly after will always be in the form `??000000`. Combining the two, we can conclude the numbers that we are looking for will be in the shape `0100000000000000??000000` in memory.

Let's do a search for the number `0xf3` with that pattern using [radare2](https://github.com/radareorg/radare2):

```plain
$ r2 ./plain_core
[0x7f3df5e843d2]> /x 0100000000000000f3000000
0x7f3df60a5f50 hit0_0 0100000000000000f3000000
[0x7f3df5e843d2]> px 32 @ 0x7f3df60a5f50-0x10
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7f3df60a5f40  0900 0000 0000 0000 60b6 07f6 3d7f 0000  ........`...=...
0x7f3df60a5f50  0100 0000 0000 0000 f300 0000 0000 0000  ................
```

Bingo! We found our first `PyLongObject` in memory. Referring to the notes above, we can see that this struct store the value `0xf3` and have `0x09` references to it. In addition, we now know the type pointer for `PyLongObject` is `60b6 07f6 3d7f 0000` or `0x7f3df607b660`.

Now, it's a good time to write a script to automate some of the steps. To do this, we can use [r2pipe](https://github.com/radareorg/radare2-r2pipe) to send r2 commands from python:

```python
import r2pipe
from pwn import *

r2 = r2pipe.open("./plain_core")

PyLongObject_pattern = '00'*7+(p64(0x7f3df607b660)+p64(0x1)).encode('hex')+'..'+'00'*7
vals = r2.cmd('/x {}'.format(PyLongObject_pattern))
vals = map(lambda x: int(x.strip().split(' ')[0], 16)-1,vals.strip().split('\n'))

val_map = {}
for val in vals:
  int_val = u64(r2.cmd('p8 8 @ {}'.format(val+0x18)).strip().decode('hex'))
  print '{}: {}'.format(hex(int_val),hex(val))
  val_map[val] = int_val
```

```plain
$ python r2p.py
0x1: 0x7f3df60a4100
0x2: 0x7f3df60a4120
0x3: 0x7f3df60a4140
...
0xff: 0x7f3df60a60c0
```

With this script, we found the `PyLongObject` addresses of values 0x01 to 0xff. The only missing one now is the value zero.

Again, referring to the notes we have above, we can find the comment `zero is represented by ob_size == 0.` With this, we can find the address of zero by hand:

```plain
$ r2 ./plain_core
[0x7f3df5e843d2]> /x 0000000000000060b607f63d7f000000000000000000000000000000000000
0x7f3df590c1a1 hit0_0 0000000000000060b607f63d7f000000000000000000000000000000000000
[0x7f3df5e843d2]> px 32 @ 0x7f3df590c1a1-1
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7f3df590c1a0  0100 0000 0000 0000 60b6 07f6 3d7f 0000  ........`...=...
0x7f3df590c1b0  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Now, with the addresses of all the number objects that we are interested in, it's time to focus on looking for the `PyListObject`.

```c
typedef struct {
    PyObject_VAR_HEAD
    /* Vector of pointers to list elements.  list[0] is ob_item[0], etc. */
    PyObject **ob_item;

    /* ob_item contains space for 'allocated' elements.  The number
     * currently in use is ob_size.
     * Invariants:
     *     0 <= ob_size <= allocated
     *     len(list) == ob_size
     *     ob_item == NULL implies ob_size == allocated == 0
     * list.sort() temporarily sets allocated to -1 to detect mutations.
     *
     * Items must normally not be NULL, except during construction when
     * the list is not yet visible outside the function that builds it.
     */
    Py_ssize_t allocated;
} PyListObject;
```
> [source](https://github.com/python/cpython/blob/c45dbe93b7094fe014442c198727ee38b25541c4/Include/cpython/listobject.h#L5)

A `PyListObject` seems to be quite straight forward. Its `ob_item` field is a pointer to a list of pointers that points to the list's elements. Ok, maybe not so simple...

Let me visualize what I'm describing:

```
addd    val
0x1000: 0x2000 <-- this is our ob_item field that points to 0x2000
...
0x2000: 0x3000 <-- this is ob_item[0] which stores the pointer to the first list element
0x2002: 0x3010
0x2004: 0x3020
0x2008: 0x3030
...
0x3000: 0x???? <-- actual PyObject data
...
```

With this in mind, we can start searching for the rc4 state.

```python
class RC4:
    def __init__(self, key):
        S = list(range(0x100))
        j = 0
        for i in range(0x100):
            j = (S[i] + key[i % len(key)] + j) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S = S
        self.keystream = self._keystream_generator()
```

We know the list has a length of 0x100, and we have all the addresses of the `PyObject` it will point to which are all in the form of `0x7f3df60a???0`. We can create another search query based on this information:

```python
import r2pipe
from pwn import *

r2 = r2pipe.open("./plain_core")

PyLongObject_pattern = '00'*7+(p64(0x7f3df607b660)+p64(0x1)).encode('hex')+'..'+'00'*7
vals = r2.cmd('/x {}'.format(PyLongObject_pattern))
vals = map(lambda x: int(x.strip().split(' ')[0], 16)-1,vals.strip().split('\n'))

val_map = {}
for val in vals:
  int_val = u64(r2.cmd('p8 8 @ {}'.format(val+0x18)).strip().decode('hex'))
  print '{}: {}'.format(hex(int_val),hex(val))
  val_map[val] = int_val

val_map[0x7f3df60a40e0] = 0 # adding zero manually

arrs = r2.cmd('/x {}'.format('.0..0af63d7f0000'*0x100))
arrs = map(lambda x: int(x.strip().split(' ')[0], 16), arrs.strip().split('\n'))
for arr in arrs:
  temp = []
  data = r2.cmd('p8 {} @ {}'.format(0x100*8, arr)).strip()
  for i in range(0, len(data), 16):
    val_addr = u64(data[i:i+16].decode('hex'))
    temp.append(val_map[val_addr])
  print temp
```

```
$ python r2p.py
...
[125, 99, 188, 176, 15, 153, 102, 139, 226, 53, 30, 100, 126, 81, 88, 63, 190, 232, 119, 7, 40, 192, 37, 52, 113, 68, 77, 44, 36, 235, 167, 38, 108, 159, 26, 152, 80, 21, 173, 54, 194, 252, 168, 18, 216, 200, 223, 162, 67, 244, 23, 127, 207, 27, 237, 121, 48, 94, 5, 196, 130, 215, 56, 49, 255, 166, 231, 123, 59, 34, 143, 92, 93, 61, 85, 35, 224, 217, 76, 161, 236, 74, 182, 110, 70, 225, 234, 24, 242, 241, 98, 203, 133, 71, 46, 198, 253, 186, 69, 28, 187, 239, 33, 11, 120, 20, 249, 22, 8, 41, 10, 124, 205, 84, 60, 141, 220, 114, 12, 58, 132, 14, 16, 212, 211, 0, 134, 101, 214, 163, 199, 183, 45, 57, 95, 65, 191, 89, 222, 72, 96, 204, 118, 116, 154, 43, 245, 39, 218, 131, 117, 171, 164, 230, 178, 251, 64, 106, 29, 149, 75, 208, 78, 156, 2, 180, 31, 83, 247, 4, 147, 195, 111, 103, 160, 19, 158, 73, 201, 42, 145, 47, 122, 185, 172, 227, 140, 137, 112, 1, 175, 213, 148, 146, 62, 142, 221, 128, 91, 82, 105, 248, 219, 6, 107, 3, 86, 150, 240, 136, 135, 129, 25, 189, 254, 151, 246, 138, 51, 97, 181, 177, 193, 32, 170, 184, 157, 115, 155, 90, 202, 169, 109, 17, 179, 197, 250, 243, 209, 229, 87, 238, 9, 104, 66, 233, 206, 79, 13, 174, 165, 210, 144, 50, 55, 228]
[141, 73, 31, 95, 204, 220, 208, 248, 115, 145, 86, 164, 54, 12, 48, 12, 93, 6, 128, 190, 8, 40, 132, 147, 128, 29, 142, 198, 61, 146, 231, 52, 188, 207, 146, 68, 70, 111, 165, 144, 196, 163, 156, 197, 210, 121, 17, 37, 219, 207, 111, 231, 108, 114, 160, 78, 208, 208, 107, 246, 132, 141, 149, 134, 156, 74, 57, 152, 215, 208, 43, 85, 83, 30, 151, 19, 225, 227, 76, 80, 240, 224, 34, 120, 106, 210, 60, 212, 119, 49, 110, 59, 203, 85, 19, 140, 150, 99, 167, 246, 114, 99, 248, 43, 74, 207, 119, 73, 212, 59, 21, 219, 215, 52, 222, 163, 188, 235, 139, 14, 54, 206, 231, 201, 76, 238, 1, 129, 31, 41, 90, 5, 26, 245, 170, 214, 230, 90, 43, 169, 99, 230, 27, 205, 146, 158, 134, 135, 240, 47, 9, 53, 120, 234, 14, 167, 255, 120, 25, 252, 137, 21, 136, 138, 248, 254, 213, 10, 114, 213, 35, 255, 177, 110, 115, 127, 218, 231, 215, 30, 117, 13, 149, 80, 157, 13, 206, 180, 71, 190, 139, 92, 155, 87, 138, 23, 217, 102, 138, 251, 83, 165, 38, 229, 86, 118, 181, 95, 5, 18, 140, 210, 205, 102, 70, 140, 6, 8, 144, 55, 77, 185, 89, 186, 212, 98, 198, 87, 43, 104, 83, 80, 78, 189, 67, 16, 214, 34, 58, 144, 101, 147, 222, 227, 215, 10, 177, 59, 27, 248, 98, 110, 0, 238, 52, 200]
[56, 206, 188, 67, 173, 180, 110, 102, 236, 82, 86, 159, 25, 194, 8, 209, 100, 87, 156, 124, 94, 145, 90, 217, 195, 129, 153, 42, 17, 21, 239, 218, 82, 254, 147, 27, 194, 167, 233, 101, 253, 50, 255, 5, 167, 184, 182, 200, 129, 228, 231, 62, 111, 29, 174, 181, 6, 23, 103, 45, 130, 75, 245, 78, 38, 90, 234, 242, 8, 215, 62, 99, 72, 255, 111, 114, 212, 221, 10, 244, 27, 245, 140, 187, 5, 216, 66, 184, 220, 248, 74, 42, 219, 163, 136, 201, 185, 14, 47, 225, 149, 47, 81, 130, 252, 154, 23, 122, 241, 152, 231, 154, 226, 66, 15, 112, 105, 144, 32, 107, 58, 141, 219, 76, 10, 128, 119, 23, 219, 127, 19, 97, 39, 123, 210, 185, 98, 73, 166, 177, 123, 19, 2, 143, 155, 119, 124, 111, 41, 83, 43, 2, 122, 80, 0, 97, 98, 6, 191, 124, 141, 119, 164, 142, 68, 199, 18, 235, 154, 75, 200, 229, 126, 61, 42, 156, 17, 162, 154, 247, 235, 132, 232, 231, 84, 34, 24, 150, 226, 216, 46, 143, 102, 79, 147, 171, 173, 141, 154, 237, 186, 122, 179, 111, 5, 191, 227, 193, 247, 252, 145, 130, 1, 17, 13, 14, 31, 34, 113, 63, 46, 40, 161, 104, 89, 186, 166, 141, 255, 98, 191, 62, 242, 174, 207, 40, 33, 196, 224, 233, 77, 13, 158, 63, 81, 83, 38, 228, 140, 139, 209, 245, 177, 118, 243, 88]
[243, 160, 106, 51, 9, 72, 217, 121, 141, 55, 210, 22, 184, 25, 110, 28, 197, 149, 173, 178, 95, 212, 250, 163, 198, 111, 2, 200, 166, 209, 55, 103, 33, 132, 48, 82, 234, 240, 59, 235, 190, 235, 255, 143, 125, 50, 82, 77, 213, 224, 103, 42, 96, 47, 144, 19, 215, 172, 223, 225, 249, 149, 8, 9, 190, 87, 186, 152, 24, 89, 82, 170, 161, 166, 226, 53, 227, 204, 136, 151, 169, 120, 105, 58, 28, 214, 101, 129, 28, 25, 228, 148, 194, 224, 64, 69, 178, 225, 36, 47, 60, 237, 153, 121, 130, 187, 18, 226, 254, 109, 191, 147, 149, 74, 38, 177, 246, 153, 108, 202, 12, 35, 20, 3, 105, 129, 111, 24, 27, 99, 170, 219, 113, 129, 186, 98, 144, 219, 37, 249, 247, 156, 141, 235, 87, 119, 144, 167, 116, 149, 137, 80, 224, 11, 171, 198, 49, 88, 120, 32, 55, 96, 105, 214, 60, 114, 125, 41, 8, 217, 217, 206, 118, 187, 120, 121, 86, 109, 107, 211, 124, 118, 131, 139, 188, 121, 178, 4, 20, 94, 80, 163, 228, 11, 35, 89, 172, 12, 243, 141, 52, 82, 134, 125, 66, 29, 122, 1, 28, 65, 26, 116, 197, 195, 244, 130, 155, 184, 144, 95, 77, 33, 144, 60, 35, 169, 113, 49, 181, 226, 67, 168, 109, 193, 77, 195, 84, 208, 195, 24, 155, 60, 46, 180, 253, 32, 150, 28, 91, 52, 219, 98, 99, 17, 238, 7]
[171, 17, 166, 86, 102, 12, 96, 198, 249, 243, 249, 34, 55, 33, 166, 169, 208, 125, 86, 154, 231, 141, 226, 145, 39, 74, 190, 129, 147, 207, 111, 243, 217, 68, 223, 179, 129, 106, 188, 66, 223, 7, 203, 173, 250, 169, 36, 72, 93, 36, 181, 251, 254, 117, 236, 43, 4, 198, 75, 141, 191, 16, 252, 127, 147, 245, 249, 8, 176, 78, 87, 75, 6, 253, 106, 141, 35, 237, 93, 236, 207, 100, 123, 204, 159, 188, 28, 42, 205, 90, 6, 23, 247, 163, 245, 217, 52, 114, 208, 125, 196, 188, 163, 154, 231, 164, 171, 137, 250, 87, 23, 47, 153, 252, 202, 181, 129, 30, 198, 133, 86, 248, 175, 136, 208, 221, 189, 196, 213, 142, 94, 201, 138, 174, 222, 61, 190, 41, 242, 93, 130, 46, 226, 70, 212, 215, 87, 167, 34, 147, 42, 4, 104, 150, 100, 226, 8, 52, 230, 97, 116, 4, 65, 85, 58, 173, 225, 115, 166, 1, 36, 74, 106, 112, 245, 128, 82, 206, 9, 105, 195, 225, 119, 155, 75, 199, 26, 155, 212, 255, 226, 168, 59, 232, 106, 180, 178, 129, 13, 61, 246, 165, 136, 99, 64, 158, 150, 45, 16, 139, 242, 60, 106, 151, 169, 148, 64, 2, 198, 10, 0, 94, 109, 201, 64, 255, 44, 60, 64, 83, 76, 108, 144, 202, 100, 251, 33, 57, 44, 176, 85, 143, 162, 134, 243, 212, 53, 33, 131, 67, 118, 124, 245, 134, 4, 238]
[163, 154, 7, 185, 175, 134, 228, 98, 118, 13, 20, 119, 62, 98, 196, 116, 128, 160, 238, 97, 185, 55, 62, 178, 0, 78, 97, 233, 220, 142, 165, 101, 129, 125, 116, 54, 81, 169, 181, 252, 80, 169, 24, 29, 14, 188, 10, 99, 64, 218, 55, 120, 96, 240, 188, 225, 201, 54, 32, 140, 43, 206, 13, 155, 84, 255, 20, 193, 51, 204, 159, 10, 68, 66, 87, 168, 24, 27, 150, 225, 33, 40, 74, 199, 142, 126, 152, 80, 24, 216, 117, 211, 64, 196, 194, 62, 223, 36, 240, 128, 0, 180, 156, 52, 226, 54, 204, 133, 234, 182, 104, 135, 102, 249, 204, 167, 21, 203, 250, 0, 107, 173, 78, 223, 5, 64, 115, 240, 29, 104, 226, 218, 5, 139, 225, 152, 134, 17, 151, 115, 240, 122, 190, 111, 107, 67, 96, 180, 103, 86, 70, 225, 245, 209, 172, 1, 40, 33, 83, 176, 30, 46, 94, 154, 47, 66, 206, 19, 66, 148, 78, 190, 2, 5, 129, 150, 74, 168, 2, 146, 247, 198, 209, 152, 131, 76, 198, 11, 19, 182, 205, 31, 25, 154, 94, 143, 145, 173, 182, 104, 121, 134, 95, 197, 246, 226, 40, 242, 45, 114, 224, 186, 120, 234, 182, 115, 177, 227, 229, 128, 55, 100, 76, 8, 34, 37, 219, 71, 138, 132, 106, 239, 51, 59, 105, 220, 54, 72, 37, 249, 124, 57, 189, 170, 5, 179, 62, 95, 62, 30, 45, 209, 179, 135, 166, 174]
[88, 222, 156, 71, 4, 82, 236, 118, 238, 124, 197, 1, 200, 254, 170, 39, 48, 97, 163, 3, 220, 129, 62, 19, 38, 116, 86, 24, 190, 220, 15, 67, 249, 79, 225, 164, 135, 115, 230, 151, 203, 180, 67, 172, 149, 171, 254, 117, 172, 105, 92, 28, 221, 171, 108, 162, 179, 227, 22, 145, 176, 236, 134, 227, 11, 244, 255, 192, 128, 132, 75, 221, 245, 223, 3, 30, 43, 139, 171, 131, 73, 156, 77, 99, 13, 48, 240, 191, 198, 90, 95, 102, 130, 25, 129, 214, 90, 190, 153, 9, 10, 4, 239, 130, 159, 214, 13, 15, 250, 74, 146, 71, 72, 109, 18, 85, 54, 181, 165, 120, 144, 110, 38, 212, 167, 243, 163, 25, 248, 165, 152, 152, 22, 219, 52, 32, 214, 160, 19, 84, 34, 215, 77, 94, 179, 36, 160, 167, 200, 233, 88, 191, 251, 248, 227, 253, 106, 69, 111, 57, 99, 220, 81, 233, 24, 119, 132, 215, 190, 28, 210, 11, 135, 216, 159, 170, 140, 136, 99, 88, 219, 170, 8, 98, 85, 11, 196, 177, 127, 136, 22, 109, 122, 142, 181, 82, 19, 120, 105, 246, 220, 75, 44, 9, 175, 109, 156, 235, 31, 1, 232, 173, 130, 129, 164, 191, 41, 148, 85, 181, 78, 7, 49, 20, 245, 39, 5, 169, 157, 181, 219, 174, 210, 194, 142, 218, 120, 97, 27, 8, 170, 111, 49, 42, 31, 185, 43, 107, 117, 0, 247, 173, 67, 184, 74, 205]
```

We found seven lists matching our description. This makes sense because `cryptor.py` also created six other lists trying to throw us off:

```python
K1 = [random.randrange(0, 256, 1) for i in range(256)] 
K2 = [random.randrange(0, 256, 1) for i in range(256)] 
K3 = [random.randrange(0, 256, 1) for i in range(256)] 
K4 = [random.randrange(0, 256, 1) for i in range(256)] 
K5 = [random.randrange(0, 256, 1) for i in range(256)] 
K6 = [random.randrange(0, 256, 1) for i in range(256)] 
```

# RC4 Decryption from Internal State

After all this trouble, we have finally found what we are looking for: the internal state of the rc4 algorithm. Now is time to put that to use.

```python
def _keystream_generator(self):
    x = y = 0
    while True:
        x = (x + 1) & 0xff
        y = (self.S[x] + y) & 0xff
        self.S[x], self.S[y] = self.S[y], self.S[x]
        i = (self.S[x] + self.S[y]) & 0xff
        yield self.S[i]
```

Taking a look at the keystream generator, it is immediately clear that we need a way to find `x` and `y`.

```python
x = len(cipher) & 0xff
```

`x` is quite easy to find as it increments by one each time and we know the length of the cipher. `y` on the other hand take a bit more work to find.


Here's where another piece of random information turns out to be helpful:

```python
os.system("echo 0x3f > /proc/self/coredump_filter && python3.8 %s/cryptor.py %s/flag.png < input" % (curr_dir, curr_dir))
```

We know the file that got encrypted is originally a png image. This means it has to end with the byte `82`. What this allows us to do is to recover the last byte of the key stream and in turn help us find `y`:

```python
x = len(cipher) & 0xff

key_last = cipher[-1]^0x82
i = S.index(key_last)
if i < S[x]:
  i += 0x100
y = S.index(i - S[x])
```

With both `x` and `y`, we can start stepping backward and recover the full key stream:

```python
out_stream = []
for xxxx in range(len(cipher)):
  i = (S[x] + S[y]) & 0xff
  out_stream.append(S[i])
  S[x], S[y] = S[y], S[x]
  y = (y - S[x]) &0xff
  x = (x - 1) & 0xff
out_stream = out_stream[::-1]
```

Using this key stream, we can then decrypt the original file 🎉

{{< figure src="/blog/2020-07-27-cybrics-writeup/flag.png" >}}

flag: `cybrics{22a4cf1d90d67ae8ab6fb228d4cae06f66c4a945}`


# Closing

Overall, this is a very fun challenge to work on. I learned a lot about cpython internals, rec4 encryption, coredump analysis, and more. Huge thanks to the challenge author Egor Zaytsev (@groke) as well as all the CTF admins for making this experience possible!

If you want to read more about cpython internals, consider checking out my friend Lord_Idiot's awesome [writeup](https://blog.idiot.sg/2018-12-30/35c3-ctf-2018-collection/) on exploiting pymalloc.