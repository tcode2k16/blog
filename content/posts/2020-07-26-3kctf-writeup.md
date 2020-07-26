---
title: "3kCTF 2020 Writeup"
date: 2020-07-26T22:15:56+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  'pillow',
  'unity',
  'ILSpy'
]
description: My solves for 3kCTF 2020 challenges
---

# pyzzle1

## Problem

A puzzle be a game, problem, or toy dat tests a personz ingenuity or knowledge. In a puzzle, tha solver is sposed ta fuckin put pieces together up in a logical way, up in order ta arrive all up in tha erect or funk solution of tha puzzle.

[challenge](/blog/2020-07-26-3kctf-writeup/pyzzle.zip)


2nd flag : change it from 3K-text to 3k{text}

## Solution

By taking a look at the file and searching up some of the key terms like `SimpleStatementLine`, we quickly realize that the given file is a [LibCST](https://github.com/Instagram/LibCST) concrete syntax tree.

Some [documentation reading](https://libcst.readthedocs.io/en/latest/tutorial.html#Generate-Source-Code) reveals that by accessing `.code` on a syntax tree object, we can recover its source code.

Using this knowledge, I tweaked the file a bit:

```python
from libcst import *
abc = Module(
  ...
)
print(abc.code)
```

Running this edited file gives us the source code:

```python
import binascii

plaintext = "REDACTED"

def exor(a, b):
    temp = ""
    for i in range(n):
        if (a[i] == b[i]):
            temp += "0"
        else:
            temp += "1"
    return temp


def BinaryToDecimal(binary):
    string = int(binary, 2)
    return string

# encryption
PT_Ascii = [ord(x) for x in plaintext]

PT_Bin = [format(y, '08b') for y in PT_Ascii]
PT_Bin = "".join(PT_Bin)

n = 26936
K1 = '...'
K2 = '...'

L1 = PT_Bin[0:n]
R1 = PT_Bin[n::]

f1 = exor(R1, K1)
R2 = exor(f1, L1)
L2 = R1

f2 = exor(R2, K2)
R3 = exor(f2, L2)
L3 = R2

R3 = '...'
L3 = '...'
cipher = L3+R3

# decryption (redacted)
plaintext = L6+R6
plaintext = int(plaintext, 2)
plaintext = binascii.unhexlify('%x' % plaintext)
print(plaintext)
```

We can see that some xor operations have been performed on the original plaintext. We can walk backward and undo all those changes:

```python
R2 = L3
L2 = exor(exor(R3, R2), K2)

R1 = L2
L1 = exor(exor(K1, R1), R2)

plaintext = L1+R1
plaintext = int(plaintext, 2)
plaintext = binascii.unhexlify('%x' % plaintext)
plaintext = binascii.unhexlify(plaintext)
print(plaintext)
```

This yields the original file which contains our first flag:

```
33D32945 STP File, STP Format Version 1.0
SECTION Comment
Name "3k{almost_done_shizzle_up_my_nizzle}"
END

SECTION Graph
Nodes 144
Edges 116
E 1 2 1
...
END

SECTION Coordinates
DD 1 5 5
...
END

EOF
```

flag: `3k{almost_done_shizzle_up_my_nizzle}`

# pyzzle2

## Problem

A puzzle be a game, problem, or toy dat tests a personz ingenuity or knowledge. In a puzzle, tha solver is sposed ta fuckin put pieces together up in a logical way, up in order ta arrive all up in tha erect or funk solution of tha puzzle.

[challenge](/blog/2020-07-26-3kctf-writeup/pyzzle.zip)


2nd flag : change it from 3K-text to 3k{text}

## Solution

Continuing from where we [left off](#pyzzle1), we need a way to visualize the STP file.

The file itself is quite readable. It consists of three sections `Comment`, `Graph`, and `Coordinates`. The `Coordinates` describes points and the `Graph` tells us how to connect these points.

The line `DD 144 1845 105` likely means to define a point with the id of `144` and the xy coordinate of `(1845, 105)`

While a line like `E 29 30 1` tells us to draw a line between the point with id `29` and the point with id `30`

I hacked together a python script using PIL to draw out the image:

```python
from PIL import Image, ImageDraw


img = Image.new( 'RGB', (2000,200),color=(0,0,0))
draw = ImageDraw.Draw(img)

pixels = img.load()

edges = ['1 2','2 3','3 5','4 5','6 8','7 8','8 9','8 10','11 12','13 14','13 15','15 16','14 16','15 17','18 20','19 20','20 21','22 23','23 24','24 25','25 26','27 28','28 29','29 30','30 31','32 33','33 34','34 35','36 37','36 38','38 39','38 40','40 41','42 43','44 45','44 46','46 47','46 48','49 50','49 51','50 52','51 53','53 54','52 54','55 56','57 58','57 59','59 60','61 62','60 62','63 65','64 66','65 66','65 67','66 68','69 70','70 71','70 72','72 74','73 74','74 75','76 77','77 78','78 79','79 80','81 82','82 83','83 84','84 85','86 87','87 88','88 89','90 91','90 92','92 93','92 94','94 95','96 97','98 101','99 101','98 100','99 102','100 103','102 104','105 107','106 107','107 108','109 110','111 113','111 114','112 115','113 116','114 117','115 117','118 119','119 120','119 121','121 123','122 123','123 124','125 126','126 127','127 128','128 129','130 131','131 132','132 133','133 134','135 136','136 137','137 138','139 140','139 141','141 142','141 143','143 144']
edges = map(lambda x: map(int, x.split(' ')), edges)

print edges

points = ['1 5 5','2 55 5','3 5 55','4 5 105','5 55 105','6 65 5','7 115 5','8 65 55','9 65 105','10 115 105','11 125 55','12 175 55','13 185 5','14 235 5','15 185 55','16 235 55','17 185 105','18 245 5','19 295 5','20 270 55','21 270 105','22 355 5','23 405 5','24 380 55','25 355 105','26 405 105','27 415 5','28 465 5','29 440 55','30 415 105','31 455 105','32 475 5','33 475 55','34 475 105','35 525 105','36 535 5','37 585 5','38 535 55','39 585 55','40 535 105','41 585 105','42 595 105','43 645 105','44 655 5','45 705 5','46 655 55','47 705 55','48 655 105','49 715 5','50 765 5','51 715 55','52 765 55','53 715 105','54 765 105','55 775 105','56 825 105','57 835 5','58 885 5','59 835 55','60 885 55','61 835 105','62 885 105','63 895 5','64 945 5','65 895 55','66 945 55','67 895 105','68 945 105','69 955 5','70 980 5','71 1005 5','72 980 55','73 955 105','74 980 105','75 1005 105','76 1015 5','77 1065 5','78 1040 55','79 1015 105','80 1065 105','81 1075 5','82 1125 5','83 1100 55','84 1075 105','85 1125 105','86 1135 5 ','87 1135 55','88 1135 105','89 1185 105','90 1195 5','91 1245 5','92 1195 55','93 1245 55','94 1195 105','95 1245 105','96 1255 105','97 1305 105','98 1315 5','99 1365 5','100 1315 55','101 1340 55','102 1365 55','103 1315 55','104 1365 105','105 1375 5','106 1425 5','107 1400 55','108 1400 105','109 1435 105','110 1485 105','111 1495 5','112 1545 5','113 1495 5','114 1520 55','115 1545 55','116 1495 105','117 1545 105','118 1555 105','119 1580 5','120 1605 5','121 1580 55','122 1555 105','123 1580 105','124 1605 105','125 1615 5','126 1665 5','127 1640 5','128 1615 105','129 1665 105','130 1675 5','131 1725 5','132 1700 55','133 1675 105','134 1725 105','135 1735 5','136 1735 55','137 1735 105','138 1785 105','139 1795 5','140 1845 5','141 1795 55','142 1845 55','143 1795 105','144 1845 105']
points = map(lambda x: map(int, x.strip().split(' '))[1:], points)
print points

for each in edges:
  a,b = each
  p1 = points[a-1]
  p2 = points[b-1]
  draw.line([tuple(p1), tuple(p2)])

img.save('test.png')
```

This script is good enough to get us the second flag:

{{< figure src="/blog/2020-07-26-3kctf-writeup/pyzzle2.png" >}}

flag: `3k{PYZZLE_FO_SHIZZLE_MY_NIZZLE}`

# game 1

## Problem

find your way to the heart of the maze

challenge:

[For Windows](https://drive.google.com/file/d/1VHlnOdGuoIKPer_s2AV5-tQjOzaCQlyB/view)

[For Linux](/blog/2020-07-26-3kctf-writeup/Linux.zip)

flag format is different:
3K-string

## Solution

> The flags for game 1 and game 2 seem to be swapped during the competition, so the flag for game 1 in this writeup is submitted for game 2 and vice versa.

The game is a typical maze, and based on the description, we need to find a way to the center.


Using [uTinyRipper](https://github.com/mafaca/UtinyRipper) on `level0`, we are able to recover most of the game assets including the game scene.

Then by opening the scene in Unity, we can see the maze in its entirety:

{{< figure src="/blog/2020-07-26-3kctf-writeup/game1.png" >}}

Using this image as reference, we can travel to the center and obtain the first flag:


{{< figure src="/blog/2020-07-26-3kctf-writeup/game1-flag.png" >}}

flag: `3K-CTF-A-MAZE-ING`

# game 2

## Problem

the shortest route is often the best

challenge:

[For Windows](https://drive.google.com/file/d/1VHlnOdGuoIKPer_s2AV5-tQjOzaCQlyB/view)

[For Linux](/blog/2020-07-26-3kctf-writeup/Linux.zip)

flag format is different:
3K-string

## Solution

For this challenge, we need to look more into the game logic. To accomplish this, I used another tool called [ILSpy](https://github.com/icsharpcode/ILSpy).

Opening `Managed/Assembly-CSharp.dll`, we are able to see most of the game logic:

```c#
// CTF.GameManager
using UnityEngine;

private void OnTriggerEnter(Collider other)
{
	if (other.tag == "Box1")
	{
		if (isCollidingBox1)
		{
			return;
		}
		isCollidingBox1 = true;
		UiManager.current.UpdateTexte(Box1);
		Object.Destroy(other.gameObject);
	}
	if (other.tag == "Box2")
	{
		if (isCollidingBox2)
		{
			return;
		}
		isCollidingBox2 = true;
		UiManager.current.UpdateTexte(Box2);
		Object.Destroy(other.gameObject);
	}
	if (other.tag == "Box3")
	{
		if (isCollidingBox3)
		{
			return;
		}
		isCollidingBox3 = true;
		UiManager.current.UpdateTexte(Box3);
		Object.Destroy(other.gameObject);
	}
	if (other.tag == "Box4")
	{
		if (isCollidingBox4)
		{
			return;
		}
		isCollidingBox4 = true;
		UiManager.current.UpdateTexte(Box4);
		Object.Destroy(other.gameObject);
	}
	if (other.tag == "Box5")
	{
		if (isCollidingBox5)
		{
			return;
		}
		isCollidingBox5 = true;
		UiManager.current.UpdateTexte(Box5);
		Object.Destroy(other.gameObject);
	}
	if (other.tag == "Box6" && !isCollidingBox6)
	{
		isCollidingBox6 = true;
		UiManager.current.UpdateTexte(Box6);
		Object.Destroy(other.gameObject);
	}
}
```

```c#
// CTF.UiManager
public void UpdateTexte(string textToAdd)
{
	counter++;
	textHolder.text += textToAdd;
	if (counter == 6)
	{
		cText = Encrypt.current.DecryptString(textHolder.text);
		textHolder.text = cText;
	}
}
```

```c#
// CTF.Encrypt
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public string DecryptString(string key)
{
	byte[] array = Convert.FromBase64String(cipherText);
	using (Aes aes = Aes.Create())
	{
		Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(key, new byte[13]
		{
			73,
			118,
			97,
			110,
			32,
			77,
			101,
			100,
			118,
			101,
			100,
			101,
			118
		});
		aes.Key = rfc2898DeriveBytes.GetBytes(32);
		aes.IV = rfc2898DeriveBytes.GetBytes(16);
		try
		{
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
				{
					cryptoStream.Write(array, 0, array.Length);
					cryptoStream.Close();
				}
				cipherText = Encoding.Unicode.GetString(memoryStream.ToArray());
			}
			return cipherText;
		}
		catch (Exception)
		{
			return "wrong Order mate ";
		}
	}
}
```

By reading the code, we see that the player is able to append six different words to a string in various orders by hitting different boxes in the maze. The concatenated string is then used as a key to decrypt a cipher message yielding the flag.

To recover the six words and the ciphertext, we can do a simple `strings` or `xxd` on the `level0` asset file:

words:

- `Tanit`
- `Astarté`
- `Amilcar`
- `Melqart`
- `Dido`
- `Hannibal`

ciphertext

- `jR9MDCzkFQFzZtHjzszeYL1g6kG9+eXaATlf0wCGmnf62QJ9AjmemY0Ao3mFaubhEfVbXfeRrne/VAD59ESYrQ==`

At this point, a brute force script should be able to yield the flag, but for some reason, it did not work for me.

In a hopeful attempt, I marked out all the box locations and played the game hitting each of them in the shortest path. Luckily, it worked and gave me the flag...


{{< figure src="/blog/2020-07-26-3kctf-writeup/game2-maze.jpg" >}}

> order: `Hannibal --> Dido --> Melqart --> Amilcar --> Astarté --> Tanit`


flag: `3K-CTF-GamingIsNotACrime`