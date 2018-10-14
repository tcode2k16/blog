---
title: "PicoCTF 2018 Writeup: General Skills"
date: 2018-10-13T08:56:01+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  "picoctf"
]
description: solves for picoCTF 2018 General Skills challenges
---

# General Warmup 1

## Problem

If I told you your grade was 0x41 in hexadecimal, what would it be in ASCII?

## Solution

This is a basic introduction to ASCII codes. If you have not memorized that `0x41` is `A` in ASCII (which you should), you can use python to find it:

```
>>> chr(0x41)
'A'
```

flag: `picoCTF{A}`

# General Warmup 2

## Problem

Can you convert the number 27 (base 10) to binary (base 2)?

## Solution

You can learn more about base 2 numbers over [here](https://en.wikipedia.org/wiki/Binary_number). Other than doing this challenge by hand, you can also solve it using python:

```
>>> bin(27)
'0b11011'
```

flag: `picoCTF{11011}`

# General Warmup 3

## Problem

What is 0x3D (base 16) in decimal (base 10).

## Solution

Base 16, base 2, and base 10 are the three most important base in computer science and CTF problems. You can solve this problem both by hand or using python:

```
>>> 0x3d
61
```

flag: `picoCTF{61}`

# Resources

## Problem

We put together a bunch of resources to help you out on our website! If you go over there, you might even find a flag! https://picoctf.com/resources ([link](https://picoctf.com/resources))

## Solution

Just go to the website.

flag: `picoCTF{xiexie_ni_lai_zheli}`

> side note: this flag is in Chinese, and it means "Thanks for being here".

# grep 1

## Problem

Can you find the flag in [file](/blog/picoctf-2018-writeup/General Skills/grep 1/file)? This would be really obnoxious to look through by hand, see if you can find a faster way. You can also find the file in /problems/grep-1_2_ee2b29d2f2b29c65db957609a3543418 on the shell server.

## Solution

This problem introduces a helpful command line tool called `grep`. The tool helps you search for text in a file, and here is how you use it:

```
❯ cat file | grep pico
picoCTF{grep_and_you_will_find_52e63a9f}
```

The command above basically prints out the content of the file, pipe it through a filter (`grep`), and only shows the lines that include the text `pico` in it which gives us the flag. Learn more about pipes in bash [here](http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO-4.html).

flag: `picoCTF{grep_and_you_will_find_52e63a9f}`

# net cat

## Problem

Using netcat (nc) will be a necessity throughout your adventure. Can you connect to `2018shell2.picoctf.com` at port `22847` to get the flag?

## Solution

This challenge introduces another useful command line tool called `nc` (netcat). This command, as the name implies, print out the content of a connection between the host and another server. Here is how you can use it:

```
❯ nc 2018shell2.picoctf.com 22847
That wasn't so hard was it?
picoCTF{NEtcat_iS_a_NEcESSiTy_69222dcc}
```

flag: `picoCTF{NEtcat_iS_a_NEcESSiTy_69222dcc}`

# strings

## Problem

Can you find the flag in this [file](/blog/picoctf-2018-writeup/General Skills/strings/strings) without actually running it? You can also find the file in /problems/strings_4_40d221755b4a0b134c2a7a2e825ef95f on the shell server.

## Solution

As the problem name implies, you have to use the command line tool called `strings` to solve this challenge. This command prints out all the human readable text from a file. Here is how you can use it:

```
❯ strings strings | grep pico
picoCTF{sTrIngS_sAVeS_Time_d7c8de6c}
```

Read my solution for [grep 1](#grep-1) if you don't understand the `| grep pico` part.

flag: `picoCTF{sTrIngS_sAVeS_Time_d7c8de6c}`

# pipe

## Problem

During your adventure, you will likely encounter a situation where you need to process data that you receive over the network rather than through a file. Can you find a way to save the output from this program and search for the flag? Connect with `2018shell2.picoctf.com 44310`.

## Solution

Read my solution for [grep 1](#grep-1) if you don't know `grep` and [net cat](#net-cat) if you don't know `nc`.

This problem basically combines what we learned in the first few challenges. Here is how you can solve it:

```
❯ nc 2018shell2.picoctf.com 44310 | grep pico
picoCTF{almost_like_mario_a13e5b27}
```

flag: `picoCTF{almost_like_mario_a13e5b27}`

# grep 2

## Problem

This one is a little bit harder. Can you find the flag in /problems/grep-2_2_413a577106278d0711d28a98f4f6ac28/files on the shell server? Remember, grep is your friend.

## Solution

This is the same as [grep 1](#grep-1), but you now have to print more files. Here is how you can solve it:

```
alanc@pico-2018-shell-2:/problems/grep-2_2_413a577106278d0711d28a98f4f6ac28/files$ cat */* | grep pico
picoCTF{grep_r_and_you_will_find_8eb84049}
```

The `*/*` means to print out all the files in the current directory recursively. 

flag: `picoCTF{grep_r_and_you_will_find_8eb84049}`

# Aca-Shell-A

## Problem

It's never a bad idea to brush up on those linux skills or even learn some new ones before you set off on this adventure! Connect with `nc 2018shell2.picoctf.com 33158`.

## Solution

This is just a summary of the past few challenges and introduces a few new command to you.

Here is a walk-through of the whole process:

```none
❯ nc 2018shell2.picoctf.com 33158
Sweet! We have gotten access into the system but we aren't root.
It's some sort of restricted shell! I can't see what you are typing
but I can see your output. I'll be here to help you along.
If you need help, type "echo 'Help Me!'" and I'll see what I can do
There is not much time left!

~/$ ls
blackmail
executables
passwords
photos
secret
~/$ cd secret
Now we are cookin'! Take a look around there and tell me what you find!
~/secret$ ls
intel_1
intel_2
intel_3
intel_4
intel_5
profile_AipieG5Ua9aewei5ieSoh7aph
profile_Xei2uu5suwangohceedaifohs
profile_ahShaighaxahMooshuP1johgo
profile_ahqueith5aekongieP4ahzugi
profile_aik4hah9ilie9foru0Phoaph0
profile_bah9Ech9oa4xaicohphahfaiG
profile_ie7sheiP7su2At2ahw6iRikoe
profile_of0Nee4laith8odaeLachoonu
profile_poh9eij4Choophaweiwev6eev
profile_poo3ipohGohThi9Cohverai7e
Sabatoge them! Get rid of all their intel files!
~/secret$ rm int*
Nice! Once they are all gone, I think I can drop you a file of an exploit!
Just type "echo 'Drop it in!' " and we can give it a whirl!
~/secret$ echo 'Drop it in!'
Drop it in!
I placed a file in the executables folder as it looks like the only place we can execute from!
Run the script I wrote to have a little more impact on the system!
~/secret$ cd ..
~/$ ls
blackmail
executables
passwords
photos
secret
~/$ cd executables
~/executables$ ls
dontLookHere
~/executables$ ./dontLookHere
 cf69 a945 2efc 049b c832 b41f b76f f57e 9e0a 3275 d297 e0b0 7a9a b2c8 c64a 8150 5d5b ccd4 2d68 eed4 4111 abc2 aeb0 f650 f489
 5e42 49d2 0b85 7627 a089 db3f 3788 0d72 3ee6 e1e1 295d a61b 6ce6 b4f4 26e5 0c19 af21 94f7 5f22 e213 7176 53ea d99d c44c f9d7
 571f 031f 43ec c803 9200 d377 b04f e0da 3ae0 b741 4e61 e11e 6c3b 4c73 bc18 2f92 fc7b c406 9e40 c5e9 47c9 f67c 8bb1 0d4c 80db
 65a8 f775 e505 cec5 9d90 4f23 d382 788a f3a9 deb8 e83d ae83 c136 d390 651d b58c 734f 02c0 1cf3 f5dc 160f 6eab 505b 3f7f 3567
 50f7 0feb cc71 4051 1395 15bf 659b 1595 d70f 711e d699 2c71 f68f 50fe 145b eed4 32ae 725e e0b3 3a28 2d5f 86f2 0d15 922a 8515
 52a6 9f7f 2901 09d2 00b9 88a4 af8a 01ab 00d4 363a 010f 0cf9 180a b9a6 f3fe beb2 3317 90e1 3cd1 2027 0548 ba3d 9139 b591 4ea5
 8fcc 7ef9 1f01 2980 d036 8ac4 a322 834a a1b8 f648 53fc e2cf 5c97 0a3c 2527 eb74 f478 ba32 a253 8086 e93d 0cb2 58ae bbca 287d
 b835 48fe 1ff5 b0f9 46ca e08d 1893 382c 47f7 2a4f 21cd 1d22 aad0 97f8 c38d ceaa 3c74 f421 a7f6 4b1c 270a 7798 f7b0 45d3 8529
 3994 2d68 4cc5 8690 628f 292b a742 d795 b2f4 6e5d 1bb5 4bed 34cc 4f6d 3d04 8509 50a6 8185 3114 7bb9 c093 b626 97fa ada0 1a91
 5769 ecaf 3e3a bc69 e73e 171a 3fa1 82f7 bf41 f9df cf19 a428 d2ee 595d f1a9 0511 201f e950 cdba ab22 0f5a b270 85aa 9940 aa4b
 7d11 bcbe 8b0c 6742 729c cca0 f4ea 2077 bf4c 812b 18fa 1209 ddd2 8103 061f 21f2 c765 7479 fecc c6e8 aa92 95b8 25ef ce2c a103
 0921 f65a c332 8782 d6d4 2d15 3947 15cd dd67 2e8c 8bbd e946 9399 8357 6432 182e 2b89 92ea c1f2 8b09 22a6 1946 8e66 4b19 81b1
 8be0 35be 3893 508b 0330 b7b0 fbe5 40a5 8b7c 29f3 20bb 925c abc7 24f2 1eda 02f0 d063 66dc 4e24 4d7b b7c1 4783 3472 e887 d9c6
 8a39 f0a6 d38f c58f 6499 c3c5 6f40 e9b6 e912 31e8 1854 5ffb 0068 41b7 c628 d9fa a2ad a2a5 6012 a468 9fcd 890a 5f2e f480 2231
 27fe b6e8 da5b 14a9 4f3e fc4f 15b8 0b47 a1de a573 3c89 2c3e c623 b173 1225 85e3 f556 9e63 22ef 07af d680 97f0 019f a9d8 1e1b
 08da 4271 9d8b 2308 e434 b51a e0c9 f045 a08a c2bf 2cf2 b91e 51f0 8097 967e cacb 78a9 5ef3 bbb7 ca13 9388 f61f abff bf47 a1ae
 4130 e52d 2cce 304d 981a a70e c224 b182 ee1f 1759 b47b 99f7 1b30 11cf 77c5 0945 82e1 9023 babf 5676 1658 a4d4 72af a559 e806
 70f3 0eaa c313 3ddf 9a88 b84e 1c75 483f 20f5 ed2f a56d f132 ec15 e63c 6da0 078a e1b4 1562 a0ac d22d d5cf 8bca 1a6c 9d11 53f4
 a17f 49f4 9cbe 3d14 5a08 227d f25f b797 1ea6 1432 33d3 5e3d e6ba 1ed6 14ab 30b5 1d5f 246b 20ee 9d55 5d65 d0d8 1182 be0d c9b0
 00ea b594 cd44 7ac4 d171 52d4 e84c 4c09 c1c4 3acb 8ed5 dabf 6ccd e114 cd12 a810 d935 8a93 cdd5 d385 5b09 c872 9025 75d1 b78e
 989c e635 7f52 bebf c6a5 7ded a1be 9e4c 7b13 7cad e89b 38e5 1525 c675 0c3c e220 0fd5 40ad d8e7 f5bb f3d6 faa7 1015 ba04 9d0c
 26a7 de49 745f 19dd acd1 baa2 d90d 1b97 223d d9fb 4165 a388 8467 88d8 9111 5b36 4360 c277 44af ea3e 936a 48b1 bd50 b8a9 6bf8
 cb9f d283 8c48 5895 d193 197b 9aba b7d0 673e af37 5d56 8aec 4972 6ac2 6882 81a8 24e7 56a9 db6e f46b 413c 9a59 3977 0af7 38f3
 c889 01ed 9c61 8113 4320 3ae1 71ce aaba 90da e360 d63a d166 7372 848a a34c d0a9 df1d 71a3 8d50 aebb 090a 5982 276f 5f6e bb83
 d4b9 92d5 fb9a aa26 405c 5570 ec22 2554 108b 1ed4 acb3 9e7a 98f8 10fc dadd 2606 d038 f2cb 8264 f816 9283 5209 6a25 9e9a 886a
 4d32 6fc1 31f3 69a0 2492 a18e 00bd 227d a917 5823 14bc c373 9f32 46b2 4bc5 e820 7b24 0c6e 4dce dcce 5827 cd7b a0d9 b5fd 8156
 e545 e098 b896 2f77 be76 4307 51bb 35b2 a32f 71cc f454 1c49 2467 7a82 1044 0c2b 3f84 08db 4c9a f1e9 bcf2 3374 c125 41da 2b18
 c5f6 fb5d 2717 53d5 0385 ed7a f40c e91d 8881 432d 687c 6832 010f da13 a7d9 4e85 0bfe 66ed 50f0 cfd8 e24e fb93 c6e4 0edd b3af
 ba54 ee13 f127 e3a3 0730 33f1 f302 f810 d1b0 d7d7 e1ba b243 6af1 cb9f f6c3 e489 0148 62a5 f6e0 4932 651a c1dc ee88 e2e0 fd47
Looking through the text above, I think I have found the password. I am just having trouble with a username.
Oh drats! They are onto us! We could get kicked out soon!
Quick! Print the username to the screen so we can close are backdoor and log into the account directly!
You have to find another way other than echo!
~/executables$ whoami
l33th4x0r
Perfect! One second!
Okay, I think I have got what we are looking for. I just need to to copy the file to a place we can read.
Try copying the file called TopSecret in tmp directory into the passwords folder.
~/executables$ cp /tmp/TopSecret ../passwords
Server shutdown in 10 seconds...
Quick! go read the file before we lose our connection!
~/executables$ cd ..
~/$ cd passwords
~/passwords$ ls
TopSecret
~/passwords$ cat TopSecret
Major General John M. Schofield's graduation address to the graduating class of 1879 at West Point is as follows: The discipline which makes the soldiers of a free country reliable in battle is not to be gained by harsh or tyrannical treatment.On the contrary, such treatment is far more likely to destroy than to make an army.It is possible to impart instruction and give commands in such a manner and such a tone of voice as to inspire in the soldier no feeling butan intense desire to obey, while the opposite manner and tone of voice cannot fail to excite strong resentment and a desire to disobey.The one mode or other of dealing with subordinates springs from a corresponding spirit in the breast of the commander.He who feels the respect which is due to others, cannot fail to inspire in them respect for himself, while he who feels,and hence manifests disrespect towards others, especially his subordinates, cannot fail to inspire hatred against himself.
picoCTF{CrUsHeD_It_9edaa84a}
```

flag: `picoCTF{CrUsHeD_It_9edaa84a}`

# environ

## Problem

Sometimes you have to configure environment variables before executing a program. Can you find the flag we've hidden in an environment variable on the shell server?

## Solution

This is an introduction to environment variables in bash. We can solve this problem in many ways. Here is how I solved it:

```
alanc@pico-2018-shell-2:~$ cat /proc/self/environ
SECRET_FLAG=picoCTF{eNv1r0nM3nT_v4r14Bl3_fL4g_3758492}FLAG=Finding the flag wont be that easy...TERM=xterm-256colorSHELL=/bin/bashSSH_CLIENT=203.211.155.38 59174 22OLDPWD=/problems/grep-2_2_413a577106278d0711d28a98f4f6ac28/filesSSH_TTY=/dev/pts/60USER=alancLS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:MAIL=/var/mail/alancPATH=/home/alanc/bin:/home/alanc/.local/bin:/home/alanc/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/binPWD=/home/alancLANG=en_US.UTF-8SHLVL=1HOME=/home/alancPICOCTF_FLAG=Nice try... Keep looking!LOGNAME=alancXDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktopSSH_CONNECTION=203.211.155.38 59174 172.31.32.197 22LC_CTYPE=en_US.UTF-8LESSOPEN=| /usr/bin/lesspipe %sLESSCLOSE=/usr/bin/lesspipe %s %s_=/bin/cat
```

Here, I dumped the content of the file `/proc/self/environ` which contains all the environment variables.

flag: `picoCTF{eNv1r0nM3nT_v4r14Bl3_fL4g_3758492}`

# ssh-keyz

## Problem

As nice as it is to use our webshell, sometimes its helpful to connect directly to our machine. To do so, please add your own public key to ~/.ssh/authorized_keys, using the webshell. The flag is in the ssh banner which will be displayed when you login remotely with ssh to with your username.

## Solution

This problem can be solved without even setting up the ssh keys. You can just do `ssh USERNAME@2018shell2.picoctf.com` and the flag will be given to you.

If you do want to learn how to add your own ssh keys, you can watch this [video](https://www.youtube.com/watch?v=3CN65ccfllU&list=PLJ_vkrXdcgH-lYlRV8O-kef2zWvoy79yP&index=4) or use a tool such as `ssh-copy-id`.

flag: `picoCTF{who_n33ds_p4ssw0rds_38dj21}`

# what base is this?

## Problem

To be successful on your mission, you must be able read data represented in different ways, such as hexadecimal or binary. Can you get the flag from this program to prove you are ready? Connect with `nc 2018shell2.picoctf.com 1225`.

## Solution

This problem is about the different number bases. Although it is possible to solve this one by hand, it is a lot easier to just write a script to do it. I used python and this CTF library called [pwntools](https://github.com/Gallopsled/pwntools) to write my solution:

```python
from pwn import *

sh = remote('2018shell2.picoctf.com', 1225)

# bin to string
data = sh.recvuntil('Input:\n').split('\n')[-4][19:-11]
sh.sendline(unbits(data.replace(' ', '')))

# hex to string
data = sh.recvuntil('Input:\n').split('\n')[-3][19:-11]
sh.sendline(unhex(data))

# oct to string
data = sh.recvuntil('Input:\n').split('\n')[-3][20:-11]
data = ''.join([chr(int(x, 8)) for x in data.split(' ')])
sh.sendline(data)

print sh.recvall()
```

flag: `picoCTF{delusions_about_finding_values_451a9a74}`

# you can't see me

## Problem

'...reading transmission... Y.O.U. .C.A.N.'.T. .S.E.E. .M.E. ...transmission ended...' Maybe something lies in /problems/you-can-t-see-me_2_cfb71908d8368e3062423b45959784aa.

## Solution

First, we can use `ls -al` to list all files including the hidden ones that start with a `.`:

```bash
alanc@pico-2018-shell-2:/problems/you-can-t-see-me_2_cfb71908d8368e3062423b45959784aa$ ls -al
total 60
drwxr-xr-x   2 root       root        4096 Sep 28 08:34 .
-rw-rw-r--   1 hacksports hacksports    57 Sep 28 08:34 .
drwxr-x--x 576 root       root       53248 Sep 30 03:50 ..
```

As you can see, there is, in fact, a hidden file. We can read the file using `cat`, and the tab completion with just give us the filename as it is the only file in this directory:

```bash
alanc@pico-2018-shell-2:/problems/you-can-t-see-me_2_cfb71908d8368e3062423b45959784aa$ cat .\ \
picoCTF{j0hn_c3na_paparapaaaaaaa_paparapaaaaaa_093d6aff}
```

flag: `picoCTF{j0hn_c3na_paparapaaaaaaa_paparapaaaaaa_093d6aff}`

# absolutely relative

## Problem

In a filesystem, everything is relative ¯\_(ツ)_/¯. Can you find a way to get a flag from this [program](/blog/picoctf-2018-writeup/General Skills/absolutely relative/absolutely-relative)? You can find it in /problems/absolutely-relative_0_d4f0f1c47f503378c4bb81981a80a9b6 on the shell server. [Source](/blog/picoctf-2018-writeup/General Skills/absolutely relative/absolutely-relative.c).

## Solution

Let's first look at the source code:

```c
#include <stdio.h>
#include <string.h>

#define yes_len 3
const char *yes = "yes";

int main()
{
    char flag[99];
    char permission[10];
    int i;
    FILE * file;


    file = fopen("/problems/absolutely-relative_0_d4f0f1c47f503378c4bb81981a80a9b6/flag.txt" , "r");
    if (file) {
    	while (fscanf(file, "%s", flag)!=EOF)
    	fclose(file);
    }   
	
    file = fopen( "./permission.txt" , "r");
    if (file) {
    	for (i = 0; i < 5; i++){
            fscanf(file, "%s", permission);
        }
        permission[5] = '\0';
        fclose(file);
    }
    
    if (!strncmp(permission, yes, yes_len)) {
        printf("You have the write permissions.\n%s\n", flag);
    } else {
        printf("You do not have sufficient permissions to view the flag.\n");
    }
    
    return 0;
}
```

As you can see, there's a difference in how the two paths are written. The flag path here is a absolute path as it points to the same file regardless of which directory you are in. On the other hand, the path of the permission file is relative as it point to different files depending on which directory you are in.

To solve this problem, we can go to another directory, create a fake `permission.txt`, and then run the program from that location.

```
alanc@pico-2018-shell-2:~$ echo "yes" > permission.txt
alanc@pico-2018-shell-2:~$ /problems/absolutely-relative_0_d4f0f1c47f503378c4bb81981a80a9b6/absolutely-relative
You have the write permissions.
picoCTF{3v3r1ng_1$_r3l3t1v3_befc0ce1}
```

flag: `picoCTF{3v3r1ng_1$_r3l3t1v3_befc0ce1}`

# in out error

## Problem

Can you utlize stdin, stdout, and stderr to get the flag from this [program](/blog/picoctf-2018-writeup/General Skills/in out error/in-out-error)? You can also find it in /problems/in-out-error_1_24ebc7186086f0f9a710de008628c561 on the shell server

## Solution

This problem introduces the three standard streams: stdin (0), stdout (1), and stderr (2). We can redirect these streams to get the flag. Here is how it can be done in bash:

```
alanc@pico-2018-shell-2:/problems/in-out-error_1_24ebc7186086f0f9a710de008628c561$ echo "Please may I have the flag?" | ./in-out-error 1>/dev/null 2>~/flag
alanc@pico-2018-shell-2:/problems/in-out-error_1_24ebc7186086f0f9a710de008628c561$ cat ~/flag
picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}picoCTF{p1p
```

flag: `picoCTF{p1p1ng_1S_4_7h1ng_7b9360ca}`

# learn gdb

## Problem

Using a debugging tool will be extremely useful on your missions. Can you run this [program](/blog/picoctf-2018-writeup/General Skills/learn gdb/run) in gdb and find the flag? You can find the file in /problems/learn-gdb_4_2ca642e0eb4e21999bb1e6650342e545 on the shell server.

## Solution

This is an introduction to the debuging tool `gdb`, but I decided to change up a bit and solve this problem using another tool called [radare2](https://rada.re/r/). Here is how I did it with `r2`:

```
$ r2 ./run
 -- Step through your seek history with the commands 'u' (undo) and 'U' (redo)
[0x00400690]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[0x00400690]> s main
[0x004008c9]> pdf
            ;-- main:
/ (fcn) sym.main 82
|   sym.main (int argc, char **argv, char **envp);
|           ; var char **local_10h @ rbp-0x10
|           ; var int local_4h @ rbp-0x4
|           ; arg int argc @ rdi
|           ; arg char **argv @ rsi
|           ; DATA XREF from entry0 (0x4006ad)
|           0x004008c9      55             push rbp
|           0x004008ca      4889e5         mov rbp, rsp
|           0x004008cd      4883ec10       sub rsp, 0x10
|           0x004008d1      897dfc         mov dword [local_4h], edi   ; argc
|           0x004008d4      488975f0       mov qword [local_10h], rsi  ; argv
|           0x004008d8      488b05f90a20.  mov rax, qword [sym.stdout] ; obj.stdout ; [0x6013d8:8]=0
|           0x004008df      b900000000     mov ecx, 0                  ; size_t size
|           0x004008e4      ba02000000     mov edx, 2                  ; int mode
|           0x004008e9      be00000000     mov esi, 0                  ; char *buf
|           0x004008ee      4889c7         mov rdi, rax                ; FILE*stream
|           0x004008f1      e85afdffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
|           0x004008f6      bfd0094000     mov edi, str.Decrypting_the_Flag_into_global_variable__flag_buf ; 0x4009d0 ; "Decrypting the Flag into global variable 'flag_buf'" ; const char *s
|           0x004008fb      e800fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400900      b800000000     mov eax, 0
|           0x00400905      e87cfeffff     call sym.decrypt_flag
|           0x0040090a      bf080a4000     mov edi, str.Finished_Reading_Flag_into_global_variable__flag_buf_._Exiting. ; 0x400a08 ; "Finished Reading Flag into global variable 'flag_buf'. Exiting." ; const char *s
|           0x0040090f      e8ecfcffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400914      b800000000     mov eax, 0
|           0x00400919      c9             leave
\           0x0040091a      c3             ret
[0x004008c9]> ood
Process with PID 2150 started...
File dbg:///home/node/tmp/run  reopened in read-write mode
= attach 2150 2150
2150
[0x7f1718226090]> db 0x0040090a
[0x7f1718226090]> dc
Decrypting the Flag into global variable 'flag_buf'
.....................................
hit breakpoint at: 40090a
[0x0040090a]> pdf @ sym.decrypt_flag
/ (fcn) sym.decrypt_flag 323
|   sym.decrypt_flag ();
|           ; var int local_24h @ rbp-0x24
|           ; var int local_20h @ rbp-0x20
|           ; var signed int local_1ch @ rbp-0x1c
|           ; var long local_18h @ rbp-0x18
|           ; var char *str @ rbp-0x10
|           ; var int local_fh @ rbp-0xf
|           ; var int local_eh @ rbp-0xe
|           ; var int canary @ rbp-0x8
|           ; CALL XREF from sym.main (0x400905)
|           0x00400786      55             push rbp
|           0x00400787      4889e5         mov rbp, rsp
|           0x0040078a      4883ec30       sub rsp, 0x30               ; '0'
|           0x0040078e      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=-1 ; '(' ; 40
|           0x00400797      488945f8       mov qword [canary], rax
|           0x0040079b      31c0           xor eax, eax
|           0x0040079d      bf2f000000     mov edi, 0x2f               ; '/' ; 47 ; size_t size
|           0x004007a2      e899feffff     call sym.imp.malloc         ;  void *malloc(size_t size)
|           0x004007a7      4889053a0c20.  mov qword obj.flag_buf, rax ; [0x6013e8:8]=0x848260 ; "`\x82\x84"
|           0x004007ae      488b05330c20.  mov rax, qword obj.flag_buf ; [0x6013e8:8]=0x848260 ; "`\x82\x84"
|           0x004007b5      4885c0         test rax, rax
|       ,=< 0x004007b8      7514           jne 0x4007ce
|       |   0x004007ba      bfa8094000     mov edi, str.malloc___returned_NULL._Out_of_Memory ; 0x4009a8 ; "malloc() returned NULL. Out of Memory\n" ; const char *s
|       |   0x004007bf      e83cfeffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x004007c4      bfffffffff     mov edi, 0xffffffff         ; -1 ; int status
|       |   0x004007c9      e892feffff     call sym.imp.exit           ; void exit(int status)
|       |   ; CODE XREF from sym.decrypt_flag (0x4007b8)
|       `-> 0x004007ce      c645f200       mov byte [local_eh], 0
|           0x004007d2      c745dc020000.  mov dword [local_24h], 2
|           0x004007d9      c745e0000000.  mov dword [local_20h], 0
|           0x004007e0      c745e4000000.  mov dword [local_1ch], 0
|       ,=< 0x004007e7      e99d000000     jmp 0x400889
|       |   ; CODE XREF from sym.decrypt_flag (0x400890)
|      .--> 0x004007ec      bf2e000000     mov edi, 0x2e               ; '.' ; 46 ; int c
|      :|   0x004007f1      e8fafdffff     call sym.imp.putchar        ; int putchar(int c)
|      :|   0x004007f6      bf90d00300     mov edi, 0x3d090
|      :|   0x004007fb      b800000000     mov eax, 0
|      :|   0x00400800      e86bfeffff     call sym.imp.usleep
|      :|   0x00400805      8b45e4         mov eax, dword [local_1ch]
|      :|   0x00400808      4898           cdqe
|      :|   0x0040080a      0fb680801060.  movzx eax, byte [rax + str.45_uL3EmN__38dDTWA44rau4lQ18__.E__y29g2lsd3O11ByMNf_z8J850Ut_kjNV_.43Cy9oM_W_I1Oj19uZxK6RtU_QS:37j_g_AX_J1n_h134ict_G__TMHxX__3E_Bbj_SP__2jnwj_28s4n2CVg_oe_5_CML34vHw4Uu_KPT___vQI248z5MPq6_i4V__xvSEo_2ATn___pE_iL_1xyIuiqA45dUc_upguw_y.al4T_1n408ta_x5hvdGnRD_Z_0Rb_._47Anu.Rd_n_aH_VKO:I_El:_34_vtqK1__FUsK2TH_Fyk_trK4AEXTlYe1_Br5LNKI_6UBSP00N0A_st_DJOq____Fw0:n___r_G_708_xESNtBajDj_3u_VRXz___HoOg3B__rZN.gM3_l_TAe8cvLG__pb_7u4AVfGG9Aw0m_UvT__J___w_C_Pf_d_21wn072_bjewbm__wVjV___u4_M7z__34xR___acLI_Ln56y:JJQd..C_EI__rp0EHE.z__BesQSq:OIxlh_qA6__r_b_Xo_3Bkyc_yFt9oUAr0O_U_x_4fkR____Vrg_B361rBe__mp.IEr_ew_LkjSb_ald5S4Ki_Iw0B.Nf6__Tt__rL____V__w_S_L_jJh__5_U_38S80T___w___tSEF_OvLw__X0z2_YonQ__:80CR_5_QFfj_9T_dH2b_qI2bfMusf3utdxiO_3_063CDH6c_GaDX:P_JWUI4n__zzikKID_B8FRl_O39C__423_Z__s91ZHYTok7TCWVjP_6_rs___Q_JO52ET7_9b2_ig_Z_tC__kqQF__vgs__VF_65P4___R] ; obj.enc_buf ; [0x601080:1]=52 ; "45>uL3EmN[/38dDTWA44rau4lQ18!@.E,,y29g2lsd3O11ByMNf[z8J850Ut^kjNV$.43Cy9oM+W_I1Oj19uZxK6RtU!QS:37j@g|AX*J1n+h134ict$G>_TMHxX|@3E+Bbj SP|&2jnwj%28s4n2CVg_oe_5/CML34vHw4Uu[KPT`~+vQI248z5MPq6]i4V% xvSEo;2ATn]*<pE(iL<1xyIuiqA45dUc;upguw?y.al4T_1n408ta`x5hvdGnRD(Z>0Rb|./47Anu.Rd)n%aH,VKO:I(El:#34>vtqK1[@FUsK2TH#Fyk`trK4AEXTlYe1!Br5LNKI,6UBSP00N0A)st~DJOq%-/[Fw0:n|(|r@G)708 xESNtBajDj 3u%VRXz?/_HoOg3B;]rZN.gM3)l$TAe8cvLG$)pb+7u4AVfGG9Aw0m-UvT@|J)(~w%C)Pf]d)21wn072+bjewbm/-wVjV $@u4,M7z)_34xR;+/acLI^Ln56y:JJQd..C;EI-|rp0EHE.z*=BesQSq:OIxlh=qA6>]r?b<Xo 3Bkyc~yFt9oUAr0O[U)x;4fkR&^"
|      :|   0x00400811      8845f0         mov byte [str], al
|      :|   0x00400814      0fb645f0       movzx eax, byte [str]
|      :|   0x00400818      3c30           cmp al, 0x30                ; '0' ; 48
|     ,===< 0x0040081a      7518           jne 0x400834
|     |:|   0x0040081c      8b45e4         mov eax, dword [local_1ch]
|     |:|   0x0040081f      83c001         add eax, 1
|     |:|   0x00400822      4898           cdqe
|     |:|   0x00400824      0fb680801060.  movzx eax, byte [rax + str.45_uL3EmN__38dDTWA44rau4lQ18__.E__y29g2lsd3O11ByMNf_z8J850Ut_kjNV_.43Cy9oM_W_I1Oj19uZxK6RtU_QS:37j_g_AX_J1n_h134ict_G__TMHxX__3E_Bbj_SP__2jnwj_28s4n2CVg_oe_5_CML34vHw4Uu_KPT___vQI248z5MPq6_i4V__xvSEo_2ATn___pE_iL_1xyIuiqA45dUc_upguw_y.al4T_1n408ta_x5hvdGnRD_Z_0Rb_._47Anu.Rd_n_aH_VKO:I_El:_34_vtqK1__FUsK2TH_Fyk_trK4AEXTlYe1_Br5LNKI_6UBSP00N0A_st_DJOq____Fw0:n___r_G_708_xESNtBajDj_3u_VRXz___HoOg3B__rZN.gM3_l_TAe8cvLG__pb_7u4AVfGG9Aw0m_UvT__J___w_C_Pf_d_21wn072_bjewbm__wVjV___u4_M7z__34xR___acLI_Ln56y:JJQd..C_EI__rp0EHE.z__BesQSq:OIxlh_qA6__r_b_Xo_3Bkyc_yFt9oUAr0O_U_x_4fkR____Vrg_B361rBe__mp.IEr_ew_LkjSb_ald5S4Ki_Iw0B.Nf6__Tt__rL____V__w_S_L_jJh__5_U_38S80T___w___tSEF_OvLw__X0z2_YonQ__:80CR_5_QFfj_9T_dH2b_qI2bfMusf3utdxiO_3_063CDH6c_GaDX:P_JWUI4n__zzikKID_B8FRl_O39C__423_Z__s91ZHYTok7TCWVjP_6_rs___Q_JO52ET7_9b2_ig_Z_tC__kqQF__vgs__VF_65P4___R] ; obj.enc_buf ; [0x601080:1]=52 ; "45>uL3EmN[/38dDTWA44rau4lQ18!@.E,,y29g2lsd3O11ByMNf[z8J850Ut^kjNV$.43Cy9oM+W_I1Oj19uZxK6RtU!QS:37j@g|AX*J1n+h134ict$G>_TMHxX|@3E+Bbj SP|&2jnwj%28s4n2CVg_oe_5/CML34vHw4Uu[KPT`~+vQI248z5MPq6]i4V% xvSEo;2ATn]*<pE(iL<1xyIuiqA45dUc;upguw?y.al4T_1n408ta`x5hvdGnRD(Z>0Rb|./47Anu.Rd)n%aH,VKO:I(El:#34>vtqK1[@FUsK2TH#Fyk`trK4AEXTlYe1!Br5LNKI,6UBSP00N0A)st~DJOq%-/[Fw0:n|(|r@G)708 xESNtBajDj 3u%VRXz?/_HoOg3B;]rZN.gM3)l$TAe8cvLG$)pb+7u4AVfGG9Aw0m-UvT@|J)(~w%C)Pf]d)21wn072+bjewbm/-wVjV $@u4,M7z)_34xR;+/acLI^Ln56y:JJQd..C;EI-|rp0EHE.z*=BesQSq:OIxlh=qA6>]r?b<Xo 3Bkyc~yFt9oUAr0O[U)x;4fkR&^"
|     |:|   0x0040082b      8845f0         mov byte [str], al
|     |:|   0x0040082e      c645f100       mov byte [local_fh], 0
|    ,====< 0x00400832      eb12           jmp 0x400846
|    ||:|   ; CODE XREF from sym.decrypt_flag (0x40081a)
|    |`---> 0x00400834      8b45e4         mov eax, dword [local_1ch]
|    | :|   0x00400837      83c001         add eax, 1
|    | :|   0x0040083a      4898           cdqe
|    | :|   0x0040083c      0fb680801060.  movzx eax, byte [rax + str.45_uL3EmN__38dDTWA44rau4lQ18__.E__y29g2lsd3O11ByMNf_z8J850Ut_kjNV_.43Cy9oM_W_I1Oj19uZxK6RtU_QS:37j_g_AX_J1n_h134ict_G__TMHxX__3E_Bbj_SP__2jnwj_28s4n2CVg_oe_5_CML34vHw4Uu_KPT___vQI248z5MPq6_i4V__xvSEo_2ATn___pE_iL_1xyIuiqA45dUc_upguw_y.al4T_1n408ta_x5hvdGnRD_Z_0Rb_._47Anu.Rd_n_aH_VKO:I_El:_34_vtqK1__FUsK2TH_Fyk_trK4AEXTlYe1_Br5LNKI_6UBSP00N0A_st_DJOq____Fw0:n___r_G_708_xESNtBajDj_3u_VRXz___HoOg3B__rZN.gM3_l_TAe8cvLG__pb_7u4AVfGG9Aw0m_UvT__J___w_C_Pf_d_21wn072_bjewbm__wVjV___u4_M7z__34xR___acLI_Ln56y:JJQd..C_EI__rp0EHE.z__BesQSq:OIxlh_qA6__r_b_Xo_3Bkyc_yFt9oUAr0O_U_x_4fkR____Vrg_B361rBe__mp.IEr_ew_LkjSb_ald5S4Ki_Iw0B.Nf6__Tt__rL____V__w_S_L_jJh__5_U_38S80T___w___tSEF_OvLw__X0z2_YonQ__:80CR_5_QFfj_9T_dH2b_qI2bfMusf3utdxiO_3_063CDH6c_GaDX:P_JWUI4n__zzikKID_B8FRl_O39C__423_Z__s91ZHYTok7TCWVjP_6_rs___Q_JO52ET7_9b2_ig_Z_tC__kqQF__vgs__VF_65P4___R] ; obj.enc_buf ; [0x601080:1]=52 ; "45>uL3EmN[/38dDTWA44rau4lQ18!@.E,,y29g2lsd3O11ByMNf[z8J850Ut^kjNV$.43Cy9oM+W_I1Oj19uZxK6RtU!QS:37j@g|AX*J1n+h134ict$G>_TMHxX|@3E+Bbj SP|&2jnwj%28s4n2CVg_oe_5/CML34vHw4Uu[KPT`~+vQI248z5MPq6]i4V% xvSEo;2ATn]*<pE(iL<1xyIuiqA45dUc;upguw?y.al4T_1n408ta`x5hvdGnRD(Z>0Rb|./47Anu.Rd)n%aH,VKO:I(El:#34>vtqK1[@FUsK2TH#Fyk`trK4AEXTlYe1!Br5LNKI,6UBSP00N0A)st~DJOq%-/[Fw0:n|(|r@G)708 xESNtBajDj 3u%VRXz?/_HoOg3B;]rZN.gM3)l$TAe8cvLG$)pb+7u4AVfGG9Aw0m-UvT@|J)(~w%C)Pf]d)21wn072+bjewbm/-wVjV $@u4,M7z)_34xR;+/acLI^Ln56y:JJQd..C;EI-|rp0EHE.z*=BesQSq:OIxlh=qA6>]r?b<Xo 3Bkyc~yFt9oUAr0O[U)x;4fkR&^"
|    | :|   0x00400843      8845f1         mov byte [local_fh], al
|    | :|   ; CODE XREF from sym.decrypt_flag (0x400832)
|    `----> 0x00400846      488d45f0       lea rax, [str]
|      :|   0x0040084a      ba10000000     mov edx, 0x10               ; 16 ; int base
|      :|   0x0040084f      be00000000     mov esi, 0                  ; char * *endptr
|      :|   0x00400854      4889c7         mov rdi, rax                ; const char *str
|      :|   0x00400857      e8d4fdffff     call sym.imp.strtol         ; long strtol(const char *str, char * *endptr, int base)
|      :|   0x0040085c      488945e8       mov qword [local_18h], rax
|      :|   0x00400860      488b15810b20.  mov rdx, qword obj.flag_buf ; [0x6013e8:8]=0x848260 ; "`\x82\x84"
|      :|   0x00400867      8b45e0         mov eax, dword [local_20h]
|      :|   0x0040086a      4898           cdqe
|      :|   0x0040086c      4801d0         add rax, rdx                ; '('
|      :|   0x0040086f      488b55e8       mov rdx, qword [local_18h]
|      :|   0x00400873      83c22b         add edx, 0x2b               ; '+'
|      :|   0x00400876      8810           mov byte [rax], dl
|      :|   0x00400878      8345e001       add dword [local_20h], 1
|      :|   0x0040087c      8345dc01       add dword [local_24h], 1
|      :|   0x00400880      8b45dc         mov eax, dword [local_24h]
|      :|   0x00400883      83c002         add eax, 2
|      :|   0x00400886      0145e4         add dword [local_1ch], eax
|      :|   ; CODE XREF from sym.decrypt_flag (0x4007e7)
|      :`-> 0x00400889      817de4520300.  cmp dword [local_1ch], 0x352 ; [0x352:4]=-1 ; 850
|      `==< 0x00400890      0f8e56ffffff   jle 0x4007ec
|           0x00400896      488b154b0b20.  mov rdx, qword obj.flag_buf ; [0x6013e8:8]=0x848260 ; "`\x82\x84"
|           0x0040089d      8b45e0         mov eax, dword [local_20h]
|           0x004008a0      4898           cdqe
|           0x004008a2      4801d0         add rax, rdx                ; '('
|           0x004008a5      c60000         mov byte [rax], 0
|           0x004008a8      bf0a000000     mov edi, 0xa                ; int c
|           0x004008ad      e83efdffff     call sym.imp.putchar        ; int putchar(int c)
|           0x004008b2      90             nop
|           0x004008b3      488b45f8       mov rax, qword [canary]
|           0x004008b7      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x004008c0      7405           je 0x4008c7
|       |   0x004008c2      e849fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       |   ; CODE XREF from sym.decrypt_flag (0x4008c0)
|       `-> 0x004008c7      c9             leave
\           0x004008c8      c3             ret
[0x0040090a]> ps @ 0x848260
picoCTF{gDb_iS_sUp3r_u53fuL_9fa6c71d}
```

Basically, we have to run the program, set a break point after the `decrypt_flag` function, and extract the flag from memory.

flag: `picoCTF{gDb_iS_sUp3r_u53fuL_9fa6c71d}`

# roulette

## Problme

This Online [Roulette](/blog/picoctf-2018-writeup/General Skills/roulette/roulette) Service is in Beta. Can you find a way to win $1,000,000,000 and get the flag? [Source](/blog/picoctf-2018-writeup/General Skills/roulette/roulette.c). Connect with `nc 2018shell2.picoctf.com 26662`

## Solution

To solve this problem, we need to find the two bugs in this program.

The first bug is a leak of the seed value that is later used for generating the random numbers:

```c
long get_rand() {
  long seed;
  FILE *f = fopen("/dev/urandom", "r");
  fread(&seed, sizeof(seed), 1, f);
  fclose(f);
  seed = seed % 5000;
  if (seed < 0) seed = seed * -1;
  srand(seed);
  return seed;
}
...
int main(int argc, char *argv[]) {
  ...
  cash = get_rand();
  ...
}
```

As you can see here, the seed is used directly to initiate the cash variable,so the starting cash value is the seed that is used for the random number generator.

Knowing that, we can now guess the outcome of every bet using this script:

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

int main(int argc, char *argv[]) {
  printf("%d\n", argc);
  unsigned long seed = strtol(argv[1], argv[1]+strlen(argv[1]), 10);
  printf("%d\n", seed);
  srand(seed);
  
  for (int i = 0; i < 10; i++) {
    printf("%d\n", (rand() % 36)+1);
  }
  // printf('%d', rand());
  return 0;
}
```

> Not the best C code, but it works :)

Now we are able to win everytime; however, we will be kicked out before we reach a billion dollars. So we need to find another bug that will give up a billion dollars instantly.

That bug that we are looking for lies in the `get_long` function. The function returns a signed long value; however, it is competed using a varible that have the type `uint64_t` which is unsigned. Using this fact, we can construct a input that is huge but will be negative when viewed as signed.

```c
long get_long() {
    printf("> ");
    uint64_t l = 0;
    char c = 0;
    while(!is_digit(c))
      c = getchar();
    while(is_digit(c)) {
      if(l >= LONG_MAX) {
        l = LONG_MAX;
        break;
      }
      l *= 10;
      l += c - '0';
      c = getchar();
    }
    while(c != '\n')
      c = getchar();
    return l;
}
```

Now combining the two bugs, we can first win three time and intensionally lose the fourth round which we will bet a huge negative number. After all that, we will then be able to get the flag:

```
❯ nc 2018shell2.picoctf.com 26662
Welcome to ONLINE ROULETTE!
Here, have $4548 to start on the house! You'll lose it all anyways >:)

How much will you wager?
Current Balance: $4548 	 Current Wins: 0
> 4548
Choose a number (1-36)
> 28

Spinning the Roulette for a chance to win $9096!

Roulette  :  28

You're not cheating are you?

How much will you wager?
Current Balance: $9096 	 Current Wins: 1
> 9096
Choose a number (1-36)
> 31

Spinning the Roulette for a chance to win $18192!

Roulette  :  31

Wow, you won!

How much will you wager?
Current Balance: $18192 	 Current Wins: 2
> 18192
Choose a number (1-36)
> 5

Spinning the Roulette for a chance to win $36384!

Roulette  :  5

Wow.. Nice One!

How much will you wager?
Current Balance: $36384 	 Current Wins: 3
> 3221225472
Choose a number (1-36)
> 10

Spinning the Roulette for a chance to win $2147483648!

Roulette  :  15

Not this time..
It's over for you.

*** Current Balance: $1073778208 ***
Wow, I can't believe you did it.. You deserve this flag!
picoCTF{1_h0p3_y0u_f0uNd_b0tH_bUg5_25142e09}
```

flag: `picoCTF{1_h0p3_y0u_f0uNd_b0tH_bUg5_25142e09}`

# store

## Problem

We started a little [store](/blog/picoctf-2018-writeup/General Skills/store/store), can you buy the flag? [Source](/blog/picoctf-2018-writeup/General Skills/store/source.c). Connect with `2018shell2.picoctf.com 43581`.

## Solution

This is a easy integer overflow problem:

```
❯ nc 2018shell2.picoctf.com 43581
Welcome to the Store App V1.0
World's Most Secure Purchasing App

[1] Check Account Balance

[2] Buy Stuff

[3] Exit

 Enter a menu selection
2
Current Auctions
[1] I Can't Believe its not a Flag!
[2] Real Flag
1
Imitation Flags cost 1000 each, how many would you like?
10000000000000000

Your total cost is: -1981284352

Your new balance: 1981285452

Welcome to the Store App V1.0
World's Most Secure Purchasing App

[1] Check Account Balance

[2] Buy Stuff

[3] Exit

 Enter a menu selection
2
Current Auctions
[1] I Can't Believe its not a Flag!
[2] Real Flag
2
A genuine Flag costs 100000 dollars, and we only have 1 in stock
Enter 1 to purchase1
YOUR FLAG IS: picoCTF{numb3r3_4r3nt_s4f3_6bd13a8c}
```

flag: `picoCTF{numb3r3_4r3nt_s4f3_6bd13a8c}`

# script me

## Problem

Can you understand the language and answer the questions to retrieve the flag? Connect to the service with `nc 2018shell2.picoctf.com 7866`

## Solution

One of my teammates, Gary Kim, solved this problem, and here is his solution:

```python
from pwn import *
import re

r = remote("2018shell2.picoctf.com","7866")
print(r.recvuntil("up."))
final = False
while not final:
    temp = r.recvuntil("(")
    print(temp)
    if temp.find("not") != -1:
        print(temp)
        print(r.recv())
        exit()
    if temp.find("Final") != -1:
        final = True
    question = "(" + r.recvuntil("???")
    question = question[:-6]
    print(question)
    while question.find("+") is not -1:
        depth1 = [1]
        depth0 = [1]
        question = re.sub(" *", "",question)
        print(question)
        questionarr = list(question)
        value = 0
        for x in range(1,len(question)):
            value += 1
            if question[x] == "+" :
                break
            if question[x] == "(":
                depth0.append(depth0[len(depth0) - 1] + 1)
            if question[x] == ")":
                depth0.append(depth0[len(depth0) - 1] - 1)
        value += 1
        for x in range(value + 1,len(question)):
            if question[x] == "+":
                break
            if question[x] == "(":
                depth1.append(depth1[len(depth1) - 1] + 1)
            if question[x] == ")":
                depth1.append(depth1[len(depth1) - 1] - 1)
        if max(depth0) > max(depth1):
            question = question[0:len(depth0) - 1] + question[value:value + len(depth1)] + question[len(depth0) - 1:len(depth0)] + question[value + len(depth1):]
        if max(depth0) < max(depth1):
            question = question[value:value + 1] + question[0:len(depth0)] + question[value + 1:value + len(depth1)] + question[value + len(depth1):]
        if max(depth0) == max(depth1):
            question = question[0:len(depth0)] + question[value:value + len(depth1)] + question[value + len(depth1):]
    r.recvline()
    r.sendline(question)
r.interactive()
```

flag: `picoCTF{5cr1pt1nG_l1k3_4_pRo_45ca3f85}`

# Dog or Frog

## Problem

Dressing up dogs are kinda the new thing, see if you can get this lovely girl ready for her costume party. [Dog Or Frog](http://2018shell2.picoctf.com:11889/)

[model](/blog/picoctf-2018-writeup/General Skills/Dog or Frog/model.h5)

[solution template](/blog/picoctf-2018-writeup/General Skills/Dog or Frog/solution_template.py)

[notes](/blog/picoctf-2018-writeup/General Skills/Dog or Frog/notes.txt)

[source](/blog/picoctf-2018-writeup/General Skills/Dog or Frog/source.tar.gz)

## Solution

The challenge asks you to craft a image that is similar to the origanal dog image but would be classified as a tree frog by the neural network.

I solved this challenge mostly by reading other people's work online. Here are a few that helped me along the way:

* [How to trick a neural network into thinking a panda is a vulture](https://codewords.recurse.com/issues/five/why-do-neural-networks-think-a-panda-is-a-vulture) - best article that explained the overall concept
* [Explaining and Harnessing Adversarial Examples](https://arxiv.org/abs/1412.6572) - the paper used by the article above
* [Machine Learning is Fun Part 8: How to Intentionally Trick Neural Networks](https://medium.com/@ageitgey/machine-learning-is-fun-part-8-how-to-intentionally-trick-neural-networks-b55da32b7196) - have a real code implementation that does not work well
* [4 ways to easily fool your deep neural net](https://buzzrobot.com/4-ways-to-easily-fool-your-deep-neural-net-dca49463bd0) - other methods

Here is my final solution (code borrowed from articles mentioned above):

```python
from keras.applications.mobilenet import preprocess_input
from keras.models import load_model
from keras.preprocessing.image import img_to_array, array_to_img
from PIL import Image
from imagehash import phash
import numpy as np
from keras import backend as K

IMAGE_DIMS = (224, 224)
TREE_FROG_IDX = 31
TREE_FROG_STR = "tree_frog"

# I'm pretty sure I borrowed this function from somewhere, but cannot remember
# the source to cite them properly.
def hash_hamming_distance(h1, h2):
    s1 = str(h1)
    s2 = str(h2)
    return sum(map(lambda x: 0 if x[0] == x[1] else 1, zip(s1, s2)))


def is_similar_img(path1, path2):
    image1 = Image.open(path1)
    image2 = Image.open(path2)

    dist = hash_hamming_distance(phash(image1), phash(image2))
    return dist <= 1


def prepare_image(image, target=IMAGE_DIMS):
    # if the image mode is not RGB, convert it
    if image.mode != "RGB":
        image = image.convert("RGB")

    # resize the input image and preprocess it
    image = image.resize(target)
    image = img_to_array(image)
    image = np.expand_dims(image, axis=0)
    image = preprocess_input(image)
    # return the processed image
    return image


def create_img(img_path, img_res_path, model_path, target_str, target_idx, des_conf=0.95):
    original_image = Image.open(img_path).resize(IMAGE_DIMS)
    original_image = prepare_image(original_image)
    model = load_model(model_path)

    model_input_layer = model.layers[0].input
    model_output_layer = model.layers[-1].output

    max_change_above = original_image + 0.01
    max_change_below = original_image - 0.01

    # Create a copy of the input image to hack on
    hacked_image = np.copy(original_image)

    # How much to update the hacked image in each iteration
    learning_rate = 0.01

    # Define the cost function.
    # Our 'cost' will be the likelihood out image is the target class according to the pre-trained model
    cost_function = model_output_layer[0, TREE_FROG_IDX]

    # We'll ask Keras to calculate the gradient based on the input image and the currently predicted class
    # In this case, referring to "model_input_layer" will give us back image we are hacking.
    gradient_function = K.gradients(cost_function, model_input_layer)[0]

    # Create a Keras function that we can call to calculate the current cost and gradient
    grab_cost_and_gradients_from_model = K.function([model_input_layer, K.learning_phase()], [cost_function, gradient_function])

    cost = 0.0

    # In a loop, keep adjusting the hacked image slightly so that it tricks the model more and more
    # until it gets to at least 80% confidence
    while cost < 0.99:
        # Check how close the image is to our target class and grab the gradients we
        # can use to push it one more step in that direction.
        # Note: It's really important to pass in '0' for the Keras learning mode here!
        # Keras layers behave differently in prediction vs. train modes!
        cost, gradients = grab_cost_and_gradients_from_model([hacked_image, 0])

        # Move the hacked image one step further towards fooling the model
        # print gradients
        hacked_image += np.sign(gradients) * learning_rate

        # Ensure that the image doesn't ever change too much to either look funny or to become an invalid image
        hacked_image = np.clip(hacked_image, max_change_below, max_change_above)
        hacked_image = np.clip(hacked_image, -1.0, 1.0)

        print("Model's predicted likelihood that the image is a tree frog: {:.8}%".format(cost * 100))

    hacked_image = hacked_image.reshape((224,224,3))
    img = array_to_img(hacked_image)
    img.save(img_res_path)


if __name__ == "__main__":
    create_img("./trixi.png", "./trixi_frog.png", "./model.h5", TREE_FROG_STR, TREE_FROG_IDX)
    assert is_similar_img("./trixi.png", "./trixi_frog.png")
```

And here is the command to install all the required dependencies:

```bash
$ sudo pip install tensorflow keras Pillow numpy ImageHash
```

flag: `picoCTF{n0w_th4t3_4_g00d_girl_9ceacf46}`

> Feel free to leave a comment if any of the challenges is not well explained.