---
title: "35c3ctf 2018 Writeup"
date: 2018-12-30T11:17:12+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: My solves for 35c3ctf 2018 challenges
---

# box of blink

## Problem

As every year, can you please decode [this](/blog/2018/35c3ctf-writeup/box of blink/blink.csv.gz) for me?

{{< figure src="/blog/2018/35c3ctf-writeup/box of blink/image.jpg" >}}

## Solution

For this challenge, we are given a huge csv file that seems to consist of electronic signals collected by an oscilloscope:

```
❯ cat blink.csv | sed 30q
#Model,MDO3014
#Firmware Version,1.26
#
#Waveform Type,DIGITAL,,,,,,,,,,,,,
#Point Format,Y,,,,,,,,,,,,,
#Horizontal Units,s,,,,,,,,,,,,,
#Horizontal Scale,0.004,,,,,,,,,,,,,
#,,,,,,,,,,,,,,
#Sample Interval,4e-09,,,,,,,,,,,,,
#Record Length,1e+07,,,,,,,,,,,,,
#Gating,0.0% to 100.0%,,,,,,,,,,,,,
#,,,,,,,,,,,,,,
#Vertical Units,V,V,V,V,V,V,V,V,V,V,V,V,V,V
#Threshold Used,1.65,1.65,1.65,1.65,1.65,1.65,1.65,1.65,1.65,1.65,1.65,1.65,1.65,1.65
#,,,,,,,,,,,,,,
#,,,,,,,,,,,,,,
#,,,,,,,,,,,,,,
#,,,,,,,,,,,,,,
#,,,,,,,,,,,,,,
#Label,OE,LAT,CLK,E,D,C,B,A,B2,B1,G2,G1,R2,R1
#TIME,D13,D12,D11,D10,D9,D8,D7,D6,D5,D4,D3,D2,D1,D0
-1.0000000e-03,0,0,0,0,1,0,0,0,0,0,0,1,0,1
-9.9999600e-04,0,0,0,0,1,0,0,0,0,0,0,1,0,1
-9.9999200e-04,0,0,0,0,1,0,0,0,0,0,0,1,0,1
-9.9998800e-04,0,0,0,0,1,0,0,0,0,0,0,1,0,1
-9.9998400e-04,0,0,0,0,1,0,0,0,0,0,0,1,0,1
-9.9998000e-04,0,0,0,0,1,0,0,0,0,0,0,1,0,1
-9.9997600e-04,0,0,0,0,1,0,0,0,0,0,0,1,0,1
-9.9997200e-04,0,0,0,0,1,0,0,0,0,0,0,1,0,1
-9.9996800e-04,0,0,0,0,1,0,0,0,0,0,0,1,0,1
```

The image also shows the setup that generated the data, and suggests that the signals might be from a rgb dot matrix controlled by a raspberry pi.

I jumped into research about how a rgb dot matrix actually works. I found these articles that are really helpful:

* [Adafruit RGB LED Matrix](http://www.rayslogic.com/propeller/Programming/AdafruitRGB/AdafruitRGB.htm)
* [Everything You Didn't Want to Know About RGB Matrix Panels](https://www.sparkfun.com/sparkx/blog/2650)

In a brief summary, a rgb dot matrix doesn't update on all the pixels at once, instead, it goes through each line and update the display one line at a time.

The wiring consist of a clock signal or `clk` that is responsible for defining time intervals. Basically, the micro-controller only read data from the wires when the `clk` signal goes from low (0) to high (1).

Then, there are the A, B, C, D, E signals that work together to denote the row that is going to be updated. The display needs more wires if it has more rows. For example, a 8 row display will only need the A, B, C wires. Also, the A wire is always the least significant bit. For example, if A=0, B=1, C=1, then row `0b110` or `6` will be updated.

Also, there are the color wires: R1, R2, G1, G2, B1, B2. The dot matrix can only display 64 different colors which means that the red, green, blue values each range from 0-3 which can each be encoded by two bits or two wires; therefore, in total, the color of one pixel can be expressed by six wires. The display will clock in the color for each pixel in a row one at a time. For this challenge, there's 128 pixels per line, so the `clk` signal goes from 0 to 1 128 times for each row, and each time the clock signal changes the color value will be recorded for one of the pixels. The color values for that row is then stored inside a shift register, and will be updated to the display when the `LAT` or the latch signal is turned on. In addition, there's the `OE` or output enable signal that turns the display on and off.

Now knowing what each wire is doing and the value for each one (the `#Label,OE,LAT,CLK,E,D,C,B,A,B2,B1,G2,G1,R2,R1` comment in the csv file is quite helpful in telling you which signal corresponds to a certain wire), we can now write a program to reconstruct the image.

Here are just a few key points when writing the program:

* only look at data when `clk` goes from `0` to `1` because that is when the micro-controller read data
* render the canvas once it updated all the rows
* check which signal is the least significant bit and which is the most

Here is the final script:

```python
from PIL import Image

w = 128
h = 32
pixels = [(256,256,256)]*(w*h)
count = 0

img = Image.new("RGB", (w, h))

last_addr = 0
col_count = 0
count = 0

isOn = False
with open('./blink.test.csv') as f:
  for line in f:
    data = line.strip().split(',')[1:]
    clk = int(data[2],2)
    row_addr = int(''.join(data[3:8]),2)
    rgb = [int(''.join(data[12:14]),2), int(''.join(data[8:10]),2),int(''.join(data[10:12]),2)]
    
    if clk == 1 and isOn or clk == 0 and not isOn:
      continue
    
    isOn = not isOn

    if clk == 0:
      continue
    
    if last_addr != row_addr:
      
      last_addr = row_addr
      col_count = 0
      if row_addr == 0:
        img.putdata(pixels)
        img.save(str(count)+".jpg")
        count += 1

    if rgb != [0,0,0]:
      pixels[row_addr*w+col_count] =(0,0,0)
    else:
      pixels[row_addr*w+col_count] = (256,256,256)
    
    col_count += 1
    

img.putdata(pixels)

img.save("flag.jpg")
```

And this is the final image:

{{< figure src="/blog/2018/35c3ctf-writeup/box of blink/flag.png" >}}

flag: `35C3_D4s_blInk3nL1cht3n_1st_so_wund3rb4r`

# juggle

## Problem

Can you help this restaurant Stack the right amount of Eggs in their ML algorithms?

Guest challenge by Tethys.

Note that you need to send a shutdown(2) after you sent your solution. The nmap netcat will do so for you, e.g.: `ncat 35.246.237.11 1 < solution.xml`

> /usr/bin/ncat --help | grep -n 1 Ncat 7.60 ( https://nmap.org/ncat )

Files [here](/blog/2018/35c3ctf-writeup/juggle/juggle.tar)

## Solution

This is a ML challenge as in XML.

You are given a `xslt` file which is basically a templating language for XML. The xslt file processor takes in a xml file and spits out another one according to the xslt file.

In this case, the xslt implements a virtual machine using food and drinks. Here is a list of the available instructions and their corresponding food name:

```
宫保鸡丁
--> print chef-drinks and drink
paella
--> pre-pend drinks
불고기
--> get $drinks[$arg0 + 2] + 0
Борщ
--> remove first chef-drinks if it is the same as drinks
दाल
--> give flag if not chef-drinks left
ラーメン
--> 1 if first drink larger than first chef-drink, 0 otherwise
stroopwafels
--> compare the first two items
--> return 1 if arg1 > arg0
köttbullar
--> insert arg0 at arg1
γύρος
--> remove at index arg0
rösti
--> arg0 + arg1
לאַטקעס
--> arg0 - arg1
poutine
--> arg0 * arg1
ُمُّص
--> arg0 // arg1
æblegrød
--> if arg0 jump to arg1
```

As you might be able to tell, the virtual machine operates values on a stack of drinks. All the instructions either push or pop values/drinks from the stack.

The objective of the challenge is to write a program using the food instructions and guess five random numbers that range from 0 to 4294967296, and the program have to be done in less than 30000 instructions.

First, brute force is out of the window because of the limited number of instructions, but we do have the `ラーメン` instruction. This instruction allows us to make a less than or more than comparison between the random value and another value that we can specify. Using this one simple instruction, we can build out a binary search algorithm that can guess the numbers efficiently. Also, the `æblegrød` instruction aka the jump instruction makes loops possible.

Here is the final food list that gives us the flag:

```xml
<meal>
  <state>
    <drinks>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
      <value>0</value>
    </drinks>
  </state>
  <course>
    <plate>
      <!-- try_flag -->
      <दाल></दाल>
    </plate>

    <plate>
      <paella>9</paella>
    </plate>
    <plate>
      <paella>0</paella>
    </plate>
    <plate>
      <köttbullar></köttbullar>
    </plate>

    <plate>
      <paella>10</paella>
    </plate>

    <plate>
      <γύρος></γύρος>
    </plate>

    <plate>
    <paella>10</paella>
    </plate>
    <plate>
      <paella>4294967296</paella>
    </plate>
    <plate>
      <köttbullar></köttbullar>
    </plate>

    <plate>
      <paella>11</paella>
    </plate>

    <plate>
      <γύρος></γύρος>
    </plate>

    <!-- <plate>
      <宫保鸡丁></宫保鸡丁>
    </plate> -->

    <plate>
      <!-- jump to loop -->
      <paella>1</paella>
    </plate>
    <plate>
      <paella>1</paella>
    </plate>

    <plate>
      <æblegrød></æblegrød>
    </plate> 
  </course>
  <course>

    <!-- check if A < B -->
    <plate>
      <paella>9</paella>
    </plate>
    <plate>
      <불고기></불고기>
    </plate>

    <plate>
      <paella>11</paella>
    </plate>
    <plate>
      <불고기></불고기>
    </plate>

    <plate>
      <stroopwafels></stroopwafels>
    </plate>

    <plate>
      <paella>1</paella>
    </plate>
    <plate>
      <!-- more than case -->
      <paella>0</paella>
    </plate>
    <plate>
      <köttbullar></köttbullar>
    </plate>

    <plate>
      <宫保鸡丁></宫保鸡丁>
    </plate>

    <plate>
      <æblegrød></æblegrød>
    </plate>

    <!-- loop (8) -->

    <plate>
      <!-- div 2 -->
      <paella>2</paella>
    </plate>

    <plate>
      <paella>11</paella>
    </plate>
    <plate>
      <불고기></불고기>
    </plate>

    <plate>
      <paella>11</paella>
    </plate>
    <plate>
      <불고기></불고기>
    </plate>

    <plate>
      <!-- + -->
      <rösti></rösti>
    </plate>

    <plate>
      <!-- //2 -->
      <حُمُّص></حُمُّص>
    </plate>

    <plate>
      <paella>0</paella>
    </plate>
    <plate>
      <불고기></불고기>
    </plate>

    <plate>
      <!-- try_remove -->
      <Борщ></Борщ>
    </plate>

    <plate>
      <paella>0</paella>
    </plate>
    <plate>
      <불고기></불고기>
    </plate>

    <plate>
      <ラーメン></ラーメン>
    </plate>

    <plate>
      <paella>1</paella>
    </plate>
    <plate>
      <!-- more than case -->
      <paella>2</paella>
    </plate>
    <plate>
      <köttbullar></köttbullar>
    </plate>

    <plate>
      <æblegrød></æblegrød>
    </plate>

    <!-- arg < chef -->

    <plate>
      <paella>1</paella>
    </plate>
    <plate>
      <paella>1</paella>
    </plate>
    <plate>
      <köttbullar></köttbullar>
    </plate>

    <plate>
      <rösti></rösti>
    </plate>

    <plate>
      <paella>1</paella>
    </plate>
    <plate>
      <paella>9</paella>
    </plate>
    <plate>
      <köttbullar></köttbullar>
    </plate>
    
    <plate>
      <köttbullar></köttbullar>
    </plate>

    <plate>
      <paella>10</paella>
    </plate>

    <plate>
      <γύρος></γύρος>
    </plate>

    <plate>
      <!-- jump to loop -->
      <paella>1</paella>
    </plate>
    <plate>
      <paella>1</paella>
    </plate>

    <plate>
      <æblegrød></æblegrød>
    </plate>
  </course>
  <course>
    <plate>
      <paella>1</paella>
    </plate>
    <plate>
      <paella>1</paella>
    </plate>
    <plate>
      <köttbullar></köttbullar>
    </plate>

    <plate>
      <לאַטקעס></לאַטקעס>
    </plate>

    <plate>
      <paella>1</paella>
    </plate>
    <plate>
      <paella>10</paella>
    </plate>
    <plate>
      <köttbullar></köttbullar>
    </plate>
    
    <plate>
      <köttbullar></köttbullar>
    </plate>

    <plate>
      <paella>11</paella>
    </plate>

    <plate>
      <γύρος></γύρος>
    </plate>

    <plate>
      <!-- jump to loop -->
      <paella>1</paella>
    </plate>
    <plate>
      <paella>1</paella>
    </plate>

    <plate>
      <æblegrød></æblegrød>
    </plate>
  </course>
</meal>
```

In conclusion, this is a fun challenge that I enjoyed a lot as I got to practice my programming skill with something that is out of the ordinary.

flag: `35C3_The_chef_gives_you_his_compliments`