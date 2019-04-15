---
title: "WPICTF 2019 S3L3CT Writeup"
date: 2019-04-15T14:29:45+08:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  'machine-learning'
]
description: Solution for the "S3L3CT" challenge in WPICTF 2019
---

# Problem

**Points**: 400

**Solves**: 3

Are you smarter than an AI?

https://drive.google.com/open?id=1Inoxm1Wyiq6keSVwBt9zU5aRbRaScuTq

made by calper-pq

# Solution

## Getting started

For this challenge, you are given three npy files: `X.npy`, `Y.npy`, and `key.npy`.

With some googling, I found that npy files can be loaded with numpy:

```python
import numpy as np

data_x = np.load('./X.npy')
data_y = np.load('./Y.npy')
data_key = np.load('./key.npy')

print data_x.shape
print data_y.shape
print data_key.shape
```

```bash
❯ python main.py
(10000, 50, 50, 3)
(10000,)
(296, 50, 50, 3)
```

Judging from the shape of the data, I made an educated guess that `X.npy` and `Y.npy` are the training inputs and training outputs, and our goal is to make a machine learning algorithm that can predict the outputs for the data stored in the `key.npy` file.

Since the outputs in `Y.npy` are either 0 or 1, we can expect to get a binary string with the length of 296 that would likely be the flag.

## Making a convolutional neural network

Now our task becomes making a neural network that can classify the data for us.

The shape of the data helped again as (50, 50, 3)  hinted at the fact that the input could be seen as a 50x50 pixel RGB image, and we can use a neural network that is best optimized for image recognition - [a convolutional neural network](https://en.wikipedia.org/wiki/Convolutional_neural_network).

I won't go into the details about how a convolutional neural network works because there are already quite a lot of good resources out there. Here are just a few that I used:

* [Machine Learning is Fun! Part 3: Deep Learning and Convolutional Neural Networks](https://medium.com/@ageitgey/machine-learning-is-fun-part-3-deep-learning-and-convolutional-neural-networks-f40359318721)
* [A Beginner's Guide To Understanding Convolutional Neural Networks](https://adeshpande3.github.io/adeshpande3.github.io/A-Beginner's-Guide-To-Understanding-Convolutional-Neural-Networks/)

I picked [Keras](https://keras.io/) as my library of choice simply because I have used it before for a few other CTF challenges ([this](/blog/posts/2019-03-11-utctf-writeup/#facesafe-1400pts) and [this](/blog/posts/2019-02-03-nullcon-hackim-writeup/#mlauth)).

Now I have a scope that is narrow enough: I need to build a **convolutional neural network** using **Keras** to do **binary image classification**. Let the google rampage begin.

## Striking gold

After reading around 20 articles online and experimenting with a few different models, I finally found one that works.

Using the model described in this [great article](https://towardsdatascience.com/image-classification-python-keras-tutorial-kaggle-challenge-45a6332a58b8), here's my final code:

```python
import keras
from keras.models import Sequential
from keras.layers import Dense, Flatten, Conv2D, Activation, MaxPooling2D, BatchNormalization, Dropout
from keras.utils import to_categorical

import numpy as np

model = Sequential()

data_x = np.load('./X.npy')
data_y = np.load('./Y.npy')
data_key = np.load('./key.npy')

data_y = to_categorical(data_y)

x_train = data_x[:len(data_x)//2]
x_test = data_x[len(data_x)//2:]

y_train = data_y[:len(data_x)//2]
y_test = data_y[len(data_x)//2:]


model = Sequential()
model.add(Conv2D(32, kernel_size = (3, 3), activation='relu', input_shape=(50, 50, 3),data_format="channels_last",))
model.add(MaxPooling2D(pool_size=(2,2)))
model.add(BatchNormalization())
model.add(Conv2D(64, kernel_size=(3,3), activation='relu'))
model.add(MaxPooling2D(pool_size=(2,2)))
model.add(BatchNormalization())
model.add(Conv2D(64, kernel_size=(3,3), activation='relu'))
model.add(MaxPooling2D(pool_size=(2,2)))
model.add(BatchNormalization())
model.add(Conv2D(96, kernel_size=(3,3), activation='relu'))
model.add(MaxPooling2D(pool_size=(2,2)))
model.add(BatchNormalization())
# model.add(Conv2D(32, kernel_size=(3,3), activation='relu'))
# model.add(MaxPooling2D(pool_size=(2,2)))
# model.add(BatchNormalization())
model.add(Dropout(0.2))
model.add(Flatten())
model.add(Dense(128, activation='relu'))
#model.add(Dropout(0.3))
model.add(Dense(2, activation = 'softmax'))
model.compile(loss=keras.losses.categorical_crossentropy,
              optimizer=keras.optimizers.SGD(lr=0.01),
              metrics=['accuracy'])

print model.summary()

model.fit(x_train, y_train, epochs=20, batch_size=50,  verbose=1, validation_data=(x_test, y_test),)

model.save('my_model.h5')

v = model.predict(data_key)
print v

flag = ''
for i in range(len(v)):
    k = v[i]
    if k[0] > k[1]:
            flag+='0'
    else:
            flag+='1'
print flag
```

flag: `WPI{+++#(((--ELON_IS_SKYNET--)))#+++}`