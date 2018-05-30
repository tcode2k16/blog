---
title: "Barcode Scanner"
date: 2018-05-30T08:03:41+08:00
draft: false
tags: [
  "project",
  "school",
  "javascript"
]
description: cross-platform zero-install ISBN barcode scanner with javascript
---

{{< figure src="/blog/barcode-scanner/dev.png" caption="Development environment with vscode and iTerm" >}}

# Problem

There is a used-book sale program at our school, and currently, it is difficult to find books people want as books are not indexed and sorted properly. The maintainers all mentioned the experience of being asked wherever a specific book is within the large collection of books.

# Solution

I attempt to make an efficient system for indexing all the books and encourage more people to buy books they want from the book sale.

One of the major problems is time. The book sale program only has a limit number of volunteers that come in twice a month meaning that human input is not a viable solution.

I came up with the idea of scanning the barcode on each book and use that to obtain detailed information for each book. By doing a little bit of research, I learned about [ISBN](https://en.wikipedia.org/wiki/International_Standard_Book_Number) or *International Standard Book Number* which is unique for each book.

Here are some fun facts about ISBN:

- It contains 13 digits (formerly 10)
- It always starts with `978`
- The 4th digit indicates country
  - 0 or 1 for English-speaking countries
  - 2 for French-speaking countries
  - 3 for German-speaking countries
  - 4 for Japan
  - 5 for Russian-speaking countries
  - 7 for People's Republic of China

Using the barcode scanner, I can then search up the ISBN number in an online database. I used google books API in this case. That will then give me the title, description, author and etc about a certain book that is being scanned.

# Implementation

I made the web app using [vue.js](https://vuejs.org/) for the UI and [quaggaJS](https://serratus.github.io/quaggaJS/) for the barcode scanning part. The app will currently scan a barcode located on a book and then give you the title and cover image of the book. I decided to go with a web app as it avoids the process of going through an app store, and it also makes the app cross-platform at the same time.

> Side note: It is still a pain to use `getUserMedia` to access the camera inside the browser (IOS 10 doesn't have support).

{{< figure src="/blog/barcode-scanner/caniuse.png" attr="From caniuse.com" >}}

# Future

I am planning on a backend database that will take the information and store them. That will then allow me to implement functionalities such as: search, wishing list, and more.

# End

**[Here](https://tcode2k16.github.io/book-scanner/)** is the web app. (It is still WIP)