---
title: "Automated School Calendar"
date: 2018-05-17T08:45:01+08:00
draft: false
tags: [
  "project",
  "google",
  "school"
]
description: Making an automated google calendar with google apps script in 30 min
---

### Introduction

I have finally got the chance to experiment with google apps script, and decided to use it to make my school life easier.

I used google apps script along with the calendar api to create a web app that can auto generate my class schedule based on another calendar provided by my school.

<img alt="google apps script" style="max-width:400px;" src="/blog/images/google-apps-script.png"></img>

### Method

The script first pulls all the events from an existing calendar given a certain range for the date, and then it generates a new calendar. The new calendar is then populated day by day with the correct schedule for that given day.

### Result

Here is the generated calendar:
![google calendar](/blog/images/google-calendar.png)

[Here](https://script.google.com/a/sas.edu.sg/macros/s/AKfycbx62010MtD639TSusvURtHxbld9QZqj2GWZQn0FpPmuD23XsqKT/exec) is the web app.


