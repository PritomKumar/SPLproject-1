# Text Bandit

[![Platform](https://img.shields.io/badge/platform-Linux-yellow.svg)](https://www.linux.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![C](https://img.shields.io/badge/c-%2300599C.svg?style=flat-square&logo=c&logoColor=white)
![C#](https://img.shields.io/badge/c%23-%23239120.svg?style=flat-square&logo=c-sharp&logoColor=white)
![Socket](https://img.shields.io/badge/Socket-black?style=flat-square&logo=socket.io&badgeColor=010101)
[![Awesome Badge](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://java-lang.github.io/awesome-java)

---

### Table of Contents

- [About The Project](#about-the-project)
- [Features and Architecture](#Features-and-Architecture)
- [Project Demo](#project-demo)
- [Main Project Files](#main-project-files)
- [License](#license)
- [Author Info](#author-info)

---

## About The Project


This program is used to steal data from open HTTP connection in any network. We just need to be present in the network to steal it!
Working procedures:
1. First the pcapCapture.cpp is called to capture the data in an open HTTP connection. It captures all the packets sending and receving in the connection. Then it writes all the packets in a user-specified file.
2. After caputuring the files the pcapAnalyze.cpp is called. It analyzes the packets gathers all the packets from the same connection in order. Then we can save the result in a user-specfied file and see the results. Thus the steal is complete!
3. After that the data packets are sorted according to their source IP adress, destination IP adress, source port number, destination port number. Then the packets are placed according to the sequence number.


[![](https://img.shields.io/badge/back%20to%20top-%E2%86%A9-blue)](#Text-Bandit)

---

## Features and Architecture

### Features

- Terminal Program
- Capture data packets
- Store data packets
- Analyze the packets
- Check if there are any open HTTP connection in the network.
---

### Application Architecture

- OS: Linux
- Language: C, C++
- IDE: Visual Studio Code
- Libraries: sys/socket.h

[![](https://img.shields.io/badge/back%20to%20top-%E2%86%A9-blue)](#Text-Bandit)

---

## Project Demo

### Member Application Screenshots

---

<table style="width:100%">
  <tr>
    <th>Output Page 1</th>
  </tr>
  <tr>
    <td><img src="Demo/1.png"/></td>
  </tr>
  <tr>
    <th>Output Page 2</th>
  </tr>
  <tr>
    <td><img src="Demo/2.png"/></td>
  </tr>
  <tr>
    <th>Output Page 3</th>
  </tr>
  <tr>
    <td><img src="Demo/3.png"/></td>
  </tr>
  <tr>
    <th>Output Page 4</th>
  </tr>
  <tr>
    <td><img src="Demo/4.png"/></td>
  </tr>
  
</table>

[![](https://img.shields.io/badge/back%20to%20top-%E2%86%A9-blue)](#Text-Bandit)

---

## Main Project Files
*For detailed project code overview go inside the "Code" folder or click [here](https://github.com/PritomKumar/SPLproject-1/tree/master/Code).*


[![](https://img.shields.io/badge/back%20to%20top-%E2%86%A9-blue)](#Text-Bandit)

---

## License

```
MIT License

Copyright (c) 2021 PritomKumar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

[![](https://img.shields.io/badge/back%20to%20top-%E2%86%A9-blue)](#Text-Bandit)

---

## Author Info

- Linkedin - [Linked In](https://www.linkedin.com/in/pritomkumar/fr)
- Website - [Pritom Kumar Das](https://sites.google.com/view/pritom-kumar-das/)

[![](https://img.shields.io/badge/back%20to%20top-%E2%86%A9-blue)](#Text-Bandit)
