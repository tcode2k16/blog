---
title: "A Hands-on Introduction to Coq"
date: 2020-11-22T21:00:41Z
draft: false
tags: [
  "ctf",
  "cyber-security",
  "write-up",
  'coq'
]
description: My journey in learning coq and solving the DragonCTF 2020 challenge "babykok"
---

# Introduction

I have been doing quite a bit of functional programming in haskell for the past few months as a part of my university study. That's why I am delighted to see a relevant challenge come up in this year's DragonCTF.

The challenge involves proving a few mathematical theorems using [Coq](https://coq.inria.fr/), a functional programming language / interactive theorem prover. I have heard of Coq before but have never got the time to learn it. This challenge became the perfect opportunity for me to get to know it and write a hands-on introduction about it :)

# Warmup

The challenge starts out with a few easy proofs for us to first get a hang of Coq.


```coq
Theorem problem0: forall A B, A \/ B -> B \/ A.

1 subgoal (ID 3)
  
  ============================
  forall A B : Prop, A \/ B -> B \/ A
```

In this proof, we are asked to prove that for two propositions, (A or B) is the same as (B or A) which is quite trivial.

We can try it first in our local environment using the Coq interactive session `coqtop` in the terminal:

```coq
$ coqtop
Welcome to Coq 8.12.1 (November 2020)

Coq < Theorem problem0: forall A B, A \/ B -> B \/ A.
1 subgoal
  
  ============================
  forall A B : Prop, A \/ B -> B \/ A

problem0 < 
```

As you can see we are greeted with a list of subgoals that we need to validate once we input the theorem that we are trying to prove.

We can first introduce A, B and move them into our context using the `intros` command:

```coq
problem0 < intros A B.
1 subgoal
  
  A, B : Prop
  ============================
  A \/ B -> B \/ A
```

What this does is effectively give a name to A and B and add that to the context. We can certainly use other names for the two propositions as well. Another point to note is that all coq commands need to end with a `.` just like how every line in C needs to end with `;`.

The next step would be to again introduce our hypothesis that `A \/ B`:

```coq
problem0 < intros H.
1 subgoal
  
  A, B : Prop
  H : A \/ B
  ============================
  B \/ A
```

Now with our named propositions A and B and hypothesis H, we can start proving our goal that `B \/ A`.

We can use the `destruct` keyword or tactic as it's commonly called in Coq. What it does is that it breaks down hypothesis `H : A \/ B` into two cases: one with `H: A` and one with `H : B` and we can prove those two separately as two subgoals:


```coq
problem0 < destruct H.
2 subgoals
  
  A, B : Prop
  H : A
  ============================
  B \/ A

subgoal 2 is:
 B \/ A

problem0 < 
```

Next, we use `right` to suggest that we want to prove that the right-hand side of `B \/ A` is true. Because it is an OR statement, we only need to show that one of the two is true, not both. Similarly, `left` is another valid tactic as well.

```coq
problem0 < right.
2 subgoals
  
  A, B : Prop
  H : A
  ============================
  A

subgoal 2 is:
 B \/ A
```

Now, we can see that our hypothesis H matches the statement we are trying to prove exactly. We can use `exact H` to finish this sub-proof:

```coq
problem0 < exact H.
1 subgoal
  
  A, B : Prop
  H : B
  ============================
  B \/ A
```

Now, we only have 1 subgoal left which is when `H: B`. As you can already tell, this is very similar to our last case. To not repeat ourselves, we can use the `auto` tactic to solve this case automatically:

```coq
problem0 < auto.
No more subgoals.
```

Just like that, we finished our first proof in Coq! 🎉🎉🎉

The next few proofs are similar in difficulty:

```coq
Coq < Theorem problem0: forall A B,  ((((A -> B) -> A) -> A) -> B) -> B.
1 subgoal
  
  ============================
  forall A B : Type, ((((A -> B) -> A) -> A) -> B) -> B

problem0 < intros A B.
1 subgoal
  
  A : Type
  B : Type
  ============================
  ((((A -> B) -> A) -> A) -> B) -> B

problem0 < auto.
No more subgoals.
```
> This proof is so simple that `auto` can just handle it by itself.

```coq
Coq < Theorem problem0: forall (m n: nat),  m + n = n + m.
1 subgoal
  
  ============================
  forall m n : nat, m + n = n + m

problem0 < intros m n.
1 subgoal
  
  m, n : nat
  ============================
  m + n = n + m

problem0 < induction m.
2 subgoals
  
  n : nat
  ============================
  0 + n = n + 0

subgoal 2 is:
 S m + n = n + S m

problem0 < simpl.         
2 subgoals
  
  n : nat
  ============================
  n = n + 0

subgoal 2 is:
 S m + n = n + S m

problem0 < trivial.
1 subgoal
  
  m, n : nat
  IHm : m + n = n + m
  ============================
  S m + n = n + S m

problem0 < simpl.
1 subgoal
  
  m, n : nat
  IHm : m + n = n + m
  ============================
  S (m + n) = n + S m

problem0 < rewrite IHm.
1 subgoal
  
  m, n : nat
  IHm : m + n = n + m
  ============================
  S (n + m) = n + S m

problem0 < trivial.
No more subgoals.

problem0 < 
```
> This proof of the commutativity of addition is a bit more involved. We used the `induction` tactic on `m` and later rewrote `(m+n)` as `(n+m)` in the inductive case utilizing the inductive hypothesis.


```coq
Coq < Theorem problem0: forall A B C D: Prop,(A->B)/\(C->D)/\A/\C -> B/\D.
1 subgoal
  
  ============================
  forall A B C D : Prop, (A -> B) /\ (C -> D) /\ A /\ C -> B /\ D

problem0 < intros A B C D.
1 subgoal
  
  A, B, C, D : Prop
  ============================
  (A -> B) /\ (C -> D) /\ A /\ C -> B /\ D

problem0 < intros H.
1 subgoal
  
  A, B, C, D : Prop
  H : (A -> B) /\ (C -> D) /\ A /\ C
  ============================
  B /\ D

problem0 < destruct H.
1 subgoal
  
  A, B, C, D : Prop
  H : A -> B
  H0 : (C -> D) /\ A /\ C
  ============================
  B /\ D

problem0 < destruct H0.
1 subgoal
  
  A, B, C, D : Prop
  H : A -> B
  H0 : C -> D
  H1 : A /\ C
  ============================
  B /\ D

problem0 < destruct H1.
1 subgoal
  
  A, B, C, D : Prop
  H : A -> B
  H0 : C -> D
  H1 : A
  H2 : C
  ============================
  B /\ D

problem0 < apply H in H1. apply H0 in H2.
1 subgoal
  
  A, B, C, D : Prop
  H : A -> B
  H0 : C -> D
  H1 : B
  H2 : C
  ============================
  B /\ D

1 subgoal
  
  A, B, C, D : Prop
  H : A -> B
  H0 : C -> D
  H1 : B
  H2 : D
  ============================
  B /\ D

problem0 < split.
2 subgoals
  
  A, B, C, D : Prop
  H : A -> B
  H0 : C -> D
  H1 : B
  H2 : D
  ============================
  B

subgoal 2 is:
 D

problem0 < assumption.
1 subgoal
  
  A, B, C, D : Prop
  H : A -> B
  H0 : C -> D
  H1 : B
  H2 : D
  ============================
  D

problem0 < auto.
No more subgoals.
```
> Few noteworthy points in this proof include:

> - We can use the `assumption` tactic in place of `exact ???` when the thing we are trying to prove is already in our context
> - When we have `A And B`, we can use `split` to break it into two cases of proving `A` and proving `B`. 
> - Just like how equality can be used to rewrite statements using `rewrite`, implications can be applied to statements using `apply`
> - The `in` keyword allows us to manipulate hypotheses rather than our goal.
 
```coq
Coq < Theorem problem0: forall (C:Prop) (T:Set) (B: T -> Prop), (exists x : T, C -> B x) -> C -> exists x : T, B x.
1 subgoal
  
  ============================
  forall (C : Prop) (T : Set) (B : T -> Prop),
  (exists x : T, C -> B x) -> C -> exists x : T, B x

problem0 < intros C T B H.
1 subgoal
  
  C : Prop
  T : Set
  B : T -> Prop
  H : exists x : T, C -> B x
  ============================
  C -> exists x : T, B x

problem0 < destruct H.
1 subgoal
  
  C : Prop
  T : Set
  B : T -> Prop
  x : T
  H : C -> B x
  ============================
  C -> exists x0 : T, B x0

problem0 < exists x.
1 subgoal
  
  C : Prop
  T : Set
  B : T -> Prop
  x : T
  H : C -> B x
  H0 : C
  ============================
  B x

problem0 < apply H in H0.
1 subgoal
  
  C : Prop
  T : Set
  B : T -> Prop
  x : T
  H : C -> B x
  H0 : B x
  ============================
  B x

problem0 < exact H0.
No more subgoals.
```
> Most of the tactics in the proof are introduced before with the exception of `exists` which simply states that a variable in our context satisfies the goal that we are trying to prove.


```coq
Coq < Theorem problem0: forall b1 b2, negb (b1 && b2) = orb (negb b1) (negb b2).
1 subgoal
  
  ============================
  forall b1 b2 : bool, negb (b1 && b2) = (negb b1 || negb b2)%bool

problem0 < intros b1 b2.
1 subgoal
  
  b1, b2 : bool
  ============================
  negb (b1 && b2) = (negb b1 || negb b2)%bool

problem0 < destruct b1.
2 subgoals
  
  b2 : bool
  ============================
  negb (true && b2) = (negb true || negb b2)%bool

subgoal 2 is:
 negb (false && b2) = (negb false || negb b2)%bool

problem0 < simpl.
2 subgoals
  
  b2 : bool
  ============================
  negb b2 = negb b2

subgoal 2 is:
 negb (false && b2) = (negb false || negb b2)%bool

problem0 < trivial.
1 subgoal
  
  b2 : bool
  ============================
  negb (false && b2) = (negb false || negb b2)%bool

problem0 < simpl.
1 subgoal
  
  b2 : bool
  ============================
  true = true

problem0 < trivial.
No more subgoals.
```
> This last one is also quite easy to prove. We have two boolean values which only lead to four cases. Using `destruct`, we can divide-and-conquer each of the cases.

# Fun with Math

With the easy ones out of the way, we face a slightly more challenging question:

```coq
Coq < Require Import Arith.Mult.
Theorem math_problem: forall m n, (n + m) * (n + m) =  n * n + 2 * n * m + m * m.

Coq < 1 subgoal
  
  ============================
  forall m n : nat, (n + m) * (n + m) = n * n + 2 * n * m + m * m
```

Here we can see that [Arith.Mult.](https://www.cs.princeton.edu/courses/archive/fall07/cos595/stdlib/html/Coq.Arith.Mult.html) has been imported suggesting that we might need to use some of its properties.

Again, we start with introducing the variables:

```coq
math_problem < intros m n.
1 subgoal
  
  m, n : nat
  ============================
  (n + m) * (n + m) = n * n + 2 * n * m + m * m
```

Then we can use the distributivity of multiplication in `Arith.Mult.` and a few other properties on addition to simplify our expression.

```coq
math_problem < rewrite mult_plus_distr_r.
1 subgoal
  
  m, n : nat
  ============================
  n * (n + m) + m * (n + m) = n * n + 2 * n * m + m * m

math_problem < rewrite mult_plus_distr_l.
1 subgoal
  
  m, n : nat
  ============================
  n * n + n * m + m * (n + m) = n * n + 2 * n * m + m * m

math_problem < rewrite mult_plus_distr_l.
1 subgoal
  
  m, n : nat
  ============================
  n * n + n * m + (m * n + m * m) = n * n + 2 * n * m + m * m

math_problem < simpl.
1 subgoal
  
  m, n : nat
  ============================
  n * n + n * m + (m * n + m * m) = n * n + (n + (n + 0)) * m + m * m

math_problem < rewrite plus_0_r.  
1 subgoal
  
  m, n : nat
  ============================
  n * n + n * m + (m * n + m * m) = n * n + (n + n) * m + m * m

math_problem < rewrite mult_plus_distr_r.
1 subgoal
  
  m, n : nat
  ============================
  n * n + n * m + (m * n + m * m) = n * n + (n * m + n * m) + m * m

math_problem < rewrite plus_assoc.
1 subgoal
  
  m, n : nat
  ============================
  n * n + n * m + m * n + m * m = n * n + (n * m + n * m) + m * m

math_problem < rewrite plus_assoc.        
1 subgoal
  
  m, n : nat
  ============================
  n * n + n * m + m * n + m * m = n * n + n * m + n * m + m * m

```

At this point, what we really need to prove is that `n * m` is the same as `m * n`. We can use `cut` to state that as a hypothesis and prove it later:

```coq
math_problem < cut (n*m=m*n).
2 subgoals
  
  m, n : nat
  ============================
  n * m = m * n ->
  n * n + n * m + m * n + m * m = n * n + n * m + n * m + m * m

subgoal 2 is:
 n * m = m * n

math_problem < intros H. 
2 subgoals
  
  m, n : nat
  H : n * m = m * n
  ============================
  n * n + n * m + m * n + m * m = n * n + n * m + n * m + m * m

subgoal 2 is:
 n * m = m * n

math_problem < rewrite H.
2 subgoals
  
  m, n : nat
  H : n * m = m * n
  ============================
  n * n + m * n + m * n + m * m = n * n + m * n + m * n + m * m

subgoal 2 is:
 n * m = m * n

math_problem < trivial.
1 subgoal
  
  m, n : nat
  ============================
  n * m = m * n

math_problem < apply mult_comm.
No more subgoals.
```

# Proof on Lists

As the last question, we are asked to write a proof about lists:

```coq
Require Import Le.
Section last_stage.
  Variable A : Type.

  Inductive list : Type  := 
   | nil : list
   | cons : A -> list -> list.


  Fixpoint nth (l : list) (n : nat) : option A :=
    match n,l with
      | 0, cons x xs  => Some x 
      | S n, cons _ xs  => nth xs n
      | _, _ => None
    end.

  Fixpoint length (l:list) : nat :=
    match l with
      | nil => 0
      | cons _ xs => 1 + length xs
    end.

Theorem nth_in:  forall (n:nat) (l:list), n < length l -> exists a: A, nth l n = Some a.
```

I struggled a lot with this proof and solved it in the end by referencing [a similar proof](https://github.com/coq/coq/blob/master/theories/Lists/List.v#L468) on the standard list type in coq.

Here is my attempt at it:

```coq
unfold lt. intro n.

induction n as [| n hn].
    
    simpl. intro l.
    
    destruct l.
        simpl. intro H. apply le_Sn_O in H. contradiction.
        simpl. exists a. trivial.

    simpl. destruct l.
        simpl. intros H. apply le_Sn_O in H. contradiction.
        simpl. intros H. apply le_S_n in H. apply hn in H. exact H.
```

The basic idea is to do a nested induction on both the index `n` as well as the list `l`. However, you need to be careful with the order in which you introduce things otherwise Coq will generate inductive hypotheses not strong enough to prove the theorem.

# Summary

I really enjoyed getting to know Coq this weekend and managed to catch a glimpse of the full power of Coq as an interactive theorem prover. I really hope this blog post can inspire more people to try Coq and have some fun with it.

Here are some resources that aided me in the process of learning Coq:

- [Coq cheat sheet](http://www.inf.ed.ac.uk/teaching/courses/tspl/cheatsheet.pdf): A great introduction to all the tactics available in Coq and a clear breakdown of when to use what
- [Theorem proving with Coq](http://flint.cs.yale.edu/cs430/sectionNotes/section1/CoqTutorial.pdf): A wonderful example-based introduction the language that shows the full process of proving things
- [Coq Tactics Index](https://pjreddie.com/coq-tactics/): A more in-depth look at the various tactics with some small tricks mixed in


# Exploit + Flag

If you care about my exploit script and want to see the flag, here you go:

```python
from pwn import *

context.log_level = 'debug'

sh = remote('babykok.hackable.software', 1337)


solves = {
  'forall A B : Type, ((((A -> B) -> A) -> A) -> B) -> B': '''
    intros A B.
    auto.
  ''',

  'forall A B : Prop, A \\/ B -> B \\/ A': '''
    intros A B.
    intros H.
    destruct H.
    right.
    exact H.
    auto.
  ''',

  'forall A B C D: Prop,(A->B)/\\(C->D)/\\A/\\C -> B/\\D.': '''
    intros A B C D.
    intros H.
    destruct H.
    destruct H0.
    destruct H1.
    split.
    apply H.
    exact H1.
    auto.
  ''',


  'forall (C:Prop) (T:Set) (B: T -> Prop), (exists x : T, C -> B x) -> C -> exists x : T, B x.': '''
    intros C T B.
    intros H.
    destruct H.
    exists x.
    apply H.
    exact H0.
  ''',

  'forall (m n: nat),  m + n = n + m.': '''
    intros m n.
    induction m.
    simpl.
    trivial.
    simpl.
    rewrite IHm.
    trivial.
  ''',

  'forall b1 b2, negb (b1 && b2) = orb (negb b1) (negb b2).': '''
    intros b1 b2.
    destruct b1.
    simpl.
    trivial.
    simpl.
    trivial.
  ''',


  'forall m n, (n + m) * (n + m) =  n * n + 2 * n * m + m * m.': '''
    intros M N.
    rewrite mult_plus_distr_r.
    rewrite mult_plus_distr_l.
    rewrite mult_plus_distr_l.
    rewrite plus_assoc.
    cut (2*N*M=N*M+M*N).
    intros H.
    rewrite H.
    rewrite plus_assoc.
    trivial.
    simpl.
    rewrite plus_0_r.
    rewrite mult_plus_distr_r.
    cut (M * N = N * M).
    intros H1.
    rewrite H1.
    trivial.
    apply mult_comm.
  ''',


  'forall (n:nat) (l:list), n < length l -> exists a: A, nth l n = Some a.': '''
    unfold lt.
    intro n.
    induction n as [| n hn].
    simpl.
    intro l.
    destruct l.
    simpl.
    intro H.
    apply le_Sn_O in H.
    contradiction.
    simpl.
    exists a.
    trivial.
    simpl. 
    destruct l.
    simpl.
    intros H.
    apply le_Sn_O in H.
    contradiction.
    simpl.
    intros H.
    apply le_S_n in H.
    apply hn in H.
    exact H.
  ''',
}

while True:
  question = sh.recvuntil('\n> ')
  print question
  for ques in solves:
    ans = solves[ques]

    if ques in question:
      ans = map(lambda x: x.strip(), ans.strip().split('\n'))
      sh.sendline(ans[0])
      for line in ans[1:]:
        sh.sendlineafter('\n> ', line)
      break
  else:
    print question
    sh.interactive()

```

flag: `DrgnS{xxxx_my_c0q_for_4_flag_17bcbc34b7c565a766e335}`