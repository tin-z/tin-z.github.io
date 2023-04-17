---
layout: post
title:  "Finding vulnerabilities on *Unix kernel with Coccinelle and hacker1"
categories: [coccinelle, vuln_research, kernel]
author: Altin (tin-z)


---

## Intro ##
In this post i will introduce brief concepts regarding variant analysis and
coccinelle. Then i will show how i was able to perform such analyses on real
case scenarios.

- The objective was to perform code pattern and find similar vuln to the [https://hackerone.com/reports/1350653](https://hackerone.com/reports/1350653) one, which is a heap overflow

   * ps4/5 kernel is based on netbsd 9

---

## Some knowledge ##

### Variant analysis ###
Variant analysis is a technique for code analysis which we can use to find
vulnerabilities inside our source code. The tool behind makes a set of graph
representation structure out of the source code. Then users could query those
graphs and find common code pattern associating to it common class of
vulnerabilities. Finally we match those set of rules with our future source
code projects and make "profits".

In variant analysis, a code pattern is abstracted using a logical
representation of the code. We can then use this representation to identify
similar code patterns in other source code.


### Coccinelle ###

Coccinelle is a source code analysis tool having in mind *Unix kernel source
codes. Its syntax is simple, and it uses graph representations to analyze the
code. In addition to code and variant analysis, Coccinelle can automate
program patching by using the patch notation. In summary, Coccinelle is a
versatile tool that can help with source code analysis and patching.


Semantic patch language (SmPL) is the language used by coccinelle to query the source code.
 * A rule does start with the notation `@@` or `@<name-rule>@`
 * Inside `@@` notation we have metavariables
 * Following that there's the code pattern matching

```smpl

@name_function@

// declare variable 'e1'
expression e1;

// declare variable 'e2' which is a pointer
expression * e2;

// constant value 'c'
constant c;

// type
type T;

// position code/data
position p1;
@name_function@

// from here there's the code pattern matching part
- T e1 = well_known_function(...);
+ T * e2 = well_known_function(...);
```

Inside the code pattern matching we declare the rule as follow :

 * `-` match and remove this line
 * `+` match the rule above and add this line after
 * `*` if the code is matched print this line to stdout
 * `(` if the line starts with `(` and in the line below we have the operator or `|`, then we are saying to coccinelle to match any of the following line in or mode
 * `...` whatever there's after the code matched above. This notation can also be used inside a function which we are not interested in the arguments
 * `?` when we have '?' at the begining of the line, it means the matching is optional
 * `<... ...>` to define a block over what can be matched and modified more than once.

<br />

**Example 1**

Find function calling kzalloc inside a single file, or directory with the `--dir` parameter

```
// comment
// usage: spatch --sp-file ./ex2.cocci --dir <path>


@cfu@
expression arg1, arg2;
@@

* kzalloc(arg1, arg2);

```

 - Coccinelle does offer also a python interface.

<br />

**Example 2**

Find kzalloc calls, and print output the python interface.

```
// comment
// usage: spatch --sp-file ./ex2.cocci --dir <path>


@cfu@
expression * e;
expression arg1, arg2;
type T;
position p1;
@@

* T * e = (T *) kzalloc@p1(arg1, arg2);


@script:python@
p1 << cfu.p1;
@@
l1 = p1[0].line
print("kzalloc on line: {}".format(l1))
```

<br />

**external resources**
 
 More material:

 - [Julia Lawall: An Introduction to Coccinelle Bug Finding - video](https://www.youtube.com/watch?v=buZrNd6XkEw), [pdf](https://coccinelle.gitlabpages.inria.fr/website/papers/tutorial.pdf)

 - [Coccinelle quickstart - blog](https://lwn.net/Articles/315686/)

 - [Case study: Searching for a vulnerability pattern in the Linux kernel - blog](https://a13xp0p0v.github.io/2019/08/10/cfu.html)

 - [Kernel Exploitationvia Uninitialized Stack - doc](https://outflux.net/slides/2011/defcon/kernel-exploitation.pdf)

 - [coccinelle_exercises repo](https://github.com/tin-z/coccinelle_exercises/tree/main/advanced_queries)


<br />

**Final tips for working with Coccinelle:**

 - Start with simple semantic patches that match common cases.
 - Develop incrementally by restricting the semantic patch to reduce false positives.
 - Instead of creating a single complex rule, split it into multiple rules to improve accuracy and scripting.

By following these tips, you can improve the effectiveness and efficiency of your Coccinelle analyses.


---

## Start ##

 - The objective was to perform code pattern and find similar vuln to the [https://hackerone.com/reports/1350653](https://hackerone.com/reports/1350653) ones, which is a heap overflow

    * ps4 is based on netbsd 9


<p align ="center">
  <img src="/files/2022-10-07/1.jpg">
</p>

<br />


 - The vulnerability in the code is caused by a failure to check the size of user input before copying it to a "mbuffer" struct.

 - The "mbuffer" is returned from the call to MCLGET, which returns a fixed-sized "mbuff" with a size of MCLBYTES bytes.

 - After applying the patch, we compared the source code before and after and noted that a compare statement was added.


```
...
  if (<len> >= MCLBYTES)
...
  if (<len> > MHLEN) { 
...
  <copy from user-controlled-input>
```

Our goal is to identify all MCLGET calls in the code that lack a length
comparison. To achieve this, we need to write a rule that matches each MCLGET
call and saves its position. By identifying these calls, we can then ensure
that the length comparison is added to prevent vulnerabilities caused by
copying user input to a fixed-size buffer. We do it like so


```
@r1@
position p1;
@@
MCLGET@p1(...)
```

After identifying the MCLGET calls, we need to match the patched scenario
 - Note: `exists` flag is inserted after the rule name to instruct coccinelle to match only the exact code patterns

```
@r2 exists@
identifier f;

// take the same position matched by rule 'r1'
position r1.p1;

expression e;
statement S1;
@@

(
if (e > MCLBYTES)
  S1
|
if (e >= MCLBYTES)
  S1
|
if (e <= MCLBYTES)
  S1
)

...

MCLGET@p1(...)
```

 Finally write a rule excluding all 'r2' cases and get the function exposing such behavior
 
```
@result depends on (!r2) @
position r1.p1;
position p2;
identifier f;
@@

f@p2(...)
{
  ...  when any
* MCLGET@p1(...)
  ...  when any
}

@script:python depends on result@
f << result.f;
p1 << r1.p1;
@@
l1 = p1[0]
print("MCLGET called by function '{}' at line: {}:{}".format(f, l1.file, l1.line))
```

 - The final result can be found at [https://github.com/tin-z/coccinelle_exercises/tree/main/advanced_queries/5-find_vuln_ps4](https://github.com/tin-z/coccinelle_exercises/tree/main/advanced_queries/5-find_vuln_ps4)


