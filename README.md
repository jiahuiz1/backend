# 02-While: Monadic State and Parsing (240 points)

## Overview

The overall objective of this assignment is to get some 
experience using the *State monad* and *Parser Combinators*.

The assignment is in the following files that you will modify

- [Eval.hs](/src/CSE230/Eval.hs)
- [Parse.hs](/src/CSE230/Parse.hs)

The following file contains useful definitions but does not need to be modified:

- [Types.hs](/src/CSE230/Types.hs)

Finally, there are a`Test.hs` has some sample tests to be used  
to check your assignments before submitting.

- [test/Test.hs](/test/Test.hs)

You should **only modify** the parts of the files which say:

```haskell
error "fill this in"
```

with suitable Haskell implementations. 

**You are free to write and use any helper functions.**

## Instructions

### Assignment Testing and Evaluation


Most of the points, will be awarded automatically, by
**evaluating your functions against a given test suite**.

[Tests.hs](/test/Test.hs) contains a very small suite
of tests which gives you a flavor of of these tests.
When you run

```shell
$ make test
```

Your last lines should have

```
All N tests passed (...)
OVERALL SCORE = ... / ...
```

**or**

```
K out of N tests failed
OVERALL SCORE = ... / ...
```

**If your output does not have one of the above your code will receive a zero**

If for some problem, you cannot get the code to compile,
leave it as is with the `error "fill me in"` with your 
partial solution enclosed below as a comment.

The other lines will give you a readout for each test.
You are encouraged to try to understand the testing code,
but you will not be graded on this.

### Submission Instructions

To submit your code, just do:

```bash
$ make turnin
```
### Collaborators

As before please add the name of any collaborator in the file `COLLABORATORS.md`

## Problem 1: An Evaluator for WHILE (160 points)

Fill in the missing code in [Eval.hs](/src/CSE230/Eval.hs)

## Problem 2: A Parser for WHILE (80 points)

Fill in the missing code in [Parse.hs](/src/CSE230/Parse.hs)

