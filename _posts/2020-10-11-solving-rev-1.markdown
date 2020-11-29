---
layout: post
title:  "Solving reverse engineering challenges in a CTF - r2 & angr 101"
---

## Intro ##

The idea is that you read the bullet point text and then you replicate the associated figure.
Before reading the next point, you should reason on what you have, and what should be the next steps to follow.
Each point starts with some previous reasoning.


#### Requirements ####
 - some basic knowledge about binary files, and assembly
 - [radare2](https://github.com/radareorg) and [angr](https://angr.io/) are present in our test environment

<p align="center">
  <img width="50%" height="50%" src="/files/solving-rev-1/ctf_rev_cheatsheet.png">
</p>

<br />

## Start ##

We have the following binary file: [angrmanagement](/files/solving-rev-1/angrmanagement)

We immagine that the binary file is running remotely and so we can't do patching/debugging tricks to get the flag.


 - We start with some basic static analysis by using radare2 (r2). You can find some r2 cheatsheet [here](https://gist.github.com/tin-z/b80498d4ded2d55a74b0372b10653910)
<p align="center">
  <img src="/files/solving-rev-1/t1.png">
</p>

<br />

 - Nothing strange till here. We print the imported functions and printable strings
<p align="center">
  <img src="/files/solving-rev-1/t2.png">
</p>

<br />

 - As we can see, there's nothing suspicious here, it sems a classical reverse challenge of a ctf. Before we start executing the binary on docker or on a clean VM, we do some checking of the main function
<p align="center">
  <img src="/files/solving-rev-1/t3.png">
</p>

<br />

 - [endbr64](https://stackoverflow.com/questions/56905811/what-does-endbr64-instruction-actually-do) is a typical instruction breaking some binary analysis tools, such as angr. After that, we get the [control flow graph](https://www2.cs.arizona.edu/~collberg/Teaching/453/2009/Handouts/Handout-15.pdf) (CFG), we summarize the new concepts here:
   - The CFG is composed of basic blocks, more precisally, we refer to the path that links together them
   - Basic block is a blob of assembly instructions, that are followed by a Change of Flow Instruction (COFI), such as jmp, call, and ret.
   - The Control flow executed (CFE) is a subset of the CFG, in the sense, it refers to a control flow we captured by executing the program

<br />

 - We type `VV` for going in a graph mode, then we should see the screen following below (to move on the graph, use the arrow keys or 'h','j','k','l' if you're familiar with vim)
<p align="center">
  <img src="/files/solving-rev-1/t4.png">
</p>

<br />
 
 - By looking at the strings we note that the program is asking us to insert some password. Nothing strange till here, we go further
<p align="center">
  <img src="/files/solving-rev-1/t5.png">
</p>

<br />

 - The name labels of the functions are self-explanatory because of the debug symbols. We can already say that after we insert the input, then the program will do a comparison of the length of the string, and if successful, then the other checks.
   Now run it !
<p align="center">
  <img src="/files/solving-rev-1/t6.png">
</p>

<br />

 - We go back to graph mode, we look the assembly in 'sym.check_len' function.
   We can directly jump to a function which is called in our graph mode, by pressing the keyword commented just after the operand, that in my case is `od` .
   For more commands that can be invoked in graph mode, we can use the help menu by pressing `?` , and the `q` to exit.
<p align="center">
  <img src="/files/solving-rev-1/t7.png">
</p>

<br />

 - The instruction `cmp rax, 0x20` changes the status of register eflags, then `sete al` will set to 1 register `al` if the zero flag is 0.
   So now we know the password must be 0x20 byte long. To go backward in graph mode, press `x` and then the enter key
<p align="center">
  <img src="/files/solving-rev-1/t8.png">
</p>
<p align="center">
  <img src="/files/solving-rev-1/t9.png">
</p>

<br />

 - Basically we have 32 functions that must be true, and so their return value, rax, must be greater than zero. In fact, after each check function there's a `test al, al` instruction that sets to 1 the zero flag if al==0, and so `jz` instruction will jump if the zero flag is set.
<p align="center">
  <img src="/files/solving-rev-1/t10.png">
</p>
<p align="center">
  <img src="/files/solving-rev-1/t11.png">
</p>

<br />

 - The left path prints the content of the 'flag.txt' file. We reverse the check functions, starting with `check_0` function
<p align="center">
  <img src="/files/solving-rev-1/t12.png">
</p>

<br />

 - These comparisons show us the values that cannot be present in our input, we can summary `check_0` function as follows:
   - ` input[15] != 'h' and input[25] != '|' and input[27] != '>' `

   We inspect the `check_1` function.
<p align="center">
  <img src="/files/solving-rev-1/t13.png">
</p>

<br />

 - Now, we can note the binary is obfuscated, and we identify his taxonomy of obfuscation to progress more quickly. We inspect the last check function `check_31`
<p align="center">
  <img src="/files/solving-rev-1/t15.png">
</p>
<p align="center">
  <img src="/files/solving-rev-1/t14.png">
   The figure is taken from <a href="https://github.com/malrev/ABD">here</a>
</p>

<br />

 - It sems we have some encode literals and arithmetic obfuscations. We can solve them by using dataflow analysis techniques or symbolic execution, whether we can control the path grow, we have the following informations, already:
   1. The length of the string must be 32 byte, and starting from the main function, it is located at rbp-0x30 address of the stack
   2. We must avoid to jump the offset 0x2347, and instead follow the path to reach 0x2359 offset
   3. The instruction `je 0x2347` is 6 byte long, and after each of them, there's a basic block that we want to match in our path
   4. The instruction `endbr64` must be patched/hooked
   5. The function main has offset 0x206f

<br />

 - We write some python to automate the 2,3,4,5 points ([utils.py](/files/solving-rev-1/utils.py)). We could do it in angr, as well. 

{% highlight python %}
import r2pipe
import re

class r2Ctf(r2pipe.open_sync.open):
   
  def __init__(self, binary_name, symbols=[]):
    super(r2Ctf,self).__init__(binary_name)
    self.binary_name = binary_name
    self.symbols = symbols
    self.__init_obj()
  
  def __init_obj(self):
    self.cmd('aa')
    self.offsets=dict()
    self.offsets['find'] = [0x2359]  #+ [ x["offset"] + x["len"] for x in self.cmdj('/aaj je 0x2347') ]
    self.offsets['avoid'] = [0x2347]
    self.offsets['patch'] = [(0x1fff,4)] + [ (x["offset"], x["len"]) for x  in self.cmdj('/aaj endbr64') ]

    for x in self.cmdj('aflj') :
      match = x['name']
      rets = re.search("^sym\.imp\.(.*)$", match)
      if rets :
        match = rets.group(1)

      if match in self.symbols :
        self.offsets[match] = x["offset"]
   
  def __str__(self):
    return  "Binary: {}\n".format(self.binary_name)

{% endhighlight %}

<br />

 - Good, now we write some script for angr, read the comments in the code for more explanations or the [official docs](https://docs.angr.io/core-concepts/toplevel)

{% highlight python %}

import angr
import claripy
import utils

proj_name = "angrmanagement"
binary = utils.r2Ctf(proj_name, symbols=["main", "fgets"])

# Initialize Project, generate CFG
proj = angr.Project(proj_name, auto_load_libs=False)

# Get base address from virtual loader
main_obj = proj.loader.main_object
base_address = main_obj.min_addr

{% endhighlight %}

 - The symbolic execution in angr is composed of one 'SimulationManager' object and many 'SimState' that we get from traversing the basic blocks.
   The state gives us access to the registers, memory, and so it is a sort of cool.
   Now, if we want to hook something in angr we need the state reached as input

{% highlight python %}

def ret0_x64(state):
  state.regs.rax = 0
  state.regs.rip = state.mem[state.regs.rsp].uint64_t.resolved
  state.regs.rsp = state.regs.rsp + 8

def ret_nops(state):
  pass

{% endhighlight %}

 - Now we want to map our symbolic variable instead of some memory address mapped in the current state.
   In this case, the memory address we want is in the stack, so we must patch it dynamically by executing till a point, or simply by hooking again ;)
   And so we hook the fgets@plt, and get the address of the buffer from the rdi register

{% highlight python %}

user_arg = claripy.BVS("user_arg", 0x20*8) #*
flg_add_constraints = False

def add_constraints(state, user_arg) :
  for byte in user_arg.chop(8):
    state.add_constraints(byte >= ' ')  # \x20
    state.add_constraints(byte <= '~')  # \x7e
    state.add_constraints(byte != 0)    # NULL

def inject_symbol(state):
  global user_arg
  buffer_addr = state.regs.rdi
  print("Buffer:", buffer_addr)
  state.memory.store(buffer_addr, user_arg)
  if flg_add_constraints :
    add_constraint(state, user_arg)
  return utils.ret0_x64(state)

# Here we hook/patch
hooks = [ (base_address + x, utils.ret_nops, length) for x,length in binary.offsets['patch']  ]
for x, ff, y in hooks:
  if (x - base_address) == binary.offsets["fgets"] :
    proj.hook(x, inject_symbol)
  else :
    proj.hook(x, ff, length=y)

{% endhighlight %}

 - Then we start symbolic execution

{% highlight python %}

state = proj.factory.entry_state(addr=base_address+binary.offsets['main'])
simgr = proj.factory.simulation_manager(state)

# this will take time, give a look to the memory
simgr.explore(find=[base_address+x for x in binary.offsets['find']], avoid=[base_address+x for x in binary.offsets['avoid']])

password = simgr.found[0].solver.eval(user_arg, cast_to=bytes)
print("Password: {}".format(password))

proc = subprocess.Popen("./angrmanagement", stderr=subprocess.PIPE, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
stdout, stdin = proc.stdout, proc.stdin
stdin.write(password + "\n")
print( "".join(stdout.readlines()) )

{% endhighlight %}

<br />

 - After executing [solution.py](/files/solving-rev-1/solution.py), [utils.py](/files/solving-rev-1/utils.py) we get the password:

   '```<#P(J\xb9ZmT[$D5\x06X` hbAd\x880(`.+?@ACj```'

<p align="center">
  <img src="/files/solving-rev-1/t16.png">
</p>

<br />



