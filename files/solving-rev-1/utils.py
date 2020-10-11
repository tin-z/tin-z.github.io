import r2pipe
import re

# R2 tasks
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


# Symbolic utils
def ret0_x64(state):
  state.regs.rax = 0
  state.regs.rip = state.mem[state.regs.rsp].uint64_t.resolved
  state.regs.rsp = state.regs.rsp + 8

def ret0_x86(state):
  state.regs.eax = 0
  state.regs.eip = state.mem[state.regs.esp].uint32_t.resolved
  state.regs.esp = state.regs.esp + 4

def ret0_armel(state):
  state.regs.r0 = 0
  state.regs.pc = state.regs.lr
  state.regs.lr = state.mem[state.regs.r11].uint32_t.resolved

def get_right_hook(arch_now):
  archs = {"<Arch X86 (LE)>":ret0_x86, "<Arch AMD64 (LE)>":ret0_x64, "<Arch ARMEL (LE)>":ret0_armel}
  try: 
    rets = archs[arch_now]
  except:
    raise Exception("The Arch {0} is not supported\nYou can implement it by yourself and than update the archs list")
  return rets

def ret_nops(state):
  pass


