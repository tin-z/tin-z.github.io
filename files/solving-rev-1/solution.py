import angr
import claripy
import utils
import subprocess


user_arg = claripy.BVS("user_arg", 0x20*8)
flg_add_constraints = False

def add_constraints(state, user_arg) :
  for byte in user_arg.chop(8):
    state.add_constraints(byte >= ' ') # '\x20'
    state.add_constraints(byte <= '~') # '\x7e'
    state.add_constraints(byte != 0) # null

def inject_symbol(state):
  global user_arg
  buffer_addr = state.regs.rdi
  print("Buffer:", buffer_addr)
  state.memory.store(buffer_addr, user_arg)
  if flg_add_constraints :
    add_constraint(state, user_arg)
  return utils.ret0_x64(state)


# Solver
def angr_solver(proj_name) :
  binary = utils.r2Ctf(proj_name, symbols=["main", "fgets"])
  proj = angr.Project(proj_name, auto_load_libs=False)
  main_obj = proj.loader.main_object
  base_address = main_obj.min_addr
  
  hooks = [ (base_address + x, utils.ret_nops, length) for x,length in binary.offsets['patch']  ]
  for x, ff, y in hooks:
    if (x - base_address) == binary.offsets["fgets"] :
      proj.hook(x, inject_symbol)
    else :
      proj.hook(x, ff, length=y)

  state = proj.factory.entry_state(addr=base_address+binary.offsets['main'])
  simgr = proj.factory.simulation_manager(state)
  simgr.explore(find=[base_address+x for x in binary.offsets['find']], avoid=[base_address+x for x in binary.offsets['avoid']])

  return simgr


if __name__ == "__main__" :
  proj_name = "angrmanagement"
  simgr = angr_solver(proj_name)
  password = simgr.found[0].solver.eval(user_arg, cast_to=bytes)
  # password = '<#P(J\xb9ZmT[$D5\x06X` hbAd\x880(`.+?@ACj'
  print("Password: {}".format(password))

  proc = subprocess.Popen("./"+proj_name, stderr=subprocess.PIPE, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  stdout, stdin = proc.stdout, proc.stdin
  stdin.write(password + "\n")
  print( "".join(stdout.readlines()) )



