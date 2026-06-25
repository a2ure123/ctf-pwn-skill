#!/usr/bin/env python3
from pwn import *
import os

BIN = args.BIN or './<target-elf>'
context.binary = elf = ELF(BIN)
context.log_level = 'debug' if args.DEBUG else 'info'

libc = ELF('./libc.so.6', checksec=False) if os.path.exists('./libc.so.6') else None
ld = './ld-linux-x86-64.so.2'
HOST = args.HOST or '127.0.0.1'
PORT = int(args.PORT or 1337)

gdbscript = '''
set pagination off
set disassemble-next-line on
# b *main
continue
'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if libc and os.path.exists(ld):
        io = process([ld, '--library-path', '.', elf.path])
    else:
        io = process([elf.path])
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def choice(n):
    io.sendlineafter(b'> ', str(n).encode())

def add(size, data=b'A'):
    choice(1)
    io.sendlineafter(b'Size:', str(size).encode())
    io.sendafter(b'Data:', data)

def edit(idx, data):
    choice(2)
    io.sendlineafter(b'Index:', str(idx).encode())
    io.sendafter(b'Data:', data)

def show(idx):
    choice(3)
    io.sendlineafter(b'Index:', str(idx).encode())

def delete(idx):
    choice(4)
    io.sendlineafter(b'Index:', str(idx).encode())

def u64leak(data):
    return u64(data.ljust(8, b'\x00'))

io = start()

# TODO: adapt wrappers and implement one stage at a time.

io.interactive()
